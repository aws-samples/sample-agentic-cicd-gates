import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

spec = importlib.util.spec_from_file_location(
    "prepare_review", pathlib.Path(__file__).with_name("prepare_review.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Offline Test")
        self.policy = self.root / "approved.yaml"
        self.policy.write_text("version: 1\n")
        self.now = datetime(2026, 10, 2, tzinfo=timezone.utc)

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, file, content):
        (self.repo / file).write_text(content)
        self.git("add", file)
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", file)
        return self.git("rev-parse", "HEAD")

    def execution(self, id, revision, status, minutes):
        return {
            "pipelineExecutionId": id, "status": status,
            "startTime": self.now + timedelta(minutes=minutes),
            "lastUpdateTime": self.now + timedelta(minutes=minutes + 1),
            "sourceRevisions": [{"revisionId": revision}],
        }

    def prepare(self, rows, head):
        return module.prepare(
            rows, "current", head, self.policy, self.root / "out", str(self.repo)
        )

    def test_multi_commit_push_includes_earlier_change(self):
        base = self.commit("app.py", "safe\n")
        self.commit("app.py", "unsafe\n")
        head = self.commit("README.md", "documentation\n")
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        result = self.prepare(rows, head)
        self.assertEqual(result["baseline_revision"], base)
        self.assertEqual(set(result["changed_files"]), {"app.py", "README.md"})
        self.assertIn("+unsafe", (self.root / "out/change.diff").read_text())

    def test_failed_revision_cannot_become_baseline(self):
        base = self.commit("app.py", "safe\n")
        head = self.commit("app.py", "unsafe\n")
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("failed", head, "Failed", 5),
                self.execution("current", head, "InProgress", 10)]
        self.assertEqual(self.prepare(rows, head)["baseline_revision"], base)
        self.assertIn("+unsafe", (self.root / "out/change.diff").read_text())

    def test_first_release_reviews_full_tree(self):
        head = self.commit("app.py", "initial code\n")
        result = self.prepare([self.execution("current", head, "InProgress", 10)], head)
        self.assertEqual(result["baseline_kind"], "initial_full_tree")
        self.assertIn("+initial code", (self.root / "out/change.diff").read_text())

    def test_later_success_does_not_move_baseline_mid_execution(self):
        base = self.commit("app.py", "base\n")
        head = self.commit("app.py", "candidate\n")
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("other", head, "Succeeded", 11),
                self.execution("current", head, "InProgress", 10)]
        self.assertEqual(self.prepare(rows, head)["baseline_revision"], base)

    def test_revision_mismatch_fails(self):
        head = self.commit("app.py", "code\n")
        with self.assertRaises(ValueError):
            self.prepare([self.execution("current", "0" * 40, "InProgress", 10)], head)

    def test_missing_current_execution_fails(self):
        head = self.commit("app.py", "code\n")
        with self.assertRaises(ValueError):
            self.prepare([], head)

    def test_missing_baseline_commit_fails(self):
        head = self.commit("app.py", "code\n")
        rows = [self.execution("release", "a" * 40, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare(rows, head)

    def big(self, count, width=60):
        return "".join(f"line {i:06d} {'x' * width}\n" for i in range(count))

    def test_cap_is_three_million_bytes(self):
        self.assertEqual(module.MAX_DIFF_BYTES, 3_000_000)
        self.assertEqual(module.review_chunks.CHUNK_BYTES, 100_000)

    def test_delta_larger_than_one_chunk_is_planned_not_refused(self):
        base = self.commit("app.py", "safe\n")
        self.commit("site-a.js", self.big(3000))
        head = self.commit("site-b.js", self.big(2500))
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        result = self.prepare(rows, head)
        self.assertGreater(result["diff_bytes"], 400_000)
        plan = result["chunk_plan"]
        self.assertGreaterEqual(plan["chunks"], 5)
        self.assertTrue(all(size <= 100_000 for size in plan["chunk_sizes"]))
        self.assertEqual(plan["split_files"], ["site-a.js", "site-b.js"])
        out = self.root / "out"
        doc = json.loads((out / "chunk-plan.json").read_text())
        self.assertEqual(doc["diff_sha256"], result["diff_sha256"])
        self.assertEqual(len(list((out / "chunks").glob("*.diff"))), plan["chunks"])
        self.assertEqual(hashlib.sha256((out / "chunk-plan.json").read_bytes()).hexdigest(),
                         plan["plan_sha256"])

    def test_small_delta_plans_one_chunk(self):
        base = self.commit("app.py", "safe\n")
        head = self.commit("app.py", "candidate\n")
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        plan = self.prepare(rows, head)["chunk_plan"]
        self.assertEqual(plan["chunks"], 1)
        out = self.root / "out"
        self.assertEqual((out / "chunks/0000.diff").read_text(), (out / "change.diff").read_text())

    def test_over_the_cap_refuses_and_writes_nothing(self):
        base = self.commit("app.py", "safe\n")
        head = self.commit("site-a.js", self.big(2000))
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        original = module.MAX_DIFF_BYTES
        module.MAX_DIFF_BYTES = 100_000
        try:
            with self.assertRaisesRegex(ValueError, "review limit"):
                self.prepare(rows, head)
        finally:
            module.MAX_DIFF_BYTES = original
        self.assertFalse((self.root / "out").exists())

    def test_unplannable_delta_refuses_and_writes_nothing(self):
        base = self.commit("app.py", "safe\n")
        head = self.commit("min.js", "x" * 150_000 + "\n")
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        with self.assertRaises(module.review_chunks.PlanError):
            self.prepare(rows, head)
        self.assertFalse((self.root / "out").exists())

    def test_dry_run_builds_the_same_inputs_without_history(self):
        base = self.commit("app.py", "safe\n")
        head = self.commit("site-a.js", self.big(3000))
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        real = self.prepare(rows, head)
        dry = module.dry_run(base[:12], "HEAD", self.policy, self.root / "dry", str(self.repo))
        self.assertTrue(dry["dry_run"])
        self.assertEqual(dry["baseline_kind"], "explicit_dry_run")
        self.assertEqual((dry["baseline_revision"], dry["head_revision"]), (base, head))
        for key in ("diff_sha256", "diff_bytes", "changed_files", "chunk_plan", "policy_sha256"):
            self.assertEqual(dry[key], real[key], key)
        self.assertEqual((self.root / "dry/change.diff").read_bytes(),
                         (self.root / "out/change.diff").read_bytes())



class ApprovedBaselineTests(unittest.TestCase):
    """An operator-approved starting commit, used only when history has no success."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Offline Test")
        self.policy = self.root / "approved.yaml"
        self.policy.write_text("version: 1\n")
        self.now = datetime(2026, 10, 2, tzinfo=timezone.utc)

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, file, content):
        (self.repo / file).write_text(content)
        self.git("add", file)
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", file)
        return self.git("rev-parse", "HEAD")

    def execution(self, id, revision, status, minutes):
        return {
            "pipelineExecutionId": id, "status": status,
            "startTime": self.now + timedelta(minutes=minutes),
            "lastUpdateTime": self.now + timedelta(minutes=minutes + 1),
            "sourceRevisions": [{"revisionId": revision}],
        }

    def approval(self, commit, **changes):
        doc = {"version": 1, "commit": commit, "approved_by": "release-approver",
               "approved_at": "2026-10-31T09:00:00Z",
               "reviewed": "https://example.com/reviews/whole-repo-1"}
        doc.update(changes)
        for key in [k for k, v in changes.items() if v is DROP]:
            del doc[key]
        return self.write(json.dumps(doc).encode())

    def write(self, data):
        path = self.root / "approved-baseline.json"
        path.write_bytes(data)
        return path

    def prepare(self, rows, head, approval=None, version=None):
        return module.prepare(rows, "current", head, self.policy, self.root / "out",
                              str(self.repo), approved_baseline=approval,
                              approved_baseline_version=version)

    def test_approved_commit_is_the_baseline_when_history_has_no_success(self):
        approved = self.commit("app.py", "reviewed once\n")
        head = self.commit("app.py", "candidate\n")
        path = self.approval(approved)
        rows = [self.execution("failed", head, "Failed", 5),
                self.execution("current", head, "InProgress", 10)]
        result = self.prepare(rows, head, path, "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY")
        self.assertEqual(result["baseline_kind"], "approved_baseline")
        self.assertEqual(result["baseline_revision"], approved)
        self.assertEqual(result["changed_files"], ["app.py"])
        diff = (self.root / "out/change.diff").read_text()
        self.assertIn("+candidate", diff)
        self.assertNotIn("+reviewed once", diff)
        self.assertIs(result["approved_baseline_used"], True)
        self.assertEqual(result["approved_by"], "release-approver")
        self.assertEqual(result["approved_at"], "2026-10-31T09:00:00Z")
        self.assertEqual(result["reviewed"], "https://example.com/reviews/whole-repo-1")
        self.assertEqual(result["approval_sha256"],
                         hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(result["approval_version_id"], "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY")
        written = json.loads((self.root / "out/input-metadata.json").read_text())
        self.assertEqual(written["baseline_kind"], "approved_baseline")
        self.assertEqual(written["approval_sha256"], result["approval_sha256"])

    def test_the_version_id_is_optional(self):
        approved = self.commit("app.py", "reviewed once\n")
        head = self.commit("app.py", "candidate\n")
        result = self.prepare([self.execution("current", head, "InProgress", 10)], head,
                              self.approval(approved))
        self.assertEqual(result["baseline_kind"], "approved_baseline")
        self.assertIsNone(result["approval_version_id"])

    def test_history_wins_and_the_unused_approval_is_recorded(self):
        approved = self.commit("app.py", "reviewed once\n")
        released = self.commit("app.py", "released\n")
        head = self.commit("app.py", "candidate\n")
        path = self.approval(approved)
        rows = [self.execution("release", released, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        result = self.prepare(rows, head, path, "v1")
        self.assertEqual(result["baseline_kind"], "last_successful_release")
        self.assertEqual(result["baseline_revision"], released)
        self.assertIs(result["approved_baseline_used"], False)
        self.assertEqual(result["approval_sha256"],
                         hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(result["approval_version_id"], "v1")
        self.assertNotIn("approved_by", result)

    def test_without_a_file_nothing_changes(self):
        head = self.commit("app.py", "initial code\n")
        result = self.prepare([self.execution("current", head, "InProgress", 10)], head)
        self.assertEqual(result["baseline_kind"], "initial_full_tree")
        self.assertNotIn("approved_baseline_used", result)

    def test_a_commit_that_is_not_an_ancestor_is_refused(self):
        root = self.commit("app.py", "root\n")
        self.git("checkout", "-q", "-b", "side")
        side = self.commit("side.py", "elsewhere\n")
        self.git("checkout", "-q", "-")
        head = self.commit("app.py", "candidate\n")
        self.assertNotEqual(root, head)
        with self.assertRaisesRegex(ValueError, "not an ancestor"):
            self.prepare([self.execution("current", head, "InProgress", 10)], head,
                         self.approval(side))
        self.assertFalse((self.root / "out").exists())

    def test_an_unknown_commit_is_refused(self):
        head = self.commit("app.py", "code\n")
        with self.assertRaisesRegex(ValueError, "not in the repository"):
            self.prepare([self.execution("current", head, "InProgress", 10)], head,
                         self.approval("a" * 40))
        self.assertFalse((self.root / "out").exists())

    def test_the_head_itself_may_be_approved(self):
        head = self.commit("app.py", "code\n")
        result = self.prepare([self.execution("current", head, "InProgress", 10)], head,
                              self.approval(head))
        self.assertEqual(result["baseline_revision"], head)
        self.assertEqual(result["changed_files"], [])

    def test_malformed_files_are_refused_even_when_history_would_win(self):
        released = self.commit("app.py", "released\n")
        head = self.commit("app.py", "candidate\n")
        good = {"version": 1, "commit": released, "approved_by": "approver",
                "approved_at": "2026-10-31T09:00:00Z", "reviewed": "whole-repo review 7"}
        def doc(**changes):
            d = {**good, **changes}
            return json.dumps({k: v for k, v in d.items() if v is not DROP}).encode()
        cases = {
            "unknown version": doc(version=2),
            "version as text": doc(version="1"),
            "version as bool": doc(version=True),
            "short sha": doc(commit=released[:12]),
            "upper-case sha": doc(commit=released.upper()),
            "sha not text": doc(commit=1),
            "missing commit": doc(commit=DROP),
            "missing approved_by": doc(approved_by=DROP),
            "missing approved_at": doc(approved_at=DROP),
            "missing reviewed": doc(reviewed=DROP),
            "missing version": doc(version=DROP),
            "empty approved_by": doc(approved_by=""),
            "blank reviewed": doc(reviewed="   "),
            "approved_by not text": doc(approved_by=["a"]),
            "local time": doc(approved_at="2026-10-31T09:00:00"),
            "offset time": doc(approved_at="2026-10-31T09:00:00+02:00"),
            "date only": doc(approved_at="2026-10-31"),
            "impossible date": doc(approved_at="2026-02-30T09:00:00Z"),
            "extra key": doc(note="hi"),
            "repeated key": doc()[:-1] + b', "version": 1}',
            "not json": b"commit=" + released.encode(),
            "not utf-8": b"\xff\xfe",
            "a list": b"[1]",
            "empty file": b"",
            "over 16 KB": doc(reviewed="x" * (16 * 1024)),
        }
        rows = [self.execution("release", released, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        for name, data in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.prepare(rows, head, self.write(data))
                self.assertFalse((self.root / "out").exists())
        with self.assertRaisesRegex(ValueError, "version id"):
            self.prepare(rows, head, self.write(doc()), "")
        self.assertEqual(self.prepare(rows, head, self.write(doc()))["baseline_revision"],
                         released)

    def test_a_16_kb_file_is_accepted(self):
        approved = self.commit("app.py", "reviewed\n")
        head = self.commit("app.py", "candidate\n")
        base = json.dumps({"version": 1, "commit": approved, "approved_by": "a",
                           "approved_at": "2026-10-31T09:00:00.5Z", "reviewed": ""})
        data = base.replace('"reviewed": ""',
                            '"reviewed": "' + "r" * (16 * 1024 - len(base)) + '"').encode()
        self.assertEqual(len(data), 16 * 1024)
        result = self.prepare([self.execution("current", head, "InProgress", 10)], head,
                              self.write(data))
        self.assertEqual(result["baseline_kind"], "approved_baseline")

    def test_an_oversized_full_tree_points_to_the_procedure(self):
        head = self.commit("site.js", "".join(f"line {i:06d} {'x' * 60}\n"
                                              for i in range(2000)))
        original = module.MAX_DIFF_BYTES
        module.MAX_DIFF_BYTES = 100_000
        try:
            with self.assertRaisesRegex(ValueError, "Approved starting commit.*deploy/README.md"):
                self.prepare([self.execution("current", head, "InProgress", 10)], head)
        finally:
            module.MAX_DIFF_BYTES = original
        self.assertFalse((self.root / "out").exists())

    def test_an_oversized_release_delta_keeps_the_old_message(self):
        base = self.commit("app.py", "safe\n")
        head = self.commit("site.js", "".join(f"line {i:06d} {'x' * 60}\n"
                                              for i in range(2000)))
        rows = [self.execution("release", base, "Succeeded", 0),
                self.execution("current", head, "InProgress", 10)]
        original = module.MAX_DIFF_BYTES
        module.MAX_DIFF_BYTES = 100_000
        try:
            with self.assertRaises(ValueError) as caught:
                self.prepare(rows, head)
        finally:
            module.MAX_DIFF_BYTES = original
        self.assertIn("review limit", str(caught.exception))
        self.assertNotIn("Approved starting commit", str(caught.exception))

    def test_the_command_line_takes_the_file_and_version(self):
        source = pathlib.Path(module.__file__).read_text()
        self.assertIn('"--approved-baseline"', source)
        self.assertIn('"--approved-baseline-version"', source)
        run = subprocess.run([sys.executable, module.__file__, "--pipeline", "p",
                              "--execution-id", "e", "--revision", "r",
                              "--approved-baseline-version", "v1"],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("needs --approved-baseline", run.stderr)


DROP = object()


class DeltaCheckTests(unittest.TestCase):
    """Every byte of the delta reaches a reviewer, or the gate stops first."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Offline Test")
        self.policy = self.root / "approved.yaml"
        self.policy.write_text("version: 1\n")
        self.base = self.commit({"README.md": b"base\n"})

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, files=None, remove=(), symlinks=None):
        for name, data in (files or {}).items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or path.exists():
                path.unlink()
            path.write_bytes(data)
        for name, target in (symlinks or {}).items():
            path = self.repo / name
            if path.exists() or path.is_symlink():
                path.unlink()
            path.symlink_to(target)
        for name in remove:
            (self.repo / name).unlink()
        self.git("add", "-A")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "change")
        return self.git("rev-parse", "HEAD")

    def dry(self, base=None, out="out"):
        return module.dry_run(base or self.base, "HEAD", self.policy, self.root / out,
                              str(self.repo))

    def refused(self, pattern, base=None):
        with self.assertRaisesRegex(ValueError, pattern):
            self.dry(base)
        self.assertFalse((self.root / "out").exists())

    def test_a_carriage_return_inside_a_line_is_refused_and_nothing_written(self):
        # Read as text, the CR would become a line break and the content after
        # it a file header that hides the rest of page.html from scoped seats.
        self.commit({"page.html": b"<p>ok</p>\rdiff --git a/zz.js b/zz.js\n<div onclick=x()>\n"})
        self.refused("carriage return inside a line")

    def test_crlf_line_ends_are_read_exactly_as_before(self):
        head = self.commit({"OFL.txt": b"Copyright\r\nLicense text\r\n", "a.js": b"x;\n"})
        result = self.dry()
        text = (self.root / "out/change.diff").read_text()
        before = subprocess.check_output(  # what prepare_review always produced
            ["git", "diff", "--no-ext-diff", "--no-textconv", self.base, head],
            cwd=self.repo, text=True)
        self.assertEqual(text, before)
        self.assertNotIn("\r", text)
        self.assertEqual(result["diff_bytes"], len(before.encode()))

    def test_source_that_renders_as_binary_is_refused(self):
        self.commit({"src/app.js": b"el.innerHTML = location.hash;\0\n"})
        self.refused(r"src/app.js renders as binary")

    def test_media_binaries_are_allowed_and_listed_with_their_sizes(self):
        mp3, png = b"ID3\0" + b"a" * 300, b"\x89PNG\r\n\x1a\n\0" + b"p" * 40
        first = self.commit({"site/score.mp3": mp3, "site/Logo.PNG": png, "site/a.js": b"x;\n"})
        plan = self.dry()["chunk_plan"]
        self.assertEqual(plan["binary_sections"], [
            {"path": "site/Logo.PNG", "change": "added", "bytes": len(png), "previous_bytes": 0},
            {"path": "site/score.mp3", "change": "added", "bytes": len(mp3), "previous_bytes": 0}])
        self.assertEqual(plan["binary_bytes"], len(mp3) + len(png))
        self.commit({"site/Logo.PNG": png + b"q"}, remove=["site/score.mp3"])
        rows = self.dry(base=first, out="out2")["chunk_plan"]["binary_sections"]
        self.assertEqual(rows, [
            {"path": "site/Logo.PNG", "change": "modified", "bytes": len(png) + 1,
             "previous_bytes": len(png)},
            {"path": "site/score.mp3", "change": "deleted", "bytes": 0,
             "previous_bytes": len(mp3)}])

    def test_deleting_a_binary_file_of_any_type_is_allowed(self):
        first = self.commit({"tools/blob.bin": b"\0\1\2"})
        self.commit(remove=["tools/blob.bin"])
        rows = self.dry(base=first)["chunk_plan"]["binary_sections"]
        self.assertEqual([(r["path"], r["change"]) for r in rows], [("tools/blob.bin", "deleted")])

    def test_a_gitattributes_change_is_refused_wherever_it_is(self):
        for name in (".gitattributes", "web/.gitattributes"):
            with self.subTest(name=name):
                head = self.commit({name: b"*.mjs -diff\n", "web/x.mjs": b"evil();\n"})
                self.refused(r"changes .*\.gitattributes")
                self.base = head

    def test_unusual_paths_renames_and_type_changes_match_git(self):
        first = self.commit({"sp ace.js": b"k\n", "a b/c.js": b"c\n", "old.js": b"q\n",
                             "f.txt": b"hello\n", "run.sh": b"echo\n"})
        (self.repo / "run.sh").chmod(0o755)                    # mode-only change
        self.git("mv", "old.js", "new.js")                     # pure rename
        self.commit({"sp ace.js": b"k2\n", "a b/c.js": b"c2\n", "café.js": b"x\n",
                     'quo"te.js': b"y\n", "tab\tname.js": b"z\n"},
                    symlinks={"f.txt": "new.js"})              # file -> symlink
        result = self.dry(base=first)
        self.assertEqual(result["chunk_plan"]["binary_sections"], [])
        sections = module.review_chunks.parse_sections((self.root / "out/change.diff").read_text())
        entries = module.changed_entries(first, "HEAD", str(self.repo))
        # The type change is one --raw entry but two file sections.
        self.assertEqual([e["status"] for e in entries].count("T"), 1)
        self.assertEqual(len(sections), len(entries) + 1)

    def test_a_diff_that_imitates_a_file_boundary_is_refused(self):
        head = self.commit({"page.html": b"<p>x</p>\n", "z.js": b"y;\n"})
        entries = module.changed_entries(self.base, head, str(self.repo))
        diff = subprocess.check_output(["git", "diff", self.base, head], cwd=self.repo, text=True)
        forged = diff.replace("+<p>x</p>\n", "+<p>x</p>\ndiff --git a/z.js b/z.js\n+evil\n")
        with self.assertRaisesRegex(ValueError, "does not match git's list of changed files"):
            module.check_delta(module.review_chunks.parse_sections(forged), entries, str(self.repo))

    def test_section_paths_reads_every_header_form_git_writes(self):
        cases = {
            "diff --git a/x.js b/x.js\n": ("x.js", "x.js"),
            "diff --git a/a b/c.js b/a b/c.js\n": ("a b/c.js", "a b/c.js"),
            'diff --git "a/caf\\303\\251.js" "b/caf\\303\\251.js"\n': ("café.js", "café.js"),
            "diff --git a/o.js b/n.js\nsimilarity index 90%\nrename from o.js\nrename to n.js\n":
                ("o.js", "n.js"),
            'diff --git a/o.js "b/t\\tn.js"\ncopy from o.js\ncopy to "t\\tn.js"\n': ("o.js", "t\tn.js"),
        }
        for header, expected in cases.items():
            with self.subTest(header=header):
                self.assertEqual(module.section_paths(header), expected)
        for header in ("diff --git a/x.js b/y.js\n", "diff --git x.js x.js\n"):
            with self.subTest(header=header), self.assertRaises(ValueError):
                module.section_paths(header)


if __name__ == "__main__":
    unittest.main()
