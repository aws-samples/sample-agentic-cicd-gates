import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "check_evidence", pathlib.Path(__file__).with_name("check_evidence.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

BASE, HEAD = "b" * 40, "c" * 40
SEATS = [{"name": "Security", "scoped": False}, {"name": "Accessibility", "scoped": True}]
MP3 = {"path": "site/score.mp3", "change": "added", "bytes": 1477110, "previous_bytes": 0}
OLD = {"path": "old.woff2", "change": "deleted", "bytes": 0, "previous_bytes": 9}


def row(item):
    return {"item": item, "chunks": [item], "bytes": 10, "files": ["f"], "verdict": "PASS",
            "blocking": 0, "error": None, "attempts": 1}


def evidence(chunks=3, binaries=(MP3, OLD)):
    plan = {"plan_file": "chunk-plan.json", "plan_sha256": "p" * 64, "chunk_bytes": 100_000,
            "chunks": chunks, "chunk_sizes": [90_000] * chunks, "split_files": [],
            "binary_sections": [dict(b) for b in binaries],
            "binary_bytes": sum(b["bytes"] for b in binaries)}
    dry = {"dry_run": True, "baseline_revision": BASE, "head_revision": HEAD,
           "baseline_kind": "explicit_dry_run", "policy_origin": "local_file",
           "policy_sha256": "a" * 64, "diff_sha256": "d" * 64,
           "changed_files": ["site/score.mp3", "site/a.js"], "diff_bytes": 270_000,
           "chunk_plan": plan}
    review_input = {**copy.deepcopy(dry), "baseline_kind": "last_successful_release",
                    "pipeline_execution_id": "e", "policy_origin": "pipeline_deployment"}
    review_input.pop("dry_run")
    findings = {"verdict": "PASS", "stats": {"blocking": 0, "total": 0,
                                            "suppressed_below_threshold": 0},
                "findings": [], "review_input": review_input,
                "agents": [{"name": "Security", "verdict": "PASS", "blocking": 0, "error": None,
                            "chunks": [row(i) for i in range(chunks)]},
                           {"name": "Accessibility", "verdict": "PASS", "blocking": 0,
                            "error": None, "chunks": [row(0)]}]}
    if chunks > 1:
        findings["chunking"] = {"mode": "chunked", "chunks": chunks, "plan_sha256": "p" * 64,
                                "reviews_scheduled": chunks + 1, "reviews_completed": chunks + 1,
                                "deadline_reached": False, "retries": 0}
    else:
        for agent in findings["agents"]:
            agent.pop("chunks")
    schedule = {"seats": [{"name": "Security", "reviews": chunks},
                          {"name": "Accessibility", "reviews": 1}]}
    return findings, dry, schedule


def problems(findings, dry, schedule=None, expect=("site/score.mp3",)):
    return module.check(findings, dry, SEATS, BASE, HEAD, schedule,
                        None if expect is None else list(expect))


class EvidenceTests(unittest.TestCase):
    def test_complete_chunked_pass_is_approvable(self):
        findings, dry, schedule = evidence()
        self.assertEqual(problems(findings, dry, schedule), [])

    def test_single_call_pass_is_approvable(self):
        findings, dry, _ = evidence(chunks=1)
        self.assertEqual(problems(findings, dry), [])

    def test_retried_chunk_that_passed_is_approvable(self):
        findings, dry, schedule = evidence()
        findings["agents"][0]["chunks"][1].update(attempts=2, earlier_errors=["Throttling"])
        findings["chunking"]["retries"] = 1
        self.assertEqual(problems(findings, dry, schedule), [])

    def assert_refused(self, mutate, reason, schedule_used=True, expect=("site/score.mp3",)):
        findings, dry, schedule = evidence()
        mutate(findings, dry, schedule)
        found = problems(findings, dry, schedule if schedule_used else None, expect)
        self.assertTrue(any(reason in r for r in found), found)

    def test_advisory_error_is_not_a_pass(self):
        def mutate(f, d, s):
            f["verdict"] = "ADVISORY_ERROR"
            f["agents"][0].update(verdict="ADVISORY_ERROR", error="timeout")
        self.assert_refused(mutate, "not PASS")
        self.assert_refused(mutate, "Security: ADVISORY_ERROR")

    def test_a_chunk_row_that_did_not_pass_is_refused(self):
        def mutate(f, d, s):
            f["agents"][0]["chunks"][2].update(verdict=None, error="not reviewed")
        self.assert_refused(mutate, "Security chunk item 2")

    def test_incomplete_or_late_review_is_refused(self):
        self.assert_refused(lambda f, d, s: f["chunking"].update(reviews_completed=3),
                            "3 of 4 reviews completed")
        self.assert_refused(lambda f, d, s: f["chunking"].update(deadline_reached=True),
                            "deadline was reached")

    def test_an_unscoped_seat_missing_a_chunk_is_refused(self):
        def mutate(f, d, s):
            f["agents"][0]["chunks"].pop()
        self.assert_refused(mutate, "Security: 2 chunk rows for 3 chunks", schedule_used=False)
        self.assert_refused(mutate, "schedule says 3")

    def test_a_scoped_seat_is_held_to_its_schedule(self):
        def mutate(f, d, s):
            s["seats"][1]["reviews"] = 2
        self.assert_refused(mutate, "Accessibility: 1 chunk rows, schedule says 2")

    def test_seats_must_be_the_policy_seats(self):
        self.assert_refused(lambda f, d, s: f["agents"].pop(), "differ from the policy")

    def test_the_reviewed_range_must_be_the_expected_one(self):
        self.assert_refused(lambda f, d, s: f["review_input"].update(baseline_revision="e" * 40),
                            "pipeline baseline")
        self.assert_refused(lambda f, d, s: d.update(head_revision="e" * 40), "dry run head")
        self.assert_refused(lambda f, d, s: f["review_input"].update(baseline_kind="initial_full_tree"),
                            "baseline_kind")

    def test_the_review_must_cover_the_dry_run_delta_and_policy(self):
        for key in ("diff_sha256", "policy_sha256"):
            self.assert_refused(lambda f, d, s, key=key: f["review_input"].update({key: "0" * 64}),
                                f"{key} differs from the dry run")
        self.assert_refused(lambda f, d, s: d["chunk_plan"].update(chunks=4),
                            "chunk_plan differs from the dry run")

    def test_unread_bytes_must_be_exactly_the_expected_media(self):
        def extra(f, d, s):
            for doc in (f["review_input"], d):
                doc["chunk_plan"]["binary_sections"].append(
                    {"path": "site/x.png", "change": "added", "bytes": 5, "previous_bytes": 0})
        self.assert_refused(extra, "are not the expected")
        findings, dry, schedule = evidence()
        self.assertEqual(problems(findings, dry, schedule, expect=["site/score.mp3"]), [])

    def test_expecting_no_binary_refuses_any_unread_file(self):
        findings, dry, schedule = evidence()
        self.assertTrue(any("are not the expected []" in r
                            for r in problems(findings, dry, schedule, expect=[])))
        findings, dry, schedule = evidence(binaries=(OLD,))   # a deletion adds no bytes
        self.assertEqual(problems(findings, dry, schedule, expect=[]), [])

    def test_evidence_without_binary_listing_is_refused(self):
        def mutate(f, d, s):
            for doc in (f["review_input"], d):
                doc["chunk_plan"].pop("binary_sections")
        self.assert_refused(mutate, "does not list its binary sections")

    def test_gitattributes_in_the_delta_is_refused(self):
        def mutate(f, d, s):
            for doc in (f["review_input"], d):
                doc["changed_files"].append("web/.gitattributes")
        self.assert_refused(mutate, "the delta changes web/.gitattributes")

    def test_plan_and_report_shapes_must_agree(self):
        findings, dry, _ = evidence(chunks=1)
        findings["chunking"] = {"mode": "chunked"}
        self.assertIn("a single-chunk plan with a chunked report", problems(findings, dry))
        self.assert_refused(lambda f, d, s: f.pop("chunking"),
                            "a multi-chunk plan without a chunked review")

    def test_command_line_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            findings, dry, schedule = evidence()
            (root / "dry").mkdir()
            (root / "dry/input-metadata.json").write_text(json.dumps(dry))
            (root / "schedule.json").write_text(json.dumps(schedule))
            (root / "rules.yaml").write_text(
                "version: 1\nagents:\n  - name: Security\n    rules: [SEC-]\n"
                "  - name: Accessibility\n    rules: [A11Y-]\n    file_patterns: ['**/*.html']\n")
            args = [sys.executable, str(pathlib.Path(__file__).with_name("check_evidence.py")),
                    "--findings", str(root / "findings.json"), "--dry-run", str(root / "dry"),
                    "--rules", str(root / "rules.yaml"), "--baseline", BASE, "--head", HEAD,
                    "--schedule", str(root / "schedule.json"),
                    "--expect-binary", "site/score.mp3"]
            (root / "findings.json").write_text(json.dumps(findings))
            # Expecting no unread files refuses evidence that lists the score.
            none = subprocess.run(args[:-2] + ["--expect-no-binary"], capture_output=True,
                                  text=True)
            self.assertEqual(none.returncode, 1, none.stdout + none.stderr)
            self.assertIn("are not the expected []", none.stdout)
            both = subprocess.run(args + ["--expect-no-binary"], capture_output=True, text=True)
            self.assertEqual(both.returncode, 2, both.stderr)   # argparse usage error
            for verdict, code, word in (("PASS", 0, "EVIDENCE: PASS"),
                                        ("ADVISORY_ERROR", 1, "EVIDENCE: FAIL")):
                findings["verdict"] = verdict
                (root / "findings.json").write_text(json.dumps(findings))
                proc = subprocess.run(args, capture_output=True, text=True)
                self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
                self.assertIn(word, proc.stdout)
                self.assertIn("unread binary: site/score.mp3", proc.stdout)


if __name__ == "__main__":
    unittest.main()
