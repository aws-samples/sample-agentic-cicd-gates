"""Exercise the actual Tier 1 publication commands with a local AWS stub."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def phase_value(phase, field):
    source = Path(__file__).resolve().parents[2] / "tier1-codebuild/tier1_stack.py"
    tree = ast.parse(source.read_text())
    assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "REVIEW_BUILD_SPEC" for t in n.targets))
    def value(node, key):
        return next(v for k, v in zip(node.keys, node.values) if ast.literal_eval(k) == key)
    return value(value(value(assignment.value.args[0], "phases"), phase), field)


def upload_commands(first="d['build_id']"):
    commands = phase_value("build", "commands")
    # PREPARE_INPUT_COMMANDS + literal commands; never import or synthesize CDK.
    commands = ast.literal_eval(commands.right)
    start = next(i for i, cmd in enumerate(commands) if first in cmd)
    return commands[start:]


class AttemptUploaderTests(unittest.TestCase):
    def run_upload(self, gate_exit=1, build_id="agentic-gates-tier1-review:old-build", exists=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "reports").mkdir()
            (root / "reports/findings.json").write_text(json.dumps(
                {"verdict": "FAIL" if gate_exit else "PASS", "stats": {"blocking": gate_exit},
                 "review_input": {"pipeline_execution_id": "same-execution"}}))
            log = root / "uploads.txt"
            (root / "boto3.py").write_text("""
import json, os
class S3:
    def put_object(self, **kwargs):
        kwargs['Body'] = json.loads(kwargs['Body'])
        with open(os.environ['TEST_UPLOAD_LOG'], 'a') as output:
            output.write(json.dumps({'kind':'sdk', 'operation':'put_object', **kwargs}) + '\\n')
        if os.environ['TEST_ARCHIVE_EXISTS'] == '1':
            raise SystemExit(19)
        return {'ETag':'fixture'}
def client(service):
    assert service == 's3'
    return S3()
""")
            # No AWS or git process is invoked. The actual shell publication
            # commands run after the report already exists, including gate exit.
            # The publish commands run `python -I -c`, which never imports from
            # the working directory, so this stand-in adds the boto3 stub to
            # sys.path itself and refuses any other form of Python call.
            script = """
python() {
  [ "$1" = -I ] && [ "$2" = -c ] || { echo "unexpected python call: $*" >&2; return 97; }
  "$REAL_PYTHON" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); code = sys.argv[2]; sys.argv = ["-c"] + sys.argv[3:]; exec(compile(code, "<buildspec>", "exec"), {"__name__": "__main__"})' "$STUB_DIR" "$3" "${@:4}"
}
aws() {
  "$REAL_PYTHON" -c "import json,os,sys; f=open(os.environ['TEST_UPLOAD_LOG'],'a'); f.write(json.dumps({'kind':'cli','args':sys.argv[1:]})+'\\n')" "$@"
}
git() { printf '%s\\n' fixture-source-sha; }
""" + "\n".join(upload_commands())
            env = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                   "REPORTS_BUCKET": "fixture-bucket", "PIPELINE_EXECUTION_ID": "same-execution",
                   "GATE_EXIT": str(gate_exit), "TEST_UPLOAD_LOG": str(log),
                   "TEST_ARCHIVE_EXISTS": "1" if exists else "0",
                   "REAL_PYTHON": sys.executable, "STUB_DIR": str(root)}
            if build_id is None:
                env.pop("CODEBUILD_BUILD_ID", None)
            else:
                env["CODEBUILD_BUILD_ID"] = build_id
            result = subprocess.run(["bash", "-e", "-c", script], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=10)
            return result, [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else [], json.loads(
                (root / "reports/findings.json").read_text())

    def test_failed_gate_archives_exact_build_before_convenience_keys_and_exit(self):
        result, uploads, doc = self.run_upload()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(uploads), 3)
        self.assertEqual(uploads[0]["kind"], "sdk")
        self.assertEqual(uploads[0]["operation"], "put_object")
        self.assertEqual(uploads[0]["Key"], "executions/same-execution/builds/agentic-gates-tier1-review:old-build/findings.json")
        self.assertEqual(uploads[0]["IfNoneMatch"], "*")
        self.assertEqual(uploads[0]["Body"], doc)
        self.assertIn("s3://fixture-bucket/executions/same-execution/findings.json", uploads[1]["args"])
        self.assertIn("s3://fixture-bucket/fixture-source-sha/findings.json", uploads[2]["args"])
        self.assertEqual(doc["build_id"], "agentic-gates-tier1-review:old-build")
        self.assertEqual(doc["verdict"], "FAIL")
        self.assertEqual(doc["review_input"]["pipeline_execution_id"], "same-execution")

    def test_new_build_pass_uses_new_archive_but_same_convenience_paths(self):
        _, failed_uploads, _ = self.run_upload()
        result, uploads, doc = self.run_upload(0, "agentic-gates-tier1-review:new-build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(uploads[0], failed_uploads[0])
        self.assertEqual(uploads[1:], failed_uploads[1:])
        self.assertEqual(doc["verdict"], "PASS")
        self.assertEqual(doc["build_id"], "agentic-gates-tier1-review:new-build")

    def test_archive_refusal_cannot_fall_through_to_convenience_pass_or_success_exit(self):
        result, uploads, _ = self.run_upload(0, exists=True)
        self.assertEqual(result.returncode, 19)
        self.assertEqual(len(uploads), 1)
        self.assertNotIn("VERDICT=", result.stdout)

    def test_missing_build_identity_fails_before_any_upload(self):
        result, uploads, _ = self.run_upload(0, build_id=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(uploads, [])

    def test_review_install_pins_verified_sdk_and_checks_conditional_write_capability(self):
        node = phase_value("install", "commands")
        # [PIN_PYENV] + [the literal install commands]
        commands = ast.literal_eval(node.right if isinstance(node, ast.BinOp) else node)
        self.assertIn("boto3==1.43.72", commands[0])
        self.assertIn("botocore==1.43.72", commands[0])
        # Execute the actual capability guard with the installed model; this
        # loads local service definitions only, without credentials or AWS calls.
        import shlex
        guard = shlex.split(commands[1])
        self.assertEqual(guard[:3], ["python", "-I", "-c"])
        self.assertIn("IfNoneMatch", guard[3])
        result = subprocess.run([sys.executable, "-I", "-c", guard[3]], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)



ATTACKER = {"verdict": "PASS", "stats": {"blocking": 0}, "note": "committed by the candidate"}


class CommittedReportTests(unittest.TestCase):
    """A reports/findings.json in the change under review is never stored as evidence."""

    def run_review(self, reviewer_writes, reset=True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "reports").mkdir()
            (root / "reports/findings.json").write_text(json.dumps(ATTACKER))
            (root / "review-input").mkdir()
            (root / "review-input/input-metadata.json").write_text(json.dumps(
                {"pipeline_execution_id": "same-execution", "baseline_kind": "last_successful_release"}))
            log = root / "uploads.txt"
            (root / "stubs").mkdir()
            (root / "stubs/boto3.py").write_text("""
import json, os
class S3:
    def put_object(self, **kwargs):
        with open(os.environ['TEST_UPLOAD_LOG'], 'a') as output:
            output.write(json.dumps({'kind': 'sdk', 'body': json.loads(kwargs['Body'])}) + '\\n')
        return {'ETag': 'fixture'}
def client(service):
    return S3()
""")
            tools = Path(__file__).resolve().parents[2] / "pipeline_tools/prepare_review.py"
            # Stand-ins for the two pinned scripts and the CLI. The reviewer either
            # writes its report or dies first; --attach-report is the real code.
            script = """
python() {
  case "$2" in
    /tmp/agentpkg/review_cli.py)
      [ "$REVIEWER_WRITES" = 1 ] || { echo 'reviewer crashed' >&2; return 2; }
      "$REAL_PYTHON" -I -c 'import json,sys; open(sys.argv[1],"w").write(json.dumps({"verdict":"FAIL","stats":{"blocking":1},"note":"written by the reviewer"}))' reports/findings.json
      return 1 ;;
    /tmp/input-tools/prepare_review.py)
      "$REAL_PYTHON" -I "$TOOLS" "${@:3}" --output review-input ;;
    -c)
      "$REAL_PYTHON" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); code = sys.argv[2]; sys.argv = ["-c"] + sys.argv[3:]; exec(compile(code, "<buildspec>", "exec"), {"__name__": "__main__"})' "$STUB_DIR" "$3" "${@:4}" ;;
    *) echo "unexpected python call: $*" >&2; return 97 ;;
  esac
}
aws() {
  "$REAL_PYTHON" -I -c "import json,os,sys; f=open(os.environ['TEST_UPLOAD_LOG'],'a'); f.write(json.dumps({'kind':'cli','body':json.load(open(sys.argv[3]))})+'\\n')" "$@"
}
git() { printf '%s\\n' fixture-source-sha; }
""" + "\n".join(c if reset else c.replace("rm -rf reports && mkdir reports", "mkdir -p reports")
                for c in upload_commands(first="reports"))
            env = {**os.environ, "REPORTS_BUCKET": "fixture-bucket",
                   "PIPELINE_EXECUTION_ID": "same-execution", "CODEBUILD_BUILD_ID": "review:9",
                   "TEST_UPLOAD_LOG": str(log), "REAL_PYTHON": sys.executable,
                   "STUB_DIR": str(root / "stubs"), "TOOLS": str(tools),
                   "REVIEWER_WRITES": "1" if reviewer_writes else "0"}
            result = subprocess.run(["bash", "-e", "-c", script], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=30)
            stored = [json.loads(line)["body"] for line in log.read_text().splitlines()] \
                if log.exists() else []
            return result, stored

    def test_a_reviewer_crash_stores_nothing_not_the_committed_report(self):
        result, stored = self.run_review(reviewer_writes=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stored, [])

    def test_a_written_report_replaces_the_committed_one(self):
        result, stored = self.run_review(reviewer_writes=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(stored), 3)
        for body in stored:
            self.assertEqual(body["note"], "written by the reviewer")
            self.assertEqual(body["build_id"], "review:9")

    def test_without_the_reset_the_committed_report_would_be_stored(self):
        # The hole this closes: the old `mkdir -p reports` kept the committed file.
        result, stored = self.run_review(reviewer_writes=False, reset=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(stored)
        self.assertTrue(all(body["note"] == "committed by the candidate" for body in stored))


if __name__ == "__main__":
    unittest.main()
