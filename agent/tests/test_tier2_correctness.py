"""Artifact and baseline regression tests; AWS clients are always fakes."""
import io
import json
import zipfile
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError

from conftest import ROOT
from reviewer.bedrock_reviewer import _scope_diff, review_diff
from reviewer.rules import load_rules
from reviewer.verdict import Verdict

RULES = (ROOT / ".reviewer.yaml").read_text()
RS = load_rules(RULES)


def archive(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()


def error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetObject")


def report(verdict="PASS", **changes):
    return {"verdict": verdict, "stats": {"total": 0, "blocking": 0}, "findings": [],
            "agents": [{"name": "reviewer", "verdict": verdict, "blocking": 0,
                        "error": None}], **changes}


@pytest.fixture
def gate(monkeypatch, load_module):
    clients = {name: Mock() for name in ("codepipeline", "bedrock-agentcore", "s3")}
    monkeypatch.setattr(boto3, "client", lambda name, **kw: clients[name])
    mod = load_module("tier2-agentcore/gate/lambda_handler.py")
    monkeypatch.setenv("STATE_BUCKET", "offline-state")
    old = archive({".reviewer.yaml": RULES, "web/src/app.tsx": "old\n"})
    new = archive({".reviewer.yaml": RULES, "web/src/app.tsx": "new\n"})
    mod.s3_state.get_object.side_effect = lambda **kw: {
        "Body": io.BytesIO(old), "ETag": '"approved"'}
    monkeypatch.setattr(mod, "_artifact_zip", lambda data: new)
    mod.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(report()).encode())}
    return mod


def invoke(gate):
    gate.handler({"CodePipeline.job": {
        "id": "offline-job", "data": {"actionConfiguration": {"configuration": {
            "UserParameters": json.dumps({"runtime_arn": "offline-runtime"})}}}}}, None)


def assert_blocked(gate):
    gate.s3_state.put_object.assert_not_called()
    gate.codepipeline.put_job_success_result.assert_not_called()
    gate.codepipeline.put_job_failure_result.assert_called_once()


@pytest.mark.parametrize("ext", [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
                                ".html", ".htm", ".css", ".svg", ".vue", ".svelte"])
def test_frontend_files_reach_git_scoped_diff(gate, ext):
    path = f"web/src/component{ext}"
    tree = gate._tree(archive({path: "old\n", "logo.png": b"\xff"}))
    diff = gate._tree_diff(tree, {path: ["new\n"]})
    assert list(tree) == [path]
    assert _scope_diff(diff, [f"**/*{ext}"]) == diff
    assert "+new\n" in diff


@pytest.mark.parametrize("path", ["src/arcade.py", "web/src/space name.tsx",
    'web/src/quote"b.tsx', "web/src/café.tsx", "web/src/back\\slash.tsx"])
def test_paths_additions_deletions_and_missing_newline(gate, path):
    old, new = {path: ["old"]}, {path: ["new"]}
    for a, b in [(old, new), ({}, new), (old, {})]:
        diff = gate._tree_diff(a, b)
        assert _scope_diff(diff, ["**/*.tsx", "**/arcade.py"]) == diff
        assert "\\ No newline at end of file\n" in diff
        if not a or not b:
            assert "/dev/null" in diff


def test_empty_file_add_and_delete_are_visible(gate):
    for old, new in [({}, {"a.tsx": []}), ({"a.tsx": []}, {})]:
        assert "file mode" in gate._tree_diff(old, new)


def test_non_git_scoped_input_errors_without_model():
    agent = RS.agents[-1]
    outcome = review_diff("--- a/a.tsx\n+++ b/a.tsx\n@@ -1 +1 @@\n-x\n+y\n",
                          RS, agent=agent)
    assert outcome.result.verdict == Verdict.BLOCKED_ERROR


def test_real_git_space_header_and_rename_scope():
    diff = "diff --git a/web/some name.tsx b/other/new name.txt\nrename\n"
    assert _scope_diff(diff, ["**/*.tsx"]) == diff


def test_a_rename_with_b_slash_in_the_old_path_stays_in_scope():
    # Continuum, round 4 (G05): the lazy header split landed inside the old path,
    # so the quoted new path no longer matched and the section was dropped.
    diff = ('diff --git a/old b/name.txt "b/web/st\\tyle.css"\n'
            "similarity index 90%\n"
            "rename from old b/name.txt\n"
            'rename to "web/st\\tyle.css"\n'
            "--- a/old b/name.txt\n"
            '+++ "b/web/st\\tyle.css"\n'
            "@@ -1 +1 @@\n-a\n+b\n")
    assert _scope_diff(diff, ["**/*.css"]) == diff
    assert _scope_diff("diff --git a/x.py b/x.py\n+y\n" + diff, ["**/*.css"]) == diff


@pytest.mark.parametrize("verdict", ["FAIL", "BLOCKED_ERROR", "ADVISORY_ERROR", "BOGUS"])
def test_rejected_or_error_review_never_advances(gate, verdict):
    gate.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(report(verdict)).encode())}
    invoke(gate)
    assert_blocked(gate)


@pytest.mark.parametrize("bad_report", [
    report(error="timeout"),
    report(agents=[]),
    report(stats={"blocking": 0}),
    report(stats={"total": 0, "blocking": True}),
    report(agents=[{"name": "reviewer", "verdict": "ADVISORY_ERROR", "error": "timeout"}]),
    report(agents=[{"name": "reviewer", "verdict": "PASS", "error": "timeout", "blocking": 0}]),
    report(findings=[{"blocking": True}], stats={"total": 1, "blocking": 0}),
])
def test_inconsistent_pass_does_not_advance(gate, bad_report):
    gate.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(bad_report).encode())}
    invoke(gate)
    assert_blocked(gate)


def test_missing_baseline_blocks_without_seeding(gate):
    gate.s3_state.get_object.side_effect = error("NoSuchKey")
    invoke(gate)
    assert_blocked(gate)
    gate.agentcore.invoke_agent_runtime.assert_not_called()
    msg = gate.codepipeline.put_job_failure_result.call_args.kwargs["failureDetails"]["message"]
    assert "BASELINE_MISSING" in msg


@pytest.mark.parametrize("problem", [
    error("AccessDenied"), error("NoSuchBucket"), error("SlowDown"), error("404"),
    TimeoutError("read timeout")])
def test_storage_error_is_not_initialization(gate, problem):
    gate.s3_state.get_object.side_effect = problem
    invoke(gate)
    assert_blocked(gate)
    msg = gate.codepipeline.put_job_failure_result.call_args.kwargs["failureDetails"]["message"]
    assert "BASELINE_MISSING" not in msg


@pytest.mark.parametrize("previous", [b"corrupt zip", archive({"app.js": "x"})])
def test_invalid_baseline_does_not_take_policy_from_current(gate, previous):
    gate.s3_state.get_object.side_effect = lambda **kw: {
        "Body": io.BytesIO(previous), "ETag": '"approved"'}
    invoke(gate)
    assert_blocked(gate)
    gate.agentcore.invoke_agent_runtime.assert_not_called()


def test_model_exception_and_oversize_diff_block(gate, monkeypatch):
    gate.agentcore.invoke_agent_runtime.side_effect = TimeoutError("model timeout")
    invoke(gate)
    assert_blocked(gate)
    gate.codepipeline.reset_mock()
    gate.agentcore.reset_mock()
    monkeypatch.setattr(gate, "MAX_DIFF", 1)
    invoke(gate)
    assert_blocked(gate)
    gate.agentcore.invoke_agent_runtime.assert_not_called()


def test_failed_retry_reuses_approved_base_then_success_advances(gate):
    reports = iter([report("FAIL"), report("FAIL"), report()])
    gate.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(next(reports)).encode())}
    invoke(gate)
    invoke(gate)
    gate.s3_state.put_object.assert_not_called()
    payloads = [json.loads(c.kwargs["payload"]) for c in
                gate.agentcore.invoke_agent_runtime.call_args_list]
    assert payloads[0] == payloads[1]
    assert "-old\n+new\n" in payloads[0]["diff"]
    assert payloads[0]["rules_yaml"] == RULES
    invoke(gate)
    gate.s3_state.put_object.assert_called_once()
    assert gate.s3_state.put_object.call_args.kwargs["IfMatch"] == '"approved"'
    gate.codepipeline.put_job_success_result.assert_called_once()


def test_candidate_policy_cannot_replace_baseline_policy(gate, monkeypatch):
    monkeypatch.setattr(gate, "_artifact_zip", lambda data: archive({
        ".reviewer.yaml": "version: 1\nrules: []\n", "web/src/app.tsx": "new\n"}))
    invoke(gate)
    payload = json.loads(gate.agentcore.invoke_agent_runtime.call_args.kwargs["payload"])
    assert payload["rules_yaml"] == RULES
    assert "rules: []" in payload["diff"]


def test_advisory_findings_in_an_error_free_pass_can_advance(gate):
    advisory = report(findings=[{"rule_id": "STYLE-101", "blocking": False}],
                      stats={"total": 1, "blocking": 0})
    gate.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(advisory).encode())}
    invoke(gate)
    gate.s3_state.put_object.assert_called_once()
    gate.codepipeline.put_job_success_result.assert_called_once()


def test_scoped_reviewer_receives_frontend_changes(gate):
    diff = gate._tree_diff({"web/component.tsx": ["old\n"], "src/db.py": ["old\n"]},
                          {"web/component.tsx": ["new\n"], "src/db.py": ["new\n"]})
    client = Mock()
    client.converse.return_value = {
        "output": {"message": {"content": [{"text": '{"findings":[]}'}]}}}
    result = review_diff(diff, RS, agent=RS.agents[-1], client=client).result
    assert result.verdict == Verdict.PASS
    client.converse.assert_called_once()
    payload = client.converse.call_args.kwargs["messages"][0]["content"][0]["text"]
    assert "web/component.tsx" in payload and "+new\n" in payload
    assert "src/db.py" not in payload


def test_logged_review_input_names_the_pipeline_execution(gate, capsys):
    """The dashboard binds a Lambda-log report to its run only by this ID."""
    gate.handler({"CodePipeline.job": {
        "id": "offline-job", "data": {"actionConfiguration": {"configuration": {
            "UserParameters": json.dumps({"runtime_arn": "offline-runtime",
                                          "pipeline_execution_id": "run-1"})}}}}}, None)
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()
               if line.startswith("{")]
    assert [p["review_input"]["pipeline_execution_id"] for p in printed] == ["run-1", "run-1"]
    assert printed[-1]["verdict"] == "PASS"


def test_baseline_write_conflict_reports_failure(gate):
    gate.s3_state.put_object.side_effect = error("PreconditionFailed")
    invoke(gate)
    gate.codepipeline.put_job_success_result.assert_not_called()
    gate.codepipeline.put_job_failure_result.assert_called_once()


def test_corrupt_supported_text_does_not_disappear(gate):
    with pytest.raises(UnicodeDecodeError):
        gate._tree(archive({"component.tsx": b"\xff"}))
