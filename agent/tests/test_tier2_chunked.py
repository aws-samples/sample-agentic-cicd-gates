"""Tier 2 reviews large deltas in chunks with Tier 1's code and semantics.

The gate (tier2-agentcore/gate/lambda_handler.py) and the runtime handler
(tier2-agentcore/runtime/handler.py) run in-process here: the fake AgentCore
client hands the gate's JSON payload to the runtime's entrypoint and returns
its JSON report, so every test crosses the same boundary production does.
Models are fakes that answer from markers in the diff they are shown; AWS
clients are always fakes.
"""
import ast
import hashlib
import io
import json
import re
import sys
import time
import zipfile
from types import SimpleNamespace
from unittest.mock import Mock

import boto3
import pytest

from conftest import ROOT
from reviewer import bedrock_reviewer, chunked
from reviewer.rules import load_rules
from test_chunked_review import FakeBedrock, added

RULES = (ROOT / ".reviewer.yaml").read_text()
RS = load_rules(RULES)
SECURITY, QUALITY, ARCHITECTURE, ACCESSIBILITY = (a.name for a in RS.agents)
CHUNK = 100_000


class _App:
    """Stand-in for bedrock_agentcore.BedrockAgentCoreApp: the entrypoint is the function."""

    def entrypoint(self, func):
        return func

    def run(self, **kwargs):  # pragma: no cover - never called by tests
        raise AssertionError("tests call the entrypoint directly")


@pytest.fixture
def runtime(monkeypatch, load_module):
    """The runtime handler, laid out as in the image (planner and CLI beside it)."""
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", SimpleNamespace(BedrockAgentCoreApp=_App))
    monkeypatch.syspath_prepend(str(ROOT / "pipeline_tools"))
    return load_module("tier2-agentcore/runtime/handler.py")


@pytest.fixture
def model(monkeypatch):
    fake = FakeBedrock()
    monkeypatch.setattr(chunked, "bedrock_client", lambda region, **kw: fake)
    monkeypatch.setattr(bedrock_reviewer, "bedrock_client", lambda region, **kw: fake)
    yield fake
    fake.release.set()  # free any thread a deadline test abandoned


def archive(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()


def module(tag, special=""):
    """One ~33 KB JavaScript module; `special` lands on line 21."""
    lines = [f"export const {tag}{i} = {i}; // {'.' * 50}" for i in range(500)]
    lines[20] = special or lines[20]
    return "".join(f"{line}\n" for line in lines)


BASE = {".reviewer.yaml": RULES, "web/index.html": "<main><h1>Troy</h1></main>\n"}


def large_site(**special):
    """A candidate tree whose delta is ~400 KB: twelve modules plus HTML and CSS."""
    files = dict(BASE)
    for i in range(12):
        files[f"web/js/m{i:02d}.js"] = module(f"m{i}_", special.get(f"m{i:02d}", ""))
    files["web/index.html"] = "<main><h1>Troy</h1><p>The horse is at the gate.</p></main>\n"
    files["web/style.css"] = "body { color: #111; background: #fff; }\n"
    return files


class Gate:
    """The gate with fake AWS clients; AgentCore calls the in-process runtime."""

    def __init__(self, mod, runtime, baseline, candidate):
        self.mod, self.runtime = mod, runtime
        self.baseline, self.candidate = archive(baseline), archive(candidate)
        self.payloads, self.reports = [], []
        mod.s3_state.get_object.side_effect = lambda **kw: {
            "Body": io.BytesIO(self.baseline), "ETag": '"approved"'}
        mod._artifact_zip = lambda data: self.candidate
        mod.agentcore.invoke_agent_runtime.side_effect = self._invoke

    def _invoke(self, **kw):
        payload = json.loads(kw["payload"])
        self.payloads.append(payload)
        report = self.runtime.review(payload)
        self.reports.append(report)
        return {"response": io.BytesIO(json.dumps(report).encode())}

    def run(self, context=None):
        self.mod.handler({"CodePipeline.job": {
            "id": "11111111-2222-3333-4444-555555555555", "data": {
                "actionConfiguration": {"configuration": {
                    "UserParameters": json.dumps({"runtime_arn": "offline-runtime"})}}}}},
            context)
        return self.reports[-1] if self.reports else None

    @property
    def advanced(self):
        return self.mod.s3_state.put_object.called

    @property
    def failure(self):
        call = self.mod.codepipeline.put_job_failure_result.call_args
        return call.kwargs["failureDetails"]["message"] if call else None


@pytest.fixture
def gate_module(monkeypatch, load_module):
    clients = {name: Mock() for name in ("codepipeline", "bedrock-agentcore", "s3")}
    monkeypatch.setattr(boto3, "client", lambda name, **kw: clients[name])
    monkeypatch.setenv("STATE_BUCKET", "offline-state")
    return load_module("tier2-agentcore/gate/lambda_handler.py")


@pytest.fixture
def make_gate(gate_module, runtime, model):
    def make(candidate, baseline=BASE):
        return Gate(gate_module, runtime, baseline, candidate)
    return make


def seat(report, name):
    return next(a for a in report["agents"] if a["name"] == name)


def logged(capsys):
    """Every JSON object the gate printed, in order."""
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.startswith("{")]


# --- a delta of one chunk keeps today's exact path ---------------------------------

def test_one_chunk_delta_takes_todays_single_call_path_and_report(make_gate, runtime,
                                                                    monkeypatch, capsys):
    gate = make_gate({**BASE, "web/app.js": "export const ok = 1;\n"})
    calls = []
    real = runtime.review_panel

    def panel(diff, ruleset, **kw):
        calls.append(diff)
        return real(diff, ruleset, **kw)

    monkeypatch.setattr(runtime, "review_panel", panel)
    monkeypatch.setattr(runtime, "review_panel_chunked",
                        lambda *a, **k: pytest.fail("chunked path used for a one-chunk delta"))
    monkeypatch.setattr(runtime.review_chunks, "plan",
                        lambda *a, **k: pytest.fail("planner used for a one-chunk delta"))
    report = gate.run()
    assert calls == [gate.payloads[0]["diff"]] and "+export const ok = 1;\n" in calls[0]
    assert list(report) == ["verdict", "stats", "findings", "agents"]
    assert [list(a) for a in report["agents"]] == [
        ["name", "model", "thinking", "verdict", "blocking", "error"]] * 4
    assert report["verdict"] == "PASS" and gate.advanced
    # The logged result is that report plus the gate's evidence, nothing else.
    result = logged(capsys)[-1]
    assert {k: v for k, v in result.items() if k != "review_input"} == report
    assert result["review_input"]["diff_bytes"] <= CHUNK


def test_single_call_report_equals_the_tier1_cli_report_for_the_same_panel(runtime, model):
    diff = added("web/app.js", ["fetch('/x') // ROBUST_ME"] + [f"const v{i} = {i};" for i in range(30)])
    report = runtime.review({"diff": diff, "rules_yaml": RULES})
    panel = bedrock_reviewer.review_panel(diff, RS)
    assert report == runtime._report(panel)[1]
    assert seat(report, QUALITY)["verdict"] == "PASS" and report["stats"]["total"] == 1


# --- a larger delta: every seat, every chunk, one verdict --------------------------

def test_every_seat_reviews_every_chunk_in_its_scope_and_the_pass_advances(make_gate, model,
                                                                          capsys):
    gate = make_gate(large_site())
    report = gate.run()
    c = report["chunking"]
    assert report["verdict"] == "PASS" and c["chunks"] >= 4 and c["workers"] == 16
    assert c["deadline_seconds"] == gate.mod.REVIEW_DEADLINE_SECONDS
    assert c["reviews_completed"] == c["reviews_scheduled"] and not c["deadline_reached"]
    for name in (SECURITY, QUALITY, ARCHITECTURE):     # unscoped: every chunk
        assert [r["chunks"] for r in seat(report, name)["chunks"]] == [[i] for i in range(c["chunks"])]
    [a11y] = seat(report, ACCESSIBILITY)["chunks"]        # scoped: only its files
    assert a11y["files"] == ["web/index.html", "web/style.css"]
    a11y_inputs = [kw["messages"][0]["content"][0]["text"] for kw in model.calls
                   if "A11Y-001:" in kw["system"][0]["text"]]
    assert a11y_inputs and not any("web/js/" in text for text in a11y_inputs)
    assert gate.advanced and gate.mod.s3_state.put_object.call_args.kwargs["IfMatch"] == '"approved"'
    sent = gate.payloads[0]["diff"].encode()
    assert c["diff_sha256"] == hashlib.sha256(sent).hexdigest() and c["diff_bytes"] == len(sent)
    result = logged(capsys)[-1]
    assert result["chunking"] == c and result["review_input"]["diff_sha256"] == c["diff_sha256"]
    assert "chunks=" in gate.mod.codepipeline.put_job_success_result.call_args.kwargs[
        "executionDetails"]["summary"]


def component(tag):
    """One ~15 KB TSX file: in the Accessibility seat's scope."""
    return "".join(f"export const {tag}{i} = () => <button>{i}</button>; // {'.' * 12}\n"
                   for i in range(240))


def test_a_scoped_seat_reviews_items_of_at_most_the_runtime_cap(make_gate, runtime, model,
                                                                 load_module, tmp_path):
    files = {**large_site(), **{f"web/src/C{i}.tsx": component(f"c{i}_") for i in range(5)}}
    gate = make_gate(files)
    report = gate.run()
    c = report["chunking"]
    assert report["verdict"] == "PASS" and gate.advanced
    assert c["scoped_item_bytes"] == runtime.SCOPED_ITEM_BYTES == 30_000
    rows = seat(report, ACCESSIBILITY)["chunks"]
    in_scope = ["web/index.html", *(f"web/src/C{i}.tsx" for i in range(5)), "web/style.css"]
    assert len(rows) >= 3 and [f for row in rows for f in row["files"]] == in_scope
    assert all(row["bytes"] <= 30_000 or len(row["files"]) == 1 for row in rows)
    for name in (SECURITY, QUALITY, ARCHITECTURE):     # unscoped seats keep the chunks
        assert [r["chunks"] for r in seat(report, name)["chunks"]] == [[i] for i in range(c["chunks"])]
    shown = [kw["messages"][0]["content"][0]["text"] for kw in model.calls
             if "A11Y-001:" in kw["system"][0]["text"] and "validation stage" not in kw["system"][0]["text"]]
    for i in range(5):                                 # every line once, in one item
        for j in (0, 119, 239):
            assert sum(f"+export const c{i}_{j} = () =>" in text for text in shown) == 1
    # Tier 1 (no cap) would give the same seat this whole view as one item.
    planner = load_module("pipeline_tools/review_chunks.py")
    diff = gate.payloads[0]["diff"]
    out = tmp_path / "plan"
    out.mkdir()
    planner.write_plan(planner.plan(diff), diff, planner.CHUNK_BYTES, out)
    plan = chunked.load_plan(out / planner.PLAN_FILE, diff)
    [whole] = chunked.seat_items(plan, RS.agents[3])
    assert whole.files == tuple(in_scope) and whole.nbytes == sum(row["bytes"] for row in rows)


def test_a_blocking_finding_in_one_chunk_fails_and_the_baseline_stays(make_gate, model):
    gate = make_gate(large_site(m07="el.innerHTML = location.hash; // BLOCK_ME"))
    report = gate.run()
    assert report["verdict"] == "FAIL" and not gate.advanced
    [finding] = [f for f in report["findings"] if f["blocking"]]
    assert (finding["path"], finding["agent"]) == ("web/js/m07.js", SECURITY)
    rows = seat(report, SECURITY)["chunks"]
    assert "web/js/m07.js" in rows[finding["chunk"]]["files"]
    assert "SEC-003 web/js/m07.js:21" in gate.failure and "chunks=" in gate.failure


def test_a_truncated_chunk_fails_closed_after_one_retry(make_gate, model):
    gate = make_gate(large_site(m03="// TRUNCATE_SEC"))
    report = gate.run()
    assert report["verdict"] == "BLOCKED_ERROR" and not gate.advanced
    security = seat(report, SECURITY)
    assert "stopReason=max_tokens" in security["error"] and "web/js/m03.js" in security["error"]
    [row] = [r for r in security["chunks"] if r["verdict"] == "BLOCKED_ERROR"]
    assert row["attempts"] == 2 and "stopReason=max_tokens" in row["earlier_errors"][0]
    assert "stopReason=max_tokens" in gate.failure


def test_a_transient_error_is_retried_and_the_pass_advances(make_gate, model):
    gate = make_gate(large_site(m05="// FLAKY_SEC"))
    report = gate.run()
    assert report["verdict"] == "PASS" and gate.advanced
    [row] = [r for r in seat(report, SECURITY)["chunks"] if r["attempts"] == 2]
    assert "web/js/m05.js" in row["files"] and "ThrottlingException" in row["earlier_errors"][0]
    assert (report["chunking"]["retries"], report["chunking"]["retries_completed"]) == (1, 1)


def test_the_deadline_fails_unfinished_chunks_closed_and_returns_promptly(make_gate, model,
                                                                         monkeypatch):
    gate = make_gate(large_site(m02="// HANG_ME"))
    monkeypatch.setattr(gate.mod, "REVIEW_DEADLINE_SECONDS", 1)
    started = time.monotonic()
    report = gate.run()
    assert time.monotonic() - started < 15
    assert report["verdict"] == "BLOCKED_ERROR" and not gate.advanced
    assert report["chunking"]["deadline_reached"] is True
    assert report["chunking"]["deadline_seconds"] == 1
    assert "not reviewed before the review deadline" in seat(report, SECURITY)["error"]
    assert "deadline_reached" in gate.failure


def test_an_advisory_seat_error_still_blocks_tier2(make_gate, model):
    # Tier 1 exits 0 on ADVISORY_ERROR; Tier 2 must not advance on missing evidence.
    gate = make_gate(large_site(m04="// TRUNCATE_ROB"))
    report = gate.run()
    assert report["verdict"] == "ADVISORY_ERROR" and seat(report, QUALITY)["verdict"] == "ADVISORY_ERROR"
    assert not gate.advanced and gate.failure.startswith("verdict=ADVISORY_ERROR")


def test_a_delta_that_cannot_be_planned_is_blocked_before_any_model(runtime, model):
    diff = added("web/blob.js", ["x" * 120_000])
    report = runtime.review({"diff": diff, "rules_yaml": RULES, "deadline_seconds": 720})
    assert report["verdict"] == "BLOCKED_ERROR" and "planning failed" in report["error"]
    assert all(a["error"] for a in report["agents"]) and model.calls == []


@pytest.mark.parametrize("deadline", [None, 0, -5, "720", True, float("nan")])
def test_a_chunked_review_never_runs_without_a_valid_deadline(runtime, model, deadline):
    diff = "".join(added(f"web/m{i}.js", [f"const v{j} = {j}; // {'.' * 60}" for j in range(900)])
                   for i in range(3))
    payload = {"diff": diff, "rules_yaml": RULES}
    if deadline is not None:
        payload["deadline_seconds"] = deadline
    report = runtime.review(payload)
    assert report["verdict"] == "BLOCKED_ERROR" and "chunked review refused" in report["error"]
    assert model.calls == []


def test_the_runtime_caps_a_deadline_that_would_outlast_the_read_timeout(runtime, model,
                                                                         gate_module):
    diff = "".join(added(f"web/m{i}.js", [f"const v{j} = {j}; // {'.' * 60}" for j in range(900)])
                   for i in range(3))
    report = runtime.review({"diff": diff, "rules_yaml": RULES, "deadline_seconds": 10_000})
    assert report["verdict"] == "PASS"
    assert report["chunking"]["deadline_seconds"] == runtime.MAX_DEADLINE_SECONDS
    assert runtime.MAX_DEADLINE_SECONDS < gate_module.READ_TIMEOUT_SECONDS


def test_the_runtime_report_matches_tier1_for_the_same_delta(runtime, model, load_module,
                                                            monkeypatch, tmp_path):
    files = large_site(m07="el.innerHTML = location.hash; // BLOCK_ME", m01="// ROBUST_ME")
    diff = "".join(added(path, data.splitlines()) for path, data in sorted(files.items())
                   if path != ".reviewer.yaml")
    tier2 = runtime.review({"diff": diff, "rules_yaml": RULES, "deadline_seconds": 720})
    planner = load_module("pipeline_tools/review_chunks.py")
    out = tmp_path / "review-input"
    out.mkdir()
    planner.write_plan(planner.plan(diff), diff, planner.CHUNK_BYTES, out)
    (tmp_path / "change.diff").write_text(diff)
    cli = load_module("agent/review_cli.py")
    monkeypatch.setattr(sys, "argv", ["review_cli", "--diff", str(tmp_path / "change.diff"),
                                      "--rules", str(ROOT / ".reviewer.yaml"), "--chunk-plan",
                                      str(out / "chunk-plan.json"), "--report",
                                      str(tmp_path / "findings.json")])
    assert cli.main() == 1
    tier1 = json.loads((tmp_path / "findings.json").read_text())

    def shape(report):
        return (report["verdict"], report["stats"],
                [(f["rule_id"], f["path"], f["line"], f["agent"], f["chunk"]) for f in report["findings"]],
                [(a["name"], a["verdict"], a["blocking"], len(a["chunks"])) for a in report["agents"]],
                report["chunking"]["chunks"], report["chunking"]["plan_sha256"])

    assert shape(tier2) == shape(tier1) and tier2["verdict"] == "FAIL"


# --- the gate checks the evidence before it advances --------------------------------

def _chunked_pass(gate):
    report = gate.run()
    assert report["verdict"] == "PASS" and gate.advanced
    return json.loads(json.dumps(report))


def _tamper(name):
    def no_chunking(r): r.pop("chunking")
    def other_diff(r): r["chunking"]["diff_sha256"] = "0" * 64
    def other_size(r): r["chunking"]["diff_bytes"] += 1
    def deadline(r): r["chunking"]["deadline_reached"] = True
    def incomplete(r): r["chunking"]["reviews_completed"] -= 1
    def unreviewed(r): r["agents"][0]["chunks"][1].update(verdict=None, attempts=0)
    def errored(r): r["agents"][1]["chunks"][0]["error"] = "timeout"
    def dropped_row(r): r["agents"][2]["chunks"].pop()
    def no_rows(r): r["agents"][0].pop("chunks")
    def wrong_mode(r): r["chunking"]["mode"] = "single"
    return locals()[name]


@pytest.mark.parametrize("name", ["no_chunking", "other_diff", "other_size", "deadline",
                                  "incomplete", "unreviewed", "errored", "dropped_row",
                                  "no_rows", "wrong_mode"])
def test_a_pass_without_complete_chunk_evidence_never_advances(make_gate, gate_module, name):
    gate = make_gate(large_site())
    good = _chunked_pass(gate)
    gate_module.s3_state.reset_mock()
    gate_module.codepipeline.reset_mock()
    _tamper(name)(good)
    gate_module.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(good).encode())}
    gate.run()
    assert not gate.advanced
    gate_module.codepipeline.put_job_success_result.assert_not_called()
    assert gate.failure.startswith("gate error: ValueError")


def test_chunk_evidence_for_a_one_chunk_delta_is_refused(make_gate, gate_module):
    small = make_gate({**BASE, "web/app.js": "export const ok = 1;\n"})
    report = small.run()
    gate_module.s3_state.reset_mock()
    forged = {**report, "chunking": {"mode": "chunked"}}
    gate_module.agentcore.invoke_agent_runtime.side_effect = lambda **kw: {
        "response": io.BytesIO(json.dumps(forged).encode())}
    small.run()
    assert not small.advanced


# --- the gate's own evidence and its time budget --------------------------------------

def test_the_logged_result_lists_the_files_no_reviewer_read_with_sizes(make_gate, capsys):
    baseline = {**BASE, "logo.png": b"\x89PNG" + b"0" * 96, "font.woff2": b"w" * 40,
                "same.ico": b"i" * 7, "evals/case.diff": "-old\n"}
    candidate = {**large_site(), "logo.png": b"\x89PNG" + b"1" * 196, "same.ico": b"i" * 7,
                 "data/table.ini": "k=v\n", "evals/case.diff": "+newer\n"}
    gate = make_gate(candidate, baseline)
    gate.run()
    printed = logged(capsys)
    first, last = printed[0]["review_input"], printed[-1]["review_input"]
    expected = [
        {"path": "data/table.ini", "change": "added", "bytes": 4, "previous_bytes": 0},
        {"path": "evals/case.diff", "change": "modified", "bytes": 7, "previous_bytes": 5},
        {"path": "font.woff2", "change": "deleted", "bytes": 0, "previous_bytes": 40},
        {"path": "logo.png", "change": "modified", "bytes": 200, "previous_bytes": 100},
    ]
    assert first["skipped_files"] == last["skipped_files"] == expected
    assert (last["skipped_files_total"], last["skipped_bytes"], last["skipped_unchanged_files"]) == (4, 211, 1)
    assert last["policy_origin"] == "baseline" and last["baseline_etag"] == '"approved"'
    assert last["policy_sha256"] == hashlib.sha256(RULES.encode()).hexdigest()
    assert last["runtime_session_id"].startswith("11111111-2222-3333-4444-555555555555-")
    assert 33 <= len(last["runtime_session_id"]) <= 64
    assert not any("table.ini" in p["diff"] or "case.diff" in p["diff"] for p in gate.payloads)


def test_text_named_by_its_file_name_is_reviewed_not_skipped(make_gate, gate_module, capsys):
    # The road merge changes the runtime's Dockerfile and the Makefile; the
    # artifact merge adds LICENSE and NOTICE. None has a text extension.
    baseline = {**BASE, "Makefile": "deploy:\n\tcdk deploy\n", "dashboard/.gitignore": "cdk.out/\n",
                "tier2-agentcore/runtime/Dockerfile": "FROM python:3.12-slim\n"}
    candidate = {**BASE, "Makefile": "deploy:\n\tcdk deploy -c source=codecommit\n",
                 "dashboard/.gitignore": "cdk.out/\ntests/*.png\n",
                 "tier2-agentcore/runtime/Dockerfile": "FROM python:3.12-slim\nCOPY a.py ./\n",
                 "LICENSE": "MIT No Attribution\n", "src/site/NOTICE": "Fonts: SIL OFL 1.1\n",
                 "Dockerfile.dev": "FROM z\n", "web/mylicense": "not a licence name\n"}
    gate = make_gate(candidate, baseline)
    gate.run()
    diff = gate.payloads[0]["diff"]
    for path in ("Makefile", "dashboard/.gitignore", "tier2-agentcore/runtime/Dockerfile",
                 "LICENSE", "src/site/NOTICE"):
        assert f"diff --git a/{path} b/{path}\n" in diff, path
    assert "+COPY a.py ./\n" in diff and "+\tcdk deploy -c source=codecommit\n" in diff
    review_input = logged(capsys)[-1]["review_input"]
    assert [row["path"] for row in review_input["skipped_files"]] == ["Dockerfile.dev", "web/mylicense"]
    assert gate.advanced
    is_text = gate_module._is_text
    assert all(is_text(p) for p in ("LICENSE", "a/b/Notice", "x/.dockerignore", "GNUmakefile",
                                    "Containerfile", "LICENSE.md"))
    assert not any(is_text(p) for p in ("Dockerfile.dev", "mylicense", "makefile.bak", "LICENSE/"))


def test_an_oversized_delta_is_refused_with_its_evidence_logged(make_gate, gate_module,
                                                                monkeypatch, capsys):
    gate = make_gate(large_site())
    monkeypatch.setattr(gate_module, "MAX_DIFF", 200_000)
    gate.run()
    assert gate.payloads == [] and not gate.advanced and "exceeds 200000" in gate.failure
    assert logged(capsys)[0]["review_input"]["diff_bytes"] > 200_000


def test_the_gate_sends_its_deadline_and_needs_the_time_to_wait_for_it(make_gate, gate_module):
    gate = make_gate({**BASE, "web/app.js": "export const ok = 1;\n"})
    gate.run(SimpleNamespace(get_remaining_time_in_millis=lambda: 895_000))
    assert gate.payloads[0]["deadline_seconds"] == gate_module.REVIEW_DEADLINE_SECONDS
    gate_module.s3_state.reset_mock()
    gate.run(SimpleNamespace(get_remaining_time_in_millis=lambda: 600_000))
    assert len(gate.payloads) == 1 and not gate.advanced
    assert "Lambda time left" in gate.failure


def test_the_time_budget_holds_together(gate_module, runtime, load_module):
    g = gate_module
    planner = load_module("pipeline_tools/review_chunks.py")
    assert g.CHUNK_BYTES == planner.CHUNK_BYTES == runtime.review_chunks.CHUNK_BYTES
    lambda_timeout = 15 * 60
    # AgentCore's synchronous request limit is 15 minutes; the read timeout stays under it,
    # and a call started with READ_TIMEOUT + REPORT_RESERVE left can always report back.
    assert g.READ_TIMEOUT_SECONDS + g.REPORT_RESERVE_SECONDS < lambda_timeout
    # "Well under the read timeout": room for the microVM start, planning and folding.
    assert g.READ_TIMEOUT_SECONDS - g.REVIEW_DEADLINE_SECONDS >= 120
    assert g.REVIEW_DEADLINE_SECONDS <= runtime.MAX_DEADLINE_SECONDS < g.READ_TIMEOUT_SECONDS
    # The one deadline shorter than a full reviewer call: both 15-minute limits
    # are fixed by AWS, so it cannot be raised to fit. A chunk still running at
    # the deadline fails closed (the deadline test above); it never passes.
    from reviewer.bedrock_reviewer import READ_TIMEOUT_SECONDS
    assert runtime.MAX_DEADLINE_SECONDS < lambda_timeout < READ_TIMEOUT_SECONDS
    assert g.MAX_DIFF >= 2_500_000 > 1_890_196   # the artifact merge, with margin
    # One attempt plus one retry of a full scoped item, at the slowest seat's one
    # measured rate (Accessibility: 244.5 s for 22,887 bytes), fits the deadline.
    assert runtime.SCOPED_ITEM_BYTES <= g.CHUNK_BYTES
    assert 2 * 244.5 * runtime.SCOPED_ITEM_BYTES / 22_887 < g.REVIEW_DEADLINE_SECONDS
    source = (ROOT / "tier2-agentcore/gate/lambda_handler.py").read_text()
    assert "read_timeout=READ_TIMEOUT_SECONDS" in source
    stack = (ROOT / "tier2-agentcore/infra/tier2_stack.py").read_text()
    assert "timeout=cdk.Duration.minutes(15)" in stack


def test_the_runtime_image_ships_the_planner_and_report_code():
    dockerfile = (ROOT / "tier2-agentcore/runtime/Dockerfile").read_text()
    # A rebuild pulls the base this image was tested on, not whatever the tag is today.
    [base] = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert re.fullmatch(r"FROM public\.ecr\.aws/docker/library/python:3\.12-slim@sha256:[0-9a-f]{64}",
                        base), base
    assert "COPY agent/reviewer ./reviewer" in dockerfile
    assert "COPY pipeline_tools/review_chunks.py agent/review_cli.py ./" in dockerfile
    assert "COPY tier2-agentcore/runtime/handler.py ." in dockerfile
    ignored = (ROOT / ".dockerignore").read_text().split()
    assert not {"agent", "pipeline_tools", "agent/review_cli.py"} & set(ignored)
    handler = ast.parse((ROOT / "tier2-agentcore/runtime/handler.py").read_text())
    imported = {n.module for n in ast.walk(handler) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(handler) if isinstance(n, ast.Import) for a in n.names}
    assert {"review_chunks", "review_cli", "reviewer.chunked"} <= imported
    for asset in ("tier2-agentcore/runtime/requirements.txt", "tier2-agentcore/gate/requirements.txt"):
        pins = [line for line in (ROOT / asset).read_text().splitlines()
                if line and not line.startswith("#")]
        assert pins and all("==" in line for line in pins), asset
    # One SDK version for the gate, the runtime and the repository's own pin.
    repo_boto3 = next(line for line in (ROOT / "requirements.txt").read_text().splitlines()
                      if line.startswith("boto3=="))
    for asset in ("tier2-agentcore/runtime/requirements.txt", "tier2-agentcore/gate/requirements.txt"):
        assert repo_boto3 in (ROOT / asset).read_text().splitlines(), asset


# --- the deploy smoke test ------------------------------------------------------------

def test_the_deploy_smoke_test_runs_the_chunked_path_without_any_model(runtime, model,
                                                                        load_module, tmp_path,
                                                                        monkeypatch, capsys):
    smoke = load_module("tier2-agentcore/runtime/smoke.py")
    sent = json.loads(json.dumps(smoke.payload()))         # as the CLI would send it
    assert len(sent["diff"].encode()) > CHUNK and smoke.SCOPED_ITEM_BYTES == runtime.SCOPED_ITEM_BYTES
    report = json.loads(json.dumps(runtime.review(sent)))
    assert model.calls == [] and smoke.check(report, sent) == []
    assert report["chunking"]["chunks"] >= 2
    (tmp_path / "report.json").write_text(json.dumps(report))
    assert smoke.main(["--check", str(tmp_path / "report.json")]) == 0
    assert capsys.readouterr().out.startswith("SMOKE: PASS chunked path")
    # What the 2026-08-20 image answers: today's single-call report, no chunking.
    old = {k: v for k, v in report.items() if k != "chunking"}
    old["agents"] = [{k: v for k, v in a.items() if k != "chunks"} for a in report["agents"]]
    assert "no chunking block" in smoke.check(old, sent)[0]
    # An image without the scoped item cap, or one that answered another diff.
    for key, value in (("scoped_item_bytes", None), ("diff_sha256", "0" * 64),
                       ("reviews_scheduled", 1), ("deadline_reached", True)):
        bad = json.loads(json.dumps(report))
        bad["chunking"][key] = value
        assert any(f"chunking.{key}" in p for p in smoke.check(bad, sent)), key
    (tmp_path / "html.json").write_text("<html>503</html>")
    assert smoke.main(["--check", str(tmp_path / "html.json")]) == 1
    assert "SMOKE: FAIL" in capsys.readouterr().out
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert smoke.main([]) == 0 and json.loads(sys.stdout.getvalue()) == sent
