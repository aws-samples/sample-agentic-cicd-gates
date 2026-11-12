"""Offline evaluation scoring and truthful managed-harness reports."""
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pathlib

import pytest
import yaml

from conftest import ROOT
from reviewer.bedrock_reviewer import ReviewOutcome
from reviewer.rules import AgentConfig, load_rules
from reviewer.verdict import GateResult, Verdict

RS = load_rules((ROOT / ".reviewer.yaml").read_text())


def row(verdict="PASS", **changes):
    return {"case": "case.diff", "agent": "reviewer", "verdict": verdict,
            "error": None, "hits": [], "misses": [], "fps": [], "blocking": 0,
            "secs": 0, **changes}


@pytest.mark.parametrize("actual,expected", [
    ("BLOCKED_ERROR", "PASS"), ("BLOCKED_ERROR", "FAIL"), ("ADVISORY_ERROR", "PASS")])
def test_eval_errors_are_not_pass_or_expected_fail(load_module, actual, expected):
    mod = load_module("evals/run_panel_evals.py")
    labels = {"case.diff": {"verdict": expected, "must_flag": [], "must_not_flag": []}}
    score = mod.score_cases([row(actual)], labels)["case.diff"]
    assert not score["verdict_ok"] and not score["ok"]
    assert score["verdict"] == actual
    assert score["errors"]


@pytest.mark.parametrize("change", [
    {"error": "timeout"}, {"misses": ["STYLE-101"]}, {"fps": ["SEC-003"]}])
def test_eval_correct_verdict_alone_is_insufficient(load_module, change):
    mod = load_module("evals/run_panel_evals.py")
    labels = {"case.diff": {"verdict": "PASS", "must_flag": [], "must_not_flag": []}}
    assert not mod.score_cases([row(**change)], labels)["case.diff"]["ok"]


def test_eval_empty_and_unowned_expectations_fail(load_module):
    mod = load_module("evals/run_panel_evals.py")
    labels = {"case.diff": {"verdict": "PASS", "must_flag": ["STYLE-101"], "must_not_flag": []}}
    assert not mod.score_cases([], labels)["case.diff"]["ok"]
    assert mod.score_cases([row()], labels)["case.diff"]["misses"] == ["STYLE-101"]
    assert mod.scoped(["SEC-003", "STYLE-101"], AgentConfig()) == ["SEC-003", "STYLE-101"]


def test_eval_uses_verdict_not_blocking_counter(load_module):
    mod = load_module("evals/run_panel_evals.py")
    labels = {"case.diff": {"verdict": "FAIL", "must_flag": ["SEC-003"], "must_not_flag": []}}
    assert mod.score_cases([row("FAIL", hits=["SEC-003"])], labels)["case.diff"]["ok"]


def test_panel_main_exit_includes_misses_and_errors(load_module, monkeypatch, tmp_path):
    mod = load_module("evals/run_panel_evals.py")
    (tmp_path / "labels.yaml").write_text(
        "cases:\n  case.diff: {verdict: PASS, must_flag: [STYLE-101], must_not_flag: []}\n")
    monkeypatch.setattr(mod, "HERE", tmp_path)
    monkeypatch.setattr(sys, "argv", ["evals", "--workers", "1"])
    for rows, exit_code in [([row()], 1), ([row(hits=["STYLE-101"])], 0),
                            ([row(hits=["STYLE-101"], error="timeout")], 1)]:
        monkeypatch.setattr(mod, "run_case", lambda *args: rows)
        assert mod.main() == exit_code


def test_single_model_eval_uses_all_rules_and_errors_fail(load_module, monkeypatch):
    mod = load_module("evals/run_evals.py")
    seen = []
    def review(diff, ruleset, **kwargs):
        seen.append(kwargs["agent"])
        return ReviewOutcome(GateResult(Verdict.PASS, (), 0, error="timeout"),
                             "offline-model", 0)
    monkeypatch.setattr(mod, "review_diff", review)
    monkeypatch.setattr(sys, "argv", ["evals", "--only", "xss-textcontent.diff",
                                    "--model", "offline-model"])
    assert mod.main() == 1
    assert seen[0].model == "offline-model"
    assert seen[0].rules == seen[0].file_patterns == ()


def test_sec003_labels_use_live_demo_rules_and_positive_negative_cases(load_module):
    mod = load_module("evals/run_panel_evals.py")
    assert mod.RULES == ROOT / ".reviewer.yaml"
    assert load_rules(mod.RULES.read_text()).by_id("SEC-003").blocking
    labels = yaml.safe_load((ROOT / "evals/labels.yaml").read_text())["cases"]
    positives = [name for name, spec in labels.items() if "SEC-003" in spec["must_flag"]]
    negatives = [name for name, spec in labels.items() if "SEC-003" in spec["must_not_flag"]]
    assert len(positives) >= 2 and len(negatives) >= 2
    for name in positives + negatives:
        assert (ROOT / "evals/golden" / name).read_text().startswith("diff --git ")


@pytest.fixture
def kiro(load_module, monkeypatch, tmp_path):
    if not (pathlib.Path(__file__).resolve().parents[2] / "tier3-kiro").exists():
        pytest.skip("Tier 3 is not part of the published sample")
    mod = load_module("tier3-kiro/kiro_review.py")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "change.diff").write_text("diff --git a/app.js b/app.js\n")
    monkeypatch.setattr(sys, "argv", [
        "kiro_review", "--diff", "change.diff", "--rules", str(ROOT / ".reviewer.yaml"),
        "--report", "report.json", "--model", "global-test-model"])
    monkeypatch.setenv("KIRO_API_KEY", "offline-placeholder")
    monkeypatch.setattr(mod.subprocess, "run", Mock(return_value=SimpleNamespace(
        returncode=0, stdout='{"findings":[]}', stderr="")))
    return mod


def test_kiro_reports_requested_vs_applied_settings(kiro):
    assert kiro.main() == 0
    doc = json.loads(kiro.pathlib.Path("report.json").read_text())
    assert doc["review_method"] == "single_managed_invocation_per_reviewer"
    for agent, row in zip(RS.agents, doc["agents"]):
        assert row["model"] == "global-test-model" and row["thinking"] == "n/a"
        assert row["configured_model"] == agent.model
        assert row["configured_thinking"] == agent.thinking
        assert not row["configured_model_applied"]
        assert not row["configured_thinking_applied"]
        assert not row["file_patterns_applied"]
        assert not row["model_identity_verified"]
    for call in kiro.subprocess.run.call_args_list:
        cmd = call.args[0]
        assert cmd[cmd.index("--model") + 1] == "global-test-model"
        assert not any(a.model in cmd or a.thinking in cmd for a in RS.agents)


def test_kiro_missing_key_blocks_with_truthful_report(kiro, monkeypatch):
    monkeypatch.delenv("KIRO_API_KEY")
    assert kiro.main() == 1
    doc = json.loads(kiro.pathlib.Path("report.json").read_text())
    assert doc["verdict"] == "BLOCKED_ERROR"
    assert all(row["error"] for row in doc["agents"])
    kiro.subprocess.run.assert_not_called()


def test_kiro_malformed_last_answer_does_not_reuse_earlier_empty(kiro):
    kiro.subprocess.run.return_value.stdout = '{"findings":[]}\n{"findings":null}'
    agent, result = kiro._run_seat(RS.agents[0], "change.diff", RS, 1)
    assert result.verdict == Verdict.BLOCKED_ERROR


def test_kiro_nonzero_exit_and_unknown_rule_block(kiro):
    kiro.subprocess.run.return_value.returncode = 2
    assert kiro._run_seat(RS.agents[0], "change.diff", RS, 1)[1].verdict == Verdict.BLOCKED_ERROR
    kiro.subprocess.run.return_value.returncode = 0
    kiro.subprocess.run.return_value.stdout = '{"findings":[{"rule_id":"SEC-999"}]}'
    assert kiro._run_seat(RS.agents[0], "change.diff", RS, 1)[1].verdict == Verdict.BLOCKED_ERROR


@pytest.mark.parametrize("verdict", [Verdict.BLOCKED_ERROR, Verdict.ADVISORY_ERROR])
def test_runtime_and_cli_preserve_panel_error_verdict(
        load_module, monkeypatch, tmp_path, verdict):
    sdk = SimpleNamespace(BedrockAgentCoreApp=lambda: SimpleNamespace(entrypoint=lambda f: f))
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", sdk)
    # The image ships pipeline_tools/review_chunks.py beside handler.py.
    monkeypatch.syspath_prepend(str(ROOT / "pipeline_tools"))
    runtime = load_module("tier2-agentcore/runtime/handler.py")
    cli = load_module("agent/review_cli.py")
    panel = [(RS.agents[0], ReviewOutcome(GateResult(verdict, (), 0, "timeout"), "fake", 0))]
    monkeypatch.setattr(runtime, "review_panel", lambda *args, **kw: panel)
    assert runtime.review({"diff": "", "rules_yaml": (ROOT / ".reviewer.yaml").read_text()})[
        "verdict"] == verdict.value
    diff = tmp_path / "diff"
    diff.write_text("")
    report = tmp_path / "report.json"
    monkeypatch.setattr(cli, "review_panel", lambda *args, **kw: panel)
    monkeypatch.setattr(sys, "argv", ["review_cli", "--diff", str(diff), "--rules",
                                    str(ROOT / ".reviewer.yaml"), "--report", str(report)])
    assert cli.main() == (1 if verdict == Verdict.BLOCKED_ERROR else 0)
    assert json.loads(report.read_text())["verdict"] == verdict.value
