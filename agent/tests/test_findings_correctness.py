"""Malformed evidence must not become a clean review."""
import json
from types import SimpleNamespace

import pytest

from conftest import ROOT
from reviewer.bedrock_reviewer import _parse_scores, review_diff
from reviewer.rules import AgentConfig, RulesError, load_rules
from reviewer.verdict import (FindingsValidationError, Verdict, compute_verdict,
                              error_result, panel_verdict, parse_model_findings)

RS = load_rules((ROOT / ".reviewer.yaml").read_text())
VALID = {"rule_id": "SEC-003", "path": "web/src/main.js", "line": 2,
         "message": "Untrusted input reaches innerHTML", "confidence": 95}


def parse(rows, **kwargs):
    return parse_model_findings(json.dumps({"findings": rows}), RS, **kwargs)


@pytest.mark.parametrize("raw", [None, 1, [], "finding", {},
    {**VALID, "rule_id": "SEC-999"},
    {**VALID, "rule_id": ["SEC-003"]},
    {**VALID, "path": "image.png"},
    {**VALID, "path": 1},
    {**VALID, "path": "../main.js"},
    {**VALID, "path": "/main.js"},
    {**VALID, "path": "a" * 4097},
    {**VALID, "line": -1},
    {**VALID, "line": True},
    {**VALID, "line": "2"},
    {**VALID, "confidence": "95"},
    {**VALID, "confidence": True},
    {**VALID, "confidence": 95.5},
    {**VALID, "confidence": 101},
    {**VALID, "confidence": -1},
    {**VALID, "message": None},
    {**VALID, "message": " "},
    {**VALID, "message": "m" * 2001},
    {**VALID, "suggested_code": {}},
    {**VALID, "suggested_code": "x" * 2001},
])
def test_invalid_finding_rejects_entire_response(raw):
    with pytest.raises(FindingsValidationError):
        parse([VALID, raw])


@pytest.mark.parametrize("field", ["rule_id", "path", "line", "message", "confidence"])
def test_required_fields(field):
    raw = dict(VALID)
    raw.pop(field)
    with pytest.raises(FindingsValidationError):
        parse([raw])


def test_valid_empty_and_discovery_without_confidence():
    assert compute_verdict(parse([]), RS).verdict == Verdict.PASS
    raw = dict(VALID)
    raw.pop("confidence")
    assert parse([raw], require_confidence=False)[0].confidence == 0


def test_ansi_and_fenced_valid_output_remain_accepted():
    raw = "```json\n" + json.dumps({"findings": [VALID]}) + "\n```"
    assert parse_model_findings("\x1b[32m" + raw + "\x1b[0m", RS)[0].rule_id == "SEC-003"


def test_excess_findings_are_not_silently_truncated():
    with pytest.raises(FindingsValidationError, match="truncate"):
        parse([VALID] * (RS.max_findings + 1))


@pytest.mark.parametrize("limit", [-1, 0, True, "25", 1001])
def test_invalid_max_findings(limit):
    import yaml
    doc = yaml.safe_load((ROOT / ".reviewer.yaml").read_text())
    doc["defaults"]["max_findings"] = limit
    with pytest.raises(RulesError, match="max_findings"):
        load_rules(yaml.safe_dump(doc))


@pytest.mark.parametrize("doc", [[], {}, {"scores": []}, {"scores": [None]},
    {"scores": [{"index": 0, "confidence": 90}]},
    {"scores": [{"index": 0, "confidence": 90}, {"index": 0, "confidence": 90}]},
    {"scores": [{"index": 0, "confidence": 90}, {"index": 2, "confidence": 90}]},
    {"scores": [{"index": 0, "confidence": 90}, {"index": True, "confidence": 90}]},
    {"scores": [{"index": 0, "confidence": 90}, {"index": 1, "confidence": "90"}]},
    {"scores": [{"index": 0, "confidence": 90}, {"index": 1, "confidence": 101}]},
])
def test_incomplete_or_malformed_validation_scores(doc):
    with pytest.raises(FindingsValidationError):
        _parse_scores(json.dumps(doc), 2)


def test_complete_scores_accept_reordering_and_zero():
    assert _parse_scores('{"scores":[{"index":1,"confidence":0},'
                         '{"index":0,"confidence":100}]}', 2) == {1: 0, 0: 100}


class FakeModel:
    def __init__(self, *answers):
        self.answers = iter(answers)
        self.calls = []
        self.exceptions = SimpleNamespace(ValidationException=ValueError)

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {"output": {"message": {"content": [{"text": next(self.answers)}]}}}


@pytest.mark.parametrize("answer", ['{"findings":[null]}',
                                  '{"findings":[{"rule_id":"UNKNOWN"}]}'])
def test_malformed_discovery_blocks(answer):
    result = review_diff("diff --git a/app.js b/app.js\n", RS,
                         client=FakeModel(answer)).result
    assert result.verdict == Verdict.BLOCKED_ERROR
    assert "contract violation" in result.error


def test_missing_scores_block_and_valid_empty_needs_only_discovery():
    discovery = dict(VALID)
    discovery.pop("confidence")
    result = review_diff("diff --git a/app.js b/app.js\n", RS, client=FakeModel(
        json.dumps({"findings": [discovery]}), '{"scores":[]}')).result
    assert result.verdict == Verdict.BLOCKED_ERROR
    client = FakeModel('{"findings":[]}')
    assert review_diff("", RS, client=client).result.verdict == Verdict.PASS
    assert len(client.calls) == 1


def test_two_stage_finding_retains_rule_policy_and_score():
    client = FakeModel(json.dumps({"findings": [VALID]}),
                       '{"scores":[{"index":0,"confidence":95}]}')
    assert review_diff("diff --git a/app.js b/app.js\n", RS,
                       client=client).result.verdict == Verdict.FAIL


def test_unscoped_blocking_reviewer_fails_closed():
    assert error_result(RS, "timeout", agent=AgentConfig()).verdict == Verdict.BLOCKED_ERROR
    advisory = next(a for a in RS.agents if a.rules == ("DES-",))
    assert error_result(RS, "timeout", agent=advisory).verdict == Verdict.ADVISORY_ERROR


def test_panel_preserves_error_states():
    assert panel_verdict([]) == Verdict.BLOCKED_ERROR
    assert panel_verdict(["PASS", "ADVISORY_ERROR"]) == Verdict.ADVISORY_ERROR
    assert panel_verdict(["FAIL", "BLOCKED_ERROR"]) == Verdict.BLOCKED_ERROR


def test_report_schema_accepts_accessibility_ids():
    import re
    schema = json.loads((ROOT / "agent/schemas/findings.schema.json").read_text())
    pattern = schema["properties"]["findings"]["items"]["properties"]["rule_id"]["pattern"]
    assert re.fullmatch(pattern, "A11Y-001")
