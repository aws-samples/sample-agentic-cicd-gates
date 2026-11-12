"""Offline unit tests: the verdict must derive from rule metadata only."""
import pathlib
import sys
import pytest
from dataclasses import replace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from reviewer.rules import load_rules
from reviewer.verdict import (FindingsValidationError, Verdict, compute_verdict, error_result,
                              parse_model_findings)

RULES = pathlib.Path(__file__).resolve().parents[2] / "rules/reviewer.example.yaml"
RS = load_rules(RULES.read_text())


def _mk(rule_id, path, conf, line=1):
    return parse_model_findings(
        '{"findings": [{"rule_id": "%s", "path": "%s", "line": %d, '
        '"message": "m", "confidence": %d}]}' % (rule_id, path, line, conf), RS)


def test_blocking_rule_above_threshold_fails():
    fs = _mk("SEC-001", "src/db.py", 95)
    assert compute_verdict(fs, RS).verdict is Verdict.FAIL


def test_below_threshold_suppressed():
    fs = _mk("SEC-001", "src/db.py", 50)
    r = compute_verdict(fs, RS)
    assert r.verdict is Verdict.PASS and r.suppressed_below_threshold == 1


def test_advisory_rule_never_fails():
    fs = _mk("STYLE-101", "src/db.py", 100)
    assert compute_verdict(fs, RS).verdict is Verdict.PASS


def test_model_cannot_forge_blocking_via_unknown_rule():
    with pytest.raises(FindingsValidationError, match="unknown"):
        _mk("TOTALLY-FAKE-RULE", "src/db.py", 100)


def test_model_blocking_flag_is_ignored():
    fs = parse_model_findings(
        '{"findings": [{"rule_id": "STYLE-101", "path": "a.py", "line": 1,'
        ' "message": "m", "confidence": 100, "blocking": true,'
        ' "severity": "high"}]}', RS)
    assert fs[0].blocking is False and fs[0].severity == "low"  # from rule


def test_out_of_scope_path_rejected():
    with pytest.raises(FindingsValidationError, match="scope"):
        _mk("IAM-002", "src/app.py", 99)


def test_only_advisory_rules_can_fail_open_on_error():
    advisory = replace(RS, rules=tuple(r for r in RS.rules if not r.blocking))
    assert error_result(advisory, "boom").verdict is Verdict.ADVISORY_ERROR
    assert error_result(RS, "boom").verdict is Verdict.BLOCKED_ERROR


def test_garbage_output_raises_contract_error():
    import pytest
    from reviewer.verdict import FindingsValidationError
    with pytest.raises(FindingsValidationError):
        parse_model_findings("I think this code looks great!", RS)
