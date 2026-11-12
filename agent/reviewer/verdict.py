"""Findings and verdicts.

THE core security property of this gate: the verdict is COMPUTED
here from rule metadata + validated finding counts. The model never emits a
verdict, and nothing the model writes (message text, suggested code, or an
injected instruction inside the diff) can change which rules are blocking.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from enum import Enum

from .rules import RuleSet


class Verdict(str, Enum):
    PASS = "PASS"                     # no blocking findings  # nosec B105 - a verdict name, not a credential
    FAIL = "FAIL"                     # >=1 blocking finding at/above threshold
    ADVISORY_ERROR = "ADVISORY_ERROR"  # infra/parse failure under fail_mode=open
    BLOCKED_ERROR = "BLOCKED_ERROR"    # infra/parse failure under fail_mode=closed


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    line: int
    message: str
    confidence: int
    severity: str = "medium"
    blocking: bool = False            # ALWAYS overwritten from the rule set
    suggested_code: str | None = None


class FindingsValidationError(ValueError):
    """Model output did not conform to the findings contract."""


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def normalize_model_text(raw_text: str) -> str:
    """Strip terminal control bytes and one markdown fence from model output.

    ANSI escapes are not hypothetical. Tier 3's managed harness colorizes its
    replies, and those raw ESC bytes landed INSIDE JSON string values (it
    highlights identifiers), which is illegal in JSON - so every candidate
    object failed json.loads and the seat reported "no JSON object with a
    findings[] array" as though the model had answered in prose. Bedrock
    returns plain text today, so Tiers 1 and 2 have not been bitten; this lives
    in the SHARED validator so that stays true if any surface ever grows a
    terminal in the middle of it. One definition, three tiers.
    """
    text = ANSI_RE.sub("", raw_text).strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        text = text.split("\n", 1)[1] if "\n" in text else text
    return text.strip()


def parse_model_findings(raw_text: str, ruleset: RuleSet, *,
                         require_confidence: bool = True) -> list[Finding]:
    """Validate model output into Findings.

    Contract: the model returns a JSON object {"findings": [...]}. We accept a
    fenced code block around it. Every finding must reference a known rule id;
    unknown, malformed, or out-of-scope findings invalidate the response.
    Empty findings remain valid. Discovery may omit confidence; the validation
    stage must score every candidate before a verdict is computed.
    Severity and blocking are taken from the RULE, never from the model.
    """
    text = normalize_model_text(raw_text)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FindingsValidationError(f"model output is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise FindingsValidationError('model output must be {"findings": [...]}')
    if len(doc["findings"]) > ruleset.max_findings:
        raise FindingsValidationError("findings exceeds max_findings; refusing to truncate")

    findings: list[Finding] = []
    for i, raw in enumerate(doc["findings"]):
        def invalid(reason):
            raise FindingsValidationError(f"findings[{i}]: {reason}")

        if not isinstance(raw, dict):
            invalid("must be an object")
        rule = ruleset.by_id(raw.get("rule_id"))
        if rule is None:
            invalid("unknown or missing rule_id")
        path = raw.get("path")
        if (not isinstance(path, str) or not path.strip() or len(path) > 4096
                or path.startswith("/") or any(p in (".", "..") for p in path.split("/"))
                or any(ord(c) < 32 for c in path)):
            invalid("path must be a relative repository path (1-4096 characters)")
        if not rule.matches_path(path):
            invalid(f"path is outside {rule.id} scope")
        line = raw.get("line")
        if type(line) is not int or line < 0:
            invalid("line must be a nonnegative integer")
        confidence = raw.get("confidence", None if require_confidence else 0)
        if type(confidence) is not int or not 0 <= confidence <= 100:
            invalid("confidence must be an integer from 0 to 100")
        message = raw.get("message")
        if not isinstance(message, str) or not message.strip() or len(message) > 2000:
            invalid("message must contain 1-2000 characters")
        suggested = raw.get("suggested_code")
        if suggested is not None and (not isinstance(suggested, str) or len(suggested) > 2000):
            invalid("suggested_code must be null or a string up to 2000 characters")
        findings.append(
            Finding(
                rule_id=rule.id,
                path=path,
                line=line,
                message=message,
                confidence=confidence,
                severity=rule.severity,          # from rule, not model
                blocking=rule.blocking,          # from rule, not model
                suggested_code=suggested,
            )
        )
    return findings


@dataclass(frozen=True)
class GateResult:
    verdict: Verdict
    findings: tuple[Finding, ...]
    suppressed_below_threshold: int
    error: str | None = None

    @property
    def blocking_count(self) -> int:
        return sum(1 for f in self.findings if f.blocking)

    def to_json(self) -> str:
        return json.dumps(
            {
                "verdict": self.verdict.value,
                "stats": {
                    "total": len(self.findings),
                    "blocking": self.blocking_count,
                    "suppressed_below_threshold": self.suppressed_below_threshold,
                },
                "findings": [asdict(f) for f in self.findings],
                "error": self.error,
            },
            indent=2,
        )


def compute_verdict(findings: list[Finding], ruleset: RuleSet) -> GateResult:
    """Apply the confidence floor, then derive the verdict from counts."""
    kept = [f for f in findings if f.confidence >= ruleset.confidence_threshold]
    suppressed = len(findings) - len(kept)
    blocking = any(f.blocking for f in kept)
    return GateResult(
        verdict=Verdict.FAIL if blocking else Verdict.PASS,
        findings=tuple(kept),
        suppressed_below_threshold=suppressed,
    )


def panel_verdict(verdicts) -> Verdict:
    """Preserve error states when folding a panel, including an empty panel."""
    order = [Verdict.PASS, Verdict.ADVISORY_ERROR, Verdict.FAIL, Verdict.BLOCKED_ERROR]
    values = [Verdict(v) for v in verdicts]
    return max(values, key=order.index) if values else Verdict.BLOCKED_ERROR


def error_result(ruleset: RuleSet, error: str, agent=None) -> GateResult:
    """Infra/parse failure path: fail-open (advisory) or fail-closed per rules.

    A seat that owns blocking rules fails CLOSED regardless of the global
    fail_mode. Otherwise a model that times out — or refuses the diff, which
    content-filtering models do on exploit-shaped code — would degrade to
    ADVISORY_ERROR and let a blocking gate pass on no evidence at all.
    """
    owns_blocking = any(
        r.blocking and (not agent or not agent.rules
                       or any(r.id.startswith(p) for p in agent.rules))
        for r in ruleset.rules)
    verdict = (Verdict.BLOCKED_ERROR
               if owns_blocking or ruleset.fail_mode != "open"
               else Verdict.ADVISORY_ERROR)
    return GateResult(verdict=verdict, findings=(), suppressed_below_threshold=0, error=error)
