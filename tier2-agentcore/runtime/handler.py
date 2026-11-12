"""AgentCore Runtime entrypoint — wraps the SAME two-stage reviewer core as Tier 1.

Contract (HTTP protocol): BedrockAgentCoreApp serves GET /ping and POST /invocations
on port 8080. The pipeline's Lambda gate sends {"diff": str, "rules_yaml": str,
"deadline_seconds": number} and gets back the GateResult JSON plus run metadata.
Verdicts are still derived from rule metadata (verdict.py), never from model prose —
hosting changed, guarantees didn't.

A diff of at most one review chunk takes today's single-call path unchanged. A
larger one is reviewed with Tier 1's own code, copied into this image beside the
reviewer: review_chunks.py (pipeline_tools/) plans it, reviewer/chunked.py
independently re-verifies the plan and reviews every (seat, chunk) on a worker
pool under the deadline the gate sends, and review_cli.py folds the panel into
the same report Tier 1 writes (agents[].chunks, findings[].chunk, `chunking`).
An unplannable or unverifiable delta is BLOCKED_ERROR before any model call.
"""
import json
import os
import pathlib
import tempfile

from bedrock_agentcore import BedrockAgentCoreApp

import review_chunks
from review_cli import _report
from reviewer.bedrock_reviewer import DEFAULT_MODEL, ReviewOutcome, review_panel, seat_ruleset
from reviewer.chunked import PlanVerificationError, load_plan, review_panel_chunked
from reviewer.rules import load_rules
from reviewer.verdict import Verdict, error_result, panel_verdict

app = BedrockAgentCoreApp()

# Chunk reviews in flight at once. Twice Tier 1's 8, because Tier 2 has one
# synchronous call (a 720-s deadline) where Tier 1 has 82 minutes; the panel's
# Bedrock quotas are tokens per minute in the millions, far above 16 calls of
# one ~100 KB chunk each. tier2-agentcore/gate/lambda_handler.py has the budget.
REVIEW_WORKERS = 16
# The gate's read timeout is 840 s; never wait longer than this for chunks,
# whatever the payload asks, so the report always leaves before it.
MAX_DEADLINE_SECONDS = 780.0
# A scoped seat's review items, at most this many bytes where file sections
# allow (one larger section is an item on its own). Unscoped seats keep the
# planner's 100,000-byte chunks. A scoped item is dense with exactly what its
# rules read: the one measured, the Accessibility seat (Fable 5, high) on
# 22,887 bytes, took 244.5 s with 4 candidates to validate (Tier 1, 2026-10-06),
# so one attempt plus one retry of an item this size fits the 720-s deadline.
# Packed at 100,000 bytes, the road merge gave that seat ONE 99,646-byte item
# nobody has timed. Tier 1, with 82 minutes, keeps the planner's size.
SCOPED_ITEM_BYTES = 30_000


def _deadline(value) -> float:
    if type(value) not in (int, float) or not value > 0:
        raise ValueError("deadline_seconds must be a positive number")
    return min(float(value), MAX_DEADLINE_SECONDS)


def _refused(ruleset, model, message):
    """Every seat fails closed with the reason, whatever the policy says (as review_cli)."""
    panel = [(a, ReviewOutcome(error_result(seat_ruleset(ruleset, a), message, a),
                               a.model or model, 0))
             for a in ruleset.agents or (ruleset.agent,)]
    return _report(panel, error=message, forced=Verdict.BLOCKED_ERROR)[1]


def _chunked_review(diff, ruleset, model, region, deadline):
    try:
        # The caller owns the time budget; a chunked review never runs without one.
        deadline = _deadline(deadline)
    except ValueError as exc:
        return _refused(ruleset, model, f"chunked review refused: {exc}")
    try:
        chunks = review_chunks.plan(diff)
    except review_chunks.PlanError as exc:
        return _refused(ruleset, model, f"review chunk planning failed: {exc}")
    with tempfile.TemporaryDirectory(prefix="review-plan-") as tmp:
        out = pathlib.Path(tmp)
        review_chunks.write_plan(chunks, diff, review_chunks.CHUNK_BYTES, out)
        try:
            # Verified by code that does not trust the planner; reads every
            # chunk file into memory, so the directory can go afterwards.
            plan = load_plan(out / review_chunks.PLAN_FILE, diff)
        except PlanVerificationError as exc:
            return _refused(ruleset, model, f"review chunk plan failed verification: {exc}")
    result = review_panel_chunked(plan, ruleset, model_id=model, region=region,
                                  workers=REVIEW_WORKERS, deadline_seconds=deadline,
                                  scoped_item_bytes=SCOPED_ITEM_BYTES)
    report = _report(result.panel, details=result.details, chunking=result.meta)[1]
    # Lets the gate check that this report covers exactly the diff it sent.
    report["chunking"]["diff_sha256"] = plan.diff_sha256
    return report


@app.entrypoint
def review(payload, context=None):
    diff = payload.get("diff", "")
    rules_yaml = payload.get("rules_yaml", "")
    if not rules_yaml:
        # No rules => nothing is blocking; refuse loudly rather than silently passing.
        return {"verdict": "BLOCKED_ERROR", "error": "no rules_yaml in payload",
                "stats": {"total": 0, "blocking": 0}, "findings": []}
    model = payload.get("model") or os.environ.get("REVIEWER_MODEL", DEFAULT_MODEL)
    region = os.environ.get("AWS_REGION", "us-west-2")
    if len(diff.encode("utf-8")) > review_chunks.CHUNK_BYTES:
        return _chunked_review(diff, load_rules(rules_yaml), model, region,
                               payload.get("deadline_seconds"))
    # One chunk or less: today's single-call path and report, unchanged.
    panel = review_panel(diff, load_rules(rules_yaml), model_id=model,
                         region=region)
    findings, agents = [], []
    stats = {"blocking": 0, "total": 0, "suppressed_below_threshold": 0}
    for agent, outcome in panel:
        doc = json.loads(outcome.result.to_json())
        for f in doc["findings"]:
            f["agent"] = agent.name
            findings.append(f)
        for k in stats:
            stats[k] += doc["stats"].get(k, 0)
        agents.append({"name": agent.name, "model": outcome.model_id,
                       "thinking": agent.thinking, "verdict": doc["verdict"],
                       "blocking": doc["stats"]["blocking"],
                       "error": doc.get("error")})
    return {"verdict": panel_verdict(a["verdict"] for a in agents).value, "stats": stats,
            "findings": findings, "agents": agents}


if __name__ == "__main__":
    # Explicit bind: AgentCore Runtime probes /ping over the container network,
    # and the SDK's host auto-detection can fall back to 127.0.0.1 (unreachable).
    # Container-network bind required by the AgentCore Runtime contract; the
    # microVM publishes no host port and callers reach it only via
    # InvokeAgentRuntime with SigV4.
    app.run(host="0.0.0.0")  # nosec B104  # nosemgrep: python.flask.security.audit.avoid_app_run_with_bad_host
