"""CLI entrypoint: review a diff file against a rules file. Exit 0=PASS/advisory, 1=FAIL.

Panel-aware: every persona in the rules file's `agents:` list reviews the diff
against its own rule scope. The report keeps the single-reviewer shape the
pipelines consume (top-level `verdict`, `stats.blocking`, `findings[]`) and
adds per-finding `agent` plus a per-agent `agents[]` summary block.

Chunked: with --chunk-plan (written by pipeline_tools/prepare_review.py), a
delta larger than one chunk is reviewed chunk by chunk (reviewer/chunked.py)
and folded back into the SAME report shape: one verdict, one agents[] row per
seat carrying per-chunk detail, and a top-level `chunking` summary whose
`note` states what a chunked PASS does not cover. A chunk whose review ended in
an error is reviewed once more while the deadline allows. A plan of one chunk
(or none, for an empty diff) takes the single-call path unchanged. A plan that
fails verification is BLOCKED_ERROR whatever the policy says, because an
unproven plan is missing evidence.
"""
import argparse
import json
import pathlib
import sys

# `python -I` (how the gate builds run this) does not put this file's directory on
# sys.path, so add it explicitly: the reviewer package ships beside this file.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from reviewer.bedrock_reviewer import DEFAULT_MODEL, ReviewOutcome, review_panel, seat_ruleset  # noqa: E402
from reviewer.chunked import PlanVerificationError, load_plan, review_panel_chunked, schedule  # noqa: E402
from reviewer.rules import load_rules  # noqa: E402
from reviewer.verdict import Verdict, error_result, panel_verdict  # noqa: E402


def _report(panel, details=None, chunking=None, error=None, forced=None):
    verdict = forced or panel_verdict(o.result.verdict for _, o in panel)
    findings, agents, stats = [], [], {"blocking": 0, "total": 0,
                                       "suppressed_below_threshold": 0}
    for agent, out in panel:
        doc = json.loads(out.result.to_json())
        seat = (details or {}).get(agent.name)
        for k, f in enumerate(doc["findings"]):
            f["agent"] = agent.name
            if seat:
                f["chunk"] = seat["finding_items"][k]
            findings.append(f)
        for k in stats:
            stats[k] += doc["stats"].get(k, 0)
        row = {"name": agent.name, "model": out.model_id,
               "thinking": agent.thinking,
               "verdict": doc["verdict"],
               "blocking": doc["stats"]["blocking"],
               "error": doc.get("error")}
        if seat:
            row["chunks"] = seat["items"]
            row["duplicates_removed"] = seat["duplicates_removed"]
        agents.append(row)
        print(f"[{agent.name}] VERDICT={doc['verdict']} "
              f"blocking={doc['stats']['blocking']} "
              f"discovered={out.discovery_count} model={out.model_id}",
              file=sys.stderr)
    report = {"verdict": verdict.value, "stats": stats, "findings": findings,
              "agents": agents}
    if chunking:
        report["chunking"] = chunking
    if error:
        report["error"] = error
    return verdict, report


def _finish(args, panel, **kw) -> int:
    verdict, report = _report(panel, **kw)
    text = json.dumps(report, indent=2)
    if args.report:
        pathlib.Path(args.report).write_text(text)
    print(text, flush=True)
    print(f"VERDICT={verdict.value} "
          f"blocking={report['stats']['blocking']} panel={len(report['agents'])}",
          file=sys.stderr, flush=True)
    return 1 if verdict in (Verdict.FAIL, Verdict.BLOCKED_ERROR) else 0


def main() -> int:
    p = argparse.ArgumentParser(description="Agentic review gate")
    p.add_argument("--diff", required=True, help="path to unified diff file")
    p.add_argument("--rules", required=True, help="path to .reviewer.yaml (from BASE ref)")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--report", help="write JSON report here")
    p.add_argument("--chunk-plan", help="chunk-plan.json from prepare_review.py")
    p.add_argument("--workers", type=int, default=8,
                   help="concurrent seat reviews in chunked mode")
    p.add_argument("--deadline-seconds", type=float,
                   help="chunked mode: stop waiting and fail incomplete seats closed")
    p.add_argument("--dry-run", action="store_true",
                   help="verify --chunk-plan and print each seat's schedule; no model call")
    args = p.parse_args()

    ruleset = load_rules(pathlib.Path(args.rules).read_text())
    diff = pathlib.Path(args.diff).read_text()
    plan = None
    if args.chunk_plan:
        try:
            plan = load_plan(pathlib.Path(args.chunk_plan), diff)
        except PlanVerificationError as exc:
            message = f"review chunk plan failed verification: {exc}"
            if args.dry_run:
                print(message, file=sys.stderr)
                return 1
            panel = [(a, ReviewOutcome(error_result(seat_ruleset(ruleset, a), message, a),
                                       a.model or args.model, 0))
                     for a in ruleset.agents or (ruleset.agent,)]
            return _finish(args, panel, error=message, forced=Verdict.BLOCKED_ERROR)
    if args.dry_run:
        if plan is None:
            p.error("--dry-run needs --chunk-plan")
        print(json.dumps(schedule(plan, ruleset, args.model), indent=2))
        return 0
    if plan is None or len(plan.chunks) <= 1:
        panel = review_panel(diff, ruleset, model_id=args.model, region=args.region)
        return _finish(args, panel)
    result = review_panel_chunked(plan, ruleset, model_id=args.model, region=args.region,
                                  workers=args.workers,
                                  deadline_seconds=args.deadline_seconds)
    return _finish(args, result.panel, details=result.details, chunking=result.meta)


if __name__ == "__main__":
    sys.exit(main())
