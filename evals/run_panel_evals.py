"""Panel evals: run the golden set through every configured persona.

Per persona, labels are scoped to its rule prefixes — Vector is not penalized
for missing SEC-001 and Sentinel is not penalized for missing STYLE-101.
Overall verdict preserves actual per-reviewer verdicts, including errors.
Exit zero requires every verdict, expected finding and negative label to match,
with no review errors. Token costs cover model inference only.

Usage: python run_panel_evals.py [--region us-west-2] [--workers 5]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import pathlib
import statistics
import sys
import time
from collections import defaultdict

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from reviewer import bedrock_reviewer as br  # noqa: E402
from reviewer.rules import load_rules  # noqa: E402
from reviewer.verdict import Verdict, panel_verdict  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
RULES = HERE.parent / ".reviewer.yaml"

# List prices per 1M tokens (input, output) — update alongside docs/cost.md.
# A model missing here is reported as "unpriced", never as $0.000: a silent zero
# in a cost table is worse than a blank, because it reads as free inference.
# US geographic cross-Region inference (the `us.` profiles this sample calls),
# Standard tier, short context, us-west-2, checked 2026-11-06: Claude from the
# AWS Price List API (AmazonBedrockFoundationModels), GPT from the Bedrock model
# cards. US geographic profiles cost 10% more than global ones.
PRICES = {
    "us.anthropic.claude-opus-5-5": (4.40, 22.00),
    "us.openai.gpt-6.1-sol": (2.20, 11.00),
    "us.anthropic.claude-fable-5-1": (11.00, 55.00),
    "us.anthropic.claude-sonnet-5-5": (2.20, 11.00),
    # Previous panel models, still available, for re-running older configurations.
    "us.anthropic.claude-opus-5": (5.50, 27.50),
    "us.anthropic.claude-opus-4-8": (5.50, 27.50),
    "us.openai.gpt-5.6-sol": (4.40, 22.00),
    "us.anthropic.claude-fable-5": (11.00, 55.00),
}


def scoped(ids, agent):
    return [i for i in ids if not agent.rules or any(i.startswith(p) for p in agent.rules)]


def run_case(name, spec, ruleset, region):
    diff = (HERE / "golden" / name).read_text()
    rows = []
    for agent in ruleset.agents or (ruleset.agent,):
        t0 = time.time()
        out = br.review_diff(diff, ruleset, region=region, agent=agent)
        dt = time.time() - t0
        found = {f.rule_id for f in out.result.findings}
        must = set(scoped(spec["must_flag"], agent))
        must_not = set(scoped(spec["must_not_flag"], agent))
        rows.append({
            "case": name, "agent": agent.name, "secs": dt,
            "hits": sorted(must & found), "misses": sorted(must - found),
            "fps": sorted(must_not & found),
            "blocking": out.result.blocking_count,
            "verdict": out.result.verdict.value,
            "error": out.result.error,
        })
    return rows


def score_cases(rows, labels):
    """Use actual verdicts and all labeled findings; errors never earn credit."""
    scores = {}
    for name, spec in labels.items():
        case_rows = [r for r in rows if r["case"] == name]
        verdict = panel_verdict(r["verdict"] for r in case_rows).value
        errors = [r["agent"] for r in case_rows if r["error"] or
                  r["verdict"] in (Verdict.ADVISORY_ERROR, Verdict.BLOCKED_ERROR)]
        hits = {rid for r in case_rows for rid in r["hits"]}
        # Include labels with no owning reviewer: they are misses, not ignored.
        misses = sorted((set(spec["must_flag"]) - hits) |
                        {rid for r in case_rows for rid in r["misses"]})
        fps = sorted({rid for r in case_rows for rid in r["fps"]})
        verdict_ok = bool(case_rows) and not errors and verdict == spec["verdict"]
        scores[name] = {"verdict": verdict, "verdict_ok": verdict_ok,
                        "errors": errors, "misses": misses, "fps": fps,
                        "ok": verdict_ok and not misses and not fps}
    return scores


def main() -> int:
    p = argparse.ArgumentParser(description="Panel golden-set evals")
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--rules", type=pathlib.Path, default=RULES)
    args = p.parse_args()

    ruleset = load_rules(args.rules.read_text())
    br.USAGE_LOG.clear()
    labels = yaml.safe_load((HERE / "labels.yaml").read_text())["cases"]
    print(f"panel={[a.name for a in ruleset.agents]} cases={len(labels)}")

    t0 = time.time()
    rows = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(run_case, n, s, ruleset, args.region): n
                for n, s in labels.items()}
        for fut in cf.as_completed(futs):
            rows.extend(fut.result())
    wall = time.time() - t0

    per = defaultdict(lambda: {"secs": [], "miss": 0, "fp": 0, "hit": 0,
                               "err": 0})
    for r in rows:
        a = per[r["agent"]]
        a["secs"].append(r["secs"])
        a["hit"] += len(r["hits"]); a["miss"] += len(r["misses"])
        a["fp"] += len(r["fps"])
        a["err"] += int(bool(r["error"]) or r["verdict"] in
                        (Verdict.ADVISORY_ERROR, Verdict.BLOCKED_ERROR))
        if r["misses"] or r["fps"] or r["error"] or r["verdict"].endswith("_ERROR"):
            print(f"  !! {r['case']} [{r['agent']}] "
                  f"verdict={r['verdict']} miss={r['misses']} fp={r['fps']} "
                  f"error={r['error']}")

    scores = score_cases(rows, labels)
    v_ok = sum(s["verdict_ok"] for s in scores.values())
    for name, score in scores.items():
        if not score["ok"]:
            print(f"  FAILED {name}: {score}")
    print(f"\noverall verdict accuracy: {v_ok}/{len(labels)}  "
          f"wall={wall:.0f}s\n")
    # Report every reviewer, even when an error produced no token-usage entry.
    # Multiple reviewers can also share a model, so model-level cost cannot be
    # used as the index for reviewer-level correctness or latency.
    print(f"{'reviewer':30s} {'med-s':>6s} {'p95-s':>6s} "
          f"{'hit':>4s} {'miss':>4s} {'fp':>3s} {'err':>3s}")
    for name, a in per.items():
        secs = sorted(a["secs"])
        med = statistics.median(secs)
        p95 = secs[max(0, int(len(secs) * 0.95) - 1)]
        print(f"{name:30s} {med:6.1f} {p95:6.1f} "
              f"{a['hit']:4d} {a['miss']:4d} {a['fp']:3d} {a['err']:3d}")

    usage = defaultdict(lambda: [0, 0, 0])
    for u in br.USAGE_LOG:
        m = usage[u["model"]]
        m[0] += u["in"]; m[1] += u["out"]; m[2] += 1
    print(f"\n{'model':30s} {'calls':>5s} {'tok-in':>8s} "
          f"{'tok-out':>8s} {'$/suite':>8s}")
    for model, (ti, to, calls) in usage.items():
        priced = model in PRICES
        pin, pout = PRICES.get(model, (0.0, 0.0))
        cost = ti / 1e6 * pin + to / 1e6 * pout
        cost_cell = f"{cost:8.3f}" if priced else "unpriced"
        print(f"{model:30s} {calls:5d} {ti:8d} {to:8d} {cost_cell:>8s}")
    return 0 if scores and all(s["ok"] for s in scores.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
