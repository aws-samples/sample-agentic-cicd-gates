"""Evals harness: run the reviewer over the labeled golden set.

Prints per-case results, per-rule precision/recall, and verdict accuracy.
This is the "who reviews the reviewer" mechanism behind the advisory→blocking
promotion policy: never flip `blocking: true` on a rule whose precision here
(and in ≥2 weeks of advisory production findings) isn't earning it.

Usage: python run_evals.py [--region us-west-2] [--model <id>] [--only case.diff]
Exit 0 = all verdicts correct AND no must_flag/must_not_flag violations.
"""
from __future__ import annotations

import argparse
import dataclasses
import pathlib
import sys
import time
from collections import defaultdict

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent"))
from reviewer.bedrock_reviewer import DEFAULT_MODEL, review_diff  # noqa: E402
from reviewer.rules import load_rules  # noqa: E402
from reviewer.verdict import Verdict  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
RULES = HERE.parent / ".reviewer.yaml"


def main() -> int:
    p = argparse.ArgumentParser(description="Golden-set evals")
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--only", help="run a single case file name")
    p.add_argument("--rules", type=pathlib.Path, default=RULES)
    args = p.parse_args()

    ruleset = load_rules(args.rules.read_text())
    # This harness evaluates one model against ALL labels, not just the first
    # configured reviewer's rule scope. The panel harness measures specialists.
    evaluator = dataclasses.replace(ruleset.agent, model=args.model, rules=(),
                                    file_patterns=(), persona="")
    labels = yaml.safe_load((HERE / "labels.yaml").read_text())["cases"]
    if args.only:
        labels = {args.only: labels[args.only]}

    tp: dict[str, int] = defaultdict(int)  # rule flagged where must_flag
    fp: dict[str, int] = defaultdict(int)  # rule flagged where must_not_flag
    fn: dict[str, int] = defaultdict(int)  # rule missing where must_flag
    verdict_ok = 0
    failures: list[str] = []

    print(f"model={args.model} region={args.region} threshold="
          f"{ruleset.confidence_threshold}\n")
    for name, spec in labels.items():
        diff = (HERE / "golden" / name).read_text()
        t0 = time.time()
        outcome = review_diff(diff, ruleset, model_id=args.model, region=args.region,
                              agent=evaluator)
        dt = time.time() - t0
        got_verdict = outcome.result.verdict.value
        flagged = {f.rule_id for f in outcome.result.findings}

        error = outcome.result.error
        ok = (not error and got_verdict not in
              (Verdict.ADVISORY_ERROR, Verdict.BLOCKED_ERROR)
              and got_verdict == spec["verdict"])
        verdict_ok += ok
        for rid in spec["must_flag"]:
            if rid in flagged:
                tp[rid] += 1
            else:
                fn[rid] += 1
                ok = False
        for rid in spec["must_not_flag"]:
            if rid in flagged:
                fp[rid] += 1
                ok = False

        mark = "ok " if ok else "FAIL"
        print(f"[{mark}] {name:28s} verdict={got_verdict:4s} "
              f"(want {spec['verdict']:4s}) flagged={sorted(flagged) or '-'} "
              f"{dt:.1f}s error={error or '-'}")
        if not ok:
            failures.append(name)

    print("\nPer-rule precision/recall over the labeled set:")
    for rid in sorted(set(tp) | set(fp) | set(fn)):
        prec_d, rec_d = tp[rid] + fp[rid], tp[rid] + fn[rid]
        prec = tp[rid] / prec_d if prec_d else None
        rec = tp[rid] / rec_d if rec_d else None
        print(f"  {rid:10s} precision={'-' if prec is None else f'{prec:.2f}'} "
              f"recall={'-' if rec is None else f'{rec:.2f}'} "
              f"(tp={tp[rid]} fp={fp[rid]} fn={fn[rid]})")
    print(f"\nVerdict accuracy: {verdict_ok}/{len(labels)}")
    if failures:
        print(f"FAILED cases: {', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
