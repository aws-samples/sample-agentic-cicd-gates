"""Check a Tier 1 review's evidence before anyone approves the release.

Read-only and local: it compares the pipeline's findings.json with a
`prepare_review.py --dry-run` of the same range (and, optionally, the
`review_cli.py --dry-run` schedule) and prints EVIDENCE: PASS only when

* the verdict is PASS with no blocking finding, and every seat in the policy
  is PASS with no error (ADVISORY_ERROR is not a pass);
* the review covered exactly the expected range: baseline, head, diff digest,
  changed files, policy digest and chunk plan all equal the dry run's;
* a chunked review completed every scheduled review before its deadline, every
  chunk row of every seat is PASS, unscoped seats have one row per chunk, and
  each seat has the scheduled number of rows;
* the bytes no model read (binary sections) are exactly the expected media
  files, and the delta does not touch a .gitattributes file.

    python pipeline_tools/check_evidence.py --findings findings.json \\
      --dry-run DRY_RUN_DIR --rules .reviewer.yaml --baseline SHA --head SHA \\
      [--schedule schedule.json] [--expect-binary PATH ... | --expect-no-binary]

Exit 0 on PASS, 1 otherwise. It never calls AWS or a model.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import posixpath
import sys


def _policy_seats(rules_path: pathlib.Path) -> list[dict]:
    import yaml  # PyYAML, pinned in requirements.txt

    doc = yaml.safe_load(rules_path.read_text()) or {}
    return [{"name": a.get("name"), "scoped": bool(a.get("file_patterns"))}
            for a in doc.get("agents") or []]


def check(findings: dict, dry: dict, seats: list[dict], baseline: str, head: str,
          schedule: dict | None = None, expect_binary: list[str] | None = None) -> list[str]:
    """Every reason the evidence does not support approval (empty: it does)."""
    bad = []

    def need(ok: bool, reason: str):
        if not ok:
            bad.append(reason)

    need(findings.get("verdict") == "PASS", f"verdict is {findings.get('verdict')!r}, not PASS")
    need((findings.get("stats") or {}).get("blocking") == 0, "blocking findings reported")
    need(not findings.get("error"), f"report error: {str(findings.get('error'))[:300]}")
    agents = findings.get("agents") or []
    names = [a.get("name") for a in agents]
    if seats:
        need(names == [s["name"] for s in seats],
             f"seats {names} differ from the policy's {[s['name'] for s in seats]}")
    need(bool(agents), "no seat results")
    for a in agents:
        need(a.get("verdict") == "PASS" and a.get("error") is None and a.get("blocking") == 0,
             f"{a.get('name')}: {a.get('verdict')} blocking={a.get('blocking')} "
             f"error={str(a.get('error'))[:200]}")

    ri = findings.get("review_input") or {}
    need(ri.get("baseline_kind") == "last_successful_release",
         f"baseline_kind is {ri.get('baseline_kind')!r}")
    for label, doc in (("pipeline", ri), ("dry run", dry)):
        need(doc.get("baseline_revision") == baseline,
             f"{label} baseline {doc.get('baseline_revision')} is not {baseline}")
        need(doc.get("head_revision") == head, f"{label} head {doc.get('head_revision')} is not {head}")
    for key in ("diff_sha256", "diff_bytes", "changed_files", "policy_sha256", "chunk_plan"):
        shown = f" ({ri.get(key)} vs {dry.get(key)})" if key == "diff_bytes" else ""
        need(ri.get(key) == dry.get(key), f"{key} differs from the dry run{shown}")
    plan = ri.get("chunk_plan") or {}
    for path in ri.get("changed_files") or []:
        need(posixpath.basename(path.strip('"')).lower() != ".gitattributes",
             f"the delta changes {path}")

    binaries = plan.get("binary_sections")
    need(isinstance(binaries, list), "the evidence does not list its binary sections")
    if expect_binary is not None and isinstance(binaries, list):
        got = sorted(b["path"] for b in binaries if b.get("change") != "deleted")
        need(got == sorted(expect_binary), f"binary (unread) files {got} are not "
             f"the expected {sorted(expect_binary)}")

    chunks = plan.get("chunks")
    chunking = findings.get("chunking")
    if isinstance(chunks, int) and chunks > 1:
        c = chunking or {}
        need(c.get("mode") == "chunked", "a multi-chunk plan without a chunked review")
        need(c.get("chunks") == chunks and c.get("plan_sha256") == plan.get("plan_sha256"),
             "the review did not use the plan in review_input")
        need(c.get("reviews_completed") == c.get("reviews_scheduled"),
             f"{c.get('reviews_completed')} of {c.get('reviews_scheduled')} reviews completed")
        need(c.get("deadline_reached") is False, "the review deadline was reached")
        planned = {s["name"]: s for s in seats}
        reviews = {s.get("name"): s.get("reviews") for s in (schedule or {}).get("seats", [])}
        total = 0
        for a in agents:
            rows = a.get("chunks")
            if not isinstance(rows, list):
                bad.append(f"{a.get('name')}: no per-chunk rows")
                continue
            total += len(rows)
            for row in rows:
                need(row.get("verdict") == "PASS" and row.get("error") is None,
                     f"{a.get('name')} chunk item {row.get('item')}: {row.get('verdict')} "
                     f"error={str(row.get('error'))[:200]}")
            if not planned.get(a.get("name"), {}).get("scoped", True):
                need(len(rows) == chunks, f"{a.get('name')}: {len(rows)} chunk rows for "
                     f"{chunks} chunks")
            if schedule is not None:
                need(len(rows) == reviews.get(a.get("name")),
                     f"{a.get('name')}: {len(rows)} chunk rows, schedule says "
                     f"{reviews.get(a.get('name'))}")
        need(total == c.get("reviews_scheduled"),
             f"{total} chunk rows for {c.get('reviews_scheduled')} scheduled reviews")
    else:
        need(chunking is None, "a single-chunk plan with a chunked report")
    return bad


def main() -> int:
    p = argparse.ArgumentParser(description="Check Tier 1 review evidence before approval")
    p.add_argument("--findings", required=True, help="the execution's findings.json")
    p.add_argument("--dry-run", required=True, help="prepare_review.py --dry-run output dir")
    p.add_argument("--rules", required=True, help="the deployed review policy (.reviewer.yaml)")
    p.add_argument("--baseline", required=True, help="last successful release SHA")
    p.add_argument("--head", required=True, help="the release candidate SHA")
    p.add_argument("--schedule", help="review_cli.py --dry-run output (JSON)")
    p.add_argument("--expect-binary", action="append",
                   help="a file expected to render as binary (repeat; exact set)")
    p.add_argument("--expect-no-binary", action="store_true",
                   help="require that no added or changed file renders as binary")
    args = p.parse_args()
    if args.expect_no_binary and args.expect_binary:
        p.error("--expect-no-binary contradicts --expect-binary")
    expect = [] if args.expect_no_binary else args.expect_binary
    findings = json.loads(pathlib.Path(args.findings).read_text())
    dry = json.loads((pathlib.Path(args.dry_run) / "input-metadata.json").read_text())
    schedule = json.loads(pathlib.Path(args.schedule).read_text()) if args.schedule else None
    bad = check(findings, dry, _policy_seats(pathlib.Path(args.rules)), args.baseline,
                args.head, schedule, expect)
    plan = (findings.get("review_input") or {}).get("chunk_plan") or {}
    chunking = findings.get("chunking") or {}
    print(f"verdict={findings.get('verdict')} blocking={(findings.get('stats') or {}).get('blocking')}"
          f" diff_bytes={(findings.get('review_input') or {}).get('diff_bytes')}"
          f" chunks={plan.get('chunks')} reviews={chunking.get('reviews_completed')}/"
          f"{chunking.get('reviews_scheduled')} retries={chunking.get('retries')}")
    for row in plan.get("binary_sections") or []:
        print(f"unread binary: {row.get('path')} ({row.get('change')}, {row.get('bytes')} bytes)")
    for a in findings.get("agents") or []:
        retried = [r.get("item") for r in a.get("chunks") or [] if (r.get("attempts") or 1) > 1]
        print(f"seat {a.get('name')}: {a.get('verdict')} rows={len(a.get('chunks') or [])}"
              + (f" retried items={retried}" if retried else ""))
    for reason in bad:
        print(f"  - {reason}")
    print("EVIDENCE: " + ("PASS" if not bad else f"FAIL ({len(bad)} problem(s))"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
