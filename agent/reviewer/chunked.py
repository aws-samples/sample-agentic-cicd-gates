"""Chunked review: ONE verdict over a delta larger than one model call.

pipeline_tools/prepare_review.py (pipeline-owned) splits a large delta into
chunks of whole file sections and writes chunk-plan.json beside the diff.
This module:

1. re-verifies that plan against the diff it claims to cover, without trusting
   the planner's code: every line of the diff except the `@@` hunk headers
   that splitting recomputes must appear exactly once, and the only other
   text allowed is a split file's repeated header;
2. gives every seat every chunk in its scope. Unscoped seats review the plan's
   chunks as they are. A scoped seat's in-scope file sections are re-packed in
   diff order, so its view is what it reviews today, only bounded;
3. reviews each (seat, chunk) with the SAME review_diff the single-call path
   uses: same prompts, both stages, the per-call max_findings cap, the
   confidence floor and the rule-derived blocking flag, on a bounded pool of
   worker threads with a deadline; and
4. folds each seat back into one GateResult with today's semantics. A blocking
   finding in any chunk fails the seat. An error, truncation, timeout or an
   unreviewed chunk makes the seat its error_result, which is BLOCKED_ERROR
   for any seat that owns a blocking rule. It is never PASS.

A chunk whose review ENDED IN AN ERROR (never one that ended in FAIL) is
reviewed once more while the deadline allows, and its row records every
attempt. A chunk still counts only when a review of it completes, so what PASS
means does not change; one transient error no longer costs a full re-run.

Kept findings are de-duplicated on (rule_id, path, line), keeping the highest
confidence; every kept finding already cleared the confidence floor in its own
chunk, so de-duplication cannot change a verdict.

What a chunked PASS does NOT mean is stated in every chunked report (NOTE):
each call sees its own chunk only.
"""
from __future__ import annotations

import ast
import collections
import hashlib
import json
import pathlib
import re
import sys
import threading
import time
from dataclasses import dataclass

from .bedrock_reviewer import (DEFAULT_MODEL, ReviewOutcome, _scope_diff, bedrock_client,
                               review_diff, seat_ruleset)
from .rules import RuleSet
from .verdict import (FindingsValidationError, GateResult, Verdict, compute_verdict,
                      error_result)

PLAN_VERSION = 1
MAX_PLAN_CHUNK_BYTES = 1_000_000
MAX_ERROR_CHARS = 3_000
RETRIES = 1        # further attempts for a chunk whose review ended in an error
_CHUNK_NAME = re.compile(r"chunks/\d{4,6}\.diff")

NOTE = ("Chunked review: each model call saw one chunk of at most chunk_bytes, so a flow "
        "from a source in one chunk to a sink in another was not traced, and the "
        "max_findings cap applied per chunk call, not per seat. A seat passes only if "
        "every chunk in its scope completed a review without a blocking finding. Bytes "
        "git rendered as binary were read by no model; review_input.chunk_plan."
        "binary_sections lists them.")


class PlanVerificationError(ValueError):
    """The chunk plan does not prove complete coverage of the diff."""


def _lines(text: str) -> list[str]:
    """LF-only split; other Unicode line boundaries are file content."""
    out, start = [], 0
    while start < len(text):
        end = text.find("\n", start)
        end = len(text) if end < 0 else end + 1
        out.append(text[start:end])
        start = end
    return out


def _without_hunk_headers(text: str) -> str:
    return "".join(line for line in _lines(text) if not line.startswith("@@ "))


_HUNK_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_GIT_HEADER = re.compile(r'("(?:\\.|[^"\\])*"|a/.*?) ("(?:\\.|[^"\\])*"|b/.*)')


def _hunks(text: str) -> list[tuple[str, list[str]]]:
    """(header line, body lines) of every hunk; file header lines are skipped."""
    out, in_file_header = [], True
    for line in _lines(text):
        if line.startswith("diff --git "):
            in_file_header = True
        elif line.startswith("@@ "):
            in_file_header = False
            out.append((line, []))
        elif not in_file_header and out:
            out[-1][1].append(line)
    return out


def _verify_hunk_headers(rebuilt: str, diff: str) -> None:
    """Every @@ line the plan shows follows from the diff's own headers: a hunk
    kept whole keeps its header, and each run of a split hunk gets the
    unified-diff header of its lines. A forged, dropped or renumbered @@ fails."""
    got = iter(_hunks(rebuilt))
    bad = PlanVerificationError("chunk plan hunk headers do not follow from the diff")
    for header, body in _hunks(diff):
        match = _HUNK_HEADER.match(header)
        if not match:
            raise PlanVerificationError("the diff has a malformed hunk header")
        old_start, new_start = int(match[1]), int(match[3])
        old_len = 1 if match[2] is None else int(match[2])
        new_len = 1 if match[4] is None else int(match[4])
        tail = header[match.end():]
        pieces, taken = [], 0
        while taken < len(body):
            piece = next(got, None)
            if piece is None or not piece[1]:
                raise bad
            pieces.append(piece)
            taken += len(piece[1])
        if [line for _, lines in pieces for line in lines] != body:
            raise bad
        if len(pieces) == 1:
            if pieces[0][0] != header:
                raise bad
            continue
        old_seen = new_seen = 0
        for got_header, lines in pieces:
            old = sum(1 for line in lines if line[:1] in (" ", "-"))
            new = sum(1 for line in lines if line[:1] in (" ", "+"))
            # Unified-diff convention: a zero-length side names the line BEFORE it.
            o = old_start + old_seen if old else (old_start + old_seen - 1 if old_len
                                                  else old_start)
            n = new_start + new_seen if new else (new_start + new_seen - 1 if new_len
                                                  else new_start)
            if got_header != f"@@ -{o},{old} +{n},{new} @@{tail}":
                raise bad
            old_seen, new_seen = old_seen + old, new_seen + new
    if next(got, None) is not None:
        raise bad


def _header_path(header: str) -> str:
    """The b-side path of a section's `diff --git` line, C-unquoted: its label."""
    line = _lines(header)[0][len("diff --git "):].rstrip("\n")
    match = _GIT_HEADER.fullmatch(line)
    if not match:
        return line
    value = match.group(2)
    if value.startswith('"'):
        try:
            value = ast.literal_eval("b" + value).decode("utf-8")
        except (ValueError, SyntaxError, UnicodeError):
            return line
    return value[2:]


def _count(value, name: str, low: int = 0, high: int | None = None) -> int:
    if type(value) is not int or value < low or (high is not None and value > high):
        raise PlanVerificationError(f"chunk plan field {name} is invalid")
    return value


@dataclass(frozen=True)
class PlanUnit:
    seq: int
    path: str
    part: int
    parts: int
    header: str
    text: str

    @property
    def label(self) -> str:
        return self.path if self.parts == 1 else f"{self.path} (part {self.part}/{self.parts})"


@dataclass(frozen=True)
class PlanChunk:
    index: int
    text: str
    units: tuple[PlanUnit, ...]


@dataclass(frozen=True)
class ReviewPlan:
    chunk_bytes: int
    diff_bytes: int
    diff_sha256: str
    plan_sha256: str
    chunks: tuple[PlanChunk, ...]


def load_plan(path: pathlib.Path, diff: str) -> ReviewPlan:
    """Read chunk-plan.json and its chunk files; refuse anything incomplete."""
    path = pathlib.Path(path)
    try:
        raw = path.read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise PlanVerificationError(f"chunk plan unreadable: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != PLAN_VERSION:
        raise PlanVerificationError("chunk plan has an unsupported version")
    chunk_bytes = _count(doc.get("chunk_bytes"), "chunk_bytes", 1, MAX_PLAN_CHUNK_BYTES)
    encoded = diff.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    if (_count(doc.get("diff_bytes"), "diff_bytes") != len(encoded)
            or doc.get("diff_sha256") != digest):
        raise PlanVerificationError("chunk plan was made from a different diff")
    rows = doc.get("chunks")
    if not isinstance(rows, list) or bool(rows) != bool(diff):
        raise PlanVerificationError("chunk plan must list chunks exactly when the diff is non-empty")
    chunks = []
    for position, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("index") != position:
            raise PlanVerificationError("chunk plan entries must be numbered in order")
        name = row.get("path")
        if not isinstance(name, str) or not _CHUNK_NAME.fullmatch(name):
            raise PlanVerificationError(f"chunk {position} has an invalid file name")
        try:
            data = (path.parent / name).read_bytes()
        except OSError as exc:
            raise PlanVerificationError(f"chunk {position} unreadable: {exc}") from exc
        if (len(data) != _count(row.get("bytes"), "bytes", 1, chunk_bytes)
                or hashlib.sha256(data).hexdigest() != row.get("sha256")):
            raise PlanVerificationError(f"chunk {position} does not match the plan")
        unit_rows = row.get("units")
        if not isinstance(unit_rows, list) or not unit_rows:
            raise PlanVerificationError(f"chunk {position} lists no file sections")
        units, offset = [], 0
        for unit in unit_rows:
            if not isinstance(unit, dict):
                raise PlanVerificationError(f"chunk {position} has a malformed section entry")
            size = _count(unit.get("bytes"), "unit bytes", 1)
            header_size = _count(unit.get("header_bytes"), "header_bytes", 1, size)
            piece = data[offset:offset + size]
            offset += size
            part = _count(unit.get("part"), "part", 1)
            parts = _count(unit.get("parts"), "parts", part)
            try:
                text, header = piece.decode("utf-8"), piece[:header_size].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PlanVerificationError(f"chunk {position} splits a character") from exc
            if (len(piece) != size or not header.startswith("diff --git ")
                    or any(line.startswith("@@ ") for line in _lines(header))):
                raise PlanVerificationError(f"chunk {position} has a malformed file section")
            # Every boundary sits at a line end, and no part carries a second
            # file header: a mid-line split could otherwise let a part's
            # repeated header, glued to the previous part, forge a new file.
            last = position == len(rows) - 1 and offset == len(data)
            if (not header.endswith("\n")
                    or not (text.endswith("\n") or (last and not diff.endswith("\n")))
                    or any(line.startswith("diff --git ")
                           for line in _lines(text[len(header):]))):
                raise PlanVerificationError(f"chunk {position} splits a file section "
                                            f"mid-line")
            label = str(unit.get("path", ""))
            if label != _header_path(header):
                # Report rows name this path; it must be the file actually reviewed.
                raise PlanVerificationError(f"chunk {position} labels a file section with "
                                            f"another path")
            units.append(PlanUnit(_count(unit.get("seq"), "seq"), label,
                                  part, parts, header, text))
        if offset != len(data):
            raise PlanVerificationError(f"chunk {position} sections do not tile the chunk")
        chunks.append(PlanChunk(position, data.decode("utf-8"), tuple(units)))
    _verify_coverage(chunks, diff)
    return ReviewPlan(chunk_bytes, len(encoded), digest, hashlib.sha256(raw).hexdigest(),
                      tuple(chunks))


def _verify_coverage(chunks: list[PlanChunk], diff: str) -> None:
    units: dict[tuple[int, int], PlanUnit] = {}
    for chunk in chunks:
        for unit in chunk.units:
            if (unit.seq, unit.part) in units:
                raise PlanVerificationError(f"file section {unit.seq} part {unit.part} repeats")
            units[(unit.seq, unit.part)] = unit
    seqs = sorted({seq for seq, _ in units})
    if seqs != list(range(len(seqs))):
        raise PlanVerificationError("chunk plan skips a file section")
    rebuilt = []
    for seq in seqs:
        first = units.get((seq, 1))
        if first is None or sum(1 for s, _ in units if s == seq) != first.parts:
            raise PlanVerificationError(f"file section {seq} is not covered exactly once")
        rebuilt.append(first.text)
        for part in range(2, first.parts + 1):
            unit = units.get((seq, part))
            if unit is None or unit.parts != first.parts or unit.header != first.header:
                raise PlanVerificationError(f"file section {seq} part {part} is inconsistent")
            rebuilt.append(unit.text[len(first.header):])
    text = "".join(rebuilt)
    if _without_hunk_headers(text) != _without_hunk_headers(diff):
        raise PlanVerificationError("chunk plan does not reproduce the diff exactly")
    _verify_hunk_headers(text, diff)


@dataclass(frozen=True)
class SeatItem:
    index: int
    text: str
    chunks: tuple[int, ...]
    files: tuple[str, ...]

    @property
    def nbytes(self) -> int:
        return len(self.text.encode("utf-8"))


def seat_items(plan: ReviewPlan, agent, scoped_item_bytes: int | None = None) -> list[SeatItem]:
    """What one seat reviews, one model review per item, each <= chunk_bytes.

    A scoped seat's in-scope sections are packed, in diff order, into items of
    at most `scoped_item_bytes` (default: the plan's chunk_bytes). A section
    larger than that is an item on its own; it is never split here.
    """
    cap = plan.chunk_bytes if scoped_item_bytes is None else scoped_item_bytes
    if type(cap) is not int or not 0 < cap <= plan.chunk_bytes:
        raise ValueError(f"scoped_item_bytes must be an integer in 1..{plan.chunk_bytes}")
    if not agent.file_patterns:
        return [SeatItem(c.index, c.text, (c.index,), tuple(u.label for u in c.units))
                for c in plan.chunks]
    pieces = []
    for chunk in plan.chunks:
        for unit in chunk.units:
            scoped = _scope_diff(unit.text, agent.file_patterns)
            if scoped.strip():
                pieces.append(((unit.seq, unit.part), chunk.index, scoped, unit.label))
    pieces.sort(key=lambda piece: piece[0])
    items, group, size = [], [], 0

    def close():
        items.append(SeatItem(len(items), "".join(p[2] for p in group),
                              tuple(sorted({p[1] for p in group})), tuple(p[3] for p in group)))

    for piece in pieces:
        n = len(piece[2].encode("utf-8"))
        if group and size + n > cap:
            close()
            group, size = [], 0
        group.append(piece)
        size += n
    if group:
        close()
    return items


def schedule(plan: ReviewPlan, ruleset: RuleSet, model_id: str = DEFAULT_MODEL,
             scoped_item_bytes: int | None = None) -> dict:
    """Dry run: what every seat would review. Creates no client, calls no model."""
    seats = []
    for agent in ruleset.agents or (ruleset.agent,):
        try:
            items, error = seat_items(plan, agent, scoped_item_bytes), None
        except FindingsValidationError as exc:
            items, error = [], f"contract violation: {exc}"
        seats.append({
            "name": agent.name, "model": agent.model or model_id, "thinking": agent.thinking,
            "scope": list(agent.file_patterns) or "entire diff", "error": error,
            # Two stages per review; a review that ends in an error runs again.
            "reviews": len(items), "model_calls_at_most": 2 * (1 + RETRIES) * len(items),
            "items": [{"item": i.index, "bytes": i.nbytes, "chunks": list(i.chunks),
                       "files": list(i.files)} for i in items],
        })
    return {"dry_run": True, "chunk_bytes": plan.chunk_bytes, "chunks": len(plan.chunks),
            "diff_bytes": plan.diff_bytes, "plan_sha256": plan.plan_sha256, "seats": seats}


def _failure_message(failures, total: int) -> str:
    shown = []
    for item, reason in failures[:8]:
        files = ", ".join(item.files[:3]) + (f" +{len(item.files) - 3} more"
                                             if len(item.files) > 3 else "")
        shown.append(f"chunk {item.index + 1}/{total} [{files}]: {str(reason)[:300]}")
    more = f"; and {len(failures) - 8} more" if len(failures) > 8 else ""
    message = (f"chunked review incomplete: {len(failures)} of {total} chunk(s) did not "
               f"complete a valid review - " + "; ".join(shown) + more)
    return message[:MAX_ERROR_CHARS]


def _errored(result: GateResult) -> bool:
    return result.error is not None or result.verdict in (Verdict.ADVISORY_ERROR,
                                                          Verdict.BLOCKED_ERROR)


def _attempts(got) -> list:
    """One item's completed attempts, oldest first: [(ReviewOutcome, seconds), ...]."""
    if got is None:
        return []
    return list(got) if isinstance(got, list) else [got]


def merge_seat(agent, ruleset: RuleSet, items: list[SeatItem], outcomes: list,
               *, model_id: str = DEFAULT_MODEL, plan_error: str | None = None,
               missing: str = "not reviewed", unfinished_retry=frozenset()):
    """Fold one seat's per-chunk outcomes into ONE outcome with today's semantics.

    `outcomes[i]` is the list of completed attempts for item i, oldest first
    (a single (ReviewOutcome, seconds) or None is accepted too). The LAST
    attempt is the chunk's result; earlier ones ended in errors and are kept
    in the row. `unfinished_retry` holds items whose second attempt was still
    running at the deadline. Returns (ReviewOutcome, per-chunk rows, the chunk
    of each kept finding, duplicates removed).
    """
    scoped = seat_ruleset(ruleset, agent)
    model = agent.model or model_id
    if plan_error is not None:
        return ReviewOutcome(error_result(scoped, plan_error, agent), model, 0), [], [], 0
    if not items:
        # Nothing anywhere in the delta matches this seat's scope: exactly what
        # review_diff returns today for an empty scoped diff.
        return ReviewOutcome(compute_verdict([], scoped), model, 0), [], [], 0
    rows, failures, kept = [], [], []
    suppressed = discovered = 0
    for item, got in zip(items, outcomes):
        row = {"item": item.index, "chunks": list(item.chunks), "bytes": item.nbytes,
               "files": list(item.files)}
        attempts = _attempts(got)
        if not attempts:
            row.update(verdict=None, error=missing, attempts=0)
            failures.append((item, missing))
        else:
            outcome, seconds = attempts[-1]
            result = outcome.result
            row.update(verdict=result.verdict.value, blocking=result.blocking_count,
                       kept=len(result.findings),
                       suppressed=result.suppressed_below_threshold,
                       discovered=outcome.discovery_count, seconds=seconds,
                       error=result.error, attempts=len(attempts))
            if len(attempts) > 1:
                row["earlier_errors"] = [(o.result.error or o.result.verdict.value)[:300]
                                         for o, _ in attempts[:-1]]
            discovered += outcome.discovery_count
            if _errored(result):
                reason = result.error or result.verdict.value
                if item.index in unfinished_retry:
                    row["retry"] = "not finished before the review deadline"
                    reason = f"retry unfinished at the review deadline, after: {reason}"
                failures.append((item, reason))
            else:
                kept.extend((finding, item.index) for finding in result.findings)
                suppressed += result.suppressed_below_threshold
        rows.append(row)
    best: dict = {}
    for finding, index in kept:
        key = (finding.rule_id, finding.path, finding.line)
        if key not in best or finding.confidence > best[key][0].confidence:
            best[key] = (finding, index)
    findings = [best[key][0] for key in dict.fromkeys(
        (f.rule_id, f.path, f.line) for f, _ in kept)]
    if failures:
        message = _failure_message(failures, len(items))
        result = GateResult(error_result(scoped, message, agent).verdict, tuple(findings),
                            suppressed, error=message)
    else:
        computed = compute_verdict(findings, scoped)
        result = GateResult(computed.verdict, computed.findings,
                            suppressed + computed.suppressed_below_threshold)
    where = [best[(f.rule_id, f.path, f.line)][1] for f in result.findings]
    return ReviewOutcome(result, model, discovered), rows, where, len(kept) - len(findings)


@dataclass
class ChunkedPanel:
    panel: list
    details: dict
    meta: dict


def review_panel_chunked(plan: ReviewPlan, ruleset: RuleSet, *, model_id: str = DEFAULT_MODEL,
                         region: str = "us-west-2", client=None, workers: int = 8,
                         deadline_seconds: float | None = None, emit=None,
                         scoped_item_bytes: int | None = None) -> ChunkedPanel:
    """Review every (seat, chunk) on `workers` threads; stop waiting at the deadline.

    A review that ends in an error is queued once more (RETRIES) while the
    deadline has not passed; FAIL is final. Work still running at the deadline
    is abandoned (daemon threads), and its chunks count as not reviewed, so the
    report is always written before the build's own timeout and an incomplete
    seat can never read as PASS. `scoped_item_bytes` bounds a scoped seat's
    items (seat_items); None keeps them at the plan's chunk size.
    """
    emit = emit or (lambda line: print(line, file=sys.stderr, flush=True))
    started = time.monotonic()
    end = None if deadline_seconds is None else started + deadline_seconds
    seats = []
    for agent in ruleset.agents or (ruleset.agent,):
        try:
            seats.append((agent, seat_items(plan, agent, scoped_item_bytes), None))
        except FindingsValidationError as exc:
            seats.append((agent, [], f"contract violation: {exc}"))
    # Round-robin across seats so concurrent calls spread over several models.
    jobs = [(s, i) for i in range(max((len(items) for _, items, _ in seats), default=0))
            for s, (_, items, _) in enumerate(seats) if i < len(items)]
    setup_error = None
    if jobs and client is None:
        try:
            client = bedrock_client(region, max_pool_connections=max(10, workers))
        except Exception as exc:  # noqa: BLE001 - becomes a fail-closed seat error
            setup_error = f"Bedrock client unavailable: {type(exc).__name__}: {exc}"
    pending = collections.deque(() if setup_error else jobs)
    history: dict = {}
    queued_retries: set = set()
    counts = {"in_flight": 0, "retries": 0, "retries_completed": 0}
    lock, stop = threading.Lock(), threading.Event()

    def work():
        while True:
            with lock:
                if stop.is_set() or not pending:
                    return
                s, i = pending.popleft()
                counts["in_flight"] += 1
            agent, items, _ = seats[s]
            begun = time.monotonic()
            try:
                outcome = review_diff(items[i].text, ruleset, model_id=model_id, region=region,
                                      client=client, agent=agent)
            except Exception as exc:  # noqa: BLE001 - review_diff should not raise; fail closed
                outcome = ReviewOutcome(error_result(seat_ruleset(ruleset, agent),
                                                     f"{type(exc).__name__}: {exc}", agent),
                                        agent.model or model_id, 0)
            seconds = round(time.monotonic() - begun, 1)
            with lock:
                counts["in_flight"] -= 1
                if stop.is_set():
                    return  # past the deadline: never counted, never printed
                attempts = history.setdefault((s, i), [])
                attempts.append((outcome, seconds))
                if len(attempts) > 1:
                    counts["retries_completed"] += 1
                r = outcome.result
                retry = (_errored(r) and len(attempts) <= RETRIES
                         and (end is None or time.monotonic() < end))
                if retry:
                    pending.append((s, i))
                    queued_retries.add((s, i))
                    counts["retries"] += 1
                emit(f"[{agent.name}] chunk {i + 1}/{len(items)}"
                     + (f" attempt {len(attempts)}" if len(attempts) > 1 else "")
                     + f": {r.verdict.value} blocking={r.blocking_count} "
                     f"discovered={outcome.discovery_count} seconds={seconds}"
                     + (f" error={r.error[:200]}" if r.error else "")
                     + (" -> retrying" if retry else ""))

    threads = [threading.Thread(target=work, name=f"review-{n}", daemon=True)
               for n in range(min(max(1, workers), len(pending)))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(None if end is None else max(0.0, end - time.monotonic()))
    with lock:
        stop.set()
        done = {key: list(value) for key, value in history.items()}
        outstanding = len(pending) + counts["in_flight"]
    # Work is missing either because the deadline cut it off (a thread is still
    # inside a call) or because a worker died; both fail the seat closed.
    deadline_reached = outstanding > 0 and any(t.is_alive() for t in threads)
    missing = (setup_error or ("not reviewed before the review deadline "
                               f"({deadline_seconds:.0f}s)" if deadline_reached else "not reviewed"))
    panel, details = [], {}
    for s, (agent, items, plan_error) in enumerate(seats):
        unfinished = {i for (seat, i) in queued_retries
                      if seat == s and len(done.get((seat, i), ())) < 1 + RETRIES}
        outcome, rows, where, duplicates = merge_seat(
            agent, ruleset, items, [done.get((s, i)) for i in range(len(items))],
            model_id=model_id, plan_error=plan_error, missing=missing,
            unfinished_retry=unfinished)
        panel.append((agent, outcome))
        details[agent.name] = {"items": rows, "finding_items": where,
                               "duplicates_removed": duplicates}
    meta = {"mode": "chunked", "chunk_bytes": plan.chunk_bytes, "chunks": len(plan.chunks),
            "diff_bytes": plan.diff_bytes, "plan_sha256": plan.plan_sha256,
            "reviews_scheduled": len(jobs), "reviews_completed": len(done),
            "retries": counts["retries"], "retries_completed": counts["retries_completed"],
            "workers": workers, "deadline_seconds": deadline_seconds,
            "deadline_reached": deadline_reached,
            "elapsed_seconds": round(time.monotonic() - started, 1),
            "note": NOTE}
    if scoped_item_bytes is not None:
        meta["scoped_item_bytes"] = scoped_item_bytes
    return ChunkedPanel(panel, details, meta)
