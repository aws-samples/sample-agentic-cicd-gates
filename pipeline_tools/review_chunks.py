"""Plan the review of a large delta as complete, bounded chunks.

One reviewer call handles about one chunk well. On 2026-10-02 the Security
seat (Opus 5, extra-high thinking) reviewed a 98,971-byte release diff in a
single 170 s call that used 13.1K of its 24,000 output tokens, far inside its
600 s read timeout. CHUNK_BYTES keeps every call at or below that calibrated
size, so a 1.7 MB delta becomes ~20 calls per seat instead of one call that
cannot succeed.

The plan never drops, truncates or reorders review input:

* the unit is a WHOLE FILE SECTION of the unified diff (its header and all of
  its hunks), and units keep diff order inside every chunk;
* a file section larger than a chunk is split into runs of whole hunks, and
  every piece repeats the file's header, so each piece is a self-describing
  diff that a scoped seat can still match by path;
* a single hunk larger than a chunk (an added file is ONE hunk) is split at
  line boundaries into consecutive sub-hunks with recomputed `@@` headers, so
  the line numbers a reviewer reports stay correct;
* a single line larger than a chunk cannot be split, and planning fails.

`plan()` verifies its own result before returning it: reassembling the pieces
must reproduce every line of the input exactly once. The consumers re-check
the files they read independently (agent/reviewer/chunked.py), because a
chunk that silently went missing would turn missing evidence into a PASS.
"""
# No `from __future__ import annotations`: dataclasses resolve string
# annotations through sys.modules, and test loaders import this file by path.
import ast
import hashlib
import json
import math
import pathlib
import re
from dataclasses import dataclass

CHUNK_BYTES = 100_000
MIN_CHUNK_BYTES = 4_096
PLAN_VERSION = 1
PLAN_FILE = "chunk-plan.json"

_HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_HEADER_RE = re.compile(r'("(?:\\.|[^"\\])*"|a/.*?) ("(?:\\.|[^"\\])*"|b/.*)')
# Diff prefixes of the body lines a hunk may contain.
_BODY = (" ", "+", "-", "\\")


class PlanError(ValueError):
    """The delta cannot be planned into complete chunks; the gate must stop."""


def nbytes(text: str) -> int:
    return len(text.encode("utf-8"))


def split_lines(text: str) -> list[str]:
    """Split on LF only, keeping line ends.

    str.splitlines() also breaks on \\r, \\f, \\v, \\x1c-\\x1e, \\x85, \\u2028
    and \\u2029. Those characters can sit INSIDE one diff line (they are file
    content), so splitting on them would let file content masquerade as a
    `diff --git` or `@@` line and move a chunk boundary.
    """
    lines, start, size = [], 0, len(text)
    while start < size:
        end = text.find("\n", start)
        if end < 0:
            lines.append(text[start:])
            break
        lines.append(text[start:end + 1])
        start = end + 1
    return lines


def strip_hunk_headers(text: str) -> str:
    """Everything except `@@` lines: what splitting a hunk must preserve."""
    return "".join(line for line in split_lines(text) if not line.startswith("@@ "))


@dataclass(frozen=True)
class Section:
    seq: int
    path: str
    header: str
    hunks: tuple[str, ...]

    @property
    def text(self) -> str:
        return self.header + "".join(self.hunks)


@dataclass(frozen=True)
class Unit:
    seq: int
    path: str
    part: int
    parts: int
    header: str
    body: str

    @property
    def text(self) -> str:
        return self.header + self.body

    @property
    def label(self) -> str:
        return self.path if self.parts == 1 else f"{self.path} (part {self.part}/{self.parts})"


@dataclass(frozen=True)
class Chunk:
    index: int
    units: tuple[Unit, ...]

    @property
    def text(self) -> str:
        return "".join(u.text for u in self.units)


def _section_path(line: str) -> str:
    """Display path from a `diff --git` line (git C-quotes unusual names)."""
    header = line[len("diff --git "):].rstrip("\n")
    match = _HEADER_RE.fullmatch(header)
    if not match:
        return header
    value = match.group(2)
    if value.startswith('"'):
        try:
            value = ast.literal_eval("b" + value).decode("utf-8")
        except (ValueError, SyntaxError, UnicodeError):
            return header
    return value[2:]


def parse_sections(diff: str) -> list[Section]:
    sections: list[Section] = []
    header: list[str] | None = None
    hunks: list[list[str]] = []

    def flush():
        if header is not None:
            sections.append(Section(len(sections), _section_path(header[0]), "".join(header),
                                    tuple("".join(h) for h in hunks)))

    for line in split_lines(diff):
        if line.startswith("diff --git "):
            flush()
            header, hunks = [line], []
        elif header is None:
            raise PlanError("diff text precedes the first 'diff --git' header")
        elif line.startswith("@@ "):
            hunks.append([line])
        elif hunks:
            hunks[-1].append(line)
        else:
            header.append(line)
    flush()
    if "".join(s.text for s in sections) != diff:
        raise PlanError("diff did not parse back into the same text")
    return sections


def _top_level(line: str) -> bool:
    """A blank line or one that starts a new top-level statement."""
    content = line[1:]
    return not content.strip() or content[:1] not in (" ", "\t", "}", ")", "]")


def _cut_point(lines: list[str], max_back_bytes: int) -> int | None:
    """Where to end a piece near the end of `lines`, preferring declaration gaps.

    Best: before a top-level line that follows a blank line or a top-level
    closer (between two declarations). Next best: before any top-level line.
    Never before a "\\ No newline" marker, which belongs to the line above it.
    """
    floor, scanned = len(lines) - 1, 0
    while floor > 1 and scanned + nbytes(lines[floor]) <= max_back_bytes:
        scanned += nbytes(lines[floor])
        floor -= 1
    fallback = None
    for i in range(len(lines) - 1, floor, -1):
        if lines[i][:1] == "\\" or not _top_level(lines[i]):
            continue
        if lines[i - 1][1:].strip() in ("", "}", "};", "})", "});", "]", "];"):
            return i
        fallback = fallback or i
    return fallback


def _split_hunk(hunk: str, room: int) -> list[str]:
    """Split one hunk at line boundaries into sub-hunks of at most `room` bytes."""
    lines = split_lines(hunk)
    match = _HUNK_RE.match(lines[0])
    if not match:
        raise PlanError("malformed hunk header; refusing to split it")
    old_start, new_start = int(match[1]), int(match[3])
    old_len = int(match[2]) if match[2] is not None else 1
    new_len = int(match[4]) if match[4] is not None else 1
    tail = lines[0][match.end():]
    body = lines[1:]
    if not body or any(line[:1] not in _BODY for line in body):
        raise PlanError("unexpected line in a hunk body; refusing to split it")
    # Room for the longest header this hunk could need, then the body budget.
    widest = f"@@ -{old_start + old_len},{old_len} +{new_start + new_len},{new_len} @@"
    budget = room - nbytes(widest) - nbytes(tail) - 2
    sizes = [nbytes(line) for line in body]
    if budget < 1 or max(sizes) > budget:
        raise PlanError("a single diff line is larger than one review chunk; "
                        "split the file or review it explicitly")
    pieces_wanted = max(2, math.ceil(sum(sizes) / budget))
    target = math.ceil(sum(sizes) / pieces_wanted)
    pieces: list[list[str]] = []
    current: list[str] = []
    size = 0
    for line, n in zip(body, sizes):
        # "\ No newline at end of file" belongs to the line before it.
        if current and line[:1] != "\\":
            must = size + n > budget
            want = size >= target and len(pieces) < pieces_wanted - 1
            if must or want:
                # Prefer a nearby declaration boundary over a mid-block cut, as
                # long as what moves to the next piece still fits beside `line`.
                cut = _cut_point(current, target // 4) or len(current)
                if sum(nbytes(x) for x in current[cut:]) + n > budget:
                    cut = len(current)
                pieces.append(current[:cut])
                current = current[cut:]
                size = sum(nbytes(x) for x in current)
        current.append(line)
        size += n
    pieces.append(current)
    out, old_seen, new_seen = [], 0, 0
    for piece in pieces:
        old = sum(1 for line in piece if line[:1] in (" ", "-"))
        new = sum(1 for line in piece if line[:1] in (" ", "+"))
        # Unified-diff convention: a zero-length side names the line BEFORE it.
        o = old_start + old_seen if old else (old_start + old_seen - 1 if old_len else old_start)
        n = new_start + new_seen if new else (new_start + new_seen - 1 if new_len else new_start)
        out.append(f"@@ -{o},{old} +{n},{new} @@{tail}" + "".join(piece))
        old_seen, new_seen = old_seen + old, new_seen + new
    if (old_seen, new_seen) != (old_len, new_len):
        raise PlanError("hunk line counts disagree with its header; refusing to split it")
    if any(nbytes(p) > room for p in out):
        raise PlanError("internal error: split hunk exceeds the chunk size")
    return out


def _units(section: Section, chunk_bytes: int) -> list[Unit]:
    if nbytes(section.text) <= chunk_bytes:
        return [Unit(section.seq, section.path, 1, 1, section.header, "".join(section.hunks))]
    room = chunk_bytes - nbytes(section.header)
    if room < MIN_CHUNK_BYTES // 2 or not section.hunks:
        raise PlanError(f"{section.path}: file header alone exceeds the review chunk size")
    pieces: list[str] = []
    for hunk in section.hunks:
        pieces.extend([hunk] if nbytes(hunk) <= room else _split_hunk(hunk, room))
    groups: list[list[str]] = []
    size = 0
    for piece in pieces:
        n = nbytes(piece)
        if groups and size + n <= room:
            groups[-1].append(piece)
            size += n
        else:
            groups.append([piece])
            size = n
    return [Unit(section.seq, section.path, i + 1, len(groups), section.header, "".join(g))
            for i, g in enumerate(groups)]


def verify(diff: str, chunks: list[Chunk], chunk_bytes: int) -> None:
    """Reassemble the plan and require the exact input (modulo `@@` lines)."""
    by_seq: dict[int, list[Unit]] = {}
    for position, chunk in enumerate(chunks):
        if chunk.index != position or not chunk.units:
            raise PlanError("chunks must be non-empty and numbered in order")
        if nbytes(chunk.text) > chunk_bytes:
            raise PlanError(f"chunk {position} exceeds {chunk_bytes} bytes")
        for unit in chunk.units:
            by_seq.setdefault(unit.seq, []).append(unit)
    rebuilt = []
    for seq in range(len(by_seq)):
        parts = sorted(by_seq.get(seq, []), key=lambda u: u.part)
        if (not parts or [u.part for u in parts] != list(range(1, len(parts) + 1))
                or any(u.parts != len(parts) or u.header != parts[0].header for u in parts)):
            raise PlanError(f"file section {seq} is not covered exactly once")
        rebuilt.append(parts[0].header + "".join(u.body for u in parts))
    if len(by_seq) != len(parse_sections(diff)):
        raise PlanError("plan does not cover every file section")
    if strip_hunk_headers("".join(rebuilt)) != strip_hunk_headers(diff):
        raise PlanError("plan does not reproduce the diff exactly")


def plan(diff: str, chunk_bytes: int = CHUNK_BYTES) -> list[Chunk]:
    """First-fit pack units, in diff order, into chunks of <= chunk_bytes."""
    if type(chunk_bytes) is not int or chunk_bytes < MIN_CHUNK_BYTES:
        raise PlanError(f"chunk size must be an integer of at least {MIN_CHUNK_BYTES} bytes")
    units = [u for section in parse_sections(diff) for u in _units(section, chunk_bytes)]
    bins: list[list] = []
    for unit in units:
        n = nbytes(unit.text)
        target = next((b for b in bins if b[0] + n <= chunk_bytes), None)
        if target is None:
            bins.append([n, [unit]])
        else:
            target[0] += n
            target[1].append(unit)
    chunks = [Chunk(i, tuple(b[1])) for i, b in enumerate(bins)]
    verify(diff, chunks, chunk_bytes)
    return chunks


def write_plan(chunks: list[Chunk], diff: str, chunk_bytes: int,
               output: pathlib.Path) -> dict:
    """Write chunks/NNNN.diff plus chunk-plan.json; return the metadata summary."""
    rows = []
    for chunk in chunks:
        name = f"chunks/{chunk.index:04d}.diff"
        data = chunk.text.encode("utf-8")
        (output / name).parent.mkdir(parents=True, exist_ok=True)
        (output / name).write_bytes(data)
        rows.append({
            "index": chunk.index, "path": name, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "units": [{"seq": u.seq, "path": u.path, "part": u.part, "parts": u.parts,
                       "bytes": nbytes(u.text), "header_bytes": nbytes(u.header)}
                      for u in chunk.units],
        })
    encoded = diff.encode("utf-8")
    doc = {
        "version": PLAN_VERSION,
        "chunk_bytes": chunk_bytes,
        "diff_bytes": len(encoded),
        "diff_sha256": hashlib.sha256(encoded).hexdigest(),
        "files": len({u.seq for c in chunks for u in c.units}),
        "chunks": rows,
    }
    raw = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    (output / PLAN_FILE).write_bytes(raw)
    return {
        "plan_file": PLAN_FILE,
        "plan_sha256": hashlib.sha256(raw).hexdigest(),
        "chunk_bytes": chunk_bytes,
        "chunks": len(rows),
        "chunk_sizes": [r["bytes"] for r in rows],
        "split_files": sorted({u.path for c in chunks for u in c.units if u.parts > 1}),
    }
