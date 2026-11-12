"""Bind a deployment review to its execution and last successful release.

Pipeline-owned tooling and policy are deployed separately from the candidate.
The baseline is the most recent successful execution completed before this
execution started. A failed review can never advance it. When the history has
no successful execution, an operator-approved starting commit
(`--approved-baseline`, see "Approved starting commit" in deploy/README.md) is
used if one was supplied; otherwise the complete tracked tree is reviewed.
AWS/history/Git errors and a malformed approval file stop the gate.

A delta larger than one review call is not truncated: it is planned into
complete chunks (review_chunks.py) that every seat reviews, and the plan is
written next to the diff for the Review and ThreatModel actions to consume.
`--dry-run` builds the same inputs from an explicit base with no AWS call.

Before anything is written, the rendered diff must match git's own list of
changed paths, file for file and in order, so file content cannot imitate a
file boundary. Bytes no model can read are refused unless they are media:
a section git renders only as `Binary files ... differ` must be a deletion or
have an extension in BINARY_EXTENSIONS (a NUL byte or a `-diff` attribute
makes source render that way). A delta that changes a .gitattributes file is
refused, because attributes change how git renders the delta to reviewers.
The binary sections that remain are listed in the metadata, so the evidence
says which bytes no model read.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import posixpath
import re
import subprocess
import sys
from datetime import datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import review_chunks  # noqa: E402  (shipped beside this file in the same asset)

# Largest delta the Review and ThreatModel actions accept. Above one chunk the
# review is split, never cut; above this the gate stops before any model call.
MAX_DIFF_BYTES = 3_000_000

# Files that may reach the release without any model reading their bytes:
# images, web fonts and audio. Anything else git renders as binary stops the
# gate. Deleting a binary file of any type is allowed (it adds no bytes).
BINARY_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
                               ".woff", ".woff2", ".mp3"})

# The operator-approved starting commit (deploy/README.md, "Approved starting
# commit"). A small JSON record with exactly these keys; anything else stops.
APPROVAL_MAX_BYTES = 16 * 1024
APPROVAL_KEYS = ("version", "commit", "approved_by", "approved_at", "reviewed")
APPROVAL_PROCEDURE = 'the "Approved starting commit" procedure in deploy/README.md'


def git(*args: str, cwd: str = ".") -> str:
    return subprocess.check_output(
        ["git", *args], cwd=cwd, text=True, stderr=subprocess.PIPE
    ).strip()


def diff_text(raw: bytes) -> str:
    """git diff output as the reviewers read it.

    CRLF line ends become LF, as they always have. A carriage return that does
    not end a line is refused: read as text it would become a line break, and
    the file content after it could start a line with `diff --git`.
    """
    lone = re.search(rb"\r(?!\n)", raw)
    if lone:
        line = raw.count(b"\n", 0, lone.start()) + 1
        raise ValueError(f"the delta has a carriage return inside a line (diff line {line}); "
                         "normalize that file's line endings")
    try:
        return raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ValueError(f"the delta is not UTF-8 text: {exc}") from exc


def changed_entries(base: str, head: str, repo: str) -> list[dict]:
    """git's own list of changed paths for base..head, in diff order."""
    raw = subprocess.check_output(
        ["git", "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--raw", "-z",
         "--no-abbrev", base, head], cwd=repo, stderr=subprocess.PIPE)
    fields, entries, i = raw.split(b"\0"), [], 0
    while i < len(fields) and fields[i]:
        meta = fields[i].decode("ascii").lstrip(":").split()
        if len(meta) != 5:
            raise ValueError("unexpected `git diff --raw` output")
        status = meta[4][:1]
        count = 2 if status in ("R", "C") else 1
        names = [f.decode("utf-8", "surrogateescape") for f in fields[i + 1:i + 1 + count]]
        if len(names) != count:
            raise ValueError("unexpected `git diff --raw` output")
        entries.append({"status": status, "old": names[0], "new": names[-1],
                        "old_blob": meta[2], "new_blob": meta[3]})
        i += 1 + count
    return entries


def _unquote(name: str) -> str:
    if not name.startswith('"'):
        return name
    try:
        return ast.literal_eval("b" + name).decode("utf-8", "surrogateescape")
    except (ValueError, SyntaxError) as exc:
        raise ValueError(f"unreadable quoted path in the diff: {name}") from exc


def section_paths(header: str) -> tuple[str, str]:
    """(old, new) path of one file section, read the way git writes them."""
    lines = header.split("\n")
    moved = {}
    for line in lines[1:]:
        for key in ("rename from ", "rename to ", "copy from ", "copy to "):
            if line.startswith(key):
                moved[key.split()[1]] = _unquote(line[len(key):])
    if "from" in moved and "to" in moved:
        return moved["from"], moved["to"]
    names = lines[0][len("diff --git "):]
    if names.startswith('"'):
        match = re.fullmatch(r'("(?:\\.|[^"\\])*") ("(?:\\.|[^"\\])*")', names)
        if not match:
            raise ValueError(f"unreadable diff header: {lines[0][:200]}")
        old, new = _unquote(match[1]), _unquote(match[2])
        if not (old.startswith("a/") and new.startswith("b/")):
            raise ValueError(f"unreadable diff header: {lines[0][:200]}")
        return old[2:], new[2:]
    # Without rename lines both sides name the same file: "a/NAME b/NAME", and
    # NAME may contain spaces (even " b/"), so split by length, not by search.
    name = names[2:2 + (len(names) - 5) // 2]
    if names != f"a/{name} b/{name}":
        raise ValueError(f"unreadable diff header: {lines[0][:200]}")
    return name, name


def _blob_sizes(blobs: set[str], repo: str) -> dict[str, int]:
    wanted = sorted(b for b in blobs if b.strip("0"))
    if not wanted:
        return {}
    out = subprocess.run(["git", "cat-file", "--batch-check"], cwd=repo, check=True,
                         input="".join(f"{b}\n" for b in wanted), capture_output=True,
                         text=True).stdout.split("\n")
    sizes = {}
    for row in out:
        parts = row.split()
        if len(parts) == 3 and parts[1] == "blob":
            sizes[parts[0]] = int(parts[2])
    return sizes


def check_delta(sections, entries: list[dict], repo: str) -> list[dict]:
    """Refuse a delta whose bytes would not all reach a reviewer; list binaries.

    Returns one row per binary section: the bytes no model reads.
    """
    for entry in entries:
        for name in {entry["old"], entry["new"]}:
            # Lower-cased: a case-insensitive checkout reads .GitAttributes too.
            if posixpath.basename(name).lower() == ".gitattributes":
                raise ValueError(f"the delta changes {name}; attributes decide how git renders "
                                 "the delta to the reviewers, so change them outside this gate")
    # A type change (file <-> symlink) renders as a deletion plus an addition.
    expected = [(e["old"], e["new"], e) for e in entries
                for _ in range(2 if e["status"] == "T" else 1)]
    found = [section_paths(s.header) for s in sections]
    if [(o, n) for o, n, _ in expected] != found:
        mismatch = next((k for k, pair in enumerate(found)
                         if k >= len(expected) or pair != expected[k][:2]), len(found))
        raise ValueError("the rendered diff does not match git's list of changed files "
                         f"({len(found)} file sections for {len(expected)} expected; first "
                         f"difference at section {mismatch + 1}); file content may be "
                         "imitating a file boundary")
    binary = []
    for section, (old, new, entry) in zip(sections, expected):
        header = section.header.split("\n")
        if section.hunks or not any(line.startswith("Binary files ") and line.endswith(" differ")
                                    or line == "GIT binary patch" for line in header):
            continue
        deleted = any(line.startswith("deleted file mode ") for line in header)
        added = any(line.startswith("new file mode ") for line in header)
        if not deleted and posixpath.splitext(new)[1].lower() not in BINARY_EXTENSIONS:
            raise ValueError(f"{new} renders as binary, so no reviewer would read it; only "
                             f"{', '.join(sorted(BINARY_EXTENSIONS))} files may (a NUL byte or a "
                             "-diff attribute makes source render as binary)")
        change = ("deleted" if deleted else "added" if added else
                  {"R": "renamed", "C": "copied"}.get(entry["status"], "modified"))
        binary.append({"path": new, "change": change,
                       "old_blob": None if added else entry["old_blob"],
                       "new_blob": None if deleted else entry["new_blob"]})
        if old != new:
            binary[-1]["old_path"] = old
    sizes = _blob_sizes({b[k] for b in binary for k in ("old_blob", "new_blob") if b[k]}, repo)
    for row in binary:
        old_blob, new_blob = row.pop("old_blob"), row.pop("new_blob")
        row["bytes"] = sizes.get(new_blob, 0) if new_blob else 0
        row["previous_bytes"] = sizes.get(old_blob, 0) if old_blob else 0
    return binary


def load_approval(path: pathlib.Path, version_id: str | None = None) -> dict:
    """Read and check an approved-starting-commit file. Any defect is a ValueError.

    The approval says a person other than the author approved a whole-repository
    review of `commit`. It is a trust decision recorded by an operator, not a PASS.
    """
    with open(path, "rb") as handle:
        raw = handle.read(APPROVAL_MAX_BYTES + 1)
    if len(raw) > APPROVAL_MAX_BYTES:
        raise ValueError(f"approved baseline file is larger than {APPROVAL_MAX_BYTES:,} bytes")

    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("approved baseline file repeats a key")
        return dict(pairs)

    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"approved baseline file is not JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("approved baseline file must be a JSON object")
    extra = sorted(set(doc) - set(APPROVAL_KEYS))
    missing = [k for k in APPROVAL_KEYS if k not in doc]
    if extra or missing:
        raise ValueError(f"approved baseline file has unknown keys {extra} or lacks {missing}")
    if type(doc["version"]) is not int or doc["version"] != 1:
        raise ValueError(f"approved baseline file version {doc['version']!r} is not supported")
    if not isinstance(doc["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", doc["commit"]):
        raise ValueError("approved baseline commit must be a 40-character lowercase Git SHA")
    for key in ("approved_by", "approved_at", "reviewed"):
        if not isinstance(doc[key], str) or not doc[key].strip():
            raise ValueError(f"approved baseline field {key} must be a non-empty string")
    stamp = doc["approved_at"]
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z", stamp):
            raise ValueError(stamp)
        datetime.fromisoformat(stamp[:-1])
    except ValueError as exc:
        raise ValueError("approved baseline approved_at must be an ISO-8601 UTC time "
                         "such as 2026-10-31T09:00:00Z") from exc
    if version_id is not None and (not version_id or len(version_id) > 1024
                                   or not re.fullmatch(r"[\x21-\x7e]+", version_id)):
        raise ValueError("approved baseline version id is malformed")
    return {**doc, "approval_sha256": hashlib.sha256(raw).hexdigest(),
            "approval_version_id": version_id}


def ensure_commit(sha: str, repo: str) -> None:
    """Make `sha` available locally or raise; never substitute another commit."""
    try:
        git("cat-file", "-e", f"{sha}^{{commit}}", cwd=repo)
    except subprocess.CalledProcessError:
        subprocess.run(
            ["git", "fetch", "--no-tags", "--no-recurse-submodules", "origin", sha],
            cwd=repo, check=True, capture_output=True, text=True, timeout=60,
        )
        git("cat-file", "-e", f"{sha}^{{commit}}", cwd=repo)


def choose_baseline(executions: list[dict], execution_id: str) -> tuple[str | None, dict]:
    current = next(
        (e for e in executions if e.get("pipelineExecutionId") == execution_id), None
    )
    if current is None or not current.get("startTime"):
        raise ValueError("current execution is absent from pipeline history")
    cutoff = current["startTime"]
    eligible = [
        e for e in executions
        if e.get("pipelineExecutionId") != execution_id
        and e.get("status") == "Succeeded"
        and e.get("lastUpdateTime")
        and e["lastUpdateTime"] <= cutoff
    ]
    if not eligible:
        return None, current
    previous = max(eligible, key=lambda e: e["lastUpdateTime"])
    revisions = previous.get("sourceRevisions", [])
    if len(revisions) != 1 or not revisions[0].get("revisionId"):
        raise ValueError("successful release must identify exactly one source revision")
    if not re.fullmatch(r"[0-9a-f]{40}", revisions[0]["revisionId"]):
        raise ValueError("successful release revision is not a Git commit SHA")
    return revisions[0]["revisionId"], current


def history(client, pipeline: str) -> list[dict]:
    rows, token = [], None
    for _ in range(100):
        kwargs = {"pipelineName": pipeline, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = client.list_pipeline_executions(**kwargs)
        rows.extend(page.get("pipelineExecutionSummaries", []))
        token = page.get("nextToken")
        if not token:
            return rows
    raise ValueError("pipeline history exceeded the review lookup limit")


def prepare(
    executions: list[dict], execution_id: str, expected_revision: str,
    rules_path: pathlib.Path, output: pathlib.Path, repo: str = ".",
    chunk_bytes: int = review_chunks.CHUNK_BYTES,
    approved_baseline: pathlib.Path | None = None,
    approved_baseline_version: str | None = None,
) -> dict:
    # A malformed approval stops the gate even when history would win, so a
    # bad upload is found now rather than on the day it is needed.
    approval = (load_approval(approved_baseline, approved_baseline_version)
                if approved_baseline else None)
    baseline, current = choose_baseline(executions, execution_id)
    head = git("rev-parse", "HEAD", cwd=repo)
    if head != expected_revision:
        raise ValueError("checked-out revision differs from this pipeline execution")
    current_revisions = current.get("sourceRevisions", [])
    if len(current_revisions) != 1 or current_revisions[0].get("revisionId") != head:
        raise ValueError("pipeline history revision does not match the source artifact")
    identity = {
        "pipeline_execution_id": execution_id,
        "head_revision": head,
        "baseline_revision": baseline,
        "baseline_kind": "last_successful_release" if baseline else "initial_full_tree",
        "policy_origin": "pipeline_deployment",
    }
    if baseline:
        # Do not silently substitute HEAD~1 if a force push or shallow clone
        # makes the last release unavailable.
        ensure_commit(baseline, repo)
        base = baseline
        if approval:
            # History wins; say which approval file was present and not used.
            identity.update(approved_baseline_used=False,
                            approval_sha256=approval["approval_sha256"],
                            approval_version_id=approval["approval_version_id"])
    elif approval:
        commit = approval["commit"]
        try:
            ensure_commit(commit, repo)
        except subprocess.CalledProcessError as exc:
            raise ValueError(f"approved baseline commit {commit} is not in the repository") from exc
        ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", commit, head],
                                  cwd=repo, capture_output=True, text=True)
        if ancestry.returncode == 1:
            raise ValueError(f"approved baseline commit {commit} is not an ancestor of {head}")
        if ancestry.returncode != 0:
            raise ValueError(f"could not check the ancestry of approved baseline commit "
                             f"{commit}: {ancestry.stderr.strip()}")
        base = commit
        identity.update(baseline_revision=commit, baseline_kind="approved_baseline",
                        approved_baseline_used=True,
                        **{k: approval[k] for k in ("approved_by", "approved_at", "reviewed",
                                                    "approval_sha256", "approval_version_id")})
    else:
        base = subprocess.check_output(
            ["git", "hash-object", "-t", "tree", "--stdin"],
            cwd=repo, input="", text=True,
        ).strip()
    return _materialize(base, head, rules_path, output, repo, chunk_bytes, identity)


def _materialize(base: str, head: str, rules_path: pathlib.Path, output: pathlib.Path,
                 repo: str, chunk_bytes: int, identity: dict) -> dict:
    """Diff, size-check and chunk-plan base..head, then write every input file.

    Nothing is written unless the whole delta is reviewable: an oversized,
    unplannable or unreadable delta raises first, which stops the build before
    any model runs.
    """
    # --no-renames (here and in changed_entries): a moved file shows as a whole
    # deletion plus a whole addition, so the seats read every line at the new
    # path. A 100% rename would otherwise render with no lines at all.
    diff = diff_text(subprocess.check_output(
        ["git", "diff", "--no-ext-diff", "--no-textconv", "--no-renames", base, head],
        cwd=repo, stderr=subprocess.PIPE,
    ))
    size = len(diff.encode("utf-8"))
    # Truncating a diff turns missing evidence into a plausible PASS.
    if size > MAX_DIFF_BYTES:
        message = (f"change exceeds the {MAX_DIFF_BYTES:,}-byte review limit "
                   f"({size:,} bytes); split or review explicitly")
        if identity.get("baseline_kind") == "initial_full_tree":
            message += ("; this is a full-tree review because the pipeline history has no "
                        "successful release, so review the repository once and record an "
                        f"approved starting commit ({APPROVAL_PROCEDURE})")
        raise ValueError(message)
    binary = check_delta(review_chunks.parse_sections(diff),
                         changed_entries(base, head, repo), repo)
    chunks = review_chunks.plan(diff, chunk_bytes)
    # --no-renames: a renamed template is listed under its old name too, so the
    # threat-model staleness check sees it.
    changed = git("diff", "--no-renames", "--name-only", base, head, cwd=repo).splitlines()
    policy = rules_path.read_bytes()
    if not policy.strip():
        raise ValueError("pipeline-owned review policy is empty")
    metadata = {
        **identity,
        "policy_sha256": hashlib.sha256(policy).hexdigest(),
        "diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest(),
        "changed_files": changed,
        "diff_bytes": size,
    }
    output.mkdir(parents=True, exist_ok=True)
    metadata["chunk_plan"] = review_chunks.write_plan(chunks, diff, chunk_bytes, output)
    # What no model reads: the bytes behind each `Binary files ... differ`.
    metadata["chunk_plan"]["binary_sections"] = binary
    metadata["chunk_plan"]["binary_bytes"] = sum(row["bytes"] for row in binary)
    (output / "change.diff").write_text(diff)
    (output / "changed.txt").write_text("".join(f"{p}\n" for p in changed))
    (output / "input-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def dry_run(base: str, head: str, rules_path: pathlib.Path, output: pathlib.Path,
            repo: str = ".", chunk_bytes: int = review_chunks.CHUNK_BYTES) -> dict:
    """The pipeline's review inputs for an explicit base, with no AWS or model call.

    Used to see the chunk plan a candidate would get before pushing it. The
    pipeline itself never takes the base from a caller.
    """
    base_sha = git("rev-parse", "--verify", f"{base}^{{commit}}", cwd=repo)
    head_sha = git("rev-parse", "--verify", f"{head}^{{commit}}", cwd=repo)
    return _materialize(base_sha, head_sha, rules_path, output, repo, chunk_bytes, {
        "dry_run": True,
        "head_revision": head_sha,
        "baseline_revision": base_sha,
        "baseline_kind": "explicit_dry_run",
        "policy_origin": "local_file",
    })


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pipeline")
    p.add_argument("--execution-id")
    p.add_argument("--revision")
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--rules", default="/tmp/rules.yaml")
    p.add_argument("--output", default="/tmp/review-input")
    p.add_argument("--attach-report")
    p.add_argument("--dry-run", action="store_true",
                   help="plan base..head locally (needs --base and --head); no AWS or model call")
    p.add_argument("--repo", default=".")
    p.add_argument("--base")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--chunk-bytes", type=int, default=review_chunks.CHUNK_BYTES)
    p.add_argument("--approved-baseline", metavar="PATH",
                   help="operator-approved starting commit (JSON); used only when the "
                        "pipeline history has no successful release")
    p.add_argument("--approved-baseline-version", metavar="ID",
                   help="S3 version id of the approved baseline file, recorded as evidence")
    args = p.parse_args()
    if args.approved_baseline_version and not args.approved_baseline:
        p.error("--approved-baseline-version needs --approved-baseline")
    output = pathlib.Path(args.output)
    if args.dry_run:
        if not args.base:
            p.error("--dry-run needs --base")
        result = dry_run(args.base, args.head, pathlib.Path(args.rules), output,
                         args.repo, args.chunk_bytes)
        print(json.dumps(result, indent=2))
        return 0
    if args.attach_report:
        path = pathlib.Path(args.attach_report)
        doc = json.loads(path.read_text())
        doc["review_input"] = json.loads((output / "input-metadata.json").read_text())
        path.write_text(json.dumps(doc, indent=2) + "\n")
        return 0
    if not all((args.pipeline, args.execution_id, args.revision)):
        p.error("--pipeline, --execution-id and --revision are required")
    import boto3
    client = boto3.client("codepipeline", region_name=args.region)
    result = prepare(
        history(client, args.pipeline), args.execution_id, args.revision,
        pathlib.Path(args.rules), output,
        approved_baseline=pathlib.Path(args.approved_baseline) if args.approved_baseline else None,
        approved_baseline_version=args.approved_baseline_version,
    )
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
