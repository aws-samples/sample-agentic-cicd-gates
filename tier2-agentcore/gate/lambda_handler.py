"""Tier 2 gate: CodePipeline Lambda action invoking the AgentCore reviewer.

Source-agnostic: diffs the source artifact zip against the last-reviewed
accepted snapshot kept in the state bucket. Rules load only from that
snapshot; the baseline advances only after an error-free PASS. A missing
baseline blocks and requires explicit initialization from an independently
approved revision (see ../README.md).

A delta larger than one review chunk is reviewed chunk by chunk by the
runtime (runtime/handler.py runs Tier 1's planner and chunked panel), inside
this one synchronous call and under a deadline that ends well before the read
timeout. The time budget is stated below. Every logged result carries the
gate's own evidence (`review_input`): what it diffed, against which baseline,
and the changed files it did not send to any reviewer, with their sizes.
"""
import difflib
import hashlib
import io
import json
import os
import uuid
import zipfile

import boto3
from botocore.exceptions import ClientError

MAX_SUMMARY = 500
TEXT_EXT = (".py", ".yaml", ".yml", ".json", ".md", ".txt", ".sh", ".toml", ".cfg",
            ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm",
            ".css", ".scss", ".sass", ".less", ".svg", ".vue", ".svelte")
# Text files whose NAME, not an extension, says what they are: build and
# container definitions, licences and ignore files. A change to a Dockerfile or
# a Makefile is reviewed like any other text, not merely listed as skipped.
TEXT_NAMES = frozenset({"dockerfile", "containerfile", "makefile", "gnumakefile",
                        "license", "licence", "notice", ".gitignore", ".dockerignore"})
BASELINE_KEY = "tier2/last-reviewed-source.zip"  # retained for existing deployments

# The time budget of one review, in seconds. Large deltas are chunked, never
# truncated, and the whole review happens inside ONE synchronous call. Both
# outer limits are hard: the Lambda timeout is 900 (the maximum) and
# AgentCore answers a synchronous InvokeAgentRuntime within 15 minutes (not
# adjustable).
#   READ_TIMEOUT 840: how long the gate waits for the report. The work before
#     the call (two zips, the tree diff) takes well under 10 s, and the call
#     starts only with READ_TIMEOUT + REPORT_RESERVE left, so even a call
#     that times out leaves time to report failure: the action never wedges.
#   REVIEW_DEADLINE 720: the runtime stops waiting for chunk reviews here and
#     fails every unfinished chunk closed, 120 s before the read timeout. That
#     covers the microVM start (whole gate runs over an empty diff took 7-10 s),
#     planning and independent plan verification (under 2 s for 2.5 MB) and
#     folding the report.
#   MAX_DIFF 2,500,000 with 16 review workers in the runtime. From Tier 1's
#     measured reviews: illustrated assets cost 1,442 seat-seconds for
#     1,787,547 bytes (2026-10-06, 64 reviews, 305 s on 8 workers) = ~806
#     seat-s per MB; release code cost ~300 seat-seconds for 98,971 bytes
#     (2026-10-02, four seats, 272-302 s) = ~3,050 seat-s per MB. Wall time is
#     at least that work divided by 16 AND at least the slowest single review
#     (plus its retry, if it errs), which cannot be split: 2.5 MB of assets is
#     ~126 s of work, but 2.5 MB of code is ~480 s before stragglers and
#     retries, so a code-heavy delta near the cap is likely to reach the
#     deadline; about 1 MB of code (~190 s of work) leaves room for one slow
#     review and its retry. A scoped seat's items are at most 30,000 bytes
#     (runtime/handler.py SCOPED_ITEM_BYTES), near the slowest seat's one
#     measured item. The 1,890,196-byte artifact merge is mostly the assets
#     Tier 1 reviewed in 305 s. Content that costs more fails closed at the
#     deadline with a complete report and no baseline change; push smaller
#     fast-forwards instead of reseeding (a pushed delta cannot shrink later).
#   A delta of at most CHUNK_BYTES takes the single-call path instead: four
#     seats one after another, with NO deadline (302 s for 98,971 bytes on
#     2026-10-02). A call that outlasts READ_TIMEOUT ends as a gate error, with
#     no baseline change; it fails closed, but without a chunked report.
#   One reviewer call may take up to 1,126 s (READ_TIMEOUT_SECONDS in
#     agent/reviewer/bedrock_reviewer.py: the 64,000-token cap at 60 tokens/s),
#     longer than either 15-minute limit allows. Tier 2 is the one place that
#     cannot wait for it, and it is safe because it never passes on a timeout:
#     both paths above fail closed. The slowest measured item took 244.5 s.
#     shortcut: synchronous calls cap Tier 2 at 15 minutes; move the review
#     to an asynchronous AgentCore job (up to 8 hours) if seats need the full cap.
READ_TIMEOUT_SECONDS = 840
REVIEW_DEADLINE_SECONDS = 720
REPORT_RESERVE_SECONDS = 30
MAX_DIFF = 2_500_000
CHUNK_BYTES = 100_000  # pipeline_tools/review_chunks.CHUNK_BYTES; above it the runtime chunks
MAX_LISTED_SKIPPED = 500  # keep one log event well under CloudWatch's event size limit

codepipeline = boto3.client("codepipeline")
from botocore.config import Config
agentcore = boto3.client(
    "bedrock-agentcore",
    config=Config(read_timeout=READ_TIMEOUT_SECONDS, connect_timeout=10,
                  retries={"total_max_attempts": 1}))
s3_state = boto3.client("s3")

def _artifact_zip(data):
    cred = data["artifactCredentials"]
    loc = data["inputArtifacts"][0]["location"]["s3Location"]
    s3 = boto3.client(
        "s3",
        aws_access_key_id=cred["accessKeyId"],
        aws_secret_access_key=cred["secretAccessKey"],
        aws_session_token=cred["sessionToken"])
    obj = s3.get_object(Bucket=loc["bucketName"], Key=loc["objectKey"])
    return obj["Body"].read()


def _is_text(path):
    """A file the gate diffs and sends to the reviewers (by extension or name)."""
    lower = path.lower()
    return lower.endswith(TEXT_EXT) or lower.rsplit("/", 1)[-1] in TEXT_NAMES


def _tree(zip_bytes):
    out = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for n in z.namelist():
            if n.endswith("/") or not _is_text(n):
                continue
            # A corrupt/unreadable supported file is missing evidence, not an
            # unchanged file. Propagate the error to the pipeline.
            out[n] = z.read(n).decode("utf-8").splitlines(keepends=True)
    return out


def _git_path(path):
    """Quote paths using Git's C-style byte escapes (including UTF-8 names)."""
    if all(32 < b < 127 and b not in (34, 92) for b in path.encode("utf-8")):
        return path
    return '"' + "".join(
        chr(b) if 32 <= b < 127 and b not in (34, 92) else f"\\{b:03o}"
        for b in path.encode("utf-8")) + '"'


def _tree_diff(old, new):
    parts = []
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path, []), new.get(path, [])
        if a == b and (path in old) == (path in new):
            continue
        old_path, new_path = _git_path(f"a/{path}"), _git_path(f"b/{path}")
        parts.append(f"diff --git {old_path} {new_path}\n")
        if path not in old:
            parts.append("new file mode 100644\n")
        elif path not in new:
            parts.append("deleted file mode 100644\n")
        for line in difflib.unified_diff(
                a, b, fromfile=old_path if path in old else "/dev/null",
                tofile=new_path if path in new else "/dev/null"):
            parts.append(line if line.endswith("\n") else
                         line + "\n\\ No newline at end of file\n")
    return "".join(parts)


def _skipped(old_zip, new_zip):
    """Changed files the gate sends to no reviewer (not _is_text), with sizes.

    Read from ZIP metadata (size and CRC-32), so it costs no decompression.
    Returns (rows, number of unchanged skipped files). ZIP mode changes stay
    outside coverage, as before.
    """
    def entries(data):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return {i.filename: (i.file_size, i.CRC) for i in z.infolist()
                    if not i.filename.endswith("/") and not _is_text(i.filename)}

    old, new = entries(old_zip), entries(new_zip)
    rows = []
    for path in sorted(set(old) | set(new)):
        if old.get(path) == new.get(path):
            continue
        rows.append({"path": path,
                     "change": ("added" if path not in old else
                                "deleted" if path not in new else "modified"),
                     "bytes": new[path][0] if path in new else 0,
                     "previous_bytes": old[path][0] if path in old else 0})
    return rows, sum(1 for path in new if old.get(path) == new[path])


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _review_input(job_id, data, key, etag, cur_zip, prev_zip, cur, prev, diff_bytes,
                  rules_yaml):
    """The gate's own evidence for the logged result: what was diffed, and what was not."""
    rows, unchanged = _skipped(prev_zip, cur_zip)
    sections = sum(1 for path in set(prev) | set(cur)
                   if prev.get(path, []) != cur.get(path, []) or (path in prev) != (path in cur))
    return {
        "job_id": job_id,
        "input_artifact_revision": (data.get("inputArtifacts") or [{}])[0].get("revision"),
        "source_zip_bytes": len(cur_zip), "source_zip_sha256": _sha256(cur_zip),
        "baseline_key": key, "baseline_etag": etag,
        "baseline_zip_bytes": len(prev_zip), "baseline_zip_sha256": _sha256(prev_zip),
        "policy_origin": "baseline",
        "policy_sha256": _sha256(rules_yaml.encode("utf-8")) if rules_yaml.strip() else None,
        "text_files": {"baseline": len(prev), "candidate": len(cur)},
        "diff_bytes": len(diff_bytes), "diff_sha256": _sha256(diff_bytes),
        "diff_file_sections": sections,
        "max_diff_bytes": MAX_DIFF, "chunk_bytes": CHUNK_BYTES,
        "review_deadline_seconds": REVIEW_DEADLINE_SECONDS,
        # What no model read: changed files that are not text by extension or name.
        "skipped_files": rows[:MAX_LISTED_SKIPPED],
        "skipped_files_total": len(rows),
        "skipped_bytes": sum(row["bytes"] for row in rows),
        "skipped_unchanged_files": unchanged,
    }


def _baseline(bucket, key):
    try:
        obj = s3_state.get_object(Bucket=bucket, Key=key)
        return obj["Body"].read(), obj["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchKey":
            return None
        raise  # AccessDenied, NoSuchBucket, throttling, etc. are NOT first use


def _require_clean_pass(result):
    """Refuse missing, contradictory or errored review evidence before writes."""
    if not isinstance(result, dict) or result.get("verdict") != "PASS" or result.get("error"):
        raise ValueError("baseline requires an error-free PASS report")
    stats, findings, agents = (result.get(k) for k in ("stats", "findings", "agents"))
    if (not isinstance(stats, dict) or not isinstance(findings, list)
            or not isinstance(agents, list) or not agents):
        raise ValueError("incomplete review report")
    if (type(stats.get("total")) is not int or stats["total"] != len(findings)
            or type(stats.get("blocking")) is not int or stats["blocking"] != 0):
        raise ValueError("inconsistent PASS statistics")
    if any(not isinstance(f, dict) or f.get("blocking") is not False for f in findings):
        raise ValueError("PASS contains blocking or malformed findings")
    if any(not isinstance(a, dict) or a.get("verdict") != "PASS" or a.get("error")
           or type(a.get("blocking")) is not int or a["blocking"] != 0 for a in agents):
        raise ValueError("panel contains errors or incomplete PASS evidence")


def _require_review_coverage(result, review_input):
    """Refuse a PASS that does not cover exactly the delta this gate sent.

    A delta of one chunk comes back in today's single-call shape. A larger one
    must come back chunked, over the same diff, with every scheduled chunk
    review completed as a PASS before the deadline. The runtime already makes
    any gap its seat's error verdict; this is the pipeline-side check.
    """
    chunking = result.get("chunking")
    chunked = review_input["diff_bytes"] > CHUNK_BYTES
    if chunking is None:
        if chunked:
            raise ValueError("a delta larger than one chunk came back without chunk evidence")
        return
    if not chunked or not isinstance(chunking, dict) or chunking.get("mode") != "chunked":
        raise ValueError("chunk evidence does not match the delta that was sent")
    if (chunking.get("diff_sha256") != review_input["diff_sha256"]
            or chunking.get("diff_bytes") != review_input["diff_bytes"]):
        raise ValueError("chunk evidence covers a different diff")
    scheduled = chunking.get("reviews_scheduled")
    if (chunking.get("deadline_reached") is not False or type(scheduled) is not int
            or scheduled < 0 or chunking.get("reviews_completed") != scheduled):
        raise ValueError("chunked review did not complete every scheduled chunk review")
    rows = 0
    for agent in result["agents"]:
        chunks = agent.get("chunks")
        if not isinstance(chunks, list) or any(
                not isinstance(row, dict) or row.get("verdict") != "PASS" or row.get("error")
                or type(row.get("attempts")) is not int or row["attempts"] < 1
                for row in chunks):
            raise ValueError(f"{agent.get('name')}: a chunk has no completed PASS review")
        rows += len(chunks)
    if rows != scheduled:
        raise ValueError("chunk rows do not account for every scheduled review")


def _remaining_seconds(context):
    try:
        return context.get_remaining_time_in_millis() / 1000
    except AttributeError:  # no Lambda context (local runs and tests)
        return None


def handler(event, context):
    job = event["CodePipeline.job"]
    job_id = job["id"]
    try:
        data = job["data"]
        params = json.loads(
            data["actionConfiguration"]["configuration"].get("UserParameters", "{}"))
        runtime_arn = params["runtime_arn"]
        bucket = os.environ["STATE_BUCKET"]
        key = BASELINE_KEY

        cur_zip = _artifact_zip(data)
        cur = _tree(cur_zip)
        baseline = _baseline(bucket, key)
        if baseline is None:
            raise ValueError(
                "BASELINE_MISSING: initialize tier2/last-reviewed-source.zip "
                "from an independently approved revision; no review performed, "
                "no state written (tier2-agentcore/README.md)")
        prev_zip, etag = baseline
        prev = _tree(prev_zip)
        diff = _tree_diff(prev, cur)
        encoded = diff.encode("utf-8")
        rules_yaml = "".join(prev.get(".reviewer.yaml", []))
        review_input = _review_input(job_id, data, key, etag, cur_zip, prev_zip, cur, prev,
                                     encoded, rules_yaml)
        # The dashboard shows a Lambda-log report only when it names its own run.
        review_input["pipeline_execution_id"] = params.get("pipeline_execution_id")
        # Logged before any refusal or call, so the evidence survives either.
        print(json.dumps({"review_input": review_input}))
        if len(encoded) > MAX_DIFF:
            raise ValueError(f"diff exceeds {MAX_DIFF} bytes; refusing partial review")
        if not rules_yaml.strip():
            raise ValueError("baseline has no .reviewer.yaml; refusing current-revision policy")
        print(f"diff bytes={len(encoded)} files={len(cur)} rules from baseline")

        remaining = _remaining_seconds(context)
        if remaining is not None and remaining < READ_TIMEOUT_SECONDS + REPORT_RESERVE_SECONDS:
            raise ValueError(f"only {remaining:.0f}s of Lambda time left; a bounded review "
                             f"needs {READ_TIMEOUT_SECONDS + REPORT_RESERVE_SECONDS}s")
        session = f"{job_id}-{uuid.uuid4().hex}"[:64]
        review_input["runtime_session_id"] = session
        payload = {"diff": diff, "rules_yaml": rules_yaml,
                   "deadline_seconds": REVIEW_DEADLINE_SECONDS}
        resp = agentcore.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            qualifier=os.environ.get("RUNTIME_QUALIFIER", "DEFAULT"),
            runtimeSessionId=session,
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(payload),
        )
        result = json.loads(resp["response"].read())
        print(json.dumps({**result, "review_input": review_input}
                         if isinstance(result, dict) else
                         {"result": result, "review_input": review_input}))
        verdict = result.get("verdict", "BLOCKED_ERROR")
        stats = result.get("stats", {})
        agents = result.get("agents", [])
        panel = ",".join(f"{a['name']}:{a['verdict']}" for a in agents)
        summary = (f"verdict={verdict} blocking={stats.get('blocking', '?')} "
                   f"total={stats.get('total', '?')} panel=[{panel}]")
        chunking = result.get("chunking")
        if isinstance(chunking, dict):
            summary += (f" chunks={chunking.get('chunks')}"
                        + (" deadline_reached" if chunking.get("deadline_reached") else ""))
        if verdict != "PASS":
            top = next(iter(result.get("findings", [])), None)
            if top:
                summary += f" | {top['rule_id']} {top['path']}:{top['line']}"
            if isinstance(chunking, dict):
                errors = [f"{a['name']}: {a['error']}" for a in agents if a.get("error")]
                if result.get("error") or errors:
                    summary += f" | {(result.get('error') or errors[0])[:300]}"
            codepipeline.put_job_failure_result(
                jobId=job_id,
                failureDetails={"type": "JobFailed",
                                "message": summary[:MAX_SUMMARY]})
        else:
            _require_clean_pass(result)
            _require_review_coverage(result, review_input)
            # Do not overwrite a baseline another invocation advanced while
            # this review ran. A precondition failure blocks and must be retried.
            s3_state.put_object(Bucket=bucket, Key=key, Body=cur_zip, IfMatch=etag)
            codepipeline.put_job_success_result(
                jobId=job_id,
                executionDetails={"summary": summary[:MAX_SUMMARY],
                                  "percentComplete": 100})
    except Exception as exc:  # noqa: BLE001 — never wedge the pipeline action
        print(f"GATE INFRA ERROR: {type(exc).__name__}: {exc}")
        codepipeline.put_job_failure_result(
            jobId=job_id,
            failureDetails={"type": "JobFailed",
                            "message": f"gate error: {type(exc).__name__}: {exc}"[:MAX_SUMMARY]})
    return {"ok": True}
