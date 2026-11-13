"""Bounded PR review: guard -> analyze (read only) -> publish (no model calls).

Run this file from the immutable base checkout with Python -I. The PR tree is
only data. Reports are scoped to repo/PR/base/head/run/attempt. Merge enforcement
requires repository settings; these checks alone only report evidence.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import fnmatch
import hashlib
import html
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
WORKFLOW_CONTRACT = 2
MAX_INLINE = 20
MAX_REPORT_BYTES = 2_000_000
MAX_DIFF_BYTES = 1_000_000
MAX_BODY_BYTES = 55_000
BOT = {"login": "github-actions[bot]", "type": "Bot", "id": 41898282}
SHA = r"[0-9a-f]{40}"
MARKER = re.compile(
    rf"<!-- agentic-review:v2 repo=([\w.-]+/[\w.-]+) pr=([1-9][0-9]*) "
    rf"reviewer=([0-9a-f]{{16}}) head=({SHA}) run=([1-9][0-9]*) "
    r"attempt=([1-9][0-9]*) part=([1-9][0-9]*) -->"
)
# The judge's own surface (TB-CONTROL): the workflow, the vendored gate bundle of
# an artifact repo, the rule policy and the declared trust boundaries. Each is
# read from the base ref, so a PR cannot change how it is judged, only how later
# PRs are. A PR that edits one gets no credentialed checks; a maintainer reviews
# such a change on its own (protect these paths with CODEOWNERS too).
FROZEN_DIRS = (".github", "pr-reviewer")
FROZEN_FILES = (".reviewer.yaml", "threat-model/boundaries.yaml")
# A .gitattributes anywhere can mark text as binary (`* -diff`), which would
# hide the change from the reviewed diff.
FROZEN_NAMES = (".gitattributes",)
# File types that are binary by nature. Any other file the diff shows only as
# "Binary files ... differ" (a NUL byte, an attribute) is refused, not skipped.
BINARY_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".mp3", ".mp4",
                   ".webm", ".ogg", ".wav", ".woff", ".woff2", ".ttf", ".otf", ".pdf",
                   ".zip", ".gz")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# Best-effort publication filter, not a DLP guarantee. Applied recursively before
# output reaches a report artifact, summary, or GitHub. Quantifiers are bounded
# so a long hostile string costs linear time, not quadratic.
SENSITIVE = re.compile(
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})|"
    r"(?i:bearer\s{1,8}[A-Za-z0-9._~+/=-]{16,})|"
    r"(?i:(?:secret|password|token|api[_-]?key|aws_secret_access_key)"
    r"[\"']?\s{0,8}[=:]\s{0,8}[\"']?[^\"'\s,;]{8,})|"
    r"https?://[^\s<>\"']{0,2048}?(?:\.amazon\.com|\.amazon\.dev|\.a2z\.com)"
    r"(?:[/:?#][^\s<>\"']*)?|"
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b|"
    # The account field of an ARN (arn:aws:sts::123456789012:assumed-role/...).
    r"(?<=:)[0-9]{12}(?=:)|"
    r"-----BEGIN [A-Z ]{0,64}PRIVATE KEY-----[\s\S]{0,16384}?-----END [A-Z ]{0,64}PRIVATE KEY-----"
)


def scrub(value):
    """Redact common credential/contact/internal-URL patterns in output data.

    Run it on text in its final form: a character removed after scrub() can
    join a split credential back together (see _text and _code).
    """
    if isinstance(value, str):
        return SENSITIVE.sub("[REDACTED]", value)
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value


def _gh(method, path, payload=None):
    """Call only GitHub, without following redirects with the job token."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    request = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        # Never echo response bodies: upstream errors may quote untrusted text.
        return exc.code, {}


def _require(method, path, payload=None):
    status, response = _gh(method, path, payload)
    if not 200 <= status < 300:
        raise RuntimeError(f"GitHub {method} failed (HTTP {status})")
    return response


def context():
    """Validate event identity before constructing paths or making API calls."""
    repo = os.environ["GITHUB_REPOSITORY"]
    pr = os.environ["PR_NUMBER"]
    base, head = os.environ["BASE_SHA"], os.environ["HEAD_SHA"]
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    if (not re.fullmatch(r"[\w.-]+/[\w.-]+", repo)
            or not all(re.fullmatch(r"[1-9][0-9]*", v) for v in (pr, run, attempt))
            or not all(re.fullmatch(SHA, v) for v in (base, head))):
        raise ValueError("invalid repo/PR/SHA/run identity")
    event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pull = event["pull_request"]
    if (os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
            or event["repository"]["full_name"] != repo
            or str(pull["number"]) != pr
            or pull["base"]["sha"] != base or pull["head"]["sha"] != head
            or pull["base"]["repo"]["full_name"] != repo
            or (pull["head"].get("repo") or {}).get("full_name") != repo):
        raise ValueError("unsupported event or fork PR; no credentialed review performed")
    return dict(repo=repo, pr=pr, base=base, head=head, run=run, attempt=attempt)


def _current(ctx):
    """Refuse closed, retargeted, or superseded revisions before each mutation."""
    pull = _require("GET", f"/repos/{ctx['repo']}/pulls/{ctx['pr']}")
    if (pull.get("state") != "open"
            or pull["head"]["sha"] != ctx["head"]
            or pull["base"]["sha"] != ctx["base"]
            or (pull["head"].get("repo") or {}).get("full_name") != ctx["repo"]
            or pull["base"]["repo"]["full_name"] != ctx["repo"]):
        raise RuntimeError("PR is closed or base/head changed; trigger a fresh PR event")


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=True,
        timeout=60).stdout


def guard(ctx, root):
    """Deny unauthorized actors, workflow edits, and symlink/submodule data."""
    _current(ctx)
    for actor in {os.environ["GITHUB_ACTOR"],
                  os.environ.get("GITHUB_TRIGGERING_ACTOR") or os.environ["GITHUB_ACTOR"]}:
        if not re.fullmatch(r"[A-Za-z0-9-]+(?:\[bot\])?", actor):
            raise ValueError("invalid triggering actor")
        user = urllib.parse.quote(actor, safe="")
        response = _require("GET", f"/repos/{ctx['repo']}/collaborators/{user}/permission")
        # Only roles that may push code unlock credentialed jobs. `permission`
        # is the legacy base role (maintain reads as write, triage as read);
        # `role_name` is checked too, so a triage or read role never passes.
        if (response.get("permission") not in {"admin", "maintain", "write"}
                or response.get("role_name") in {"triage", "read"}):
            raise RuntimeError("triggering actor lacks write/maintain/admin permission")
    # A three-dot diff compares against ONE merge base. With criss-cross history
    # (two merge bases) a frozen file changed against the other one would not
    # show, so such a PR is refused; merging or rebasing the base fixes it.
    bases = _git(root, "merge-base", "--all", ctx["base"], ctx["head"]).decode().split()
    if len(bases) != 1:
        raise RuntimeError(f"PR head has {len(bases)} merge bases with its base; merge or "
                           f"rebase onto the base branch, then push again")
    changed = _git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                   "--name-only", "-z", f"{ctx['base']}...{ctx['head']}").decode().split("\0")
    if any(p in FROZEN_FILES or p.rsplit("/", 1)[-1] in FROZEN_NAMES
           or any(p == d or p.startswith(d + "/") for d in FROZEN_DIRS)
           for p in changed):
        raise RuntimeError("automation files changed; maintainer must review this tooling "
                           "update separately before enabling credentialed checks")
    # Scanners must not follow PR symlinks into credentials, tooling, or output.
    # This bounded sample deliberately supports ordinary files only.
    tree = _git(root, "ls-tree", "-rz", ctx["head"]).split(b"\0")
    if any(row.startswith((b"120000 ", b"160000 ")) for row in tree):
        raise RuntimeError("PR tree contains symlinks/submodules; unsupported data context")


def _core():
    """Resolve only the trusted monorepo core or its trusted vendored copy."""
    here = pathlib.Path(__file__).resolve().parent
    mono = here.parent.parent / "agent"
    sys.path.insert(0, str(mono if (mono / "reviewer").is_dir() else here))
    from reviewer import rules, verdict
    return rules, verdict


def _rules(path):
    rules, _ = _core()
    raw = pathlib.Path(path).read_bytes()
    return rules.load_rules(raw.decode()), hashlib.sha256(raw).hexdigest()


def analyze(ctx, root, rules_path):
    """Run the model with read-only GitHub access and produce evidence only."""
    ruleset, digest = _rules(rules_path)
    from reviewer.bedrock_reviewer import DEFAULT_MODEL, review_panel
    # --no-renames, as in the frozen-path and numstat calls: a moved file shows
    # as a whole deletion plus a whole addition, so the panel reads every line
    # that lands at the new path (a 100% rename would otherwise show no lines).
    diff = _git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames",
                f"{ctx['base']}...{ctx['head']}")
    if len(diff) > MAX_DIFF_BYTES:
        raise ValueError("diff exceeds 1 MB; split the PR (no partial review performed)")
    # Which files the diff shows only as "Binary files differ", from git's
    # machine-readable list (-z: no C-quoting to parse; binary is "-\t-").
    numstat = _git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                   "--numstat", "-z", f"{ctx['base']}...{ctx['head']}")
    hidden = [path for record in numstat.split(b"\0") if record.startswith(b"-\t-\t")
              for path in [record[4:].decode("utf-8", "replace")]
              if not path.lower().endswith(BINARY_SUFFIXES)]
    if hidden:
        raise ValueError(f"the diff shows {len(hidden)} non-media file(s) only as 'Binary files "
                         f"differ' (a NUL byte or a .gitattributes rule), e.g. {hidden[0]}; "
                         f"no review of unseen code")
    rows = []
    for agent, outcome in review_panel(
            diff.decode(), ruleset, region=os.environ.get("AWS_REGION", "us-west-2")):
        rows.append(dict(name=agent.name, model=outcome.model_id,
                         result=json.loads(outcome.result.to_json())))
    return scrub(dict(version=2, context=ctx, rules_sha256=digest,
                      generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      default_model=DEFAULT_MODEL, reviews=rows))


def validate_report(report, ctx, rules_path):
    """Treat the downloaded report as data; recompute policy from base rules."""
    ruleset, digest = _rules(rules_path)
    _, verdict = _core()
    from reviewer.bedrock_reviewer import DEFAULT_MODEL
    agents = ruleset.agents or (ruleset.agent,)
    if (report.get("version") != 2 or report.get("context") != ctx
            or report.get("rules_sha256") != digest
            or report.get("default_model") != DEFAULT_MODEL
            or not isinstance(report.get("reviews"), list)
            or len(report["reviews"]) != len(agents)
            or len({a.name for a in agents}) != len(agents)):
        raise ValueError("report identity, rules digest, or reviewer set mismatch")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+\+00:00",
                        report.get("generated_at", "")):
        raise ValueError("report timestamp missing or malformed")
    checked = []
    for agent, row in zip(agents, report["reviews"]):
        if row.get("name") != agent.name or row.get("model") != (agent.model or DEFAULT_MODEL):
            raise ValueError("reviewer identity/model mismatch")
        doc = row["result"]
        scoped = dataclasses.replace(ruleset, rules=tuple(
            r for r in ruleset.rules if not agent.rules
            or any(r.id.startswith(prefix) for prefix in agent.rules)))
        if not isinstance(doc, dict):
            raise ValueError("malformed review result")
        # The model contract is the findings alone; the rest of the stored
        # result is checked below by recomputing it from those findings.
        findings = verdict.parse_model_findings(
            json.dumps({"findings": doc.get("findings")}), scoped)
        for f in findings:
            if agent.file_patterns and not any(
                    fnmatch.fnmatch(f.path, p) or fnmatch.fnmatch("/" + f.path, p)
                    for p in agent.file_patterns):
                raise ValueError("finding outside reviewer file scope")
        error = doc.get("error")
        if error is not None:
            if not isinstance(error, str) or not error.strip() or len(error) > 10000 or findings:
                raise ValueError("malformed error result")
            expected = json.loads(verdict.error_result(scoped, error, agent).to_json())
        else:
            expected = json.loads(verdict.compute_verdict(findings, scoped).to_json())
            suppressed = doc["stats"]["suppressed_below_threshold"]
            if (type(suppressed) is not int or suppressed < 0
                    or suppressed + len(findings) > ruleset.max_findings):
                raise ValueError("invalid suppressed count")
            expected["stats"]["suppressed_below_threshold"] = suppressed
        if doc != expected:
            raise ValueError("report verdict/counts/findings disagree with base policy")
        checked.append((agent, row))
    return checked


def _text(value):
    # Disable markdown links/images, mentions, HTML, and forged review markers.
    # Model text renders as ONE line: a newline would let it start its own
    # block (a fake "## Security: PASS" heading, a list, a quote).
    value = re.sub(r"\s*[\n\r\u2028\u2029\x85]\s*", " ", str(value))
    # Strip invisible characters first, then scrub: a control or bidi character
    # inside a key would hide it from scrub() and vanish right after.
    # shortcut: zero-width format characters (U+200B, U+2060, U+FEFF) are kept
    # and still split a token past scrub; strip them too if a seat emits them.
    value = scrub(CONTROL_CHARS.sub("", value))
    text = html.escape(value, quote=False).replace("@", "@\u200b")
    text = re.sub(r"([\\`*_\[\]{}()#!|~])", r"\\\1", text)
    # The text may start a line: no list item, numbered list or rule there.
    text = re.sub(r"^(\s*)([-+=])", r"\1\\\2", text)
    text = re.sub(r"^(\s*)(\d+)\.", r"\1\2\\.", text)
    # No bare autolinks: a zero-width space after the scheme, as for mentions.
    return re.sub(r"(?i)\b(https?|ftp|www)(?=[:.])", "\\1\u200b", text)


def _code(value):
    # Same invisible/bidi/control filter as _text (tabs and newlines stay),
    # applied before scrub() for the same reason.
    value = scrub(CONTROL_CHARS.sub("", str(value).replace("\r", "")))
    fence = "`" * max(3, max((len(m[0]) + 1 for m in re.finditer(r"`+", value)), default=3))
    return f"{fence}\n{value}\n{fence}"


def _reviewer_id(agent):
    return hashlib.sha256(agent.name.encode()).hexdigest()[:16]


def _marker(ctx, agent, part=1):
    return (f"<!-- agentic-review:v2 repo={ctx['repo']} pr={ctx['pr']} "
            f"reviewer={_reviewer_id(agent)} head={ctx['head']} run={ctx['run']} "
            f"attempt={ctx['attempt']} part={part} -->")


def _finding_body(f):
    text = (f"**{_text(f['rule_id'])}** — {_text(f['severity'])}, "
            f"{'blocking' if f['blocking'] else 'advisory'}, confidence {f['confidence']}\n\n"
            f"{_text(f['path'])}:{f['line']}\n\n{_text(f['message'])}")
    if f.get("suggested_code"):
        text += "\n\nSuggested code (review before applying):\n\n" + _code(f["suggested_code"])
    return text


def _finding_comment(f, agent):
    """Retain the existing inline format consumed by the PR dashboard."""
    body = (f"{_text(agent.emoji)} **{_text(agent.name)}** · **{_text(f['rule_id'])}** "
            f"({_text(f['severity'])}, {'blocking' if f['blocking'] else 'advisory'}, "
            f"confidence {f['confidence']})\n\n{_text(f['message'])}")
    if f.get("suggested_code"):
        body += "\n\nSuggested code (review before applying):\n\n" + _code(f["suggested_code"])
    return dict(path=f["path"], line=f["line"], side="RIGHT", body=body)


def review_payloads(ctx, report, agent, row):
    """Always retain every finding in the body, including inline fallbacks."""
    doc = row["result"]
    stats = doc["stats"]
    header = (
        f"## {_text(agent.emoji)} {_text(agent.name)}: **{doc['verdict']}**\n\n"
        f"Bot-generated review of `{ctx['head']}`; rules/tooling base `{ctx['base']}`.\n\n"
        f"[Workflow run](https://github.com/{ctx['repo']}/actions/runs/{ctx['run']}"
        f"/attempts/{ctx['attempt']}) · {_text(report['generated_at'])}\n\n"
        "| blocking | total | suppressed below threshold | model | configured thinking |\n"
        "|---|---|---|---|---|\n"
        f"| {stats['blocking']} | {stats['total']} | {stats['suppressed_below_threshold']} "
        f"| `{_text(row['model'])}` | {_text(agent.thinking)} |\n\n"
        "Policy is repeatable; model findings can be wrong or incomplete. "
        "PASS means no retained blocking findings, not human approval. "
        "Checks report results; merge enforcement depends on repository settings.\n\n"
    )
    if doc.get("error"):
        header += "**Review incomplete:** " + _text(doc["error"]) + "\n\n"
    chunks, current = [], header
    for finding in doc["findings"]:
        block = "### Finding\n\n" + _finding_body(finding) + "\n\n"
        if len((current + block).encode()) > MAX_BODY_BYTES:
            chunks.append(current)
            # A continuation must not look like a newer complete review to
            # consumers of the established heading/stats/inline format.
            current = (f"## {_text(agent.name)} — continued findings\n\n"
                       f"Bot-generated continuation for `{ctx['head']}`. "
                       "Verdict and counts are in this reviewer's first part.\n\n")
        current += block
    chunks.append(current)
    blocking = doc["verdict"] in {"FAIL", "BLOCKED_ERROR"}
    for i, body in enumerate(chunks, 1):
        yield dict(
            commit_id=ctx["head"],
            event="REQUEST_CHANGES" if blocking and i == 1 else "COMMENT",
            body=_marker(ctx, agent, i) + "\n" + body,
            comments=[_finding_comment(f, agent)
                      for f in doc["findings"] if f["line"] > 0][:MAX_INLINE]
            if i == 1 else [])


def _reviews(ctx):
    """Read all pages, with a cap that errors rather than losing history."""
    endpoint = f"/repos/{ctx['repo']}/pulls/{ctx['pr']}/reviews"
    out = []
    for page in range(1, 51):
        rows = _require("GET", f"{endpoint}?per_page=100&page={page}")
        if not isinstance(rows, list):
            raise ValueError("invalid GitHub review list")
        out.extend(rows)
        if len(rows) < 100:
            return out
    raise RuntimeError("review history exceeds 5000 entries; manual cleanup required")


def _owned(review):
    user = review.get("user") or {}
    return all(user.get(k) == v for k, v in BOT.items())


def _dismiss_stale_blocks(ctx, agent, reviews):
    """Only a completed PASS may withdraw this bot/reviewer's older objections."""
    for review in reviews:
        body = (review.get("body") or "").split("\n", 1)[0]
        match = MARKER.fullmatch(body)
        if not (_owned(review) and review.get("state") == "CHANGES_REQUESTED" and match):
            continue
        repo, pr, reviewer, head, run, attempt, part = match.groups()
        # A FAIL stays with its revision: re-running the SAME commit until the
        # model passes must not withdraw it. A re-run may clear only its own
        # incomplete review (BLOCKED_ERROR: a timeout, a refused call). A PASS on
        # a newer head supersedes either; a person can always dismiss one.
        shown = re.search(r": \*\*([A-Z_]+)\*\*\n", review.get("body") or "")
        retry_of_error = shown is not None and shown.group(1) == "BLOCKED_ERROR"
        if (repo != ctx["repo"] or pr != ctx["pr"] or reviewer != _reviewer_id(agent)
                or review.get("commit_id") != head or part != "1"
                or (head == ctx["head"] and not retry_of_error)
                or (int(run), int(attempt)) >= (int(ctx["run"]), int(ctx["attempt"]))):
            continue
        if head != ctx["head"]:
            # Only a real forward revision supersedes a block: the blocked
            # commit must be an ancestor of this head, and files must differ.
            # A detour commit, a reset, or an empty commit cannot withdraw it.
            compared = _require("GET", f"/repos/{ctx['repo']}/compare/{head}...{ctx['head']}")
            if compared.get("status") != "ahead" or not compared.get("files"):
                continue
        _current(ctx)
        _require("PUT", f"/repos/{ctx['repo']}/pulls/{ctx['pr']}/reviews/{int(review['id'])}"
                 "/dismissals",
                 {"message": f"This bot's {agent.name} objection is superseded by a "
                             f"completed PASS on {ctx['head']}. No approval is granted."})
        print(f"Dismissed own superseded review {int(review['id'])}")


def publish(ctx, report, rules_path):
    """Publish deterministic payloads; no model API or PR code runs in this job."""
    checked = validate_report(report, ctx, rules_path)
    _current(ctx)
    reviews = _reviews(ctx)
    # Validate/render ALL output before the first write.
    planned = [(agent, row, list(review_payloads(ctx, report, agent, row)))
               for agent, row in checked]
    if any(len(p["body"].encode()) > 60000 for _, _, ps in planned for p in ps):
        raise ValueError("a review body exceeds the publication limit; no partial output posted")
    endpoint = f"/repos/{ctx['repo']}/pulls/{ctx['pr']}/reviews"
    for agent, row, payloads in planned:
        for payload in payloads:
            marker = payload["body"].split("\n", 1)[0]
            state = "CHANGES_REQUESTED" if payload["event"] == "REQUEST_CHANGES" else "COMMENTED"
            existing = [r for r in reviews if _owned(r)
                        and r.get("commit_id") == ctx["head"]
                        and r.get("body", "").split("\n", 1)[0] == marker
                        and r.get("state") == state]
            if existing:
                if any(r["body"] != payload["body"] for r in existing):
                    raise ValueError("conflicting review already exists for this run")
                continue
            _current(ctx)
            status, response = _gh("POST", endpoint, payload)
            if status == 422 and payload["comments"]:
                # Body already includes ALL messages and suggested code.
                _current(ctx)
                status, response = _gh("POST", endpoint, {**payload, "comments": []})
            if not 200 <= status < 300:
                raise RuntimeError(f"review publication failed (HTTP {status}); rerun required")
            if not (_owned(response) and response.get("commit_id") == ctx["head"]
                    and response.get("body") == payload["body"] and response.get("state") == state):
                raise RuntimeError("GitHub did not confirm the expected bot review")
            print(f"Posted review {int(response['id'])} for {ctx['head']}")
        # ADVISORY_ERROR is not PASS: missing evidence must never clear a block.
        if row["result"]["verdict"] == "PASS":
            _dismiss_stale_blocks(ctx, agent, reviews)
    _current(ctx)
    # A FAIL stays with its commit, so a re-run that passes must not turn the
    # check green while an earlier run's block on this head is still open.
    held = sorted({agent.name for agent, _ in checked for review in reviews
                   if _open_fail(review, ctx, agent)})
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        summary = "\n\n".join(p["body"] for _, _, ps in planned for p in ps)
        if held:
            summary += (f"\n\n**Still blocked:** an earlier blocking review by "
                        f"{', '.join(held)} for this commit is open. Push a revision, "
                        f"or have a maintainer dismiss it.")
        pathlib.Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(summary)
    if held:
        print(f"Earlier blocking review(s) for {ctx['head']} still open: {', '.join(held)}")
    return int(bool(held) or any(row["result"]["verdict"] in {"FAIL", "BLOCKED_ERROR"}
                                 for _, row in checked))


def _open_fail(review, ctx, agent) -> bool:
    """This bot's undismissed FAIL for this head from this seat. A BLOCKED_ERROR
    is left out: a re-run may clear its own incomplete review (see above)."""
    match = MARKER.fullmatch((review.get("body") or "").split("\n", 1)[0])
    if not (match and _owned(review) and review.get("state") == "CHANGES_REQUESTED"):
        return False
    repo, pr, reviewer, head, _, _, part = match.groups()
    shown = re.search(r": \*\*([A-Z_]+)\*\*\n", review.get("body") or "")
    return (repo == ctx["repo"] and pr == ctx["pr"] and reviewer == _reviewer_id(agent)
            and head == ctx["head"] and review.get("commit_id") == ctx["head"]
            and part == "1" and not (shown and shown.group(1) == "BLOCKED_ERROR"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["guard", "analyze", "publish"])
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--rules", default=os.environ.get("REVIEWER_RULES", ".reviewer.yaml"))
    parser.add_argument("--report", default="review-report.json")
    args = parser.parse_args()
    try:
        ctx = context()
        if args.mode == "guard":
            guard(ctx, args.repo_root)
            print("Context guard passed; credentialed checks may run for this revision.")
        elif args.mode == "analyze":
            report = analyze(ctx, args.repo_root, args.rules)
            validate_report(report, ctx, args.rules)
            encoded = json.dumps(report, indent=2).encode()
            if len(encoded) > MAX_REPORT_BYTES:
                raise ValueError("report exceeds 2 MB; refusing partial publication")
            pathlib.Path(args.report).write_bytes(encoded)
            print("Analysis report written; review status is decided by the publishing job.")
        else:
            path = pathlib.Path(args.report)
            if path.stat().st_size > MAX_REPORT_BYTES:
                raise ValueError("report exceeds 2 MB")
            return publish(ctx, scrub(json.loads(path.read_text())), args.rules)
        return 0
    except Exception as exc:
        # Do not echo model-controlled exception strings as workflow commands.
        detail = _text(type(exc).__name__ + ": " + str(exc)).replace("\n", " ")
        message = f"Review {args.mode} failed: {detail}"
        print(message, file=sys.stderr)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                summary.write("\n\n**Review unavailable / check failed.** " + message + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
