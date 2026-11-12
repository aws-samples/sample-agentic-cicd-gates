"""Data API for the agentic gates operator dashboard.

Serves the built Cloudscape SPA and GET /api/snapshot — a consolidated view
of a commit's journey: both CodePipelines, the panel findings, the GitHub PR
surface, and a feed of timestamped events reconstructed statelessly from the
sources. Drill-down params: ?commit=<sha> pins the board to one revision
(historical stage states + that commit's findings); ?pr=<n> pins the PR
widget. While a review is running, per-agent progress streams out of the
CodeBuild log (personas finish sequentially and print VERDICT lines).

Read-only. GitHub is read with ETag conditional requests (anonymously unless a
read-only token is configured). AWS calls sit behind a short TTL cache keyed by
the drill-down params.

Access control: the HTTP API's JWT authorizer (Amazon Cognito) guards every
/api route. This handler also refuses any /api request that arrives without
verified JWT claims, so a misconfigured route fails closed. The SPA shell and
GET /auth-config are public; they carry no account data.
"""
from __future__ import annotations

import json
from datetime import datetime
import mimetypes
import os
import pathlib
import re
import time
import urllib.error
import urllib.request
from urllib.parse import quote

import boto3
from botocore.config import Config
from evidence import (pages, IncompleteEvidence, evidence, report_state, matches_execution,
                      has_execution_identity, matches_build, panel_from_policy, agent_review_history)
from health import HealthReader

REGION = os.environ.get("AWS_REGION") or "us-west-2"
def _tiers(sfx: str = "") -> tuple[str, str, str]:
    """The three pipeline names for one repo's trio."""
    return (f"agentic-gates-tier1{sfx}", f"agentic-gates-tier2{sfx}",
            f"agentic-gates-tier3{sfx}")


# Matches either trio's review build id ("agentic-gates-tier1-review:<id>" and
# "agentic-gates-tier1-road-review:<id>"). A startswith on the artifact's name
# silently stopped finding the road's in-flight review build.
REVIEW_BUILD_RE = re.compile(r"agentic-gates-tier1(-[a-z0-9]+)?-review:")
def _tier2_log(sfx: str = "") -> str:
    return f"/aws/lambda/agentic-gates-tier2{sfx}-gate"


def _tier3_log(sfx: str = "") -> str:
    return f"/aws/codebuild/agentic-gates-tier3-kiro{sfx}"


def _review_log(sfx: str = "") -> str:
    return f"/aws/codebuild/agentic-gates-tier1{sfx}-review"
# The board can watch either side of the split, because the same panel reviews
# both. `tiers` records which one the deploy pipelines actually ship: the road
# is gated on its pull requests but is not deployed by these pipelines, and
# showing empty tier cards for it would imply a failure rather than a boundary.
# Both repositories run the SAME trio of deploy tiers, and both trios deploy
# something: the artifact ships the site, the road ships this board. Each trio's
# physical names carry the repo's suffix. `deploy_target` is what the selector
# says out loud, so the claim is checkable rather than asserted.
# OWNER/NAME of each GitHub repository, from CDK context (artifact_repo,
# gates_repo). Empty means "not configured": the PR panel says so.
REPOS = [
    {"key": "artifact", "repo": os.environ.get("ARTIFACT_REPO", ""),
     "label": "Artifact — THE FALL OF TROY", "tiers": True,
     "suffix": "", "deploys": True, "deploy_target": "the site",
     "deploy_service": "AWS CodeDeploy", "health_stack": "agentic-gates-demo-app"},
    {"key": "road", "repo": os.environ.get("GATES_REPO", ""),
     "label": "The paved road itself", "tiers": True,
     "suffix": "-road", "deploys": True, "deploy_target": "this board",
     "deploy_service": "CDK in AWS CodeBuild", "health_kind": "codebuild",
     "deploy_action": "DeployDashboard", "deploy_project": "agentic-gates-tier1-road-dashboard-deploy"},
]
DEFAULT_REPO = REPOS[0]["key"]


def _repo_cfg(key: str | None) -> dict:
    return next((r for r in REPOS if r["key"] == key), REPOS[0])
GH_API = "https://api.github.com"
# Optional link to the deployed application (-c site_url).
SITE = os.environ.get("SITE_URL", "")
# This dashboard's own base URL; the road's deployable is this board.
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "")
SNAPSHOT_TTL = 2.5

# The packaged policy is the only source of reviewer names and capabilities.
# Missing metadata stays unavailable; no hardcoded reviewer list can mask it.
try:
    PANEL_POLICY = json.loads(pathlib.Path(__file__).with_name("panel_policy.json").read_text())
    PANEL_META = panel_from_policy(PANEL_POLICY)
except (OSError, ValueError, TypeError, KeyError):
    PANEL_POLICY = {"source": "Policy metadata unavailable"}
    PANEL_META = []
PERSONAS = [m["name"] for m in PANEL_META]

_cp_config = Config(connect_timeout=2, read_timeout=4,
                    retries={"mode": "standard", "total_max_attempts": 2})
_cp = boto3.client("codepipeline", region_name=REGION, config=_cp_config)
_s3 = boto3.client("s3", region_name=REGION)
_logs = boto3.client("logs", region_name=REGION)
_cfn = boto3.client("cloudformation", region_name=REGION)
_health_config = Config(connect_timeout=2, read_timeout=4, retries={"max_attempts": 1})
_health = HealthReader(_cfn,
    boto3.client("codedeploy", region_name=REGION, config=_health_config),
    boto3.client("cloudwatch", region_name=REGION, config=_health_config),
    boto3.client("lambda", region_name=REGION, config=_health_config), REGION)

_cache: dict = {}
_etags: dict = {}
_gh_errors: dict = {}
_gh_cache: dict = {}          # url -> (bucket, body) — anonymous GH is 60/hr
_bucket: dict = {}
_last_errors: dict = {}

WEB_ROOT = pathlib.Path(__file__).parent / "web"
# Seat names come from PANEL_META, never a hand-maintained list: a 4th seat
# (Aria) was added to the panel and silently vanished from this view because
# the alternation still read (Sentinel|Vector|Atlas).
_SEATS = "|".join(re.escape(m["name"]) for m in PANEL_META) or r"(?!)"
# PR reports use authenticated v2 publisher markers in evidence.py.
# Derived from the panel config, NOT typed out. This line hardcoded three retired
# codenames while the gate logs print all four current seat names, so it matched
# nothing: every seat stayed "pending" for the whole run and the live per-seat
# progress operators watch never moved. The panel-mirror check in the
# deterministic lane guards PANEL_META against .reviewer.yaml; nothing was
# guarding a regex that had the seat names baked in.
LOG_VERDICT_RE = re.compile(
    rf"\[({_SEATS})\]\s+VERDICT=(\w+)\s+blocking=(\d+)\s+discovered=(\d+)")


_TOKEN_CACHE: dict = {}


def _gh_token() -> str:
    """A read-only GitHub credential, if one is configured. Anonymous otherwise.

    Resolution order, most direct first:
      1. GITHUB_TOKEN — set directly (local runs, or a deployer who prefers it)
      2. GITHUB_TOKEN_SECRET — the NAME of a Secrets Manager secret, fetched once
         per container and cached. The value never appears in the function's
         configuration, unlike a CloudFormation dynamic reference, which resolves
         at deploy time and leaves the plaintext readable to anyone who can call
         GetFunctionConfiguration.
      3. Nothing — read anonymously. The board still works for public repos; for
         private ones GitHub answers 404 and that is reported rather than shown
         as an empty pull-request panel.

    Any failure falls back to anonymous rather than breaking the board: a missing
    or unreadable credential should degrade the PR surface, not the whole page.
    """
    direct = os.environ.get("GITHUB_TOKEN", "").strip()
    if direct:
        return direct
    name = os.environ.get("GITHUB_TOKEN_SECRET", "").strip()
    if not name:
        return ""
    if "v" in _TOKEN_CACHE:
        return _TOKEN_CACHE["v"]
    try:
        val = boto3.client("secretsmanager").get_secret_value(
            SecretId=name).get("SecretString", "").strip()
    except Exception as exc:  # noqa: BLE001
        _last_errors["github_token"] = (
            f"could not read the GitHub token from secret {name!r} "
            f"({type(exc).__name__}) — falling back to anonymous reads")
        val = ""
    _TOKEN_CACHE["v"] = val
    return val


def _gh(path: str, ttl: float = 0.0):
    """Read GitHub unauthenticated, politely — and coherently.

    Anonymous GitHub allows ~60 requests/hour per IP, and every open board
    polls for a snapshot every few seconds — so every call is served from a
    TTL cache and conditional (ETag) otherwise. A rate-limit response serves
    the last good body and is reported in `degraded` rather than silently
    looking like "no data".

    The cache is aligned to shared time buckets rather than to each container's
    own clock. A per-container TTL means two warm containers refresh at
    different moments, so the same URL can answer differently depending on
    which one takes the request — that is visible as the board flipping between
    seeing a new PR and not seeing it. Bucketing on floor(now / ttl) makes
    every container expire on the same wall-clock boundary, so any two
    containers serving inside one bucket return the same body. Total upstream
    calls are unchanged; they are merely aligned instead of staggered.
    """
    url = f"{GH_API}{path}"
    bucket = int(time.time() // ttl) if ttl else None
    hit = _gh_cache.get(url)
    if hit and ttl and hit[0] == bucket:
        return hit[1]
    etag, cached = _etags.get(url, (None, None))
    # A read-only token when one is configured. Both gated repos are PRIVATE, and
    # anonymous GitHub answers 404 for them - which arrives as "no pull requests"
    # rather than "cannot see this repo" unless it is reported. Set GITHUB_TOKEN
    # (from Secrets Manager, like the Tier 3 harness key) to restore the PR
    # surface for private repos; the board works without it for public ones.
    token = _gh_token()
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "agentic-gates-dashboard",
        **({"Authorization": f"Bearer {token}"} if token else {}),
        **({"If-None-Match": etag} if etag else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = json.loads(r.read() or b"null")
            if r.headers.get("ETag"):
                _etags[url] = (r.headers["ETag"], body)
            _gh_cache[url] = (bucket, body)
            _last_errors.pop("github", None)
            _gh_errors.pop(url, None)
            return body
    except urllib.error.HTTPError as e:
        if e.code == 304:
            # Re-stamp with the CURRENT bucket, not a timestamp: the key is
            # compared against a bucket, so a timestamp here would never match
            # and every request would re-hit a rate-limited GitHub.
            _gh_cache[url] = (bucket, cached)
            _gh_errors.pop(url, None)
            return cached
        _gh_errors[url] = f"GitHub HTTP {e.code} for {path.split('?')[0]}"
        if e.code == 404 and "/repos/" in path:
            # owner/name is always the first two segments; splitting on known
            # suffixes ("/pulls", "/commits") silently garbled any other path.
            repo = "/".join(path.split("/repos/", 1)[1].split("?")[0].split("/")[:2])
            _last_errors["github"] = (
                f"GitHub returned 404 for {repo} — it is private and this board is "
                f"reading anonymously, so its pull requests cannot be shown. Configure "
                f"GITHUB_TOKEN (read-only) to restore the PR surface.")
            return hit[1] if hit else cached
        if e.code == 403 and _gh_token():
            # With a credential present, 403 is almost always a missing
            # fine-grained permission rather than throttling - and calling it a
            # rate limit sends the reader to fix the wrong thing.
            _last_errors["github"] = (
                f"GitHub refused {path.split('?')[0]} with 403 while authenticated — the "
                f"token is missing a permission for it. Per-lane check status needs "
                f"'Actions: read' in addition to 'Contents: read' and "
                f"'Pull requests: read'. Not 'Checks: read' — that permission is "
                f"GitHub-App-only and cannot be granted to a fine-grained PAT.")
        elif e.code in (403, 429):
            _last_errors["github"] = ("GitHub rate limit reached (anonymous, 60/hr) — "
                                      "PR panel is showing the last good data")
        else:
            _last_errors["github"] = f"GitHub HTTP {e.code}"
        return hit[1] if hit else cached
    except Exception as exc:  # noqa: BLE001 — the dashboard must never wedge
        _last_errors["github"] = f"{type(exc).__name__}"
        _gh_errors[url] = str(exc)
        return hit[1] if hit else cached


def _console(pipeline: str, execution_id: str | None = None) -> str:
    view = f"executions/{quote(execution_id, safe='')}/visualization" if execution_id else "view"
    return (f"https://{REGION}.console.aws.amazon.com/codesuite/codepipeline/"
            f"pipelines/{quote(pipeline, safe='')}/{view}?region={REGION}")



def _kv(*pairs) -> list:
    """Ordered label/value pairs for a feed item's hover detail.

    Empty values are dropped so a tooltip never shows "Blocking: None" - an
    absent value and a zero are different facts and only one is worth screen
    space.
    """
    return [[k, str(v)] for k, v in pairs if v not in (None, "", [])]


def _commit_from_summary(summary: str | None, sha: str | None):
    try:
        return {"sha": sha,
                "message": json.loads(summary or "{}").get("CommitMessage", "").split("\n")[0]}
    except Exception:  # noqa: BLE001
        return {"sha": sha, "message": (summary or "")[:120]}


def _execution_summaries(name: str, target_sha: str | None = None, max_pages: int = 40,
                         target_execution: str | None = None):
    """Newest first: stop once the requested revision's newest run is known.

    Do not cache SHA-to-execution identity: a newer retry can use the same SHA.
    A missing revision requires complete pagination; a partial read is an error.
    """
    token, seen, rows = None, set(), []
    for _ in range(max_pages):
        response = _cp.list_pipeline_executions(
            pipelineName=name, maxResults=100 if target_sha or target_execution else 10,
            **({"nextToken": token} if token else {}))
        batch = response.get("pipelineExecutionSummaries", [])
        rows.extend(batch)
        if not (target_sha or target_execution) or any(
                row.get("pipelineExecutionId") == target_execution if target_execution else
                (row.get("sourceRevisions") or [{}])[0].get("revisionId") == target_sha
                for row in batch):
            return rows
        token = response.get("nextToken")
        if not token:
            return rows
        if token in seen:
            raise IncompleteEvidence("execution pagination token repeated")
        seen.add(token)
    raise IncompleteEvidence(f"execution history exceeds {max_pages} pages")


def _commits(name: str = "agentic-gates-tier1", target_sha: str | None = None,
             target_execution: str | None = None, distinct: bool = False):
    """Recent revisions through the pipeline — the drillable commit list."""
    try:
        rows = _execution_summaries(name, target_sha, target_execution=target_execution)
        _last_errors.pop(f"{name}_executions", None)
    except Exception as exc:  # noqa: BLE001
        _last_errors[f"{name}_executions"] = f"{type(exc).__name__}: {exc}"
        return []
    out, seen = [], set()
    for e in rows:
        rev = (e.get("sourceRevisions") or [{}])[0]
        sha = rev.get("revisionId")
        identity = e.get("pipelineExecutionId") if distinct else sha
        if target_execution and e.get("pipelineExecutionId") == target_execution and not sha:
            _last_errors[f"{name}_executions"] = "Requested execution has no source revision"
            return []
        if not sha or not identity or identity in seen:
            continue
        seen.add(identity)
        out.append({**_commit_from_summary(rev.get("revisionSummary"), sha),
                    "status": e.get("status"),
                    "execution_id": e.get("pipelineExecutionId"),
                    "started": e["startTime"].isoformat() if e.get("startTime") else None})
    return out


def _action_time(value):
    """Only timezone-bearing service timestamps can order distinct attempts."""
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def _latest_action_attempt(attempts, live_id=None):
    if len(attempts) == 1:
        return attempts[0]
    starts = [_action_time(a.get("startTime")) for a in attempts]
    if all(t is not None for t in starts):
        newest = max(starts)
        matches = [a for a, started in zip(attempts, starts) if started == newest]
        if len(matches) == 1:
            return matches[0]
    # A live ID is usable only if it identifies a row already scoped to this
    # execution. The latest action from another execution cannot break a tie.
    matches = [a for a in attempts if live_id and a.get("actionExecutionId") == live_id]
    return matches[0] if len(matches) == 1 else None


def _pipeline_view(name: str, execution_id: str | None, feed: list, failures: list):
    """One execution's stages — never a mix of runs.

    get_pipeline_state returns each stage's *latest* execution independently,
    so when runs stack it reports e.g. "Approval InProgress" (this run) beside
    "Deploy Succeeded" (a previous run). That is accurate per-stage and
    misleading as a whole, so the skeleton (stage/action order) comes from
    get_pipeline_state and every status is overlaid from the ONE execution
    under inspection. Actions that run has not reached read as NotStarted.
    """
    review_build, approval = None, None
    try:
        st = _cp.get_pipeline_state(name=name)
    except Exception as exc:  # noqa: BLE001
        return ({"name": name, "stages": [], "error": str(exc),
                 "console": _console(name, execution_id)}, None, None)

    detail: dict = {}
    order_errors = {}
    actions_error = None
    rows = []
    review_attempts = []
    attempt_issues = []
    if execution_id:
        try:
            rows = pages(_cp.list_action_executions, "actionExecutionDetails",
                pipelineName=name, filter={"pipelineExecutionId": execution_id},
                maxResults=100)
            grouped = {}
            live_ids = {(s["stageName"], a["actionName"]): (a.get("latestExecution") or {}).get("actionExecutionId")
                        for s in st.get("stageStates", []) for a in s.get("actionStates", [])}
            for d in rows:
                if d.get("pipelineExecutionId") not in (None, execution_id):
                    raise IncompleteEvidence("Action record belongs to another pipeline execution")
                grouped.setdefault((d["stageName"], d["actionName"]), []).append(d)
            for action_key, attempts in grouped.items():
                chosen = _latest_action_attempt(attempts, live_ids.get(action_key))
                if chosen is not None:
                    detail[action_key] = chosen
                else:
                    order_errors[action_key] = (f"Latest attempt unavailable for {' / '.join(action_key)}: "
                                                "missing or tied start timestamps and no matching latest action ID")
            _last_errors.pop(f"actions:{name}", None)
        except Exception as exc:  # noqa: BLE001
            rows, detail = [], {}
            actions_error = f"{type(exc).__name__} listing action executions: {exc}"
            _last_errors[f"actions:{name}"] = actions_error

    stages = []
    for s in st.get("stageStates", []):
        actions, seen = [], []
        for a in s.get("actionStates", []):
            d = detail.get((s["stageName"], a["actionName"]))
            live = a.get("latestExecution") or {}
            # Live fallback belongs to this action attempt only, never a later
            # execution of the same stage or a retry of the same revision.
            if not (d and d.get("actionExecutionId") and
                    d["actionExecutionId"] == live.get("actionExecutionId")):
                live = {}
            if s["stageName"] == "AutomatedGates" and a["actionName"] == "Review":
                for attempt in rows:
                    if attempt.get("stageName") != "AutomatedGates" or attempt.get("actionName") != "Review":
                        continue
                    result = (attempt.get("output") or {}).get("executionResult") or {}
                    is_current = bool(d and (
                        attempt.get("actionExecutionId") == d["actionExecutionId"]
                        if d.get("actionExecutionId") else attempt == d))
                    build_id = result.get("externalExecutionId") or (
                        live.get("externalExecutionId") if is_current else None)
                    if not _valid_review_build(build_id, name):
                        attempt_issues.append("Review action has no valid build ID: " +
                                              str(attempt.get("actionExecutionId") or "ID unavailable"))
                        continue
                    when = lambda value: value.isoformat() if hasattr(value, "isoformat") else value
                    status = attempt.get("status") or "Unavailable"
                    review_attempts.append({key: value for key, value in {
                        "build_id": build_id, "action_execution_id": attempt.get("actionExecutionId"),
                        "status": status, "started": when(attempt.get("startTime")),
                        "ended": when(attempt.get("lastUpdateTime")) if status in ("Succeeded", "Failed", "Abandoned") else None,
                        "url": result.get("externalExecutionUrl") or _console(name, execution_id),
                        "is_current": is_current}.items() if value is not None})
            if d:                                        # this execution's record
                status = d.get("status") or "NotStarted"
                result = (d.get("output") or {}).get("executionResult") or {}
                reason = result.get("externalExecutionSummary")
                # `output.executionResult` is only populated once the action
                # FINISHES, so mid-run this id is None - and it is the id that
                # identifies the review build. That is why per-seat live progress
                # never appeared during a run: review_build stayed None for the
                # whole window and _panel_progress returned None on its first
                # line. get_pipeline_state does carry the id while InProgress
                # (verified against a live run), so fall back to it. The pinned
                # record still wins when present, so a newer run cannot overwrite
                # this execution's history.
                ext_id = result.get("externalExecutionId") or live.get("externalExecutionId")
                when = d.get("lastUpdateTime") or d.get("startTime")
                url = (result.get("externalExecutionUrl")
                       or live.get("externalExecutionUrl") or _console(name, execution_id))
                token = live.get("token") if status == "InProgress" else None
            else:
                status, reason, ext_id, when, url, token = (
                    "Unavailable" if actions_error or (s["stageName"], a["actionName"]) in order_errors else "NotStarted",
                    None, None, None, _console(name, execution_id), None)

            actions.append({"name": a["actionName"], "status": status,
                            "action_execution_id": d.get("actionExecutionId") if d else None,
                            "provider": (d.get("input", {}).get("actionTypeId", {}).get("provider")
                                         if d else None),
                            "when": when.isoformat() if hasattr(when, "isoformat") else when,
                            "url": url,
                            "external_id": ext_id,
                            "started": str(d.get("startTime") or "") if d else None,
                            "reason": reason if status == "Failed" else None})
            seen.append(status)

            if status == "InProgress" and a["actionName"] == "Review" \
                    and REVIEW_BUILD_RE.match(ext_id or ""):
                review_build = ext_id.split(":", 1)[1]
            if status == "InProgress" and "approv" in a["actionName"].lower():
                approval = {"stage": s["stageName"], "action": a["actionName"],
                            "url": url, "since": actions[-1]["when"],
                            "token_present": bool(token)}
            if status == "Failed":
                failures.append({
                    "pipeline": name, "stage": s["stageName"], "action": a["actionName"],
                    "reason": reason, "url": url,
                    "log": _build_log_excerpt(ext_id)})
            if actions[-1]["when"] and status in ("Succeeded", "Failed", "InProgress"):
                feed.append({"ts": actions[-1]["when"],
                             "source": name.split("-")[-1].upper(), "status": status,
                             "text": f"{s['stageName']} / {a['actionName']} {status.lower()}",
                             "url": url,
                             "detail": _kv(("Pipeline", name), ("Stage", s["stageName"]),
                                           ("Action", a["actionName"]), ("Status", status),
                                           ("Completed", actions[-1]["when"]),
                                           ("Reason", reason))})

        stage_status = ("Unavailable" if "Unavailable" in seen
                        else "Failed" if "Failed" in seen
                        else "InProgress" if "InProgress" in seen
                        else "Succeeded" if seen and all(x == "Succeeded" for x in seen)
                        else "NotStarted")
        stages.append({"name": s["stageName"], "status": stage_status, "actions": actions})

    if order_errors:
        _last_errors[f"actions:{name}"] = "; ".join(order_errors.values())
    view_error = actions_error or "; ".join(order_errors.values()) or None
    review_attempts.sort(key=lambda a: (a["is_current"], _action_time(a.get("started")) or float("-inf"),
                                       a.get("action_execution_id", ""), a["build_id"]), reverse=True)
    attempt_state = (evidence("unavailable", view_error or "; ".join(attempt_issues))
                     if view_error or attempt_issues else
                     evidence("available", "Review action history read for selected execution")
                     if execution_id else evidence("missing", "No selected execution"))
    return ({"name": name, "stages": stages, "console": _console(name, execution_id),
             "execution_id": execution_id, "error": view_error,
             "review_attempts": review_attempts, "review_attempts_evidence": attempt_state}, review_build, approval)


def _valid_review_build(build_id, pipeline_name=None):
    if not isinstance(build_id, str) or not re.fullmatch(
            r"agentic-gates-tier1(?:-[a-z0-9]+)?-review:[A-Za-z0-9-]+", build_id):
        return False
    return not pipeline_name or build_id.startswith(f"{pipeline_name}-review:")


def _build_log_excerpt(external_id: str | None, keep: int = 10) -> list[str]:
    """The meaningful tail of a failed CodeBuild action's log.

    A red stage is useless without the reason, and the reason lives in the
    build log (e.g. "THREAT-MODEL GATE: FAIL - infra changed but
    threat-model/ was untouched"). external_id is "<project>:<buildId>".
    """
    # CloudFormation external IDs can be console URLs containing a colon.
    # They are not CodeBuild projects and must not trigger a fabricated log read.
    if not isinstance(external_id, str) or not re.fullmatch(
            r"agentic-gates-[a-z0-9-]+:[A-Za-z0-9-]+", external_id):
        return []
    project, build_id = external_id.split(":", 1)
    try:
        events = pages(_logs.filter_log_events, "events",
            logGroupName=f"/aws/codebuild/{project}",
            logStreamNames=[build_id], limit=1000)
    except Exception as exc:  # noqa: BLE001 — never wedge, but never hide either
        _last_errors["logs"] = f"{type(exc).__name__} reading /aws/codebuild/{project}"
        return [f"(gate output unavailable: {type(exc).__name__} — "
                f"the dashboard could not read /aws/codebuild/{project})"]
    _last_errors.pop("logs", None)
    lines = [e["message"].rstrip() for e in events if e.get("message")]
    keys = ("FAIL", "BLOCKING", "Traceback", "Error", "error:", "exit status",
            "GATE:", "VERDICT", "advisory", "blocking")
    # The gate's own output is the useful part; CodeBuild's [Container] lines
    # are only a fallback when the gate said nothing.
    signal = [l for l in lines if not l.startswith("[Container]")]
    hits = []
    for i, l in enumerate(signal):
        if any(k in l for k in keys):
            hits.append(l)
            # A gate states its verdict on one line and its REASONS on the
            # following lines ("  - infra changed but threat-model/ was
            # untouched"). Those continuation lines carry no keyword, so take
            # them explicitly — otherwise the banner shows "GATE: FAIL" and
            # never says why.
            for cont in signal[i + 1:i + 6]:
                stripped = cont.strip()
                if stripped.startswith(("-", "*", "•")) or cont.startswith(("  ", "\t")):
                    hits.append(cont)
                else:
                    break
    if not hits:
        hits = [l for l in lines if any(k in l for k in keys)]
    seen, deduped = set(), []
    for l in hits:
        if l not in seen:
            seen.add(l)
            deduped.append(l)
    return (deduped or signal or lines)[-keep:]


def _reports_bucket(sfx: str = "") -> str | None:
    """The reports bucket for one trio, read from its Tier 1 stack output.

    Each trio owns a CFN-generated bucket, so this used to scan s3:ListBuckets
    by prefix - which needs s3:ListAllMyBuckets on Resource "*", because that
    action has no resource-level form. The road's own IAM-002 gate blocked that
    (correctly: a wildcard resource in a stack not named *Sandbox*). Tier 1
    already publishes ReportsBucketName, so read the output instead and scope
    the permission to those two stack ARNs. Cached per suffix - a single slot
    served the road the artifact's bucket.
    """
    if sfx in _bucket:
        return _bucket[sfx]
    stack = f"Tier1PipelineStack{'Road' if sfx == '-road' else ''}"
    try:
        outs = _cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
        for o in outs:
            if o["OutputKey"] == "ReportsBucketName":
                _bucket[sfx] = o["OutputValue"]
                return o["OutputValue"]
    except Exception as exc:  # noqa: BLE001
        _last_errors["reports_bucket"] = (
            f"could not read ReportsBucketName from {stack} ({type(exc).__name__})")
    return None


def _review_action(pipeline):
    return next((a for stage in pipeline.get("stages", []) for a in stage["actions"]
                 if a["name"] in ("Review", "KiroReview", "AgentReview")), None)


def _report_in_events(events):
    """Read compact or pretty-printed reports, including across log pages."""
    text = "\n".join(ev.get("message", "") for ev in events)
    candidates = []
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            candidate, _ = decoder.raw_decode(text, match.start())
        except ValueError:
            continue
        if (isinstance(candidate, dict) and
                all(k in candidate for k in ("verdict", "agents", "findings", "stats"))):
            candidates.append(candidate)
    return candidates


def _build_report(external_id):
    if not external_id or ":" not in external_id:
        return None
    project, stream = external_id.split(":", 1)
    events = pages(_logs.filter_log_events, "events",
                   logGroupName=f"/aws/codebuild/{project}",
                   logStreamNames=[stream], limit=1000)
    return next(reversed(_report_in_events(events)), None)


def _execution_findings(tier, pipeline, sha, sfx=""):
    """Only expose reports attributable to the selected pipeline execution.

    Build-specific archives or exact build streams bind in-place action retries.
    Mutable execution convenience objects require affirmative build identity.
    """
    execution_id = pipeline.get("execution_id")
    action = _review_action(pipeline)
    ctx = {"execution_id": execution_id, "revision": sha}
    if pipeline.get("error"):
        return None, evidence("unavailable", pipeline["error"], **ctx)
    if not execution_id or not action or action.get("status") == "NotStarted":
        return None, evidence("not_reviewed", "No review action for this revision", **ctx)
    if action.get("status") == "InProgress":
        return None, evidence("reviewing", "Review action in progress", **ctx)
    ext = action.get("external_id")
    ctx["build_id"] = ext
    try:
        doc = None
        if tier == "tier1":
            if not _valid_review_build(ext, pipeline.get("name")):
                return None, evidence("unavailable", "Review action build identity unavailable", **ctx)
            bucket = _reports_bucket(sfx)
            retrieval_issue = None if bucket else "Reports bucket could not be read"
            build_key = f"executions/{execution_id}/builds/{ext}/findings.json"
            keys = (build_key, f"executions/{execution_id}/findings.json") if bucket else ()
            for key in keys:
                try:
                    obj = _s3.get_object(Bucket=bucket, Key=key)
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code")
                    if code in ("NoSuchKey", "404", "NotFound"):
                        continue
                    retrieval_issue = f"Report retrieval failed: {code or type(exc).__name__}"
                    continue
                candidate = json.loads(obj["Body"].read())
                # Only the build-specific archive is immutable across stage retries.
                bound = matches_execution(candidate, execution_id, ext)
                has_identity = has_execution_identity(candidate)
                if ((key == build_key and has_identity and not bound)
                        or (key != build_key and not matches_build(candidate, execution_id, ext))):
                    retrieval_issue = "Report cannot be bound to this exact review build (legacy or mismatched provenance)"
                    continue
                doc = candidate
                ctx["source"] = f"s3://{bucket}/{key}"
                ctx["recorded_at"] = str(obj.get("LastModified") or "")
                break
            if doc is None:
                # The review CLI also prints the full report. An exact build
                # stream can recover evidence even when the SHA object expired
                # or was overwritten by a later retry.
                doc = _build_report(ext)
                if doc:
                    ctx["source"] = f"CodeBuild log: {ext}"
                    if has_execution_identity(doc) and not matches_execution(doc, execution_id, ext):
                        return None, evidence("unavailable", "Log report has contradictory execution provenance", **ctx)
                elif retrieval_issue:
                    return None, evidence("unavailable", retrieval_issue, **ctx)
        else:
            if tier == "tier3" and ext and ":" in ext:
                project, stream = ext.split(":", 1)
                events = pages(_logs.filter_log_events, "events",
                               logGroupName=f"/aws/codebuild/{project}",
                               logStreamNames=[stream], limit=1000)
                bound_stream = True
            elif tier == "tier2" and action.get("started") and action.get("when"):
                from datetime import datetime
                millis = lambda t: int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp() * 1000)
                events = pages(_logs.filter_log_events, "events", logGroupName=_tier2_log(sfx),
                               startTime=millis(action["started"]), endTime=millis(action["when"]) + 1000,
                               limit=1000)
                bound_stream = False
            else:
                return None, evidence("unavailable", "No execution-bound log location", **ctx)
            for candidate in reversed(_report_in_events(events)):
                if not bound_stream and not matches_execution(candidate, execution_id, ext):
                    continue
                if bound_stream and has_execution_identity(candidate) and not matches_execution(candidate, execution_id, ext):
                    return None, evidence("unavailable", "Log report has contradictory execution provenance", **ctx)
                doc = candidate
                break
            if doc is None and tier == "tier2":
                return None, evidence("unavailable", "No report with matching execution provenance in the Lambda logs", **ctx)
        if doc is None:
            return None, evidence("missing", "No retained review report found; pipeline success is not review evidence", **ctx)
        review_input = doc.get("review_input") or {}
        revisions = [c[k] for c in (doc, review_input) for k in
                     ("revision", "source_revision", "head_revision") if c.get(k)]
        if any(r != sha for r in revisions):
            return None, evidence("unavailable", "Report revision contradicts the selected execution", **ctx)
        ctx.update({k: review_input[k] for k in
                    ("policy_origin", "policy_sha256", "baseline_revision", "baseline_kind")
                    if review_input.get(k)})
        state = report_state(doc, **ctx)
        # A partial panel cannot be painted green. Names come from config.
        if state["state"] == "passed" and not PERSONAS:
            state = evidence("unavailable", "Dashboard reviewer metadata unavailable; completeness cannot be checked", **ctx)
        elif state["state"] == "passed" and set(PERSONAS) - {a.get("name") for a in doc.get("agents", [])}:
            state = evidence("unavailable", "Report is missing configured reviewers", **ctx)
        return (None if state["state"] == "expired" else doc), state
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        return None, evidence("unavailable", f"Evidence retrieval failed: {code}", **ctx)


def _exec_for(pipeline: str, target_sha: str | None) -> str | None:
    """No matching revision means no execution, never the newest other run."""
    if not target_sha:
        return None
    return next((c["execution_id"] for c in _commits(pipeline, target_sha)
                 if c["sha"] == target_sha), None)


def _selected_review_attempt(pipeline, sha, build_id, current_report, current_evidence, sfx=""):
    """User-supplied IDs never become S3/log paths until action history binds them."""
    context = {"execution_id": pipeline.get("execution_id"), "revision": sha, "build_id": build_id}
    attempts = pipeline.get("review_attempts", [])
    attempt = next((a for a in attempts if a["build_id"] == build_id), None)
    # An ambiguous latest attempt does not invalidate an exact build whose
    # action identity is known. Failed/incomplete history reads retain no rows.
    if not pipeline.get("execution_id") or not attempt:
        reason = pipeline.get("error") or (
            (pipeline.get("review_attempts_evidence") or {}).get("reason")
            if (pipeline.get("review_attempts_evidence") or {}).get("state") in ("missing", "unavailable")
            else "Requested build is not a verified Review action of the selected execution")
        return {"build_id": build_id, "report": None,
                "evidence": evidence("unavailable", reason or "Review attempt metadata unavailable", **context)}
    if attempt["is_current"]:
        return {"build_id": build_id, "report": current_report, "evidence": current_evidence}
    historical = {"name": pipeline["name"], "execution_id": pipeline["execution_id"],
                  "stages": [{"name": "AutomatedGates", "actions": [{
                      "name": "Review", "external_id": build_id, "status": attempt["status"],
                      "started": attempt.get("started"), "when": attempt.get("ended"),
                      "url": attempt.get("url")}]}]}
    report, state = _execution_findings("tier1", historical, sha, sfx)
    return {"build_id": build_id, "report": report, "evidence": state}


def _panel_progress(review_build: str | None, feed: list, sfx: str = ""):
    """Per-agent progress while the tier1 Review action runs — personas
    finish sequentially and print '[Name] VERDICT=...' as they land."""
    state = {p: {"state": "pending"} for p in PERSONAS}
    if not review_build:
        return None
    try:
        events = pages(_logs.filter_log_events, "events",
            logGroupName=_review_log(sfx), logStreamNames=[review_build], limit=1000)
        for ev in events:
            m = LOG_VERDICT_RE.search(ev["message"])
            if m:
                name, verdict, blocking, disc = m.groups()
                state[name] = {"state": "done", "verdict": verdict,
                               "blocking": int(blocking), "discovered": int(disc)}
                feed.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                 time.gmtime(ev["timestamp"] / 1000)),
                             "source": "PANEL", "persona": name,
                             "status": "Succeeded" if verdict == "PASS" else "Failed",
                             "text": f"{name} finished mid-run: {verdict} "
                                     f"({disc} discovered, {blocking} blocking)",
                             "detail": _kv(
                                 ("Seat", name), ("Verdict", verdict),
                                 ("Discovered", disc), ("Blocking", blocking),
                                 ("Source", "streamed from the gate's own log while "
                                            "the run was still in flight"),
                             )})
        for p in PERSONAS:                       # first not-done persona is thinking
            if state[p]["state"] == "pending":
                state[p]["state"] = "running"
                break
        _last_errors.pop("panel_progress", None)
    except Exception as exc:  # noqa: BLE001 — advisory, but say so
        _last_errors["panel_progress"] = (
            f"{type(exc).__name__} reading the review log — per-agent progress unavailable")
        return None
    return {"active": True, "agents": state}


def _history_feed(names: list, feed: list, per_pipeline: int = 60) -> int:
    """Action events from PREVIOUS executions, so the timeline reaches back past
    the run currently on screen.

    The live feed is assembled from the ONE execution the board is pinned to, so
    it spans minutes - 14 events over ten minutes on a normal day, which is why
    raising the display cap alone changed nothing. list_action_executions returns
    action history ACROSS recent executions in a single call per pipeline, which
    is the cheapest way to reach back hours without walking executions one by
    one. Only fetched when asked for, because it is three extra calls.
    """
    added = 0
    for name in names:
        try:
            res = _cp.list_action_executions(pipelineName=name, maxResults=per_pipeline)
        except Exception as exc:                      # one bad pipeline must not
            _last_errors[f"history:{name}"] = (       # empty the whole timeline
                f"{type(exc).__name__} reading action history for {name}")
            continue
        for a in res.get("actionExecutionDetails", []):
            ts = a.get("lastUpdateTime") or a.get("startTime")
            if not ts:
                continue
            out = (a.get("output") or {}).get("executionResult") or {}
            when = ts.isoformat() if hasattr(ts, "isoformat") else ts
            feed.append({
                "ts": when,
                "source": name.split("-")[-1].upper(),
                "status": a.get("status"),
                # Marked so the row can say it is history rather than something
                # that just happened - a timeline that silently mixes the two
                # would make an old failure look live.
                "historic": True,
                "text": f"{a.get('stageName')} · {a.get('actionName')}: {a.get('status')}",
                "url": out.get("externalExecutionUrl"),
                "detail": _kv(
                    ("Pipeline", name),
                    ("Stage", a.get("stageName")),
                    ("Action", a.get("actionName")),
                    ("Status", a.get("status")),
                    ("Execution", a.get("pipelineExecutionId")),
                    ("Summary", out.get("externalExecutionSummary")),
                    ("Updated", when),
                )})
            added += 1
    return added


def _gh_read(path, ttl=20):
    result = _gh(path, ttl=ttl)
    if f"{GH_API}{path}" in _gh_errors or result is None:
        raise RuntimeError(_gh_errors.get(f"{GH_API}{path}", "GitHub data unavailable"))
    return result


def _gh_pages(path, key=None, ttl=20):
    out = []
    for page in range(1, 11):
        result = _gh_read(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}", ttl)
        rows = result.get(key, []) if key else result
        out.extend(rows)
        if len(rows) < 100:
            return out
    raise RuntimeError("GitHub evidence pagination limit reached")


def _pr_surface(feed, want_pr, GH_REPO, include_closed=False):
    if not GH_REPO:
        return {"open": [], "closed": [], "detail": None,
                "evidence": evidence("unavailable", "No GitHub repository is configured "
                                     "for this board (CDK context artifact_repo / gates_repo)")}
    try:
        result = _pr_surface_data(feed, want_pr, GH_REPO, include_closed)
        result["evidence"] = evidence("available", "GitHub reads completed")
        return result
    except Exception as exc:
        return {"open": [], "closed": [], "detail": None,
                "evidence": evidence("unavailable", str(exc))}


def _pr_surface_data(feed: list, want_pr: int | None, GH_REPO: str,
                include_closed: bool = False):
    # Budget: anonymous GitHub is ~60 req/hr, but a conditional request that
    # returns 304 Not Modified does NOT count against it — and every call here
    # carries an ETag. So the binding cost is the number of times the content
    # actually CHANGES, not the number of polls, and the bucket can be short
    # enough for a live board (a newly opened PR must appear on the board
    # within seconds, not within a minute and a half).
    # state=all costs the SAME single call as state=open, so showing closed pull
    # requests is a filtering question rather than a budget one. Checks are only
    # enriched for the ONE pull request selected below, so extra rows are free.
    prs = _gh_read(f"/repos/{GH_REPO}/pulls?state={'all' if include_closed else 'open'}"
                   f"&per_page=20&sort=updated&direction=desc")
    if want_pr and not any(p["number"] == want_pr for p in prs):
        prs.append(_gh_read(f"/repos/{GH_REPO}/pulls/{want_pr}"))

    def _row(pr: dict) -> dict:
        # Merged and closed-without-merging are different outcomes, so the row
        # carries the distinction as TEXT. Encoding it in colour alone is what
        # A11Y-004 forbids, and this board has already broken that rule once.
        state = ("open" if pr.get("state") == "open"
                 else "merged" if pr.get("merged_at") else "closed")
        return {"number": pr["number"], "title": pr["title"], "head": pr["head"]["sha"],
                "head_ref": pr["head"].get("ref"),
                "url": pr["html_url"], "updated": pr["updated_at"], "state": state}

    allrows = [_row(pr) for pr in prs]
    rows = [r for r in allrows if r["state"] == "open"][:8]
    closed = [r for r in allrows if r["state"] != "open"][:8]
    detail = None
    # Resolve a drill-down against CLOSED rows too: selecting one from the table
    # has to render its checks and reviews, not silently nothing. With no open
    # pull requests and closed ones shown, the newest closed one is the sensible
    # default - that is the state of a quiet repository.
    pick = (next((r for r in allrows if r["number"] == want_pr), None) if want_pr else
            (rows[0] if rows else (closed[0] if closed else None)))
    if pick:
        # Per-lane status comes from Actions jobs, NOT the Checks API. A
        # fine-grained PAT cannot carry "Checks: read" at all — that permission
        # is GitHub-App-only, so /commits/{sha}/check-runs answers 403 for this
        # token however it is configured. Every check on these repos IS an
        # Actions job, and a job carries the same name/status/conclusion/
        # html_url/started_at fields the board already renders, so runs → jobs
        # reproduces the row exactly under "Actions: read". A check posted by
        # some third-party App would be invisible here; we have none, and if
        # that changes this is the seam that would need an App, not a PAT.
        runs = _gh_pages(f"/repos/{GH_REPO}/actions/runs?head_sha={pick['head']}", "workflow_runs")
        jobs: list = []
        latest_runs = {}
        for run in sorted(runs, key=lambda r: (r.get("run_number", 0), r.get("run_attempt", 1)), reverse=True):
            if run.get("head_sha") != pick["head"] or run.get("event") != "pull_request":
                continue
            # Match by PR number when the run lists its pull requests. A run lists
            # none once its PR closes (or for a fork), so then only this PR's own
            # head branch counts: another PR's run on the same commit must not
            # become this PR's newest run.
            # shortcut: two forks with the same branch name and commit still
            # collide; compare head_repository too if forks ever share commits.
            if run.get("pull_requests"):
                if not any(p["number"] == pick["number"] for p in run["pull_requests"]):
                    continue
            elif run.get("head_branch") != pick["head_ref"]:
                continue
            latest_runs.setdefault(run.get("workflow_id", run["id"]), run)
        for run in latest_runs.values():
            got = _gh_pages(f"/repos/{GH_REPO}/actions/runs/{run['id']}/jobs?filter=latest", "jobs")
            jobs.extend(got)
        latest: dict = {}
        for c in jobs:                    # a re-run repeats a job name; newest wins
            k = c["name"]
            if k not in latest or (c.get("started_at") or "") > (latest[k].get("started_at") or ""):
                latest[k] = c
        pick["checks"] = [{"name": c["name"], "status": c["status"],
                           "conclusion": c.get("conclusion"), "url": c["html_url"]}
                          for c in sorted(latest.values(), key=lambda x: x["name"])]
        for c in pick["checks"]:
            if c.get("conclusion"):
                feed.append({"ts": pick["updated"], "source": "PR",
                             "status": "Succeeded" if c["conclusion"] == "success" else "Failed",
                             "text": f"PR #{pick['number']} check {c['name']}: {c['conclusion']}"})
        reviews = _gh_pages(f"/repos/{GH_REPO}/pulls/{pick['number']}/reviews", ttl=60)
        review_runs = [r for r in latest_runs.values()
                       if "review" in r.get("name", "").lower()
                       or any(c["name"] == "review" and c.get("run_id") == r["id"] for c in jobs)]
        review_running = (any(c["status"] != "completed" and c["name"] == "review"
                              for c in pick["checks"])
                          or any(r.get("status") != "completed" for r in review_runs))
        comments = _gh_pages(f"/repos/{GH_REPO}/pulls/{pick['number']}/comments", ttl=60)
        history = agent_review_history(reviews, comments, GH_REPO, pick["number"], PERSONAS)
        cards, current_seats = [], set()
        # History is newest first. Only one authenticated current attempt per seat
        # can drive the current verdict. Dismissed/older reports remain inspectable.
        for card in history:
            run = next((r for r in review_runs if str(r["id"]) == card["run_id"]
                        and int(r.get("run_attempt", 1)) == card["run_attempt"]), None)
            if card["commit_id"] != pick["head"]:
                reason = "Earlier PR head"
            elif card["state"] == "DISMISSED":
                reason = "Review dismissed on GitHub; original report retained"
            elif not run:
                reason = "Not the latest verified review workflow attempt"
            elif (run.get("run_started_at") or run.get("created_at") or "") > (card.get("submitted") or ""):
                reason = "Report predates the latest workflow attempt"
            elif card["persona"] in current_seats:
                reason = "Superseded report for this reviewer"
            else:
                reason = None
                card["is_current"] = True
                current_seats.add(card["persona"])
                cards.append(card)
            if reason:
                card["history_reason"] = reason
            # Historical failures are never emitted as present-day success events.
            feed.append({"ts": card.get("submitted"), "source": "PR", "persona": card["persona"],
                         "status": ("Unavailable" if card["evidence"]["state"] != "available" else
                                    "Succeeded" if card["verdict"] == "PASS" and not card.get("error") else "Failed"),
                         "historic": not card["is_current"],
                         "text": f"{card['persona']} reviewed PR #{pick['number']}: {card['verdict']}",
                         "url": card["url"],
                         "detail": _kv(("Head", card["commit_id"]), ("Run", card["run_id"]),
                                       ("Attempt", card["run_attempt"]), ("State", card["state"]),
                                       ("History", reason), ("Error", card.get("error")))})
        detail = {"pr": pick, "reviews": cards, "review_running": review_running,
                  "findings": [finding for card in cards for finding in card["findings"]],
                  "history": history}
    return {"open": rows, "closed": closed, "detail": detail}


def build_snapshot(commit_sha: str | None = None, pr_number: int | None = None,
                   repo_key: str | None = None, include_closed: bool = False,
                   history: bool = False, execution_id: str | None = None,
                   review_build: str | None = None):
    """Assemble the consolidated view; params pin a commit and/or a PR."""
    cfg = _repo_cfg(repo_key)
    # include_closed belongs in the cache key: without it, toggling closed pull
    # requests on would be served the cached open-only payload and look broken.
    ck = (f"{commit_sha or ''}|{pr_number or ''}|{cfg['key']}"
          f"|{int(include_closed)}|{int(history)}|{execution_id or ''}|{review_build or ''}")
    now = time.time()
    hit = _cache.get(ck)
    if hit and now - hit["at"] < SNAPSHOT_TTL:
        return hit["snap"]

    # Errors are scoped to this assembled response, not a prior repository view.
    _last_errors.clear()
    if not PANEL_META:
        _last_errors["policy"] = "Dashboard policy metadata unavailable"
    feed: list = []
    failures: list = []
    sfx = cfg.get("suffix", "")
    t1_name, t2_name, t3_name = _tiers(sfx)
    executions = _commits(t1_name, commit_sha, target_execution=execution_id, distinct=True)
    commits, seen_shas = [], set()
    for execution in executions:
        if execution["sha"] not in seen_shas:
            commits.append(execution)
            seen_shas.add(execution["sha"])
    pipelines: dict = {}

    # One execution is the subject of the whole board: the newest tier1 run,
    # or the one the viewer drilled into.
    target = None
    if execution_id:
        target = next((c for c in executions if c["execution_id"] == execution_id), None)
    elif commit_sha:
        target = next((c for c in commits if c["sha"] == commit_sha), None)
    if target is None and not (commit_sha or execution_id):
        target = commits[0] if commits else None
    selection_error = _last_errors.get(f"{t1_name}_executions")
    if target and commit_sha and target["sha"] != commit_sha:
        target = None
        selection_error = "Requested execution does not match requested revision"
    selection_state = ("unavailable" if _last_errors.get(f"{t1_name}_executions")
                       else "selected" if target else "not_found")
    if selection_error:
        selection_state = "unavailable"
    if not target and (commit_sha or execution_id) and not selection_error:
        selection_error = ("No retained execution found for requested execution ID" if execution_id
                           else "No retained execution found for requested revision")
    is_live = bool(target and executions and target["execution_id"] == executions[0]["execution_id"])

    t1, active_review_build, approval = _pipeline_view(
        t1_name, (target or {}).get("execution_id"), feed, failures)
    if selection_error:
        t1["error"] = selection_error
    pipelines[t1_name] = t1
    commit = ({"sha": target["sha"], "message": target["message"]} if target else None)
    panel_progress = _panel_progress(active_review_build, feed, sfx) if is_live else None

    # Independent pipelines must match the revision; never use a different run.
    for name in (t2_name, t3_name):
        if execution_id or not target:
            # A SHA does not bind another pipeline's retry to this exact run.
            pipelines[name] = {"name": name, "stages": [], "console": _console(name),
                               "execution_id": None,
                               "error": ("No cross-pipeline execution binding for the selected primary execution"
                                         if target else "Selected revision or execution is unavailable")}
            continue
        view, _, _ = _pipeline_view(
            name, _exec_for(name, (target or {}).get("sha")), feed, failures)
        if _last_errors.get(f"{name}_executions"):
            view["error"] = _last_errors[f"{name}_executions"]
        pipelines[name] = view

    findings, review_evidence = {}, {}
    for tier, name in zip(("tier1", "tier2", "tier3"), (t1_name, t2_name, t3_name)):
        findings[tier], review_evidence[tier] = _execution_findings(
            tier, pipelines[name], (target or {}).get("sha"), sfx)
        report = findings[tier] or {}
        action = _review_action(pipelines[name]) or {}
        for reviewer in report.get("agents", []):
            feed.append({"ts": review_evidence[tier].get("recorded_at") or action.get("when"),
                         "source": tier.upper(), "persona": reviewer["name"],
                         "status": "Succeeded" if reviewer.get("verdict") == "PASS" and not reviewer.get("error") else "Failed",
                         "text": f"{reviewer['name']}: {reviewer.get('verdict', 'unavailable')}",
                         "detail": _kv(("Execution", pipelines[name].get("execution_id")),
                                       ("Revision", (target or {}).get("sha")),
                                       ("Error", reviewer.get("error")))})

    # A gate that fails because a seat blocked has TWO reasons: the verdict (the
    # real one) and the CI wrapper that observed a nonzero exit. The wrapper -
    # "Error while executing command: exit $GATE_EXIT" - is mechanical noise
    # that says nothing about the change, so the banner leads with the verdict
    # and keeps the wrapper as secondary detail. Sourced from the same findings
    # documents the board already loaded, not re-derived from log text.
    for tier, name in zip(("tier1", "tier2", "tier3"), (t1_name, t2_name, t3_name)):
        report = findings[tier] or {}
        blocking = [f for f in report.get("findings", []) if f.get("blocking")]
        errors = [a for a in report.get("agents", []) if a.get("error")]
        error_reasons = [f"{a['name']} · {a['error']}" for a in errors]
        if report.get("error"):
            error_reasons.append(f"Review report · {report['error']}")
        for failure in failures:
            if failure["pipeline"] != name or failure["action"] not in ("Review", "KiroReview", "AgentReview"):
                continue
            if blocking:
                failure["gate_headline"] = f"Review reports {len(blocking)} blocking findings"
                if error_reasons:
                    failure["gate_headline"] += " and review errors"
                failure["gate_reason"] = [f"{f.get('agent', '')} · {f['rule_id']} · {f['path']}:{f['line']} — {f['message']}" for f in blocking] + error_reasons
            elif error_reasons:
                failure["gate_headline"] = "Review could not complete"
                failure["gate_reason"] = error_reasons
    health = _health.read(t1, (target or {}).get("sha"), cfg.get("health_stack"),
                          target={**cfg, "pipeline": t1_name})
    health.update(repo=cfg["key"], target=cfg["deploy_target"])
    deployment = health.get("deployment") or {}
    rollback = health.get("rollback") or {}
    if health.get("state") != "unavailable" and deployment.get("alarm_triggered"):
        for failure in failures:
            if failure["pipeline"] == t1_name and failure["stage"] == "Deploy":
                failure["gate_headline"] = "CloudWatch alarm stopped traffic shifting"
                failure["gate_reason"] = [
                    f"CodeDeploy {deployment['id']}: {deployment['status']}; "
                    f"version {deployment.get('original_version')} → {deployment.get('target_version')}."
                ]
                if rollback:
                    failure["gate_reason"].append(
                        f"Automatic rollback {rollback['id']}: {rollback['status']}; "
                        f"restore target version {rollback.get('target_version')}."
                    )
    pr = _pr_surface(feed, pr_number, cfg["repo"], include_closed)
    # The timeline belongs to this selection. Loading past executions here
    # mixed unrelated failures into a pinned revision's evidence.
    # The cap is a DISPLAY guard, not the reason the timeline was short: with
    # history off there are only ~15 events to show.
    feed = sorted((e for e in feed if e.get("ts")),
                  key=lambda e: str(e["ts"]), reverse=True)[:400 if history else 80]
    snap = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "commit": commit, "commits": commits, "selected_commit": commit_sha,
            "executions": executions, "selected_execution": execution_id,
            "repos": [{"key": r["key"], "label": r["label"], "repo": r["repo"],
                       "tiers": r["tiers"], "deploys": r.get("deploys", False),
                       "deploy_target": r.get("deploy_target", ""),
                       "deploy_service": r.get("deploy_service", "Deployment action")}
                      for r in REPOS],
            "selected_repo": cfg["key"],
            "pipelines": pipelines, "findings": findings, "panel_meta": PANEL_META,
            "panel_progress": panel_progress, "pr": pr, "feed": feed,
            "site": SITE if cfg["key"] == "artifact" else (
                (DASHBOARD_URL or "/") + "?repo=road"
                + ("&execution=" + quote(target["execution_id"], safe="") if target else "")),
            "failures": failures, "approval": approval, "live": is_live,
            "execution": (target or {}).get("execution_id"),
            "execution_status": (target or {}).get("status"),
            "execution_started": (target or {}).get("started"),
            "selected_review_build": review_build,
            "review_attempts": t1.get("review_attempts", []),
            "review_attempts_evidence": (evidence("unavailable", t1["error"]) if t1.get("error") else
                t1.get("review_attempts_evidence") or evidence("unavailable", "Review action attempt metadata unavailable")),
            "selection_state": selection_state,
            "selection_error": selection_error,
            "review_evidence": review_evidence,
            "health": health,
            "policy_metadata": {k: PANEL_POLICY.get(k) for k in ("source", "sha256")},
            # The pipeline NAMES for this repo, published so the client never has
            # to guess them. It used to hardcode the artifact's three names, so
            # every tier card span forever on the road - the sixth time in this
            # file that a typed-out list disagreed with the config that drives
            # the data. The names come from the same _tiers(sfx) helper that
            # built the pipelines dict above.
            "tiers": {"tier1": t1_name, "tier2": t2_name, "tier3": t3_name},
            "degraded": dict(_last_errors),
            "repo": {r["key"]: r["repo"] for r in REPOS}}
    if review_build:
        snap["review_attempt"] = _selected_review_attempt(
            t1, (target or {}).get("sha"), review_build, findings["tier1"], review_evidence["tier1"], sfx)
    # Expensive reads can outlast the TTL. Start reuse after completion, keeping
    # generated_at and health.observed_at unchanged when returning this snapshot.
    _cache[ck] = {"at": time.time(), "snap": snap}
    if len(_cache) > 24:
        _cache.pop(next(iter(_cache)))
    return snap


def _static(path: str):
    p = (WEB_ROOT / path.lstrip("/")).resolve()
    if path in ("/", "") or not p.is_relative_to(WEB_ROOT.resolve()) or not p.is_file():
        p = WEB_ROOT / "index.html"
    ctype = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
    import base64
    return {"statusCode": 200,
            "headers": {"content-type": ctype,
                        "cache-control": "public, max-age=300" if "/assets/" in path
                        else "no-cache"},
            "body": base64.b64encode(p.read_bytes()).decode(), "isBase64Encoded": True}


def _json(status: int, body) -> dict:
    return {"statusCode": status,
            "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, default=str)}


def _jwt_subject(event) -> str:
    """The verified `sub` claim the HTTP API JWT authorizer attached, or ''."""
    ctx = event.get("requestContext") or {}
    claims = (((ctx.get("authorizer") or {}).get("jwt") or {}).get("claims") or {})
    sub = claims.get("sub") if isinstance(claims, dict) else None
    return sub if isinstance(sub, str) else ""


def auth_config() -> dict:
    """Non-secret values the SPA needs to start a sign-in. Nothing else."""
    return {"region": os.environ.get("AUTH_REGION", REGION),
            "domain": os.environ.get("AUTH_DOMAIN_URL", "").rstrip("/"),
            "client_id": os.environ.get("AUTH_CLIENT_ID", ""),
            "redirect_uri": DASHBOARD_URL}


def lambda_handler(event, context):
    """HTTP entry point: public SPA shell and /auth-config; JWT-guarded /api."""
    path = (event.get("rawPath") or event.get("path") or "/")
    q = event.get("queryStringParameters") or {}
    if path == "/api" or path.startswith("/api/"):
        # Defense in depth: the JWT authorizer must have run and verified a
        # token. Without its claims this fails closed, whatever the route says.
        if not _jwt_subject(event):
            return {**_json(401, {"message": "Unauthorized"}),
                    "headers": {"content-type": "application/json",
                                "cache-control": "no-store",
                                "www-authenticate": "Bearer"}}
        if path != "/api/snapshot":
            return _json(404, {"message": "Not found"})
        pr = int(q["pr"]) if str(q.get("pr", "")).isdigit() else None
        inc = str(q.get("closed", "")).lower() in ("1", "true", "yes", "on")
        hist = str(q.get("history", "")).lower() in ("1", "true", "yes", "on")
        return _json(200, build_snapshot(q.get("commit") or None, pr,
                                         q.get("repo") or None, inc, hist,
                                         execution_id=q.get("execution") or None,
                                         review_build=q.get("review_build") or None))
    if path == "/auth-config":
        return _json(200, auth_config())
    return _static(path)
