"""Evidence states and bounded pagination. No missing evidence implies PASS."""
from datetime import datetime, timezone
import hashlib
import re


class IncompleteEvidence(RuntimeError):
    pass


def pages(call, result_key, *, max_pages=40, **kwargs):
    """Follow AWS nextToken even through empty pages; reject partial evidence."""
    token, seen, out = None, set(), []
    for _ in range(max_pages):
        result = call(**kwargs, **({'nextToken': token} if token else {}))
        out.extend(result.get(result_key, []))
        token = result.get('nextToken')
        if not token:
            return out
        if token in seen:
            raise IncompleteEvidence('pagination token repeated')
        seen.add(token)
    raise IncompleteEvidence(f'evidence exceeds {max_pages} pages')


def evidence(state, reason, **context):
    return {'state': state, 'reason': reason, **context}


def report_state(doc, **context):
    """Inspect review completeness independently from pipeline action success."""
    if not isinstance(doc, dict):
        return evidence('unavailable', 'Invalid review document', **context)
    if not isinstance(doc.get('agents'), list) or not isinstance(doc.get('findings'), list) or not isinstance(doc.get('stats'), dict):
        return evidence('unavailable', 'Malformed review evidence', **context)
    if any(not isinstance(a, dict) or not a.get('name') for a in doc['agents']):
        return evidence('unavailable', 'Malformed reviewer evidence', **context)
    expires = doc.get('expires_at')
    if expires:
        try:
            if datetime.fromisoformat(expires.replace('Z', '+00:00')) <= datetime.now(timezone.utc):
                return evidence('expired', 'Recorded evidence expiry has elapsed', **context)
        except (ValueError, TypeError):
            return evidence('unavailable', 'Invalid evidence expiry', **context)
    verdict = doc.get('verdict')
    if verdict == 'BLOCKED_ERROR':
        return evidence('blocked_error', 'Review failed closed: ' + str(doc.get('error') or 'reviewer error'), **context)
    if doc.get('error') or any(a.get('error') or a.get('verdict') in ('ADVISORY_ERROR', 'BLOCKED_ERROR')
                               for a in doc.get('agents', [])):
        return evidence('unavailable', 'One or more reviewers could not complete; inspect reported verdict', **context)
    if verdict == 'FAIL':
        return evidence('blocked', 'Policy reports blocking findings', **context)
    if verdict == 'PASS' and doc.get('agents') and all(a.get('verdict') == 'PASS' for a in doc['agents']):
        return evidence('passed', 'Completed review report for this execution', **context)
    return evidence('unavailable', f'Review incomplete or unrecognized result: {verdict}', **context)


def matches_execution(doc, execution_id, external_id=None):
    """Revision alone is insufficient: retries of a SHA are separate executions."""
    containers = [doc, doc.get('provenance') or {}, doc.get('review_input') or {}]
    executions = [c[k] for c in containers for k in ('execution_id', 'pipeline_execution_id') if c.get(k)]
    builds = [c['build_id'] for c in containers if c.get('build_id')]
    return bool(executions or builds) and all(e == execution_id for e in executions) and all(
        b == external_id for b in builds)


def has_execution_identity(doc):
    return any(c.get(k) for c in (doc, doc.get('provenance') or {}, doc.get('review_input') or {})
               for k in ('execution_id', 'pipeline_execution_id', 'build_id'))

def matches_build(doc, execution_id, build_id):
    """Mutable convenience objects need affirmative build identity, not just SHA/execution."""
    return (any(c.get("build_id") for c in
                (doc, doc.get("provenance") or {}, doc.get("review_input") or {}))
            and matches_execution(doc, execution_id, build_id))


def panel_from_policy(config):
    if not isinstance(config, dict):
        raise ValueError('Policy bundle must be an object')
    rules, agents = config.get('rules'), config.get('agents')
    if not isinstance(rules, list) or not rules or not isinstance(agents, list) or not agents:
        raise ValueError('Policy bundle needs agents and rules')
    if any(not isinstance(r, dict) or not isinstance(r.get('id'), str) or
           not isinstance(r.get('blocking'), bool) for r in rules):
        raise ValueError('Every rule needs explicit blocking metadata')
    if any(not isinstance(a, dict) or not isinstance(a.get('name'), str) or
           not isinstance(a.get('rules') or [], list) or
           any(not isinstance(prefix, str) for prefix in (a.get('rules') or [])) for a in agents):
        raise ValueError('Every reviewer needs a name and rule prefixes')
    return [{'model': 'Unspecified', 'thinking': 'default', 'emoji': '', 'persona': '',
             **a, 'rules': ' / '.join(a.get('rules') or []) or 'all rules',
             'blocking': any(r.get('blocking') is True and
                             (not a.get('rules') or
                              any(r['id'].startswith(p) for p in a['rules'])) for r in rules)}
            for a in agents]


# Same publisher identity/marker contract as pr-surface/pr-reviewer/review_pr.py.
AGENT_BOT = {"login": "github-actions[bot]", "type": "Bot", "id": 41898282}
REVIEW_MARKER = re.compile(
    r"\A<!-- agentic-review:v2 repo=([\w.-]+/[\w.-]+) pr=([1-9][0-9]*) "
    r"reviewer=([0-9a-f]{16}) head=([0-9a-f]{40}) run=([1-9][0-9]*) "
    r"attempt=([1-9][0-9]*) part=([1-9][0-9]*) -->\n")
REVIEW_STATS = re.compile(
    r"^\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|\s*([^|\n]+)\|", re.M)


def agent_author(row):
    return all((row.get("user") or {}).get(k) == v for k, v in AGENT_BOT.items())


def _unescape_markdown(value):
    return re.sub(r"\\([\\`*_\[\]{}()#!|~])", r"\1", value)


def _body_findings(body, persona, url):
    """Read publisher Finding sections, excluding headings inside code fences."""
    starts, offset, fence = [], 0, None
    for line in body.splitlines(keepends=True):
        marker = re.match(r"^(`{3,}|~{3,})", line)
        if marker:
            value = marker.group(1)
            if fence is None:
                fence = value
            elif value[0] == fence[0] and len(value) >= len(fence):
                fence = None
        elif fence is None and line.strip() == "### Finding":
            starts.append(offset + len(line))
        offset += len(line)
    findings = []
    for i, start in enumerate(starts):
        end = starts[i + 1] - len("### Finding\n") if i + 1 < len(starts) else len(body)
        section = body[start:end].strip()
        match = re.fullmatch(
            r"\*\*([A-Z0-9]+-\d+)\*\* — ([^,\n]+), (blocking|advisory), "
            r"confidence ([\d.]+)\n\n([^\n]+):(-?\d+)\n\n([\s\S]+)", section)
        if match:
            rule, severity, blocking, confidence, path, line, message = match.groups()
            findings.append({"persona": persona, "rule_id": rule, "severity": severity,
                             "blocking": blocking == "blocking", "confidence": confidence,
                             "path": _unescape_markdown(path), "line": int(line),
                             "message": message, "url": url})
    return findings


def inline_agent_finding(comment, persona, head, review_ids):
    """Only comments from the publisher and a validated report can enrich it."""
    if (not agent_author(comment) or comment.get("commit_id") != head
            or comment.get("pull_request_review_id") not in review_ids):
        return None
    body = comment.get("body") or ""
    match = re.match(
        rf"\A[^\n]*?\*\*{re.escape(persona)}\*\* · \*\*([A-Z0-9]+-\d+)\*\* "
        r"\(([^,\n]+), (blocking|advisory), confidence ([\d.]+)\)\n\n([\s\S]+)", body)
    if not match:
        return None
    rule, severity, blocking, confidence, message = match.groups()
    return {"persona": persona, "rule_id": rule, "severity": severity,
            "blocking": blocking == "blocking", "confidence": confidence,
            "path": comment.get("path"),
            "line": comment.get("line") or comment.get("original_line"),
            "outdated": comment.get("position") is None, "message": message,
            "url": comment.get("html_url")}


def agent_review_history(reviews, comments, repo, number, personas):
    """Group authenticated publisher parts; preserve complete published evidence.

    A marker is not sufficient on a human review. Counts and contiguous parts
    also matter: the publisher has no total-parts marker, so declared finding
    counts are the check for a missing final continuation.
    """
    seats = {hashlib.sha256(name.encode()).hexdigest()[:16]: name for name in personas}
    groups = {}
    for review in reviews:
        if not agent_author(review) or review.get("state") not in {"COMMENTED", "CHANGES_REQUESTED", "DISMISSED"}:
            continue
        body = review.get("body") or ""
        marker = REVIEW_MARKER.match(body)
        if not marker:
            continue
        owner, pr, seat, head, run, attempt, part = marker.groups()
        if owner != repo or int(pr) != number or head != review.get("commit_id") or seat not in seats:
            continue
        if not isinstance(review.get("id"), int):
            continue
        persona = seats[seat]
        heading = body[marker.end():].split("\n", 1)[0]
        primary = re.fullmatch(rf"## [^\n]*?{re.escape(persona)}: \*\*(PASS|FAIL|BLOCKED_ERROR|ADVISORY_ERROR)\*\*", heading)
        if int(part) == 1 and not primary:
            continue
        if int(part) != 1 and heading != f"## {persona} — continued findings":
            continue
        if int(part) == 1 and f"[Workflow run](https://github.com/{repo}/actions/runs/{run}/attempts/{attempt})" not in body:
            continue
        groups.setdefault((persona, head, run, int(attempt)), []).append((int(part), review))
    result = []
    for (persona, head, run, attempt), parts in groups.items():
        parts.sort(key=lambda p: (p[0], p[1]["id"]))
        primary = next((rv for part, rv in parts if part == 1), parts[0][1])
        body = primary["body"]
        heading = re.search(r": \*\*(PASS|FAIL|BLOCKED_ERROR|ADVISORY_ERROR)\*\*", body)
        verdict = heading.group(1) if parts[0][0] == 1 and heading else "UNAVAILABLE"
        stats = REVIEW_STATS.search(body) if parts[0][0] == 1 else None
        issues = []
        numbers = [part for part, _ in parts]
        if any(part != index for index, (part, _) in enumerate(parts, 1)):
            issues.append("Missing or duplicate publication parts")
        findings = [finding for _, rv in parts
                    for finding in _body_findings(rv["body"], persona, rv.get("html_url"))]
        if not stats:
            issues.append("Primary report counts unavailable")
        elif int(stats.group(2)) != len(findings) or int(stats.group(1)) != sum(f["blocking"] for f in findings):
            issues.append("Published findings do not match primary report counts; report may be incomplete")
        publication_issues = list(issues)
        review_error = re.search(r"^\*\*Review incomplete:\*\* ([\s\S]*?)(?=\n\n### Finding|\Z)", body, re.M)
        if review_error:
            issues.insert(0, review_error.group(1).strip())
        if verdict == "PASS" and (issues or any(f["blocking"] for f in findings)):
            issues.append("Published PASS cannot establish a complete clean review")
            verdict = "UNAVAILABLE" if publication_issues else "BLOCKED_ERROR"
        ids = [rv["id"] for _, rv in parts]
        # Body findings are complete, unlike the publisher's capped inline list.
        # Attach inline permalinks/outdated state without truncating body messages.
        for comment in comments:
            finding = inline_agent_finding(comment, persona, head, ids)
            if not finding:
                continue
            same = next((f for f in findings if all(f.get(k) == finding.get(k)
                        for k in ("rule_id", "path", "line"))), None)
            if same is not None:
                same.update({k: finding[k] for k in ("url", "outdated")})
            else:
                findings.append(finding)
        if verdict == "PASS" and any(f["blocking"] for f in findings):
            issues.append("Inline blocking finding contradicts the published PASS")
            publication_issues.append(issues[-1])
            verdict = "UNAVAILABLE"
        record = {"id": primary["id"], "persona": persona, "verdict": verdict, "posted_as": None,
                  "state": primary["state"], "submitted": primary.get("submitted_at"),
                  "url": primary.get("html_url"), "commit_id": head,
                  "run_id": run, "run_attempt": attempt, "review_ids": ids,
                  "report_body": "\n\n".join(rv["body"] for _, rv in parts),
                  "findings": findings, "is_current": False,
                  "blocking": int(stats.group(1)) if stats else None,
                  "total": int(stats.group(2)) if stats else None,
                  "suppressed": int(stats.group(3)) if stats else None,
                  "model": stats.group(4) if stats else None,
                  "thinking": stats.group(5).strip() if stats else None}
        record["evidence"] = evidence(
            "missing" if 1 not in numbers else "unavailable" if publication_issues else "available",
            "; ".join(publication_issues) if publication_issues else "Complete published agent report")
        if issues:
            record["error"] = "\n".join(issues)
        result.append(record)
    return sorted(result, key=lambda r: (r.get("submitted") or "", r["id"]), reverse=True)
