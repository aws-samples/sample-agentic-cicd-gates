"""Offline PR-surface contract tests; all GitHub and Bedrock calls are fakes."""
import copy
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml

from conftest import unisolated_python

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "pr-surface/pr-reviewer/review_pr.py"
CTX = dict(repo="owner/sample", pr="7", base="a" * 40, head="b" * 40,
           run="200", attempt="2")
RULES = """version: 1
agents:
  - name: Security
    model: test-model
    rules: [SEC-]
  - name: Design
    model: test-model
    rules: [DES-]
defaults:
  confidence_threshold: 80
  fail_mode: open
  max_findings: 100
rules:
  - id: SEC-001
    description: Security rule
    severity: high
    blocking: true
  - id: DES-001
    description: Design rule
    severity: low
    blocking: false
"""


@pytest.fixture
def surface():
    spec = importlib.util.spec_from_file_location("pr_surface_v2", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / ".reviewer.yaml"
    path.write_text(RULES)
    return path


def doc(findings=(), error=None, verdict=None):
    findings = list(findings)
    blocking = sum(f["blocking"] for f in findings)
    return dict(verdict=verdict or ("FAIL" if blocking else "PASS"),
                stats=dict(total=len(findings), blocking=blocking, suppressed_below_threshold=0),
                findings=findings, error=error)


def finding(n=1, **kwargs):
    return dict(rule_id="SEC-001", path="src/app.py", line=n, message=f"Full finding {n}",
                suggested_code=f"fix_{n}()", confidence=95, severity="high",
                blocking=True, **kwargs)


def report(surface, policy, first=None, second=None):
    from reviewer.bedrock_reviewer import DEFAULT_MODEL
    _, digest = surface._rules(policy)
    return dict(version=2, context=copy.deepcopy(CTX), rules_sha256=digest,
                default_model=DEFAULT_MODEL, generated_at="2026-10-02T12:00:00+00:00",
                reviews=[dict(name="Security", model="test-model", result=first or doc()),
                         dict(name="Design", model="test-model", result=second or doc())])


class GitHub:
    def __init__(self, surface, history=(), inline_422=False, post_status=201,
                 dismiss_status=200):
        self.surface = surface
        self.history = list(history)
        self.inline_422 = inline_422
        self.post_status, self.dismiss_status = post_status, dismiss_status
        self.calls = []
        self.pull = dict(state="open", head=dict(sha=CTX["head"], repo=dict(full_name=CTX["repo"])),
                         base=dict(sha=CTX["base"], repo=dict(full_name=CTX["repo"])))
        self.permission = "write"
        self.compare = dict(status="ahead", files=[dict(filename="src/app.py")])

    def __call__(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if method == "GET" and "/permission" in path:
            return 200, dict(permission=self.permission)
        if method == "GET" and "/compare/" in path:
            return 200, copy.deepcopy(self.compare)
        if method == "GET" and "?per_page=100&page=" in path:
            page = int(path.rsplit("=", 1)[-1])
            return 200, self.history[(page - 1) * 100:page * 100]
        if method == "GET":
            return 200, copy.deepcopy(self.pull)
        if method == "PUT":
            return self.dismiss_status, {}
        if method == "POST":
            if self.inline_422 and payload["comments"]:
                return 422, {}
            return self.post_status, dict(
                id=1000 + len(self.calls), user=self.surface.BOT,
                commit_id=payload["commit_id"], body=payload["body"],
                state="CHANGES_REQUESTED" if payload["event"] == "REQUEST_CHANGES" else "COMMENTED")
        raise AssertionError((method, path))


def owned_review(surface, agent, id=1, **changes):
    previous = dict(CTX, head="c" * 40, run="199", attempt="1")
    return dict(id=id, user=dict(surface.BOT), state="CHANGES_REQUESTED",
                commit_id=previous["head"], body=surface._marker(previous, agent) + "\nOld failure",
                **changes)


def test_full_findings_survive_inline_limit_and_422(surface, policy, monkeypatch):
    evidence = report(surface, policy, doc([finding(i) for i in range(1, 26)]))
    api = GitHub(surface, inline_422=True)
    monkeypatch.setattr(surface, "_gh", api)
    assert surface.publish(CTX, evidence, policy) == 1
    posts = [p for m, _, p in api.calls if m == "POST"]
    assert len(posts[0]["comments"]) == 20
    assert posts[1]["comments"] == []
    assert posts[0]["body"] == posts[1]["body"]
    for i in range(1, 26):
        assert f"Full finding {i}" in posts[1]["body"]
        assert f"fix_{i}()" in posts[1]["body"]
    assert all(p["commit_id"] == CTX["head"] for p in posts)
    assert all(p["event"] in {"COMMENT", "REQUEST_CHANGES"} for p in posts)
    # The existing dashboard consumes this stable human-readable contract.
    assert re.search(r"##\s*\S*\s*(Security):\s*\*\*(FAIL)\*\*", posts[0]["body"])
    assert re.search(r"\|\s*25\s*\|\s*25\s*\|\s*0\s*\|\s*`test-model`\s*\|\s*off\s*\|",
                     posts[0]["body"])
    assert re.search(r"\*\*Security\*\*\s*·\s*\*\*SEC-001\*\*\s*\(high, blocking, confidence 95\)",
                     posts[0]["comments"][0]["body"])


def test_long_reports_split_without_loss(surface, policy):
    findings = [dict(finding(i), message=f"Item {i} " + "x" * 1900,
                     suggested_code="z" * 1900) for i in range(1, 40)]
    evidence = report(surface, policy, doc(findings))
    agent, row = surface.validate_report(evidence, CTX, policy)[0]
    parts = list(surface.review_payloads(CTX, evidence, agent, row))
    assert len(parts) > 1
    assert all(len(p["body"].encode()) < 60000 for p in parts)
    assert [p["event"] for p in parts] == ["REQUEST_CHANGES"] + ["COMMENT"] * (len(parts) - 1)
    assert all("Security: **FAIL**" not in p["body"] for p in parts[1:])
    combined = "".join(p["body"] for p in parts)
    assert all(f"Item {i} " in combined for i in range(1, 40))


def test_dismissal_requires_identity_marker_reviewer_and_older_run(surface, policy, monkeypatch):
    evidence = report(surface, policy)
    agent = surface.validate_report(evidence, CTX, policy)[0][0]
    good = owned_review(surface, agent)
    bad = []
    for i, mutation in enumerate([
            {"user": dict(surface.BOT, type="User")},
            {"user": dict(surface.BOT, id=42)},
            {"user": dict(surface.BOT, login="another[bot]")},
            {"body": "## Security: **FAIL**"},
            {"body": good["body"].replace("reviewer=" + surface._reviewer_id(agent), "reviewer=" + "d" * 16)},
            {"body": good["body"].replace("pr=7", "pr=8")},
            {"body": good["body"].replace("owner/sample", "other/sample")},
            {"body": good["body"].replace("run=199", "run=201")},
            {"commit_id": "f" * 40},
            {"state": "COMMENTED"},
            {"body": "human quote\n" + good["body"]},
    ], 2):
        bad.append(dict(good, id=i, **mutation))
    # Force pagination; eligible review is on page two.
    api = GitHub(surface, [dict(bad[0], id=i + 100) for i in range(100)] + bad + [good])
    monkeypatch.setattr(surface, "_gh", api)
    assert surface.publish(CTX, evidence, policy) == 0
    puts = [path for method, path, _ in api.calls if method == "PUT"]
    assert puts == ["/repos/owner/sample/pulls/7/reviews/1/dismissals"]
    assert any("page=2" in path for _, path, _ in api.calls)


@pytest.mark.parametrize("verdict,error,expected", [
    ("ADVISORY_ERROR", "provider declined", 0),
    ("PASS", None, 0),
])
def test_advisory_error_is_never_a_pass_for_cleanup(surface, policy, monkeypatch, verdict, error, expected):
    evidence = report(surface, policy, second=doc(error=error, verdict=verdict))
    agent = surface.validate_report(evidence, CTX, policy)[1][0]
    api = GitHub(surface, [owned_review(surface, agent)])
    monkeypatch.setattr(surface, "_gh", api)
    assert surface.publish(CTX, evidence, policy) == expected
    assert any(m == "PUT" for m, _, _ in api.calls) == (verdict == "PASS")
    if error:
        assert any("Review incomplete" in p["body"] for m, _, p in api.calls if m == "POST")


def test_blocked_error_is_red_and_not_dismissed(surface, policy, monkeypatch):
    evidence = report(surface, policy, doc(error="timeout", verdict="BLOCKED_ERROR"))
    agent = surface.validate_report(evidence, CTX, policy)[0][0]
    api = GitHub(surface, [owned_review(surface, agent)])
    monkeypatch.setattr(surface, "_gh", api)
    assert surface.publish(CTX, evidence, policy) == 1
    assert not any(m == "PUT" for m, _, _ in api.calls)


@pytest.mark.parametrize("field,value", [("head", "c" * 40), ("base", "d" * 40),
                                        ("state", "closed")])
def test_stale_or_closed_pr_never_posts(surface, policy, monkeypatch, field, value):
    api = GitHub(surface)
    if field == "state":
        api.pull[field] = value
    else:
        api.pull[field]["sha"] = value
    monkeypatch.setattr(surface, "_gh", api)
    with pytest.raises(RuntimeError, match="closed or base/head changed"):
        surface.publish(CTX, report(surface, policy), policy)
    assert not any(m in {"POST", "PUT"} for m, _, _ in api.calls)


def test_head_change_after_post_prevents_dismissal(surface, policy, monkeypatch):
    evidence = report(surface, policy)
    agent = surface.validate_report(evidence, CTX, policy)[0][0]
    api = GitHub(surface, [owned_review(surface, agent)])

    def racing_api(method, path, payload=None):
        result = api(method, path, payload)
        if method == "POST":
            api.pull["head"]["sha"] = "f" * 40
        return result

    monkeypatch.setattr(surface, "_gh", racing_api)
    with pytest.raises(RuntimeError, match="changed"):
        surface.publish(CTX, evidence, policy)
    assert not any(m == "PUT" for m, _, _ in api.calls)


@pytest.mark.parametrize("mutation", [
    lambda r: r["context"].update(head="c" * 40),
    lambda r: r["context"].update(repo="other/repo"),
    lambda r: r["context"].update(pr="99"),
    lambda r: r["context"].update(run="199"),
    lambda r: r["context"].update(attempt="1"),
    lambda r: r.update(rules_sha256="forged"),
    lambda r: r.update(reviews=[]),
    lambda r: r["reviews"].reverse(),
    lambda r: r["reviews"][0].update(model="weaker-model"),
    lambda r: r["reviews"][0]["result"].update(verdict="PASS"),
    lambda r: r["reviews"][0]["result"]["findings"][0].update(blocking=False),
    lambda r: r["reviews"][0]["result"]["findings"][0].update(rule_id="UNKNOWN"),
    lambda r: r["reviews"][0]["result"]["stats"].update(total=0),
    lambda r: r["reviews"][0]["result"]["stats"].update(suppressed_below_threshold=-1),
])
def test_untrusted_report_rejected_before_any_api(surface, policy, monkeypatch, mutation):
    evidence = report(surface, policy, doc([finding()]))
    mutation(evidence)
    api = GitHub(surface)
    monkeypatch.setattr(surface, "_gh", api)
    with pytest.raises(ValueError):
        surface.publish(CTX, evidence, policy)
    assert not api.calls


@pytest.mark.parametrize("failure", ["post", "dismiss", "list"])
def test_api_failures_are_not_silent_success(surface, policy, monkeypatch, failure):
    evidence = report(surface, policy)
    agent = surface.validate_report(evidence, CTX, policy)[0][0]
    api = GitHub(surface, [owned_review(surface, agent)],
                 post_status=403 if failure == "post" else 201,
                 dismiss_status=403 if failure == "dismiss" else 200)
    def failing_api(method, path, payload=None):
        if failure == "list" and "?per_page" in path:
            return 503, {}
        return api(method, path, payload)
    monkeypatch.setattr(surface, "_gh", failing_api)
    with pytest.raises(RuntimeError, match="HTTP (403|503)"):
        surface.publish(CTX, evidence, policy)


def test_exact_retry_is_idempotent(surface, policy, monkeypatch):
    evidence = report(surface, policy)
    history = []
    for agent, row in surface.validate_report(evidence, CTX, policy):
        payload = next(surface.review_payloads(CTX, evidence, agent, row))
        history.append(dict(id=len(history) + 1, body=payload["body"], user=surface.BOT,
                            commit_id=CTX["head"], state="COMMENTED"))
    api = GitHub(surface, history)
    monkeypatch.setattr(surface, "_gh", api)
    assert surface.publish(CTX, evidence, policy) == 0
    assert not any(m in {"POST", "PUT"} for m, _, _ in api.calls)


@pytest.mark.parametrize("old_verdict,dismissed,status",
                         [("BLOCKED_ERROR", 1, 0), ("FAIL", 0, 1)])
def test_new_attempt_clears_own_same_sha_block_only_after_an_error(
        surface, policy, monkeypatch, old_verdict, dismissed, status):
    # A re-run may recover from an incomplete review, but re-running the same
    # commit until the model passes must not withdraw a FAIL (Continuum C10),
    # nor turn the required check green while that FAIL is open.
    evidence = report(surface, policy)
    agent = surface.validate_report(evidence, CTX, policy)[0][0]
    previous = dict(CTX, attempt="1")
    old = dict(owned_review(surface, agent), commit_id=CTX["head"],
               body=surface._marker(previous, agent)
               + f"\n## {agent.emoji} {agent.name}: **{old_verdict}**\n\nold result")
    api = GitHub(surface, [old])
    monkeypatch.setattr(surface, "_gh", api)
    assert surface.publish(CTX, evidence, policy) == status
    assert sum(m == "PUT" for m, _, _ in api.calls) == dismissed


def test_isolated_python_ignores_head_import_hooks_and_shadow_core(tmp_path):
    (tmp_path / "sitecustomize.py").write_text("raise RuntimeError('head hook executed')")
    (tmp_path / "reviewer").mkdir()
    (tmp_path / "reviewer/__init__.py").write_text("raise RuntimeError('head core executed')")
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('surface', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
rules, verdict = mod._core()
print(rules.__file__)
"""
    result = subprocess.run([sys.executable, "-I", "-c", script, str(TOOL)],
                            cwd=tmp_path, text=True, capture_output=True, check=True)
    assert str(ROOT / "agent/reviewer/rules.py") in result.stdout


def test_scrubbing_and_untrusted_markdown(surface):
    secret = "AKIA" + "A" * 16
    token = "ghp_" + "b" * 36
    untrusted = f"{secret} {token} https://console.aws.amazon.com/internal user@example.com"
    assert surface.scrub(untrusted).count("[REDACTED]") == 4
    text = surface._text("@all ![image](https://attacker.invalid) <!-- agentic-review:v2 -->")
    assert "@[" not in text and "@all" not in text
    assert "![image]" not in text and "<!--" not in text
    assert surface._code("```\n@all\n```").startswith("````\n")


def test_analysis_has_no_github_mutations_and_bounds_input(surface, policy, monkeypatch):
    import reviewer.bedrock_reviewer as core
    from reviewer.verdict import GateResult, Verdict
    ruleset, _ = surface._rules(policy)
    monkeypatch.setattr(surface, "_git", lambda *args: b"diff --git a/a b/a\n+safe")
    def never(*args):
        raise AssertionError("analysis called GitHub")
    monkeypatch.setattr(surface, "_gh", never)
    monkeypatch.setattr(core, "review_panel", lambda *args, **kwargs: [
        (a, SimpleNamespace(model_id=a.model, result=GateResult(Verdict.PASS, (), 0)))
        for a in ruleset.agents])
    evidence = surface.analyze(CTX, ".", policy)
    assert len(surface.validate_report(evidence, CTX, policy)) == 2
    monkeypatch.setattr(surface, "_git", lambda *args: b"x" * (surface.MAX_DIFF_BYTES + 1))
    with pytest.raises(ValueError, match="no partial review"):
        surface.analyze(CTX, ".", policy)


def event_env(surface, tmp_path, monkeypatch):
    env = dict(GITHUB_REPOSITORY=CTX["repo"], PR_NUMBER=CTX["pr"], BASE_SHA=CTX["base"],
               HEAD_SHA=CTX["head"], GITHUB_RUN_ID=CTX["run"], GITHUB_RUN_ATTEMPT=CTX["attempt"],
               GITHUB_ACTOR="writer", GITHUB_TRIGGERING_ACTOR="rerunner", GITHUB_EVENT_NAME="pull_request")
    event = dict(repository=dict(full_name=CTX["repo"]), pull_request=dict(
        number=int(CTX["pr"]), head=dict(sha=CTX["head"], repo=dict(full_name=CTX["repo"])),
        base=dict(sha=CTX["base"], repo=dict(full_name=CTX["repo"]))))
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event))
    env["GITHUB_EVENT_PATH"] = str(path)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return path, event


def test_event_scope_and_forks(surface, tmp_path, monkeypatch):
    path, event = event_env(surface, tmp_path, monkeypatch)
    assert surface.context() == CTX
    event["pull_request"]["head"]["repo"]["full_name"] = "fork/repo"
    path.write_text(json.dumps(event))
    with pytest.raises(ValueError, match="fork"):
        surface.context()
    monkeypatch.setenv("HEAD_SHA", "--exec=oops")
    with pytest.raises(ValueError, match="invalid"):
        surface.context()


@pytest.mark.parametrize("changed,tree,permission,expected", [
    (b"src/a.py\0", b"100644 blob abc\tsrc/a.py\0", "write", None),
    (b".github/workflows/agentic-review.yml\0", b"", "write", "automation files"),
    (b".github/actions/local/action.yml\0", b"", "write", "automation files"),
    (b"src/a.py\0", b"120000 blob abc\tsrc/a.py\0", "write", "symlinks"),
    (b"src/a.py\0", b"160000 commit abc\tsrc/a.py\0", "write", "submodules"),
    (b"src/a.py\0", b"", "read", "lacks"),
])
def test_guard(surface, monkeypatch, changed, tree, permission, expected):
    monkeypatch.setenv("GITHUB_ACTOR", "writer")
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", "rerunner")
    api = GitHub(surface)
    api.permission = permission
    monkeypatch.setattr(surface, "_gh", api)
    monkeypatch.setattr(surface, "_git", lambda root, cmd, *args: changed if cmd == "diff"
                        else b"a" * 40 + b"\n" if cmd == "merge-base" else tree)
    if expected:
        with pytest.raises(RuntimeError, match=expected):
            surface.guard(CTX, ".")
    else:
        surface.guard(CTX, ".")
        permissions = [path for _, path, _ in api.calls if "/permission" in path]
        assert len(permissions) == 2


def test_real_git_guard_checks_deleted_workflows_and_symlink_tree(surface, tmp_path, monkeypatch):
    repo = tmp_path / "git"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()
    git("init", "--quiet")
    git("config", "user.name", "Offline Test")
    git("config", "user.email", "test@example.invalid")
    (repo / ".github/workflows").mkdir(parents=True)
    workflow = repo / ".github/workflows/check.yml"
    workflow.write_text("original")
    git("add", ".")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    workflow.unlink()
    git("add", "-A")
    git("commit", "-qm", "delete automation")
    head = git("rev-parse", "HEAD")
    monkeypatch.setenv("GITHUB_ACTOR", "writer")
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", "writer")
    monkeypatch.setattr(surface, "_current", lambda ctx: None)
    monkeypatch.setattr(surface, "_require", lambda *args: dict(permission="write"))
    with pytest.raises(RuntimeError, match="automation files"):
        surface.guard(dict(CTX, base=base, head=head), repo)


@pytest.mark.parametrize("root", [ROOT, ROOT.parent / "sample-agentic-cicd-artifact"])
def test_readme_says_the_freeze_needs_protection_outside_the_repo(surface, root):
    # Continuum, round 4 (G04): on pull_request GitHub runs the PR's own copy of
    # the workflow, so the guard cannot hold the freeze alone. The README says
    # so, and names every path the guard freezes.
    text = " ".join((root / "README.md").read_text().split())
    assert "runs the pull request's own copy of the workflow" in text
    assert "No code in this repository can stop that" in text
    for path in (*surface.FROZEN_DIRS, *surface.FROZEN_FILES, *surface.FROZEN_NAMES):
        assert f"`{path}" in text, path


def test_codeowners_names_an_owner_for_the_rules_and_the_frozen_files():
    # One file at the root: GitHub and GitLab both read it there. The public
    # bundle runs this test too, so it also proves the bundle ships the file.
    lines = [line.split() for line in (ROOT / "CODEOWNERS").read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    owners = {path: rest for path, *rest in lines}
    # No GitLab-only sections, required or optional.
    assert not [line for line in lines if line[0].startswith(("[", "^["))]
    # The rules, the workflow, the base-branch tooling it loads, and the frozen files.
    for path in ("/.reviewer.yaml", "/rules/", "/.github/", "/agent/reviewer/", "/pr-surface/",
                 "/deterministic/", "/threat-model/validate.py",
                 "/threat-model/boundaries.yaml", ".gitattributes", "/CODEOWNERS"):
        assert owners.get(path) == ["@aws-samples/sample-agentic-cicd"], path
    assert not (ROOT / ".github/CODEOWNERS").exists()   # it would shadow the root file


@pytest.mark.parametrize("root", [ROOT, ROOT.parent / "sample-agentic-cicd-artifact"])
def test_workflow_trust_and_required_names(root):
    path = root / ".github/workflows/agentic-review.yml"
    # BaseLoader keeps YAML's 'on' key rather than coercing it to boolean.
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)  # nosec B506 - BaseLoader builds only str/list/dict
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert set(workflow["on"]) == {"pull_request"}
    jobs = workflow["jobs"]
    assert {"review", "deterministic", "threat-model"} <= jobs.keys()
    assert jobs["analyze"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert jobs["review"]["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert jobs["guard"]["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert jobs["threat-model"]["permissions"] == {"contents": "read"}
    assert jobs["analyze"]["needs"] == "guard"
    assert jobs["analyze"]["outputs"]["report_id"] == "${{ steps.evidence.outputs.artifact-id }}"
    downloader = next(s for s in jobs["review"]["steps"]
                      if s.get("uses", "").startswith("actions/download-artifact@"))
    assert downloader["with"]["artifact-ids"] == "${{ needs.analyze.outputs.report_id }}"
    assert "name" not in downloader["with"]
    assert 'REPORT_ID' in jobs["review"]["steps"][1]["run"]
    for name in ("review", "deterministic", "threat-model"):
        assert jobs[name]["if"] == "${{ always() }}"
        assert "guard" in jobs[name]["needs"]
        assert "exit 1" in jobs[name]["steps"][0]["run"]
    # Every deadline outlasts the longest single call it waits on, plus margin.
    # analyze runs the seats one after another: one call at the full read
    # timeout, a normal four-seat panel (302 s, 2026-10-02) and setup (~2 min).
    # Its OIDC session must last as long; the role allows 1 hour.
    from reviewer.bedrock_reviewer import READ_TIMEOUT_SECONDS
    analyze = int(jobs["analyze"]["timeout-minutes"]) * 60
    assert analyze >= READ_TIMEOUT_SECONDS + 302 + 120
    creds = next(s for s in jobs["analyze"]["steps"]
                 if s.get("uses", "").startswith("aws-actions/configure-aws-credentials@"))
    assert analyze <= int(creds["with"]["role-duration-seconds"]) <= 3600
    for name, job in jobs.items():
        assert int(job["timeout-minutes"]) <= (60 if name == "analyze" else 15)
        for step in job["steps"]:
            if "uses" in step:
                assert len(step["uses"].split("@")[-1]) == 40
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] == "false"
                assert step["with"]["ref"] in {"${{ github.event.pull_request.base.sha }}",
                                                "${{ github.event.pull_request.head.sha }}"}
                if name == "review":
                    assert step["with"]["path"] == "base-tooling"
            if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@"):
                policy = json.loads(step["with"]["inline-session-policy"])
                actions = policy["Statement"][0]["Action"]
                if name == "analyze":
                    assert set(actions) == {"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}
                else:
                    assert name == "deterministic" and actions == "access-analyzer:ValidatePolicy"
            run = step.get("run", "")
            assert "${{" not in run
            assert "pip install -r" not in run
            # The tests job runs the change's own tests by design; every other
            # Python call runs isolated, so no file in the checkout is imported.
            assert name == "tests" or not unisolated_python(run), (name, run)
    assert "--boundaries \"$GITHUB_WORKSPACE/base-tooling/threat-model/boundaries.yaml\"" in path.read_text()
    assert "WORKFLOW_CONTRACT = 2" in path.read_text()
    if root.name.endswith("artifact"):
        assert jobs["tests"]["permissions"] == {"contents": "read"}
        assert jobs["tests"]["steps"][-1]["run"] == (
            "python -m unittest discover -s tests -p 'test_*.py' -v")
        assert jobs["tests"]["steps"][1]["with"]["python-version"] == "3.12"
        assert "needs" not in jobs["tests"]
        steps = jobs["deterministic"]["steps"]
        guard = next(s["run"] for s in steps if s["name"].startswith("cfn-guard"))
        assert "sha256sum -c" in guard and "install-guard.sh" not in guard
        assert "/3.2.1/" in guard
