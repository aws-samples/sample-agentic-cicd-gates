"""Tier 1's optional AWS Continuum action: one switch, OFF by default, advisory.

The switch adds only a scan CodeBuild action: the integration and environment
are yours, passed as context, so the stack creates no Continuum integration,
environment, bucket or role and holds no account-wide permission. Synth checks
cover both positions of the switch, a missing identifier, and an unsupported
Region, plus offline runs of the scan script against a stub client.
"""
import importlib
import json
import subprocess
import types
import zipfile

import pytest

from conftest import ROOT, unisolated_python

APP_DIR = ROOT / "tier1-codebuild"
# The identifiers an operator passes for their own integration + environment.
ON = {"enable_continuum": "true",
      "continuum_source_bucket": "my-scan-bucket",
      "continuum_environment_id": "env-abc123"}


@pytest.fixture
def tier1(monkeypatch):
    monkeypatch.chdir(APP_DIR)
    monkeypatch.syspath_prepend(str(APP_DIR))
    module = importlib.import_module("tier1_stack")
    original = module.s3_assets.Asset

    def asset(scope, cid, *, path, **kw):   # see test_tier1_baseline.py
        return original(scope, cid, path=str((APP_DIR / path).resolve()), **kw)

    monkeypatch.setattr(module.s3_assets, "Asset", asset)
    return module


def synth(tier1, tmp_path, region="us-west-2", **context):
    import aws_cdk as cdk
    from aws_cdk.assertions import Annotations, Template
    app = cdk.App(outdir=str(tmp_path / "cdk.out"), context={"source": "codecommit", **context})
    stack = tier1.Tier1PipelineStack(app, "Tier1PipelineStack",
                                     env=cdk.Environment(region=region))
    return Template.from_stack(stack).to_json(), Annotations.from_stack(stack)


def _of_type(resources, kind):
    return {k: v for k, v in resources.items() if v["Type"] == kind}


def _statements(resources, role_id):
    found = []
    for policy in _of_type(resources, "AWS::IAM::Policy").values():
        if {"Ref": role_id} in policy["Properties"]["Roles"]:
            found += policy["Properties"]["PolicyDocument"]["Statement"]
    return found


def _actions(statement):
    a = statement["Action"]
    return a if isinstance(a, list) else [a]


def _gates_actions(template):
    [pipeline] = _of_type(template["Resources"], "AWS::CodePipeline::Pipeline").values()
    [stage] = [s for s in pipeline["Properties"]["Stages"] if s["Name"] == "AutomatedGates"]
    return pipeline, {a["Name"]: a for a in stage["Actions"]}


def test_off_by_default_adds_nothing(tier1, tmp_path):
    # The flag is unset: the sample ships this way, so a plain synth must be
    # the pre-feature stack -- no Continuum action, project, role or grant.
    template, _ = synth(tier1, tmp_path)
    assert "continuum" not in json.dumps(template).lower()
    _, actions = _gates_actions(template)
    assert "ContinuumScan" not in actions


def test_on_adds_an_advisory_action_beside_the_gates(tier1, tmp_path):
    template, _ = synth(tier1, tmp_path, **ON)
    pipeline, actions = _gates_actions(template)
    assert {"Review", "Deterministic", "ThreatModel", "ContinuumScan"} <= set(actions)
    assert actions["ContinuumScan"]["Namespace"] == "ContinuumScan"
    approval = json.dumps([s for s in pipeline["Properties"]["Stages"] if s["Name"] == "Approval"])
    assert "#{ContinuumScan.CONTINUUM_SUMMARY}" in approval
    assert "never blocks" in approval
    [project] = [p for p in _of_type(template["Resources"], "AWS::CodeBuild::Project").values()
                 if p["Properties"]["Name"] == "agentic-gates-tier1-continuum"]
    spec = project["Properties"]["Source"]["BuildSpec"]
    assert "|| true" in spec                 # the scan never fails the build
    assert "boto3==1.43.123" in spec


def test_the_scan_project_is_pinned_and_isolated_like_every_gate(tier1, tmp_path):
    template, _ = synth(tier1, tmp_path, **ON)
    [project] = [p for p in _of_type(template["Resources"], "AWS::CodeBuild::Project").values()
                 if p["Properties"]["Name"] == "agentic-gates-tier1-continuum"]
    env = {v["Name"]: v["Value"]
           for v in project["Properties"]["Environment"]["EnvironmentVariables"]}
    assert (env.get("PYTHONSAFEPATH"), env.get("PYTHONNOUSERSITE")) == ("1", "1")
    # pinned asset: version + sha256 env vars, not a bare object URL
    assert "CONTINUUM_TOOLS_VERSION" in env and "CONTINUUM_TOOLS_SHA256" in env
    assert "CONTINUUM_TOOLS_URL" not in env
    spec = json.loads(project["Properties"]["Source"]["BuildSpec"])
    install = spec["phases"]["install"]
    assert install["runtime-versions"] == {"python": "3.12"}
    assert install["commands"][0] == tier1.PIN_PYENV
    build = spec["phases"]["build"]["commands"]
    assert "rm -rf reports && mkdir reports" in build
    # the tool is fetched by pinned version + sha, never `aws s3 cp` by key
    assert any("CONTINUUM_TOOLS_VERSION" in c and "sha256" in c.lower() for c in build)
    assert not any("aws s3 cp" in c for c in build)
    # every Python command in the project runs isolated
    for command in install["commands"] + build:
        assert not unisolated_python(command), command


def test_the_zip_includes_a_file_an_export_ignore_would_hide(scan, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    (repo / "app.py").write_text("ok\n")
    (repo / "secret").mkdir()
    (repo / "secret" / "handler.py").write_text("x\n")
    (repo / ".gitattributes").write_text("secret/ export-ignore\n")
    git("add", "-A")
    git("commit", "-q", "-m", "c")

    out = tmp_path / "ls.zip"
    scan.archive(str(repo), str(out))
    names = set(zipfile.ZipFile(out).namelist())
    assert "secret/handler.py" in names and "app.py" in names   # ls-files keeps it
    # the old approach (git archive) would have hidden it behind export-ignore
    ga = tmp_path / "ga.zip"
    subprocess.run(["git", "-C", str(repo), "archive", "--format=zip", "-o", str(ga), "HEAD"],
                   check=True, capture_output=True)
    assert "secret/handler.py" not in set(zipfile.ZipFile(ga).namelist())


@pytest.mark.parametrize("value", [None, "false", "0", "off", False])
def test_off_or_unset_leaves_out_every_continuum_part(tier1, tmp_path, value):
    context = {} if value is None else {"enable_continuum": value}
    template, _ = synth(tier1, tmp_path, **context)
    text = json.dumps(template).lower()
    assert "continuum" not in text           # no action, project, role or grant
    _, actions = _gates_actions(template)
    assert "ContinuumScan" not in actions


def test_off_matches_a_stack_without_the_feature_resource_for_resource(tier1, tmp_path):
    on, _ = synth(tier1, tmp_path / "on", **ON)
    off, _ = synth(tier1, tmp_path / "off")          # unset == off (the default)
    added = set(on["Resources"]) - set(off["Resources"])
    # Everything the flag-off synth has, the flag-on synth also has: the flag
    # only ADDS, so off is the pre-feature stack resource-for-resource.
    assert set(off["Resources"]) <= set(on["Resources"])
    assert all(k.startswith(("Continuum", "PipelineAutomatedGatesContinuumScan",
                             "ScanToolsVersion"))
               for k in added), added


def test_on_without_the_identifiers_stops_synth_and_names_them(tier1, tmp_path):
    with pytest.raises(Exception) as e:
        synth(tier1, tmp_path, enable_continuum="true")      # no bucket, no env id
    message = str(e.value)
    assert "continuum_source_bucket" in message and "continuum_environment_id" in message
    # one supplied, one missing: name only the missing one
    with pytest.raises(Exception, match="continuum_environment_id"):
        synth(tier1, tmp_path, enable_continuum="true", continuum_source_bucket="b")


def test_an_unclear_switch_value_is_refused(tier1, tmp_path):
    with pytest.raises(Exception, match="enable_continuum"):
        synth(tier1, tmp_path, enable_continuum="maybe")


def test_an_unsupported_region_skips_with_a_warning_instead_of_failing(tier1, tmp_path):
    from aws_cdk.assertions import Match
    template, annotations = synth(tier1, tmp_path, region="eu-west-1", **ON)
    assert "continuum" not in json.dumps(template).lower()
    assert annotations.find_warning("*", Match.string_like_regexp(
        ".*us-east-1 and us-west-2, not eu-west-1.*"))


def test_the_stack_creates_no_continuum_integration_environment_or_bucket(tier1, tmp_path):
    template, _ = synth(tier1, tmp_path, **ON)
    resources = template["Resources"]
    # No custom resource (the old auto-create design); the operator owns those.
    assert not [k for k in resources if "Continuum" in k and resources[k]["Type"] == "Custom::AWS"]
    # No integration role assumed by the continuum service principal.
    for role in _of_type(resources, "AWS::IAM::Role").values():
        trust = json.dumps(role["Properties"].get("AssumeRolePolicyDocument", {}))
        assert "continuum.amazonaws.com" not in trust
    # The only new bucket a plain stack has is the pipeline's own artifacts; the
    # scan adds none of its own.
    assert not [k for k in resources if k.startswith("ContinuumSourceBucket")]


def test_the_scan_project_is_scoped_to_one_bucket_prefix_and_one_environment(tier1, tmp_path):
    template, _ = synth(tier1, tmp_path, **ON)
    resources = template["Resources"]
    [role_id] = [k for k in _of_type(resources, "AWS::IAM::Role")
                 if k.startswith("ContinuumScanProjectRole")]
    statements = _statements(resources, role_id)
    # continuum: only the three code-scan calls, only on the named environment.
    continuum = [s for s in statements if any(a.startswith("continuum:") for a in _actions(s))]
    assert {a for s in continuum for a in _actions(s)} == {
        "continuum:CreateCodeScan", "continuum:GetCodeScan", "continuum:ListCodeIssues"}
    for s in continuum:
        assert "environments/env-abc123" in json.dumps(s["Resource"])
        assert "environments/*" not in json.dumps(s["Resource"])    # not account-wide
    # S3: the only grant this construct adds is PutObject under code/ of the
    # named bucket. (CDK also grants the project read on the asset bucket and
    # read/write on the pipeline artifact bucket; those are scoped to named
    # buckets like every gate project, and checks.py accepts them.)
    puts = [s for s in statements if "my-scan-bucket" in json.dumps(s.get("Resource", ""))]
    assert puts, "no grant scoped to the source bucket"
    for s in puts:
        assert _actions(s) == ["s3:PutObject"]
        assert "my-scan-bucket/code/*" in json.dumps(s["Resource"])
    assert not any("bedrock:" in a for s in statements for a in _actions(s))


# ---- the scan script, offline -------------------------------------------------

@pytest.fixture
def scan(load_module):
    return load_module("tier1-codebuild/continuum_tools/continuum_scan.py")


def _args(**kw):
    base = dict(region="us-west-2", bucket="b", environment_id="env1", revision="abc",
                execution_id="exec-1", wait_seconds=60, source_dir=".", report="r.json")
    return types.SimpleNamespace(**{**base, **kw})


class StubClient:
    class exceptions:
        class ServiceQuotaExceededException(Exception):
            pass

    def __init__(self, statuses, issues, busy=False):
        self.statuses, self.issues, self.busy, self.calls = list(statuses), issues, busy, []

    def create_code_scan(self, **kw):
        self.calls.append(("create", kw))
        if self.busy:
            raise self.exceptions.ServiceQuotaExceededException()
        return {"scan": {"scanRunId": "s1", "status": self.statuses.pop(0)}}

    def get_code_scan(self, **kw):
        self.calls.append(("get", kw))
        return {"scan": {"scanRunId": "s1", "status": self.statuses.pop(0)}}

    def list_code_issues(self, **kw):
        self.calls.append(("list", kw))
        return {"items": self.issues}


class StubS3:
    def __init__(self):
        self.puts = []

    def put_object(self, **kw):
        self.puts.append(kw)


@pytest.fixture
def no_git(scan, monkeypatch, tmp_path):
    def fake_archive(src, out):
        open(out, "wb").write(b"PK")
    monkeypatch.setattr(scan, "archive", fake_archive)
    return scan


def test_an_unsupported_region_makes_no_call_and_says_why(scan):
    client = StubClient([], [])
    report = scan.run(_args(region="eu-west-1"), client=client, s3=StubS3())
    assert report["status"] == "SKIPPED_REGION" and "eu-west-1" in report["summary"]
    assert client.calls == []


def test_a_finished_scan_reports_issues_by_severity(no_git):
    issues = [{"name": "XSS in dedication", "severity": "HIGH", "status": "COMPLETED"},
              {"name": "Open redirect", "severity": "MEDIUM", "status": "IN_PROGRESS"}]
    client, s3 = StubClient(["SUBMITTED", "SCANNING", "SUCCEEDED"], issues), StubS3()
    report = no_git.run(_args(), client=client, s3=s3, sleep=lambda s: None)
    assert report["status"] == "SCAN_SUCCEEDED" and report["scan_run_id"] == "s1"
    assert report["counts"]["HIGH"] == 1 and report["counts"]["MEDIUM"] == 1
    assert "2 open issue(s) in the environment (1 HIGH, 1 MEDIUM)" in report["summary"]
    assert s3.puts[0]["Key"] == "code/source.zip"
    assert s3.puts[0]["Metadata"]["revision"] == "abc"
    assert ("create", {"environmentId": "env1", "clientToken": "exec-1"}) in client.calls


def test_a_scan_that_outlasts_the_wait_is_reported_not_failed(no_git):
    ticks = iter(range(0, 10_000, 30))
    client = StubClient(["SUBMITTED"] + ["SCANNING"] * 50, [])
    report = no_git.run(_args(wait_seconds=60), client=client, s3=StubS3(),
                        sleep=lambda s: None, clock=lambda: next(ticks))
    assert report["status"] == "SCAN_STILL_RUNNING"
    assert "still running" in report["summary"]


def test_a_scan_already_running_is_reported(no_git):
    report = no_git.run(_args(), client=StubClient([], [], busy=True), s3=StubS3())
    assert report["status"] == "SCAN_BUSY"


def test_any_error_is_reported_and_the_script_still_exits_zero(scan, tmp_path, monkeypatch):
    def broken(src, out):
        raise RuntimeError("no git here")
    monkeypatch.setattr(scan, "archive", broken)
    report = scan.run(_args(), client=StubClient([], []), s3=StubS3())
    assert report["status"] == "ERROR" and "RuntimeError" in report["error"]
    monkeypatch.setattr(scan, "run", lambda args: report)
    out = tmp_path / "r.json"
    assert scan.main(["--region", "us-west-2", "--bucket", "b", "--environment-id", "e",
                      "--report", str(out)]) == 0
    assert json.loads(out.read_text())["status"] == "ERROR"
