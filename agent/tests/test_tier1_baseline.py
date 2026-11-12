"""Tier 1's approved starting commit and pinned review policy: the bucket, the
review role's read, the fetch.

The stack is synthesized offline. The buildspec's fetch commands are run in a
shell against a stub `aws` that prints the CLI's own error lines, so no AWS call
is made.
"""
import hashlib
import importlib
import json
import os
import pathlib
import subprocess
import sys

import pytest

from conftest import ROOT, unisolated_python


@pytest.fixture
def tier1(monkeypatch, tmp_path):
    app_dir = ROOT / "tier1-codebuild"
    monkeypatch.chdir(app_dir)
    monkeypatch.syspath_prepend(str(app_dir))
    module = importlib.import_module("tier1_stack")
    # The stack's asset paths are relative to the CDK app directory. The jsii
    # runtime is a separate process that keeps the directory of the first test
    # that started it, so resolve them here instead of relying on chdir.
    original = module.s3_assets.Asset

    def asset(scope, cid, *, path, **kw):
        return original(scope, cid, path=str((app_dir / path).resolve()), **kw)

    monkeypatch.setattr(module.s3_assets, "Asset", asset)
    return module


@pytest.fixture
def template(tier1, tmp_path):
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    app = cdk.App(outdir=str(tmp_path / "cdk.out"), context={"source": "codecommit"})
    stack = tier1.Tier1PipelineStack(app, "Tier1PipelineStack",
                                     env=cdk.Environment(region="us-west-2"))
    return Template.from_stack(stack).to_json()


def _of_type(resources, kind):
    return {k: v for k, v in resources.items() if v["Type"] == kind}


def _baseline_id(resources):
    [bucket_id] = [k for k in _of_type(resources, "AWS::S3::Bucket") if k.startswith("BaselineBucket")]
    return bucket_id


def _role_statements(resources, role_prefix):
    [role_id] = [k for k in _of_type(resources, "AWS::IAM::Role") if k.startswith(role_prefix)]
    statements = []
    for policy in _of_type(resources, "AWS::IAM::Policy").values():
        if {"Ref": role_id} in policy["Properties"]["Roles"]:
            statements += policy["Properties"]["PolicyDocument"]["Statement"]
    return statements


def _listify(value):
    return value if isinstance(value, list) else [value]


def test_the_baseline_bucket_is_versioned_private_encrypted_and_retained(template):
    resources = template["Resources"]
    bucket = resources[_baseline_id(resources)]
    props = bucket["Properties"]
    assert props["VersioningConfiguration"] == {"Status": "Enabled"}
    assert props["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True}
    assert props["BucketEncryption"]["ServerSideEncryptionConfiguration"] == [
        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    assert bucket["DeletionPolicy"] == "Retain"
    assert bucket["UpdateReplacePolicy"] == "Retain"
    assert {"NoncurrentVersionExpiration": {"NoncurrentDays": 365}, "Status": "Enabled"} in \
        props["LifecycleConfiguration"]["Rules"]
    # Nothing empties it on stack deletion.
    assert not any(k.startswith("BaselineBucketAutoDeleteObjects") for k in resources)
    # enforce_ssl: the bucket policy denies any request without TLS.
    [policy] = [p for p in _of_type(resources, "AWS::S3::BucketPolicy").values()
                if p["Properties"]["Bucket"] == {"Ref": _baseline_id(resources)}]
    [deny] = policy["Properties"]["PolicyDocument"]["Statement"]
    assert deny["Effect"] == "Deny"
    assert deny["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert template["Outputs"]["BaselineBucketName"]["Value"] == {"Ref": _baseline_id(resources)}


@pytest.mark.parametrize("role_prefix", ["AgentReviewGateRole", "ThreatModelGateRole"])
def test_the_gate_roles_read_only_the_one_object(template, role_prefix):
    resources = template["Resources"]
    bucket_id = _baseline_id(resources)
    touching = [s for s in _role_statements(resources, role_prefix)
                if bucket_id in json.dumps(s.get("Resource"))]
    by_sid = {s["Sid"]: s for s in touching}
    assert set(by_sid) == {"ReadApprovedBaseline", "TellApprovedBaselineMissing"}
    read = by_sid["ReadApprovedBaseline"]
    assert read["Effect"] == "Allow"
    assert sorted(_listify(read["Action"])) == ["s3:GetObject", "s3:GetObjectVersion"]
    assert read["Resource"] == {"Fn::Join": ["", [
        {"Fn::GetAtt": [bucket_id, "Arn"]}, "/approved-baseline.json"]]}
    # Listing is only for this key name, so a missing object reads as NoSuchKey.
    listing = by_sid["TellApprovedBaselineMissing"]
    assert _listify(listing["Action"]) == ["s3:ListBucket"]
    assert listing["Resource"] == {"Fn::GetAtt": [bucket_id, "Arn"]}
    assert listing["Condition"] == {"StringEquals": {"s3:prefix": "approved-baseline.json"}}
    # No write anywhere, and no S3 grant on "*" that would reach this bucket.
    for statement in _role_statements(resources, role_prefix):
        actions = _listify(statement["Action"])
        if "*" in _listify(statement.get("Resource")):
            assert not any(a.startswith("s3:") for a in actions), statement
    assert not any(a for s in touching for a in _listify(s["Action"])
                   if a.startswith("s3:Put") or a.startswith("s3:Delete"))


@pytest.mark.parametrize("role_prefix", ["DeterministicLaneRole", "PackageAppRole"])
def test_other_roles_cannot_read_the_baseline(template, role_prefix):
    resources = template["Resources"]
    bucket_id = _baseline_id(resources)
    assert not [s for s in _role_statements(resources, role_prefix)
                if bucket_id in json.dumps(s.get("Resource"))]


def _projects(resources):
    return {p["Properties"]["Name"]: p["Properties"]
            for p in _of_type(resources, "AWS::CodeBuild::Project").values()}


def test_review_and_threat_model_fetch_the_same_object_before_preparing(template, tier1):
    resources = template["Resources"]
    projects = _projects(resources)
    for name in ("agentic-gates-tier1-review", "agentic-gates-tier1-threatmodel"):
        env = {v["Name"]: v["Value"] for v in projects[name]["Environment"]["EnvironmentVariables"]}
        assert env["BASELINE_BUCKET"] == {"Ref": _baseline_id(resources)}
        commands = json.loads(projects[name]["Source"]["BuildSpec"])["phases"]["build"]["commands"]
        fetch = commands.index(tier1.FETCH_APPROVED_BASELINE)
        prepare = next(i for i, c in enumerate(commands)
                       if "prepare_review.py --pipeline" in c)
        assert fetch < prepare
        assert '${BASELINE_FILE:+--approved-baseline "$BASELINE_FILE"}' in commands[prepare]
        assert ('${BASELINE_VERSION:+--approved-baseline-version "$BASELINE_VERSION"}'
                in commands[prepare])
    for name, project in projects.items():
        if name not in ("agentic-gates-tier1-review", "agentic-gates-tier1-threatmodel"):
            assert "approved-baseline" not in project["Source"]["BuildSpec"], name


def test_the_baseline_kind_is_exported_and_shown_to_the_approver(template):
    resources = template["Resources"]
    spec = json.loads(_projects(resources)["agentic-gates-tier1-review"]["Source"]["BuildSpec"])
    assert "BASELINE_KIND" in spec["env"]["exported-variables"]
    commands = spec["phases"]["build"]["commands"]
    export = next(i for i, c in enumerate(commands) if c.startswith("export BASELINE_KIND="))
    assert "input-metadata.json" in commands[export]
    assert export > next(i for i, c in enumerate(commands) if "prepare_review.py --pipeline" in c)
    [pipeline] = _of_type(resources, "AWS::CodePipeline::Pipeline").values()
    [approval] = [a for st in pipeline["Properties"]["Stages"] for a in st["Actions"]
                  if a["ActionTypeId"]["Category"] == "Approval"]
    assert "#{ReviewGate.BASELINE_KIND}" in approval["Configuration"]["CustomData"]


# --- the fetch command itself, against a stub AWS CLI ----------------------------------

STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$STUB_MODE" in
  found) printf '{"version": 1}' > "$STUB_OUT"; echo "$STUB_VERSION"; exit 0 ;;
  missing) echo 'An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.' >&2; exit 254 ;;
  denied) echo 'An error occurred (AccessDenied) when calling the GetObject operation: Access Denied' >&2; exit 254 ;;
  nobucket) echo 'An error occurred (NoSuchBucket) when calling the GetObject operation: The specified bucket does not exist' >&2; exit 254 ;;
  network) echo 'Could not connect to the endpoint URL: "https://example.invalid/approved-baseline.json"' >&2; exit 255 ;;
esac
exit 99
"""


def run_fetch(tier1, tmp_path, mode, version="3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "aws").write_text(STUB)
    (bin_dir / "aws").chmod(0o755)
    log = tmp_path / "aws.log"
    # The buildspec's /tmp paths, moved into this test's own directory.
    script = (tier1.FETCH_APPROVED_BASELINE.replace("/tmp/", f"{tmp_path}/") + "\n"
              # The same expansions the prepare command uses, one word per line.
              "printf '<%s>\\n' ${BASELINE_FILE:+--approved-baseline \"$BASELINE_FILE\"}"
              " ${BASELINE_VERSION:+--approved-baseline-version \"$BASELINE_VERSION\"}\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "STUB_MODE": mode,
           "STUB_VERSION": version, "STUB_LOG": str(log), "BASELINE_BUCKET": "state-bucket",
           "STUB_OUT": str(tmp_path / "approved-baseline.json")}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True,
                            timeout=30)
    return result, log.read_text()


def test_a_fetched_file_passes_the_file_and_its_version(tier1, tmp_path):
    result, calls = run_fetch(tier1, tmp_path, "found")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-4:] == [
        "<--approved-baseline>", f"<{tmp_path}/approved-baseline.json>",
        "<--approved-baseline-version>", "<3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY>"]
    assert (tmp_path / "approved-baseline.json").exists()
    assert calls.split() == ["s3api", "get-object", "--bucket", "state-bucket", "--key",
                             "approved-baseline.json", f"{tmp_path}/approved-baseline.json",
                             "--query", "VersionId", "--output", "text"]


def test_a_fetched_file_without_a_version_passes_only_the_file(tier1, tmp_path):
    result, _ = run_fetch(tier1, tmp_path, "found", version="None")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-2:] == ["<--approved-baseline>",
                                               f"<{tmp_path}/approved-baseline.json>"]
    assert "--approved-baseline-version" not in result.stdout


def test_no_such_key_goes_on_without_the_file(tier1, tmp_path):
    result, _ = run_fetch(tier1, tmp_path, "missing")
    assert result.returncode == 0, result.stderr
    assert "No approved starting commit file" in result.stdout
    assert "<--" not in result.stdout   # no flags at all
    assert not (tmp_path / "approved-baseline.json").exists()


@pytest.mark.parametrize("mode", ["denied", "nobucket", "network", "unexpected"])
def test_any_other_error_stops_the_build(tier1, tmp_path, mode):
    result, _ = run_fetch(tier1, tmp_path, mode)
    assert result.returncode == 1
    assert "stopping" in result.stderr
    assert "<--" not in result.stdout


# --- every fetched asset: one S3 version and a SHA-256 of its content, fixed at deploy ---

REVIEW, THREAT = "agentic-gates-tier1-review", "agentic-gates-tier1-threatmodel"
DETERMINISTIC = "agentic-gates-tier1-deterministic"
# env prefix, asset id, fetch command, the projects that fetch it, its first use
PINS = [
    ("REVIEW_POLICY", "ReviewPolicy", "FETCH_REVIEW_POLICY", (REVIEW, THREAT),
     "prepare_review.py --pipeline"),
    ("REVIEW_INPUTS", "ReviewInputTools", "FETCH_REVIEW_INPUTS", (REVIEW, THREAT),
     "python -I /tmp/input-tools/"),
    ("AGENT_ASSET", "AgentPackage", "FETCH_AGENT", (REVIEW,), "python -I /tmp/agentpkg/"),
    ("DET_TOOLS", "DeterministicTools", "FETCH_DET_TOOLS", (DETERMINISTIC,), "python -I /tmp/det/"),
    ("TM_TOOLS", "ThreatModelTools", "FETCH_TM_TOOLS", (THREAT,), "python -I /tmp/tm/"),
]
BOOTSTRAP_BUCKET = {"Fn::Sub": "cdk-hnb659fds-assets-${AWS::AccountId}-us-west-2"}


def _synth(tier1, outdir, **context):
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    app = cdk.App(outdir=str(outdir), context={"source": "codecommit", **context})
    stack = tier1.Tier1PipelineStack(app, "Tier1PipelineStack",
                                     env=cdk.Environment(region="us-west-2"))
    return Template.from_stack(stack).to_json()


def _shell_sha256(tier1, staged):
    """The hash the build computes: sha256sum for a file, TREE_SHA256 for a tree."""
    if staged.is_file():
        return subprocess.run(["sha256sum", str(staged)], capture_output=True, text=True,
                              check=True).stdout.split()[0]
    return subprocess.run(["sh", "-c", tier1.TREE_SHA256], cwd=staged, capture_output=True,
                          text=True, check=True).stdout.strip()


@pytest.mark.parametrize("var,asset_id,fetch_name,fetched_by,first_use", PINS,
                         ids=[p[0] for p in PINS])
def test_each_fetched_asset_is_pinned_to_a_version_and_its_staged_bytes(
        tier1, tmp_path, var, asset_id, fetch_name, fetched_by, first_use):
    template = _synth(tier1, tmp_path / "cdk.out")
    resources = template["Resources"]
    [cr_id] = [k for k, v in resources.items()
               if v["Type"] == "Custom::AWS" and k.startswith(f"{asset_id}Version")]
    projects = _projects(resources)
    keys = set()
    for name in fetched_by:
        env = {v["Name"]: v["Value"] for v in projects[name]["Environment"]["EnvironmentVariables"]}
        assert env[f"{var}_VERSION"] == {"Fn::GetAtt": [cr_id, "VersionId"]}
        assert env[f"{var}_BUCKET"] == BOOTSTRAP_BUCKET
        key = env[f"{var}_KEY"]
        keys.add(key)
        # The hash is of the staged copy cdk-assets uploads, as the build computes it.
        staged = tmp_path / "cdk.out" / f"asset.{key.removesuffix('.zip')}"
        assert env[f"{var}_SHA256"] == _shell_sha256(tier1, staged)
        commands = json.loads(projects[name]["Source"]["BuildSpec"])["phases"]["build"]["commands"]
        fetch = commands.index(getattr(tier1, fetch_name))
        assert fetch < next(i for i, c in enumerate(commands) if first_use in c)
    for name, project in projects.items():
        names = {v["Name"] for v in project["Environment"].get("EnvironmentVariables", [])}
        assert not [n for n in names if n.endswith("_URL")], name
        if name not in fetched_by:
            assert f"{var}_KEY" not in names, name
    [key] = keys
    # The version comes from a HeadObject of that same key, once per asset content.
    props = resources[cr_id]["Properties"]
    call = props["Create"]["Fn::Join"][1]
    assert call[0].startswith('{"action":"headObject","service":"S3","outputPaths":["VersionId"]')
    assert f'"Key":"{key}"' in call[2]
    assert f'"physicalResourceId":{{"id":"{key.split(".")[0]}"}}' in call[2]
    assert props["Update"] == props["Create"]
    assert props["InstallLatestAwsSdk"] is False


def test_the_pin_role_reads_asset_objects_and_an_asset_change_touches_no_iam(tier1, tmp_path):
    first = _synth(tier1, tmp_path / "a")["Resources"]
    [(role_id, role)] = [(k, v) for k, v in _of_type(first, "AWS::IAM::Role").items()
                         if k.startswith("AssetPinRole")]
    [inline] = role["Properties"]["Policies"]
    [statement] = inline["PolicyDocument"]["Statement"]
    assert statement["Action"] == "s3:GetObject"
    assert statement["Resource"]["Fn::Join"][1][-2:] == [BOOTSTRAP_BUCKET, "/*"]
    # The custom resources' provider runs as that role. No managed policy is
    # attached to it, and the only other policy writes the provider's own logs.
    [(provider_id, provider)] = [
        (k, v) for k, v in _of_type(first, "AWS::Lambda::Function").items()
        if v["Properties"]["Role"] == {"Fn::GetAtt": [role_id, "Arn"]}]
    assert provider["Properties"]["Timeout"] == 120
    assert "ManagedPolicyArns" not in role["Properties"]
    [logs] = [p for p in _of_type(first, "AWS::IAM::Policy").values()
              if {"Ref": role_id} in p["Properties"]["Roles"]]
    [write] = logs["Properties"]["PolicyDocument"]["Statement"]
    assert sorted(write["Action"]) == ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"]
    group = ["arn:aws:logs:us-west-2:", {"Ref": "AWS::AccountId"},
             ":log-group:/aws/lambda/", {"Ref": provider_id}]
    assert write["Resource"] == [{"Fn::Join": ["", group]},
                                 {"Fn::Join": ["", group + [":*"]]}]
    # A different review policy changes the pin, and no IAM resource.
    policy = tmp_path / "other-policy.yaml"
    policy.write_text((ROOT / ".reviewer.yaml").read_text() + "# a reviewed edit\n")
    second = _synth(tier1, tmp_path / "b", review_policy_file=str(policy))["Resources"]
    iam = ("AWS::IAM::Role", "AWS::IAM::Policy")
    assert {k: v for k, v in first.items() if v["Type"] in iam} == \
        {k: v for k, v in second.items() if v["Type"] in iam}
    changed = {k for k in first if first[k] != second.get(k)}
    assert {k.rstrip("0123456789ABCDEF") for k in changed} >= {"ReviewPolicyVersion"}


def test_pin_refresh_re_pins_every_asset_and_refuses_odd_values(tier1, tmp_path):
    resources = _synth(tier1, tmp_path / "a", pin_refresh="2026-11-09")["Resources"]
    pins = {k: v for k, v in resources.items() if v["Type"] == "Custom::AWS"}
    assert len(pins) == len(PINS)
    for pin in pins.values():
        assert '-2026-11-09"}}' in pin["Properties"]["Update"]["Fn::Join"][1][2]
    with pytest.raises(Exception, match="pin_refresh"):
        _synth(tier1, tmp_path / "b", pin_refresh="2026 11 09; rm")


def test_the_synth_tree_hash_is_the_one_the_build_computes(tier1, tmp_path):
    root = tmp_path / "tree"
    for name, body in {"a.py": b"x = 1\n", "sub/b c.txt": b"two words\n", ".hidden": b"",
                       "sub/deeper/é.txt": "café\n".encode(), "B.txt": b"upper first\n"}.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(body)
    (root / "empty-dir").mkdir()
    assert tier1.tree_sha256(root) == _shell_sha256(tier1, root)
    (root / "link").symlink_to(root / "a.py")
    with pytest.raises(ValueError, match="symlink"):
        tier1.tree_sha256(root)


@pytest.mark.parametrize("role_prefix", ["AgentReviewGateRole", "ThreatModelGateRole"])
def test_the_gate_roles_can_read_a_pinned_version(template, role_prefix):
    resources = template["Resources"]
    # CDK's Asset.grant_read covers the asset bucket, not one key.
    reads = [s for s in _role_statements(resources, role_prefix)
             if "cdk-hnb659fds-assets-" in json.dumps(s.get("Resource"))]
    assert reads and all(s["Effect"] == "Allow" for s in reads)
    actions = {a for s in reads for a in _listify(s["Action"])}
    assert "s3:GetObject*" in actions   # covers s3:GetObjectVersion
    assert not any(a.startswith(("s3:Put", "s3:Delete")) for a in actions)


POLICY_STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
for out; do :; done
case "$STUB_MODE" in
  found) printf '%s' "$STUB_CONTENT" > "$out"; echo '{"VersionId": "pinned"}'; exit 0 ;;
  denied) echo 'An error occurred (AccessDenied) when calling the GetObject operation: Access Denied' >&2; exit 254 ;;
  noversion) echo 'An error occurred (NoSuchVersion) when calling the GetObject operation: The specified version does not exist.' >&2; exit 254 ;;
esac
exit 99
"""
POLICY_TEXT = "version: 1\nrules: []\n"


def run_policy_fetch(tier1, tmp_path, mode="found", version="3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY",
                     sha=None, content=POLICY_TEXT):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "aws").write_text(POLICY_STUB)
    (bin_dir / "aws").chmod(0o755)
    log = tmp_path / "aws.log"
    log.write_text("")
    script = tier1.FETCH_REVIEW_POLICY.replace("/tmp/", f"{tmp_path}/")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "STUB_MODE": mode,
           "STUB_LOG": str(log), "STUB_CONTENT": content,
           "REVIEW_POLICY_BUCKET": "asset-bucket", "REVIEW_POLICY_KEY": "abc123.yaml",
           "REVIEW_POLICY_VERSION": version,
           "REVIEW_POLICY_SHA256": hashlib.sha256(POLICY_TEXT.encode()).hexdigest()
           if sha is None else sha}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True,
                            timeout=30)
    return result, log.read_text()


def test_the_pinned_version_with_the_pinned_hash_is_used(tier1, tmp_path):
    result, calls = run_policy_fetch(tier1, tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "rules.yaml").read_text() == POLICY_TEXT
    assert calls.split() == ["s3api", "get-object", "--bucket", "asset-bucket", "--key",
                             "abc123.yaml", "--version-id", "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY",
                             f"{tmp_path}/rules.yaml"]
    assert "S3 version 3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY" in result.stdout


@pytest.mark.parametrize("content,sha", [
    ("version: 1\nrules: []  # weakened\n", None),      # the object changed
    (POLICY_TEXT, "0" * 64),                             # the recorded hash differs
    (POLICY_TEXT, ""),                                   # no hash recorded
])
def test_a_hash_mismatch_stops_the_build(tier1, tmp_path, content, sha):
    result, _ = run_policy_fetch(tier1, tmp_path, content=content, sha=sha)
    assert result.returncode == 1
    assert "does not match its pinned SHA-256; stopping" in result.stderr
    assert not (tmp_path / "rules.yaml").exists()


@pytest.mark.parametrize("version", ["", "None", "null"])
def test_a_missing_version_stops_the_build_before_any_read(tier1, tmp_path, version):
    result, calls = run_policy_fetch(tier1, tmp_path, version=version)
    assert result.returncode == 1
    assert "no pinned S3 version; stopping" in result.stderr
    assert calls == ""
    assert not (tmp_path / "rules.yaml").exists()


@pytest.mark.parametrize("mode", ["denied", "noversion", "unexpected"])
def test_a_failed_read_of_the_version_stops_the_build(tier1, tmp_path, mode):
    result, _ = run_policy_fetch(tier1, tmp_path, mode=mode)
    assert result.returncode == 1
    assert "Could not read the pinned review policy version; stopping" in result.stderr
    assert not (tmp_path / "rules.yaml").exists()


# --- the four zip fetches, against a stub AWS CLI that returns a prepared zip ----------

ZIP_STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
for out; do :; done
case "$STUB_MODE" in
  found) cp "$STUB_ZIP" "$out"; echo '{"VersionId": "pinned"}'; exit 0 ;;
  denied) echo 'An error occurred (AccessDenied) when calling the GetObject operation: Access Denied' >&2; exit 254 ;;
esac
exit 99
"""
ZIP_PINS = [(var, fetch) for var, _, fetch, _, _ in PINS if var != "REVIEW_POLICY"]


def run_zip_fetch(tier1, tmp_path, var, fetch_name, mode="found", version="v1",
                  tamper=None):
    import zipfile
    tree = tmp_path / "tree"
    for name, body in {"tool.py": "print('pinned')\n", "pkg/__init__.py": "",
                       "pkg/rules.py": "LIMIT = 3\n"}.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(body)
    sha = tier1.tree_sha256(tree)
    files = {p.relative_to(tree).as_posix(): p.read_bytes() for p in tree.rglob("*") if p.is_file()}
    if tamper == "changed":
        files["pkg/rules.py"] = b"LIMIT = 300\n"
    elif tamper == "added":
        files["pkg/extra.py"] = b"import os\n"
    zip_path = tmp_path / "published.zip"
    if tamper == "corrupt":
        zip_path.write_bytes(b"not a zip")
    else:
        with zipfile.ZipFile(zip_path, "w") as z:
            for name, body in files.items():
                z.writestr(name, body)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "aws").write_text(ZIP_STUB)
    (bin_dir / "aws").chmod(0o755)
    log = tmp_path / "aws.log"
    log.write_text("")
    work = tmp_path / "work"
    work.mkdir()
    script = getattr(tier1, fetch_name).replace("/tmp/", f"{work}/")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "STUB_MODE": mode,
           "STUB_LOG": str(log), "STUB_ZIP": str(zip_path), f"{var}_BUCKET": "asset-bucket",
           f"{var}_KEY": "abc123.zip", f"{var}_VERSION": version, f"{var}_SHA256": sha}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True,
                            timeout=30)
    unpacked = [p for p in work.iterdir() if p.is_dir()]
    return result, log.read_text(), unpacked


@pytest.mark.parametrize("var,fetch_name", ZIP_PINS, ids=[v for v, _ in ZIP_PINS])
def test_a_zip_with_the_pinned_tree_is_unpacked(tier1, tmp_path, var, fetch_name):
    result, calls, [unpacked] = run_zip_fetch(tier1, tmp_path, var, fetch_name)
    assert result.returncode == 0, result.stderr
    assert (unpacked / "pkg/rules.py").read_text() == "LIMIT = 3\n"
    assert calls.split()[:8] == ["s3api", "get-object", "--bucket", "asset-bucket", "--key",
                                 "abc123.zip", "--version-id", "v1"]
    assert "S3 version v1" in result.stdout


@pytest.mark.parametrize("tamper", ["changed", "added"])
@pytest.mark.parametrize("var,fetch_name", ZIP_PINS, ids=[v for v, _ in ZIP_PINS])
def test_a_zip_whose_tree_differs_stops_the_build(tier1, tmp_path, var, fetch_name, tamper):
    result, _, unpacked = run_zip_fetch(tier1, tmp_path, var, fetch_name, tamper=tamper)
    assert result.returncode == 1
    assert "does not match its pinned SHA-256; stopping" in result.stderr
    assert unpacked == []          # nothing is left to run


@pytest.mark.parametrize("var,fetch_name", ZIP_PINS, ids=[v for v, _ in ZIP_PINS])
def test_a_zip_without_a_version_or_unreadable_stops_the_build(tier1, tmp_path, var,
                                                               fetch_name):
    for case, kwargs, message in [
            ("no-version", {"version": "null"}, "no pinned S3 version; stopping"),
            ("denied", {"mode": "denied"}, "version; stopping"),
            ("corrupt", {"tamper": "corrupt"}, "Could not unpack the pinned"),
    ]:
        case_dir = tmp_path / case
        case_dir.mkdir()
        result, calls, unpacked = run_zip_fetch(tier1, case_dir, var, fetch_name, **kwargs)
        assert result.returncode == 1, case
        assert message in result.stderr, (case, result.stderr)
        assert not [p for p in unpacked if any(p.iterdir())], case
        if case == "no-version":
            assert calls == ""


# --- no gate build imports from the candidate checkout ----------------------------------

UNIT_TESTS = "python -m unittest discover -s tests -p 'test_*.py' -v"
GATES = (REVIEW, DETERMINISTIC, THREAT)


def _buildspecs(tier1, tmp_path):
    """Every CodeBuild project's commands, all phases, for each deploy kind,
    and flag-on so the optional Continuum scan project is covered too."""
    specs = {}
    for kind in ("sam", "cdk", "none"):
        resources = _synth(tier1, tmp_path / kind, deploy_kind=kind)["Resources"]
        for name, project in _projects(resources).items():
            phases = json.loads(project["Source"]["BuildSpec"])["phases"]
            specs[name] = [c for phase in phases.values() for c in phase.get("commands", [])]
    # Flag-on adds `agentic-gates-tier1-continuum`; it needs an explicit Region
    # to synthesize (skipped on an unresolved one), so build a fresh App here.
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    app = cdk.App(outdir=str(tmp_path / "on"), context={
        "source": "codecommit", "enable_continuum": "true",
        "continuum_source_bucket": "my-scan-bucket", "continuum_environment_id": "env-abc123"})
    stack = tier1.Tier1PipelineStack(app, "Tier1PipelineStack",
                                     env=cdk.Environment(region="us-west-2"))
    for name, project in _projects(Template.from_stack(stack).to_json()["Resources"]).items():
        phases = json.loads(project["Source"]["BuildSpec"])["phases"]
        specs.setdefault(name, [c for phase in phases.values() for c in phase.get("commands", [])])
    return specs


def test_only_the_cdk_trio_lets_the_deterministic_lane_find_no_template(tier1, tmp_path):
    """The road (cdk) guards this repository, which has no template.yaml; a SAM
    artifact that misnames its template must still be refused."""
    for kind, allowed in (("sam", False), ("cdk", True), ("none", False)):
        project = _projects(_synth(tier1, tmp_path / kind, deploy_kind=kind)["Resources"])[DETERMINISTIC]
        [check] = [c for c in json.loads(project["Source"]["BuildSpec"])["phases"]["build"]["commands"]
                   if "/tmp/det/checks.py" in c]
        assert ("--allow-no-templates" in check) is allowed, (kind, check)
        assert "--templates 'template.yaml'" in check


# The one finding the deterministic lane reports on this stack and the sample
# keeps, and why (tier1_stack.py, the AppCdn statement). Any other finding, or
# this one going away, fails the test below.
ACCEPTED_FINDINGS = {
    ("sam", "AppDeployRoleDefaultPolicyBEE5B8F6",
     "write actions with an account-wide Resource arn:aws:cloudfront::<resource>:"
     "distribution/*; name the resource"):
        "CloudFront picks each distribution and cache policy ID when it creates it",
}


def test_each_kind_passes_its_own_deterministic_lane(tier1, tmp_path):
    """The stack's own templates, run through checks.py as the lane runs it,
    without the Access Analyzer call (this suite makes no AWS call)."""
    found = set()
    for kind in ("sam", "cdk", "none"):
        out = tmp_path / kind
        _synth(tier1, out, deploy_kind=kind)
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "deterministic" / "checks.py"),
             "--skip-access-analyzer", "--templates", str(out / "*.template.json"),
             "--repo-root", str(ROOT)], capture_output=True, text=True, timeout=120)
        assert "DETERMINISTIC LANE:" in result.stdout, result.stderr
        assert "(no templates matched" not in result.stdout, kind
        blocking = {(kind, *line.split("[BLOCKING] ", 1)[1].split(": ", 1))
                    for line in result.stdout.splitlines() if "[BLOCKING]" in line}
        assert result.returncode == (1 if blocking else 0), result.stdout
        found |= blocking
    assert found == set(ACCEPTED_FINDINGS)


def test_each_kind_passes_its_own_deterministic_lane_with_continuum_on(tier1, tmp_path):
    """The optional Continuum scan (-c enable_continuum=true) adds the scan
    action; the stack's own checks.py must still pass on every kind's template,
    with the SAME accepted findings as the flag-off lane -- the opt-in grants
    only a bucket-prefix PutObject and a named-environment scan, so it adds no
    account-wide write and no new blocking IAM finding. Needs an explicit Region
    so the scan actually synthesizes (it is skipped on an unresolved Region)."""
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    found = set()
    for kind in ("sam", "cdk", "none"):
        out = tmp_path / kind
        app = cdk.App(outdir=str(out), context={"source": "codecommit",
                                                 "deploy_kind": kind,
                                                 "enable_continuum": "true",
                                                 "continuum_source_bucket": "my-scan-bucket",
                                                 "continuum_environment_id": "env-abc123"})
        stack = tier1.Tier1PipelineStack(app, "Tier1PipelineStack",
                                         env=cdk.Environment(region="us-west-2"))
        template = Template.from_stack(stack).to_json()
        assert any(k.startswith("Continuum") for k in template["Resources"]), kind
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "deterministic" / "checks.py"),
             "--skip-access-analyzer", "--templates", str(out / "*.template.json"),
             "--repo-root", str(ROOT)], capture_output=True, text=True, timeout=120)
        assert "DETERMINISTIC LANE:" in result.stdout, result.stderr
        assert "(no templates matched" not in result.stdout, kind
        blocking = {(kind, *line.split("[BLOCKING] ", 1)[1].split(": ", 1))
                    for line in result.stdout.splitlines() if "[BLOCKING]" in line}
        assert result.returncode == (1 if blocking else 0), result.stdout
        found |= blocking
    assert found == set(ACCEPTED_FINDINGS)


def test_every_buildspec_runs_python_isolated(tier1, tmp_path):
    specs = _buildspecs(tier1, tmp_path)
    assert set(GATES) | {"agentic-gates-tier1-tests", "agentic-gates-tier1-dashboard-deploy",
                         "agentic-gates-tier1-continuum"} <= set(specs)
    for name, commands in specs.items():
        for command in commands:
            if command == UNIT_TESTS:     # the change's own tests, by design (tier1_stack.py)
                assert name == "agentic-gates-tier1-tests"
                continue
            assert not unisolated_python(command), (name, command)
    # The scanner itself sees the forms the buildspecs use.
    assert unisolated_python('X=$(python -c "import json")') and \
        unisolated_python("pip install x") and unisolated_python(".venv/bin/python -m pip x")
    assert not unisolated_python('X=$(python -I -c "import json") && python3 -I -m venv .venv')


def test_gate_projects_pin_the_interpreter_and_set_the_second_guard(tier1, tmp_path):
    resources = _synth(tier1, tmp_path / "cdk.out")["Resources"]
    projects = _projects(resources)
    for name in GATES:
        env = {v["Name"]: v["Value"] for v in projects[name]["Environment"]["EnvironmentVariables"]}
        assert (env["PYTHONSAFEPATH"], env["PYTHONNOUSERSITE"]) == ("1", "1"), name
        install = json.loads(projects[name]["Source"]["BuildSpec"])["phases"]["install"]
        # 3.12 honours PYTHONSAFEPATH. The image also caches 3.9, which does not;
        # PIN_PYENV keeps a checkout from picking it, and -I isolates on 3.9 too.
        assert install["runtime-versions"] == {"python": "3.12"}
        assert install["commands"][0] == tier1.PIN_PYENV, name


HOSTILE = {"json.py", "pathlib.py", "argparse.py", "boto3.py", "botocore/__init__.py",
           "reviewer/__init__.py", "yaml.py"}


def _hostile_checkout(root, marker):
    for name in HOSTILE:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(f"open({str(marker)!r}, 'a').write({name!r} + '\\n')\n")
    (root / ".python-version").write_text("3.9.0\n")


def test_a_json_py_in_the_candidate_checkout_is_never_imported(tier1, tmp_path):
    checkout, work, marker = tmp_path / "checkout", tmp_path / "work", tmp_path / "hijacked"
    checkout.mkdir()
    (work / "review-input").mkdir(parents=True)
    _hostile_checkout(checkout, marker)
    (work / "review-input/input-metadata.json").write_text('{"baseline_kind": "approved_baseline"}')
    (checkout / "reports").mkdir()
    findings = '{"verdict": "FAIL", "stats": {"blocking": 2}}'
    phases = json.loads(_projects(_synth(tier1, tmp_path / "cdk.out")["Resources"])[REVIEW]
                        ["Source"]["BuildSpec"])["phases"]
    # The review build's own Python one-liners (all but the S3 upload, which needs AWS).
    lines = [c for p in ("install", "build") for c in phases[p]["commands"]
             if "python -I -c" in c and "boto3.client" not in c]
    assert len(lines) == 5
    script = "\n".join(c.replace("/tmp/", f"{work}/") for c in lines) + \
        '\necho "KIND=$BASELINE_KIND VERDICT=$VERDICT BLOCKING=$BLOCKING"\n'
    env = {**os.environ, "PATH": f"{pathlib.Path(sys.executable).parent}:{os.environ['PATH']}",
           "CODEBUILD_BUILD_ID": "review:7"}
    env.pop("PYTHONSAFEPATH", None)

    def run(text, *flags):
        (checkout / "reports/findings.json").write_text(findings)
        marker.unlink(missing_ok=True)
        return subprocess.run(["bash", *flags, "-c", text], cwd=checkout, env=env,
                              capture_output=True, text=True, timeout=60)

    result = run(script, "-e")
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), marker.read_text()
    assert "KIND=approved_baseline VERDICT=FAIL BLOCKING=2" in result.stdout
    assert json.loads((checkout / "reports/findings.json").read_text())["build_id"] == "review:7"
    # The same commands without -I run the candidate's json.py: the hole this closes.
    run(script.replace("python -I ", "python "))
    assert {"json.py", "pathlib.py", "botocore/__init__.py"} <= set(marker.read_text().split())


def test_a_json_py_in_the_checkout_cannot_hijack_the_continuum_summary(tier1, tmp_path):
    # The Continuum scan runs with the candidate checkout as cwd and writes its
    # summary verbatim into the human approval note. python -I keeps a committed
    # json.py from running in place of the stdlib (reproduces the checker's hole).
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    checkout, marker = tmp_path / "checkout", tmp_path / "hijacked"
    checkout.mkdir()
    _hostile_checkout(checkout, marker)
    (checkout / "reports").mkdir()
    (checkout / "reports/continuum.json").write_text(
        '{"summary": "REAL: scan succeeded; 0 open issue(s) in the environment"}')
    app = cdk.App(outdir=str(tmp_path / "on"), context={
        "source": "codecommit", "enable_continuum": "true",
        "continuum_source_bucket": "b", "continuum_environment_id": "e"})
    stack = tier1.Tier1PipelineStack(app, "Tier1PipelineStack",
                                     env=cdk.Environment(region="us-west-2"))
    [project] = [p for p in _of_type(Template.from_stack(stack).to_json()["Resources"],
                                     "AWS::CodeBuild::Project").values()
                 if p["Properties"]["Name"] == "agentic-gates-tier1-continuum"]
    build = json.loads(project["Properties"]["Source"]["BuildSpec"])["phases"]["build"]["commands"]
    [summary] = [c for c in build if "CONTINUUM_SUMMARY" in c and "python -I -c" in c]
    env = {**os.environ, "PATH": f"{pathlib.Path(sys.executable).parent}:{os.environ['PATH']}"}
    env.pop("PYTHONSAFEPATH", None)

    def run(text):
        marker.unlink(missing_ok=True)
        return subprocess.run(["bash", "-c", text + '\necho "NOTE=$CONTINUUM_SUMMARY"'],
                              cwd=checkout, env=env, capture_output=True, text=True, timeout=60)

    result = run(summary)
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), marker.read_text()
    assert "NOTE=REAL: scan succeeded" in result.stdout
    # The same command without -I runs the candidate's json.py: the hole this closes.
    run(summary.replace("python -I ", "python "))
    assert "json.py" in marker.read_text()


def test_review_cli_imports_its_own_reviewer_under_python_i(tmp_path):
    marker = tmp_path / "hijacked"
    _hostile_checkout(tmp_path, marker)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    for extra in ({}, {"PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "agent/review_cli.py"), "--help"],
                                cwd=tmp_path, env={**env, **extra}, capture_output=True,
                                text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        assert "--chunk-plan" in result.stdout
        assert not marker.exists()


def test_pin_pyenv_reads_the_interpreter_outside_the_checkout(tier1, tmp_path):
    checkout, bin_dir, log = tmp_path / "checkout", tmp_path / "bin", tmp_path / "pyenv.log"
    checkout.mkdir()
    bin_dir.mkdir()
    (checkout / ".python-version").write_text("3.9.0\n")
    (bin_dir / "pyenv").write_text('#!/bin/sh\npwd >> "$PYENV_LOG"\n'
                                   '[ "$PYENV_FAIL" = 1 ] && exit 1\necho 3.12.15\n')
    (bin_dir / "pyenv").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "PYENV_LOG": str(log)}
    script = tier1.PIN_PYENV + '\necho "pinned=$PYENV_VERSION"\n'
    result = subprocess.run(["sh", "-c", script], cwd=checkout, env=env, capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "pinned=3.12.15" in result.stdout
    assert log.read_text().split() == ["/"]
    failed = subprocess.run(["sh", "-c", script], cwd=checkout, env={**env, "PYENV_FAIL": "1"},
                            capture_output=True, text=True, timeout=30)
    assert failed.returncode == 1 and "pinned=" not in failed.stdout


RESET_REPORTS = "rm -rf reports && mkdir reports"


@pytest.mark.parametrize("name", [REVIEW, THREAT])
def test_gate_reports_start_empty_before_anything_writes_them(tier1, tmp_path, name):
    commands = json.loads(_projects(_synth(tier1, tmp_path / "cdk.out")["Resources"])[name]
                          ["Source"]["BuildSpec"])["phases"]["build"]["commands"]
    first = next(i for i, c in enumerate(commands) if "reports" in c)
    assert commands[first] == RESET_REPORTS, commands[first]
    assert "mkdir -p reports" not in " ".join(commands)


def test_the_reset_removes_a_committed_reports_dir_or_link(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "findings.json").write_text("{}")
    for seeded in ("dir", "link", "file"):
        checkout = tmp_path / seeded
        checkout.mkdir()
        if seeded == "dir":
            (checkout / "reports").mkdir()
            (checkout / "reports/findings.json").write_text('{"verdict": "PASS"}')
        elif seeded == "link":
            (checkout / "reports").symlink_to(outside)
        else:
            (checkout / "reports").write_text("not a directory")
        result = subprocess.run(["sh", "-c", RESET_REPORTS], cwd=checkout, capture_output=True,
                                text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        reports = checkout / "reports"
        assert reports.is_dir() and not reports.is_symlink() and not any(reports.iterdir())
    assert (outside / "findings.json").exists()     # a link is removed, not followed
