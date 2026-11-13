"""Tier 1 and Tier 2 redeploys cannot silently re-point the pipeline or drop the domain.

Before deploy_context.py, a missing github_branch became "main", a missing
repository or connection switched the source to the CodeCommit demo repo, and
missing site_* keys dropped the application's custom domain from later
releases. Tier 2 had the same source fallback and a branch fixed to main. The
context is now complete and explicit, or synth stops.
"""
import importlib
import json
import os
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT

SAVED = {  # the shape of an operator's complete saved context
    "github_repo": "owner/artifact",
    "connection_arn": "arn:aws:codeconnections:us-west-2:111111111111:connection/x",
    "github_branch": "work/release",
    "site_domain": "app.example.com",
    "site_cert": "arn:aws:acm:us-east-1:111111111111:certificate/y",
    "site_zone": "Z0000000000000",
}


@pytest.fixture
def ctx(load_module):
    return load_module("tier1-codebuild/deploy_context.py")


def test_complete_saved_context_selects_github(ctx):
    assert ctx.source_kind(SAVED) == "github"
    ctx.check_site(SAVED)
    assert ctx.source_kind({**SAVED, "source": "github"}) == "github"


@pytest.mark.parametrize("missing", ["github_branch", "github_repo", "connection_arn"])
def test_partial_github_context_stops_synth(ctx, missing):
    with pytest.raises(ctx.ContextError, match=missing):
        ctx.source_kind({**SAVED, missing: ""})
    with pytest.raises(ctx.ContextError, match=missing):
        ctx.source_kind({k: v for k, v in SAVED.items() if k != missing})


def test_bare_context_stops_synth_instead_of_choosing_codecommit(ctx):
    with pytest.raises(ctx.ContextError, match="source=codecommit"):
        ctx.source_kind({})
    with pytest.raises(ctx.ContextError, match="no source context"):
        ctx.source_kind({"site_domain": "", "dashboard_url": ""})


def test_codecommit_is_an_explicit_choice_and_not_mixed_with_github(ctx):
    assert ctx.source_kind({"source": "codecommit"}) == "codecommit"
    with pytest.raises(ctx.ContextError, match="cannot be combined"):
        ctx.source_kind({"source": "codecommit", "github_repo": "o/r"})
    with pytest.raises(ctx.ContextError, match="choose github or codecommit"):
        ctx.source_kind({"source": "s3"})


@pytest.mark.parametrize("missing", ["site_domain", "site_cert", "site_zone"])
def test_partial_site_context_stops_synth(ctx, missing):
    with pytest.raises(ctx.ContextError, match=missing):
        ctx.check_site({**SAVED, missing: None})


def test_no_site_context_is_allowed(ctx):
    ctx.check_site({})
    ctx.check_site({"site_domain": "", "site_cert": "", "site_zone": ""})


@pytest.mark.parametrize("missing", ["dashboard_domain", "dashboard_zone_id", "dashboard_zone_name"])
def test_partial_dashboard_domain_stops_synth(ctx, missing):
    full = {"dashboard_domain": "dash.example.com", "dashboard_zone_id": "Z0000000000000",
            "dashboard_zone_name": "example.com"}
    with pytest.raises(ctx.ContextError, match=missing):
        ctx.dashboard_env({**full, missing: None})


def test_dashboard_env_passes_only_given_values_and_defaults_gates_repo(ctx):
    assert ctx.dashboard_env({}) == {}
    assert ctx.dashboard_env({"github_repo": "example-org/gates", "site_url": "https://app.example.com",
                              "auth_domain_prefix": "example-dash"}) == {
        "GATES_REPO": "example-org/gates", "SITE_URL": "https://app.example.com",
        "AUTH_DOMAIN_PREFIX": "example-dash"}
    assert ctx.dashboard_env({"github_repo": "example-org/gates", "gates_repo": "example-org/other",
                              "artifact_repo": "example-org/app"}) == {
        "GATES_REPO": "example-org/other", "ARTIFACT_REPO": "example-org/app"}


def test_stack_uses_the_checked_context_and_no_default_branch():
    source = (ROOT / "tier1-codebuild/tier1_stack.py").read_text()
    assert "source = source_kind(context)" in source
    assert "check_site(context)" in source
    assert 'branch=context["github_branch"]' in source
    assert 'try_get_context("github_branch") or "main"' not in source
    assert 'if source == "github":' in source


@pytest.mark.skipif(not (ROOT / "scripts/redeploy_tiers.sh").exists(),
                    reason="multi-stack operator scripts are not part of the published sample")
def test_redeploy_paths_carry_an_explicit_source():
    makefile = (ROOT / "Makefile").read_text()
    assert "deploy --require-approval never -c source=codecommit" in makefile
    assert "destroy --force -c source=codecommit" in makefile
    redeploy = (ROOT / "scripts/redeploy_tiers.sh").read_text()
    road = (ROOT / "scripts/deploy_road_tiers.sh").read_text()
    assert "only sanctioned path" not in redeploy
    # Both scripts take every flag from the one demo context file.
    for script, arrays in ((redeploy, ("T1", "T2", "T3")),
                           (road, ("T1ROAD", "T2ROAD", "T3ROAD"))):
        assert "source scripts/demo_context.sh" in script
        for name in arrays:
            assert f'"${{{name}[@]}}"' in script
    # Each array names its source explicitly; none relies on a default.
    demo = (ROOT / "scripts/demo_context.sh").read_text()
    for name in ("T1", "T1ROAD", "T2", "T2ROAD", "T3", "T3ROAD"):
        [line] = [ln for ln in demo.splitlines() if ln.startswith(f"{name}=(")]
        block = demo[demo.index(line):].split(")", 1)[0]
        assert "-c source=codecommit" in block, name


# --- Tier 2 applies the same rules -----------------------------------------------------

LIVE = {"github_repo": "example-org/sample-agentic-cicd-artifact",
        "connection_arn": "arn:aws:codeconnections:us-west-2:111122223333:connection/"
                          "11111111-2222-3333-4444-555555555555",
        "github_branch": "main"}


@pytest.fixture
def synth(monkeypatch, tmp_path):
    monkeypatch.chdir(ROOT / "tier2-agentcore/infra")
    monkeypatch.syspath_prepend(str(ROOT / "tier2-agentcore/infra"))
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    stack_module = importlib.import_module("tier2_stack")

    def run(context, whole=False):
        app = cdk.App(outdir=str(tmp_path / "cdk.out"),
                      context={"aws:cdk:bundling-stacks": [], **context})
        stack = stack_module.Tier2PipelineStack(
            app, context.get("stack_id", "Tier2PipelineStack"), env=cdk.Environment(region="us-west-2"))
        template = Template.from_stack(stack).to_json()
        return template if whole else template["Resources"]

    return run


def _pipeline(resources):
    [pipeline] = [r["Properties"] for r in resources.values()
                  if r["Type"] == "AWS::CodePipeline::Pipeline"]
    return pipeline


@pytest.mark.parametrize("context, reason", [
    ({}, "Tier 2 has no source context"),
    ({k: v for k, v in LIVE.items() if k != "github_branch"}, "github_branch"),
    ({k: v for k, v in LIVE.items() if k != "connection_arn"}, "connection_arn"),
    ({k: v for k, v in LIVE.items() if k != "github_repo"}, "github_repo"),
    ({"source": "codecommit", **LIVE}, "cannot be combined"),
])
def test_tier2_synth_refuses_implicit_or_partial_source_context(synth, context, reason):
    with pytest.raises(ValueError, match=reason):
        synth(context)


def test_a_complete_context_synthesizes_the_live_source_unchanged(synth):
    pipeline = _pipeline(synth({**LIVE, "stack_id": "Tier2PipelineStack", "name_suffix": ""}))
    source = pipeline["Stages"][0]["Actions"][0]
    assert pipeline["Name"] == "agentic-gates-tier2"
    assert source["ActionTypeId"]["Provider"] == "CodeStarSourceConnection"
    assert source["Configuration"] == {"ConnectionArn": LIVE["connection_arn"],
                                       "FullRepositoryId": LIVE["github_repo"],
                                       "BranchName": "main"}
    road = _pipeline(synth({**LIVE, "github_repo": "example-org/sample-agentic-cicd-gates",
                            "stack_id": "Tier2PipelineStackRoad", "name_suffix": "-road"}))
    assert road["Name"] == "agentic-gates-tier2-road"
    assert road["Stages"][0]["Actions"][0]["Configuration"]["FullRepositoryId"] == \
        "example-org/sample-agentic-cicd-gates"
    codecommit = _pipeline(synth({"source": "codecommit"}))
    assert codecommit["Stages"][0]["Actions"][0]["Configuration"]["BranchName"] == "main"


def test_the_gate_receives_its_pipeline_execution_id(synth):
    pipeline = _pipeline(synth({**LIVE, "stack_id": "Tier2PipelineStack", "name_suffix": ""}))
    [review] = pipeline["Stages"][1]["Actions"]
    params = review["Configuration"]["UserParameters"]
    # A runtime ARN token makes this an Fn::Join; the variable is a literal part of it.
    assert '"pipeline_execution_id":"#{codepipeline.PipelineExecutionId}"' in json.dumps(params) \
        .replace('\\"', '"')


@pytest.mark.skipif(not (ROOT / "scripts/redeploy_tiers.sh").exists(),
                    reason="multi-stack operator scripts are not part of the published sample")
def test_tier2_deploy_paths_carry_the_complete_source_context():
    makefile = (ROOT / "Makefile").read_text()
    assert "cd tier2-agentcore/infra && CDK_DOCKER=$${CDK_DOCKER:-finch} npx -y aws-cdk@2.1144.0 " \
           "deploy --require-approval never -c source=codecommit" in makefile
    for script, name in (("scripts/redeploy_tiers.sh", "T2"),
                         ("scripts/deploy_road_tiers.sh", "T2ROAD")):
        text = (ROOT / script).read_text()
        tier2 = text[text.index("tier2-agentcore/infra"):].split("echo")[0]
        assert f'"${{{name}[@]}}"' in tier2
    demo = (ROOT / "scripts/demo_context.sh").read_text()
    for name in ("T2", "T2ROAD"):
        [line] = [ln for ln in demo.splitlines() if ln.startswith(f"{name}=(")]
        assert "-c stack_id=" in line and "-c source=codecommit" in line


def test_the_gate_asset_ignores_bytecode_left_by_local_runs(tmp_path):
    """One commit deploys one gate zip, whichever checkout runs the deploy.

    The asset hash used to include gate/__pycache__ (written by any local test
    run), and the bundling command copied it into the zip. Synthesized from a
    copy of the stack's inputs, with and without such files, in a fresh process:
    CDK resolves the stack's relative asset paths against the working directory
    its jsii kernel started in.
    """
    for name in ("tier1-codebuild/deploy_context.py", "tier2-agentcore/infra/tier2_stack.py",
                 "tier2-agentcore/gate/lambda_handler.py", "tier2-agentcore/gate/requirements.txt",
                 "tier2-agentcore/runtime/Dockerfile", ".dockerignore"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / name, tmp_path / name)
    script = """
import json, pathlib, sys
import aws_cdk as cdk
from aws_cdk.assertions import Template
from tier2_stack import Tier2PipelineStack
context, gate = json.loads(sys.argv[1]), pathlib.Path("../gate")

def key(run):
    app = cdk.App(outdir=f"cdk.out.{run}", context={"aws:cdk:bundling-stacks": [], **context})
    stack = Tier2PipelineStack(app, "Tier2PipelineStack", env=cdk.Environment(region="us-west-2"))
    [code] = [r["Properties"]["Code"] for r in Template.from_stack(stack).to_json()["Resources"].values()
              if r["Type"] == "AWS::Lambda::Function"
              and r["Properties"].get("Handler") == "lambda_handler.handler"]
    return code["S3Key"]

keys = [key("clean")]
(gate / "__pycache__").mkdir()
(gate / "__pycache__/lambda_handler.cpython-312.pyc").write_bytes(b"stale bytecode")
(gate / "stray.pyc").write_bytes(b"more")
keys.append(key("with-bytecode"))
handler = gate / "lambda_handler.py"
handler.write_text(handler.read_text() + "# changed\\n")
keys.append(key("changed-source"))
print(json.dumps(keys))
"""
    infra = tmp_path / "tier2-agentcore/infra"
    out = subprocess.run([sys.executable, "-c", script, json.dumps(LIVE)], cwd=infra,
                         env={**os.environ, "PYTHONPATH": str(infra)}, capture_output=True,
                         text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-2000:]
    clean, with_bytecode, changed = json.loads(out.stdout.strip().splitlines()[-1])
    assert with_bytecode == clean
    assert changed != clean          # the hash still follows the source itself
    source = (ROOT / "tier2-agentcore/infra/tier2_stack.py").read_text()
    assert "cp lambda_handler.py requirements.txt /asset-output/" in source
    assert "cp -r . /asset-output" not in source
    assert "pip install --quiet --no-compile -r requirements.txt -t /asset-output" in source


# --- rolling back the runtime image never restores an older gate ----------------------

def test_a_runtime_only_rollback_changes_the_image_and_keeps_the_gate(synth, load_module,
                                                                      tmp_path, capsys):
    tool = load_module("tier2-agentcore/infra/runtime_rollback.py")
    current = synth({**LIVE, "stack_id": "Tier2PipelineStack", "name_suffix": ""}, whole=True)
    [(lid, runtime)] = [(k, r) for k, r in current["Resources"].items() if r["Type"] == tool.RUNTIME]
    [(gate_id, gate)] = [(k, r) for k, r in current["Resources"].items()
                         if r["Type"] == "AWS::Lambda::Function"
                         and r["Properties"].get("Handler") == "lambda_handler.handler"]
    # The pre-deploy template: the old image AND the old gate.
    previous = json.loads(json.dumps(current))
    old_uri = {"Fn::Sub": "${AWS::AccountId}.dkr.ecr.us-west-2.${AWS::URLSuffix}/"
                          "cdk-hnb659fds-container-assets-${AWS::AccountId}-us-west-2:" + "3" * 64}
    previous["Resources"][lid]["Properties"]["AgentRuntimeArtifact"] = {
        "ContainerConfiguration": {"ContainerUri": old_uri}}
    previous["Resources"][gate_id]["Properties"]["Code"]["S3Key"] = "b" * 64 + ".zip"
    out, before, after = tool.runtime_only(current, previous)
    assert before == old_uri and after == runtime["Properties"]["AgentRuntimeArtifact"][
        "ContainerConfiguration"]["ContainerUri"]
    assert out["Resources"][gate_id] == gate                      # the current gate stays
    out["Resources"][lid]["Properties"]["AgentRuntimeArtifact"] = runtime["Properties"][
        "AgentRuntimeArtifact"]
    assert out == current                                         # and nothing else changed
    # The CLI writes a body CloudFormation accepts inline; get-template may quote it.
    (tmp_path / "current.json").write_text(json.dumps(json.dumps(current)))
    (tmp_path / "previous.json").write_text(json.dumps(previous, indent=2))
    assert tool.main(["--current", str(tmp_path / "current.json"), "--previous",
                      str(tmp_path / "previous.json"), "--out", str(tmp_path / "out.json")]) == 0
    written = (tmp_path / "out.json").read_bytes()
    assert len(written) <= tool.MAX_TEMPLATE_BODY and b"\n" not in written
    assert json.loads(written)["Resources"][gate_id] == gate
    assert "only the runtime image changes" in capsys.readouterr().out
    # Refusals: nothing to roll back, or a template it does not understand.
    with pytest.raises(tool.RollbackError, match="nothing to roll back"):
        tool.runtime_only(current, current)
    two = json.loads(json.dumps(previous))
    two["Resources"]["Second"] = two["Resources"][lid]
    with pytest.raises(tool.RollbackError, match="2 AWS::BedrockAgentCore::Runtime"):
        tool.runtime_only(current, two)
    renamed = json.loads(json.dumps(previous))
    renamed["Resources"]["Other"] = renamed["Resources"].pop(lid)
    with pytest.raises(tool.RollbackError, match="logical IDs differ"):
        tool.runtime_only(current, renamed)
    (tmp_path / "bad.json").write_text("[]")
    assert tool.main(["--current", str(tmp_path / "bad.json"), "--previous",
                      str(tmp_path / "previous.json"), "--out", str(tmp_path / "x.json")]) == 1
    assert "REFUSED" in capsys.readouterr().out and not (tmp_path / "x.json").exists()


# --- Tier 3's CodeCommit source and the PR reviewer's pinned trust ---------------------

def _run_app(app_dir, context, tmp_path):
    """Synthesize one CDK app file in a subprocess, as the CLI does (context and
    output directory in the environment). Returns (process, output directory)."""
    env = {**os.environ, "CDK_CONTEXT_JSON": json.dumps(context), "CDK_OUTDIR": str(tmp_path)}
    proc = subprocess.run([sys.executable, "app.py"], cwd=ROOT / app_dir, env=env,
                          capture_output=True, text=True, timeout=180)
    return proc, tmp_path


ART_PINNED = "example-org@111/sample-agentic-cicd-artifact@222"
GATES_PINNED = "example-org@111/sample-agentic-cicd-gates@333"


def test_pr_reviewer_trust_pins_exact_repository_ids(tmp_path):
    proc, out = _run_app("pr-surface/infra", {"repo": f"{ART_PINNED},{GATES_PINNED}"}, tmp_path)
    assert proc.returncode == 0, proc.stderr
    resources = json.loads((out / "PrReviewerAuthStack.template.json").read_text())["Resources"]
    [role] = [r["Properties"] for r in resources.values() if r["Type"] == "AWS::IAM::Role"
              and r["Properties"].get("RoleName") == "agentic-gates-pr-reviewer"]
    [statement] = role["AssumeRolePolicyDocument"]["Statement"]
    assert statement["Condition"] == {"StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": [
            f"repo:{ART_PINNED}:pull_request", f"repo:{GATES_PINNED}:pull_request"]}}
    assert "@" not in role["Description"]


@pytest.mark.parametrize("repos", [f"{ART_PINNED},example-org/other",
                                   "example-org@x/name@1"])
def test_pr_reviewer_refuses_partial_or_malformed_pinning(tmp_path, repos):
    proc, _ = _run_app("pr-surface/infra", {"repo": repos}, tmp_path)
    assert proc.returncode != 0 and "OWNER@ID/NAME@ID" in proc.stderr


@pytest.mark.skipif(not (ROOT / "tier3-kiro").exists(),
                    reason="Tier 3 is a preview module, not part of the published sample")
def test_tier3_codecommit_source_is_explicit_and_exclusive(tmp_path):
    ctx = {"source": "codecommit", "stack_id": "Tier3PipelineStackRoad", "name_suffix": "-road"}
    proc, out = _run_app("tier3-kiro", ctx, tmp_path / "a")
    assert proc.returncode == 0, proc.stderr
    resources = json.loads((out / "Tier3PipelineStackRoad.template.json").read_text())["Resources"]
    [source] = [a for r in resources.values() if r["Type"] == "AWS::CodePipeline::Pipeline"
                for s in r["Properties"]["Stages"] if s["Name"] == "Source" for a in s["Actions"]]
    assert source["ActionTypeId"]["Provider"] == "CodeCommit"
    assert source["Configuration"]["RepositoryName"] == "agentic-gates-demo-road"
    assert source["Configuration"]["BranchName"] == "main"
    assert source["Configuration"]["OutputArtifactFormat"] == "CODEBUILD_CLONE_REF"
    proc, _ = _run_app("tier3-kiro", {**ctx, "github_repo": "o/r"}, tmp_path / "b")
    assert proc.returncode != 0 and "cannot be combined" in proc.stderr
    proc, _ = _run_app("tier3-kiro", {}, tmp_path / "c")
    assert proc.returncode != 0 and "-c source=codecommit" in proc.stderr
