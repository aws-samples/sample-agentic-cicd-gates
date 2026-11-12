"""Tier 1 — full pipeline skeleton with the CodeBuild-hosted agent gate.

Source (CodeCommit, full clone)
  → AutomatedGates (parallel):
      • Review        — agent gate (two-stage Bedrock reviewer; exit code = verdict;
                        deltas over one chunk are reviewed chunk by chunk)
                        baseline: last successful release, else an approved
                        starting commit from BaselineBucket, else the full tree
      • Deterministic — checks.py (wildcard IAM + Access Analyzer) + cfn-guard
                        + best-effort Inspector Sbomgen (advisory)
      • ThreatModel   — validate.py (schema/coverage/staleness, deterministic)
                        + STRIDE agent delta proposal (advisory, THREAT_AGENT=on)
      • Package       — cloudformation package → packaged.yaml
  → Approval          — manual approval; prompt renders #{ReviewGate.VERDICT} and
                        blocking count; deep link to the findings report in S3
  → Deploy            — CFN change set + execute; SAM DeploymentPreference does
                        canary shifting + PreTraffic hook + alarm gate + rollback

Security posture: every gate's tooling (buildspecs, checks.py,
rules.guard, validate.py) is pipeline-owned — shipped as CDK assets — so the
change under review can never edit its own gate. Only the DATA under review
(code, template.yaml, threat-model/) comes from the guarded repo. The review
policy is a separate asset. Every asset a gate build fetches is pinned at
deploy time to one S3 object version and a SHA-256 of its content; each build
fetches that version and checks the hash before anything runs or reads it.
Gate builds run every Python command isolated (`python -I`, plus PYTHONSAFEPATH
in the environment) and pin the interpreter outside the checkout, so no file
in the change under review is imported or picks the interpreter. The candidate
is compared with the last successfully released revision, not HEAD~1.
"""
import hashlib
import pathlib
import re

import aws_cdk as cdk
from aws_cdk import (
    Stack,
    aws_codebuild as codebuild,
    aws_codecommit as codecommit,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as cpactions,
    aws_iam as iam,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
    custom_resources as cr,
)
from constructs import Construct

from deploy_context import DASHBOARD_ENV, KEYS as CONTEXT_KEYS, check_site, dashboard_env, source_kind

import continuum   # optional AWS Continuum code scan, off unless -c enable_continuum=true

# Every gate build runs with the candidate checkout as its working directory.
# Python must never import from it: `python -c` and `python -m` put the working
# directory first on sys.path, so a json.py in the change under review would run
# in place of the library, with the gate's role, after the asset checks. So every
# Python command in a gate buildspec runs isolated (`python -I`), and the gate
# projects also set PYTHONSAFEPATH=1 and PYTHONNOUSERSITE=1 (GATE_PYTHON_ENV) as
# a second guard, which the 3.12 that `runtime-versions` chooses honours (3.11
# and newer do). The image also caches Python 3.9, which ignores PYTHONSAFEPATH;
# `-I` isolates on 3.9 too, and PIN_PYENV keeps a checkout from picking it.
# The image picks Python through pyenv shims, which honour a `.python-version`
# file in the working directory, so PIN_PYENV fixes the interpreter that
# `runtime-versions` chose, read from `/`, before anything runs Python.
#
# The gates also write their reports inside the checkout (`reports/`), which the
# build uploads as evidence. A candidate can commit a `reports/` of its own, so
# each gate empties it first: if the reviewer dies before writing, there is no
# report to upload, never a committed one.
PIN_PYENV = ('if command -v pyenv >/dev/null 2>&1; then'
             ' PYENV_VERSION="$(cd / && pyenv version-name)" || exit 1; export PYENV_VERSION;'
             ' echo "Python: pyenv $PYENV_VERSION, pinned outside the checkout"; fi')
GATE_PYTHON_ENV = {"PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}

PY_INSTALL = {"runtime-versions": {"python": "3.12"},
              "commands": [PIN_PYENV, "python -I -m pip install --quiet boto3 pyyaml"]}

# The operator-approved starting commit (deploy/README.md, "Approved starting
# commit"). prepare_review.py uses it only when the pipeline history has no
# successful release. A missing object means "none approved" and the build goes
# on; any other read error (access denied, missing bucket, throttling, network)
# stops the build, because silently going on would turn a broken read into a
# full-tree review or, worse, hide an approval the operator meant to use.
APPROVED_BASELINE_KEY = "approved-baseline.json"
FETCH_APPROVED_BASELINE = (
    "BASELINE_FILE=; BASELINE_VERSION=; rm -f /tmp/approved-baseline.json; "
    'if BASELINE_VERSION=$(aws s3api get-object --bucket "$BASELINE_BUCKET"'
    f" --key {APPROVED_BASELINE_KEY} /tmp/approved-baseline.json"
    " --query VersionId --output text 2>/tmp/approved-baseline.err); then"
    " BASELINE_FILE=/tmp/approved-baseline.json;"
    ' case "$BASELINE_VERSION" in None|null) BASELINE_VERSION= ;; esac;'
    ' echo "Approved starting commit file found (S3 version ${BASELINE_VERSION:-none})";'
    " elif grep -qE '[(](NoSuchKey|404)[)]' /tmp/approved-baseline.err; then"
    " BASELINE_VERSION=; rm -f /tmp/approved-baseline.json;"
    " echo 'No approved starting commit file; the pipeline history decides the baseline';"
    " else cat /tmp/approved-baseline.err >&2;"
    " echo 'Could not read the approved starting commit file; stopping' >&2; exit 1; fi"
)

# Every S3 asset a gate build fetches (the review policy and the four tooling
# packages) is pinned at deploy time to one object version and a SHA-256 of its
# content; the stack sets both (Tier1PipelineStack._pin). A key name alone is
# not a pin: the shared CDK asset bucket lets other deploy roles overwrite a
# key. A missing version, a failed read or a hash mismatch stops the build
# before anything from the asset runs or is read.
#
# A file asset is hashed as a file. A directory asset is zipped only when
# cdk-assets publishes it, so its zip bytes are unknown at synth; it is hashed
# as a tree instead: the SHA-256 of `sha256sum` lines for every file, in byte
# order of the paths. tree_sha256() computes the same value at synth.
TREE_SHA256 = ("find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum"
               " | sha256sum | cut -d' ' -f1")


def tree_sha256(root: pathlib.Path) -> str:
    """The value TREE_SHA256 prints in `root`."""
    entries = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"{path}: a symlink in a pinned asset is not supported")
        if path.is_file():
            name = "./" + path.relative_to(root).as_posix()
            if "\\" in name or "\n" in name:
                raise ValueError(f"{path}: sha256sum escapes this file name")
            entries.append((name.encode(), hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(b"".join(f"{digest}  ".encode() + name + b"\n"
                                   for name, digest in sorted(entries))).hexdigest()


def fetch_pinned(var: str, label: str, dest: str, unpack: str = "") -> str:
    """Build command: fetch asset `var` at its pinned version; stop unless the bytes match.

    `dest` receives the object; a zip is unpacked into `unpack` and hashed as a tree.
    """
    out = unpack or dest
    command = (
        f"rm -rf {dest} {unpack}".rstrip() + "; "
        f'case "${var}_VERSION" in ""|None|null)'
        f" echo 'The {label} has no pinned S3 version; stopping' >&2; exit 1 ;; esac;"
        f' aws s3api get-object --bucket "${var}_BUCKET" --key "${var}_KEY"'
        f' --version-id "${var}_VERSION" {dest} >/dev/null'
        f" || {{ echo 'Could not read the pinned {label} version; stopping' >&2; exit 1; }};")
    if unpack:
        command += (
            f" unzip -q -o {dest} -d {unpack}"
            f" || {{ echo 'Could not unpack the pinned {label}; stopping' >&2; exit 1; }};"
            f" PIN_SHA256=$(cd {unpack} && {TREE_SHA256});"
            f' [ "$PIN_SHA256" = "${var}_SHA256" ]')
    else:
        command += f' echo "${var}_SHA256  {dest}" | sha256sum -c --quiet -'
    return command + (
        f" || {{ rm -rf {out};"
        f" echo 'The {label} does not match its pinned SHA-256; stopping' >&2; exit 1; }};"
        f' echo "{label[0].upper() + label[1:]}: S3 version ${var}_VERSION,'
        f' sha256 ${var}_SHA256"')


FETCH_REVIEW_POLICY = fetch_pinned("REVIEW_POLICY", "review policy", "/tmp/rules.yaml")
FETCH_REVIEW_INPUTS = fetch_pinned("REVIEW_INPUTS", "review input tools",
                                   "/tmp/review-inputs.zip", "/tmp/input-tools")
FETCH_AGENT = fetch_pinned("AGENT_ASSET", "agent package", "/tmp/agent.zip", "/tmp/agentpkg")
FETCH_DET_TOOLS = fetch_pinned("DET_TOOLS", "deterministic tools", "/tmp/det.zip", "/tmp/det")
FETCH_TM_TOOLS = fetch_pinned("TM_TOOLS", "threat-model tools", "/tmp/tm.zip", "/tmp/tm")

# Review and ThreatModel run in parallel, so each prepares its own input with
# these same commands: the same history, the same approval object and the same
# tooling give both the same baseline. Both record it in input-metadata.json.
PREPARE_INPUT_COMMANDS = [
    FETCH_REVIEW_INPUTS,
    FETCH_REVIEW_POLICY,
    FETCH_APPROVED_BASELINE,
    'python -I /tmp/input-tools/prepare_review.py --pipeline "$PIPELINE_NAME"'
    ' --execution-id "$PIPELINE_EXECUTION_ID" --revision "$SOURCE_REVISION"'
    ' --region "$AWS_REGION" --rules /tmp/rules.yaml'
    ' ${BASELINE_FILE:+--approved-baseline "$BASELINE_FILE"}'
    ' ${BASELINE_VERSION:+--approved-baseline-version "$BASELINE_VERSION"}',
    "cp /tmp/review-input/change.diff /tmp/change.diff",
    "cp /tmp/review-input/changed.txt /tmp/changed.txt",
]

# Large deltas are reviewed in chunks (prepare_review.py plans, review_cli.py
# and stride_agent.py execute), never truncated. Sized from the 2026-10-02
# calibration, ~99 KB per call: Security (Opus 5) 170 s discovery + up to
# ~100 s validation, Architecture ~90 s, Code Quality ~70 s; STRIDE ~24 s.
#   Review, 3,000,000-byte cap at ~87% packing of 100 KB chunks = ~35 chunks:
#   35 x (270 + 90 + 70) s + ~35 x 60 s for an all-presentation delta
#   = ~17,150 s of calls / 8 workers = ~36 min, + one slow tail item = ~41 min.
#   The 82-minute deadline is ~2x that; at the deadline unfinished chunks fail
#   their seats closed and the report is still written inside the timeout.
#   ThreatModel: 35 x 24 s / 4 workers = ~4 min; the advisory STRIDE pass stops
#   at 12 minutes. Each timeout keeps 8 minutes for install, inputs and evidence.
REVIEW_TIMEOUT_MINUTES = 90
REVIEW_DEADLINE_SECONDS = (REVIEW_TIMEOUT_MINUTES - 8) * 60
REVIEW_WORKERS = 8
THREAT_TIMEOUT_MINUTES = 20
STRIDE_DEADLINE_SECONDS = (THREAT_TIMEOUT_MINUTES - 8) * 60
STRIDE_WORKERS = 4

REVIEW_BUILD_SPEC = codebuild.BuildSpec.from_object(
    {
        "version": "0.2",
        "env": {"exported-variables": ["VERDICT", "BLOCKING", "BASELINE_KIND"]},
        "phases": {
            "install": {
                "runtime-versions": {"python": "3.12"},
                # Do not depend on the managed image's floating AWS CLI version.
                "commands": [PIN_PYENV] + [
                    "python -I -m pip install --quiet boto3==1.43.72 botocore==1.43.72 pyyaml",
                    "python -I -c \"import botocore.session; assert 'IfNoneMatch' in botocore.session.Session().get_service_model('s3').operation_model('PutObject').input_shape.members\"",
                ],
            },
            "build": {
                "commands": PREPARE_INPUT_COMMANDS + [FETCH_AGENT] + [
                    # Shown in the approval prompt: last_successful_release,
                    # approved_baseline or initial_full_tree.
                    "export BASELINE_KIND=$(python -I -c \"import json;print(json.load(open('/tmp/review-input/input-metadata.json'))['baseline_kind'])\")",
                    "rm -rf reports && mkdir reports",
                    # Capture the gate exit so verdict/report export always runs.
                    "GATE_EXIT=0; python -I /tmp/agentpkg/review_cli.py --diff /tmp/change.diff --rules /tmp/rules.yaml --region $AWS_REGION --chunk-plan /tmp/review-input/chunk-plan.json --workers $REVIEW_WORKERS --deadline-seconds $REVIEW_DEADLINE_SECONDS --report reports/findings.json || GATE_EXIT=$?",
                    "python -I /tmp/input-tools/prepare_review.py --attach-report reports/findings.json",
                    "python -I -c \"import json,os,pathlib; p=pathlib.Path('reports/findings.json'); d=json.loads(p.read_text()); d['build_id']=os.environ['CODEBUILD_BUILD_ID']; p.write_text(json.dumps(d,indent=2)+'\\n')\"",
                    "export VERDICT=$(python -I -c \"import json;print(json.load(open('reports/findings.json'))['verdict'])\" 2>/dev/null || echo BLOCKED_ERROR)",
                    "export BLOCKING=$(python -I -c \"import json;print(json.load(open('reports/findings.json'))['stats']['blocking'])\" 2>/dev/null || echo '?')",
                    # Keep each build, including stage retries inside one execution.
                    # Conditional put refuses to replace an already archived attempt.
                    # Missing retained evidence is a build failure, not a PASS.
                    "python -I -c \"import boto3,os,pathlib; e=os.environ; run=e['PIPELINE_EXECUTION_ID']; build=e['CODEBUILD_BUILD_ID']; assert run and build, 'Missing execution/build identity'; boto3.client('s3').put_object(Bucket=e['REPORTS_BUCKET'],Key=f'executions/{run}/builds/{build}/findings.json',Body=pathlib.Path('reports/findings.json').read_bytes(),IfNoneMatch='*')\"",
                    "aws s3 cp reports/findings.json s3://$REPORTS_BUCKET/executions/$PIPELINE_EXECUTION_ID/findings.json --quiet",
                    "aws s3 cp reports/findings.json s3://$REPORTS_BUCKET/$(git rev-parse HEAD)/findings.json --quiet",
                    'echo "VERDICT=$VERDICT BLOCKING=$BLOCKING"',
                    "exit $GATE_EXIT",
                ]
            },
        },
        "artifacts": {"files": ["reports/**/*"]},
    }
)

def _deterministic_build_spec(allow_no_templates: bool = False):
    """The deterministic lane. A repository whose deploys are CDK apps has no
    template.yaml, so checks.py would refuse it as a misnamed template; such a
    trio passes allow_no_templates to say that on purpose."""
    flag = " --allow-no-templates" if allow_no_templates else ""
    return codebuild.BuildSpec.from_object(
        {
            "version": "0.2",
            "phases": {
                "install": {"runtime-versions": {"python": "3.12"},
                            "commands": [PIN_PYENV,
                                         "python -I -m pip install --quiet boto3 pyyaml"]},
                "build": {
                    "commands": [FETCH_DET_TOOLS] + [
                        # 1) wildcard IAM + Access Analyzer ValidatePolicy (blocking)
                        "python -I /tmp/det/checks.py --templates 'template.yaml' --region $AWS_REGION"
                            " --repo-root ." + flag,   # single-core + panel-mirror invariants
                        # 2) cfn-guard (blocking on rule failure; a download failure is
                        #    fail-open — checks.py above stays the hard layer)
                        # Pinned release, verified by SHA-256 (same artifact as the PR
                        # workflow). A download failure skips (advisory); a checksum
                        # mismatch fails the action; rule failures block.
                        "if curl --proto '=https' --tlsv1.2 -fsSL --max-time 90 --retry 2 -o /tmp/guard.tgz https://github.com/aws-cloudformation/cloudformation-guard/releases/download/3.2.1/cfn-guard-v3-x86_64-ubuntu-latest.tar.gz; then printf '%s  %s\\n' 09c2b8cfd81d513374a8da89d4805dc55006a3da52bbf598e272022d4d198e94 /tmp/guard.tgz | sha256sum -c - || exit 1; mkdir -p /tmp/guard && tar -xzf /tmp/guard.tgz -C /tmp/guard --strip-components=1 cfn-guard-v3-x86_64-ubuntu-latest/cfn-guard; /tmp/guard/cfn-guard validate --data template.yaml --rules /tmp/det/rules.guard --show-summary fail || { EC=$?; if [ $EC -eq 19 ] || [ $EC -eq 5 ]; then echo 'cfn-guard: rule failures'; exit $EC; else echo 'cfn-guard error (advisory skip)'; fi; }; else echo 'cfn-guard unavailable (advisory skip)'; fi",
                        # 3) SBOM: best-effort, ADVISORY (Inspector Sbomgen + Scan API)
                        "(curl -sf -o /tmp/sbomgen.zip https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/amd64/inspector-sbomgen.zip && cd /tmp && unzip -q -o sbomgen.zip && SBOMGEN=$(find /tmp -name inspector-sbomgen -type f | head -1) && chmod +x $SBOMGEN && $SBOMGEN directory --path $CODEBUILD_SRC_DIR -o /tmp/sbom.json && aws inspector-scan scan-sbom --sbom file:///tmp/sbom.json --output-format INSPECTOR > /tmp/sbom-scan.json && python -I -c \"import json;d=json.load(open('/tmp/sbom-scan.json'));v=d.get('sbom',{}).get('vulnerabilities',[]);print(f'SBOM SCAN (advisory): {len(v)} vulnerabilities')\") || echo 'SBOM SCAN (advisory): skipped (tooling unavailable)'",
                    ]
                },
            },
        }
    )


DETERMINISTIC_BUILD_SPEC = _deterministic_build_spec()

THREAT_BUILD_SPEC = codebuild.BuildSpec.from_object(
    {
        "version": "0.2",
        "phases": {
            "install": PY_INSTALL,
            "build": {
                "commands": PREPARE_INPUT_COMMANDS + [FETCH_TM_TOOLS] + [
                    "rm -rf reports && mkdir reports",
                    # Deterministic gate: schema + boundary coverage + staleness.
                    "python -I /tmp/tm/validate.py --model threat-model/app.tc.json --boundaries threat-model/boundaries.yaml --changed-files /tmp/changed.txt",
                    # Agentic STRIDE delta proposal — ADVISORY ONLY (exit 0 always).
                    'if [ "$THREAT_AGENT" = "on" ]; then python -I /tmp/tm/stride_agent.py --diff /tmp/change.diff --model-file threat-model/app.tc.json --region $AWS_REGION --chunk-plan /tmp/review-input/chunk-plan.json --workers $STRIDE_WORKERS --deadline-seconds $STRIDE_DEADLINE_SECONDS --report reports/stride-proposal.json; fi',
                ]
            },
        },
        "artifacts": {"files": ["reports/**/*"]},
    }
)

PACKAGE_BUILD_SPEC = codebuild.BuildSpec.from_object(
    {
        "version": "0.2",
        "phases": {
            "build": {
                "commands": [
                    "aws cloudformation package --template-file template.yaml --s3-bucket $PKG_BUCKET --s3-prefix packaged --output-template-file packaged.yaml",
                ]
            },
        },
        "artifacts": {"files": ["packaged.yaml"]},
    }
)

UNIT_TEST_BUILD_SPEC = codebuild.BuildSpec.from_object({
    "version": "0.2",
    "phases": {
        "install": {"runtime-versions": {"python": "3.12"}},
        "build": {
            # The one Python command left without -I: its job is to run the
            # change's own tests, so isolating it protects nothing. It runs in
            # its own project and role, which can read the pipeline's artifacts
            # and the repository and write only its own logs and test reports;
            # nothing it writes feeds a gate.
            "commands": ["python -m unittest discover -s tests -p 'test_*.py' -v"]
        },
    },
})

# The ROAD's deployable is the dashboard, and the dashboard is CDK, not SAM.
# `aws cloudformation package` + a change-set action cannot ship it: the app
# publishes a Lambda bundle that contains the built web files and, with a custom
# domain, takes its TLS certificate from a stack in ANOTHER REGION, both of which
# cdk handles and the change-set action does not. So this stage runs the repository's own
# deploy script, which is the same command a human would run.
#
# Stated plainly because it is an asymmetry worth owning: the artifact's Deploy
# stage uses CodePipeline's native CloudFormation actions (create change set,
# then execute), which is the more auditable shape. This one is a build action
# that calls `cdk deploy`. The gates in front of it are identical.
DASHBOARD_DEPLOY_BUILD_SPEC = codebuild.BuildSpec.from_object(
    {
        "version": "0.2",
        "phases": {
            "install": {"runtime-versions": {"nodejs": "22", "python": "3.12"}},
            "build": {
                "commands": [
                    # Every cdk.json in this repo runs `../../.venv/bin/python
                    # app.py`, so the deploy needs that virtualenv to exist. Built
                    # from the repo's pinned requirements.txt, which is the same
                    # list a reader installs — so CI and a laptop resolve
                    # identically instead of "works on mine".
                    "python3 -I -m venv .venv",
                    ".venv/bin/python -I -m pip install -q --upgrade pip",
                    ".venv/bin/python -I -m pip install -q -r requirements.txt",
                    "bash dashboard/deploy.sh",
                ]
            },
        },
    }
)


class Tier1PipelineStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)

        # Two trios run this same stack: one over the ARTIFACT (which carries a
        # template.yaml, so it packages and deploys) and one over the ROAD
        # itself — this repository — which has no deployable template because
        # the two-repo split removed it. `name_suffix` keeps every physical name
        # distinct so both can coexist; `gate_only` drops the Package action and
        # the Approval + Deploy stages for the road, whose product IS the gate.
        # Both default to today's artifact values, so a redeploy of the existing
        # trio is a no-op.
        # Two trios run this same stack. `name_suffix` keeps every physical name
        # distinct so both can coexist. `deploy_kind` says what the trio ships:
        #   sam  — the ARTIFACT: `cloudformation package` a template.yaml, then
        #          native change-set actions (the default; today's behaviour)
        #   cdk  — the ROAD: its deployable is this repo's dashboard, a CDK app
        #   none — gate only, no Approval and no Deploy
        # Either deploying kind keeps the human Approval stage, because both
        # deploy something a bad commit could break.
        suffix = self.node.try_get_context("name_suffix") or ""
        pipeline_name = f"agentic-gates-tier1{suffix}"
        deploy_kind = (self.node.try_get_context("deploy_kind") or "sam").lower()
        if self.node.try_get_context("gate_only"):      # older flag, still honoured
            deploy_kind = "none"
        assert deploy_kind in ("sam", "cdk", "none"), f"deploy_kind={deploy_kind!r}"
        if deploy_kind == "cdk" and not (pathlib.Path(__file__).resolve().parents[1]
                                         / "dashboard" / "deploy.sh").exists():
            raise ValueError("deploy_kind=cdk deploys this repository's dashboard, "
                             "which this release does not include; use sam or none")
        gate_only = deploy_kind == "none"
        # Refuse implicit or partial context before anything is built: a
        # redeploy that forgot a flag must fail here, not re-point the pipeline
        # to another branch or source, or drop the application's domain.
        context = {key: self.node.try_get_context(key) for key in CONTEXT_KEYS}
        source = source_kind(context)
        if deploy_kind == "sam":
            check_site(context)
        dash_env = (dashboard_env({k: self.node.try_get_context(k)
                                   for k in ("github_repo", *DASHBOARD_ENV)})
                    if deploy_kind == "cdk" else {})

        repo = codecommit.Repository(
            self,
            "DemoRepo",
            repository_name=f"agentic-gates-demo{suffix}",
            description="Guarded demo repo for the agentic CI/CD gate (AWS sample)",
        )

        # Pipeline-owned gate tooling (never from the repo), each asset pinned
        # to one S3 version and a SHA-256 of its content (see _pin).
        agent_asset = s3_assets.Asset(self, "AgentPackage", path="../agent")
        input_asset = s3_assets.Asset(self, "ReviewInputTools", path="../pipeline_tools")
        # A relative review_policy_file is read from the CDK app directory.
        policy_file = pathlib.Path(__file__).resolve().parent / (
            self.node.try_get_context("review_policy_file") or "../.reviewer.yaml")
        policy_asset = s3_assets.Asset(self, "ReviewPolicy", path=str(policy_file))
        det_asset = s3_assets.Asset(self, "DeterministicTools", path="../deterministic")
        tm_asset = s3_assets.Asset(self, "ThreatModelTools", path="../threat-model")
        self._pin_role = iam.Role(
            self, "AssetPinRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            # No AWSLambdaBasicExecutionRole: it lets the role write every log
            # group in the account, and the deterministic lane blocks it in the
            # form CDK writes it. The logs grant is below (AssetPinLogs), scoped
            # to the provider function's own log group.
            # HeadObject needs s3:GetObject. Scoped to the asset bucket's objects,
            # not each key, so an asset change never changes an IAM resource
            # (deploy/README.md tells operators to stop on one), and HeadObject
            # never waits on IAM propagation after a policy edit.
            inline_policies={"ReadAssetVersions": iam.PolicyDocument(statements=[
                iam.PolicyStatement(actions=["s3:GetObject"],
                                    resources=[policy_asset.bucket.arn_for_objects("*")])])},
        )
        policy_env = self._pin(policy_asset, "REVIEW_POLICY")
        agent_env = self._pin(agent_asset, "AGENT_ASSET")
        input_env = self._pin(input_asset, "REVIEW_INPUTS")
        det_env = self._pin(det_asset, "DET_TOOLS")
        tm_env = self._pin(tm_asset, "TM_TOOLS")
        # The pins share one provider function (a SingletonFunction), whose log
        # group Lambda names after it. The function's role cannot name the
        # function inline (the function needs the role first), so the grant is a
        # separate policy. shortcut: CDK's provider construct id is found by its
        # published UUID; if a CDK upgrade renames it, find_child fails the synth.
        provider = Stack.of(self).node.find_child(
            "AWS" + cr.AwsCustomResource.PROVIDER_FUNCTION_UUID.replace("-", ""))
        log_group = (f"arn:aws:logs:{self.region}:{self.account}:log-group:"
                     f"/aws/lambda/{provider.function_name}")
        iam.Policy(self, "AssetPinLogs", roles=[self._pin_role], statements=[
            iam.PolicyStatement(
                sid="WriteOwnLogs",
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[log_group, f"{log_group}:*"])])

        reports = s3.Bucket(
            self,
            "ReportsBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            lifecycle_rules=[s3.LifecycleRule(expiration=cdk.Duration.days(
                int(self.node.try_get_context("report_retention_days") or 120)))],
        )

        # The approved starting commit (deploy/README.md). This bucket is
        # security state, not a cache: its object decides what a first release
        # is compared with, and its version history is the record of who
        # approved what. So it is retained when the stack is deleted, every
        # version is kept, and replaced versions stay for a year.
        baseline_bucket = s3.Bucket(
            self,
            "BaselineBucket",
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            lifecycle_rules=[s3.LifecycleRule(
                noncurrent_version_expiration=cdk.Duration.days(365))],
        )

        env = codebuild.BuildEnvironment(
            build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5,
            compute_type=codebuild.ComputeType.SMALL,
        )

        # ---- Agent review gate (unchanged core, + verdict export & report upload)
        gate = codebuild.PipelineProject(
            self, "AgentReviewGate",
            project_name=f"agentic-gates-tier1{suffix}-review",
            build_spec=REVIEW_BUILD_SPEC,
            environment=env,
            environment_variables={
                **agent_env,
                **{k: codebuild.BuildEnvironmentVariable(value=v) for k, v in GATE_PYTHON_ENV.items()},
                "REPORTS_BUCKET": codebuild.BuildEnvironmentVariable(value=reports.bucket_name),
                **input_env,
                **policy_env,
                "BASELINE_BUCKET": codebuild.BuildEnvironmentVariable(
                    value=baseline_bucket.bucket_name),
                "PIPELINE_NAME": codebuild.BuildEnvironmentVariable(value=pipeline_name),
                "REVIEW_WORKERS": codebuild.BuildEnvironmentVariable(value=str(REVIEW_WORKERS)),
                "REVIEW_DEADLINE_SECONDS": codebuild.BuildEnvironmentVariable(
                    value=str(REVIEW_DEADLINE_SECONDS)),
            },
            timeout=cdk.Duration.minutes(REVIEW_TIMEOUT_MINUTES),
        )
        agent_asset.grant_read(gate)
        input_asset.grant_read(gate)
        policy_asset.grant_read(gate)
        reports.grant_put(gate)
        gate.add_to_role_policy(iam.PolicyStatement(
            sid="BedrockInvokeAnthropicOnly",
            actions=["bedrock:InvokeModel"],
            resources=[
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.anthropic.*",
                "arn:aws:bedrock:*::foundation-model/anthropic.*",
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.openai.*",
                "arn:aws:bedrock:*::foundation-model/openai.*",
            ]))

        # ---- Deterministic lane
        det = codebuild.PipelineProject(
            self, "DeterministicLane",
            project_name=f"agentic-gates-tier1{suffix}-deterministic",
            # The road trio (cdk) guards this repository, which has no template.yaml.
            build_spec=(_deterministic_build_spec(allow_no_templates=True)
                        if deploy_kind == "cdk" else DETERMINISTIC_BUILD_SPEC),
            environment=env,
            environment_variables={
                **det_env,
                **{k: codebuild.BuildEnvironmentVariable(value=v) for k, v in GATE_PYTHON_ENV.items()},
            },
            timeout=cdk.Duration.minutes(10),
        )
        det_asset.grant_read(det)
        # Resource '*' is the only form IAM accepts here: neither action has a
        # resource type, so no ARN can name what it acts on. Both only read the
        # document they are sent (a policy, an SBOM) and change nothing.
        # checks.py lists them in RESOURCE_STAR_ONLY for that reason.
        det.add_to_role_policy(iam.PolicyStatement(
            sid="PolicyValidationAndSbomScan",
            actions=["access-analyzer:ValidatePolicy", "inspector-scan:ScanSbom"],
            resources=["*"]))

        # ---- Threat-model lane
        threat = codebuild.PipelineProject(
            self, "ThreatModelGate",
            project_name=f"agentic-gates-tier1{suffix}-threatmodel",
            build_spec=THREAT_BUILD_SPEC,
            environment=env,
            environment_variables={
                **tm_env,
                **{k: codebuild.BuildEnvironmentVariable(value=v) for k, v in GATE_PYTHON_ENV.items()},
                "THREAT_AGENT": codebuild.BuildEnvironmentVariable(value="on"),
                **input_env,
                **policy_env,
                "BASELINE_BUCKET": codebuild.BuildEnvironmentVariable(
                    value=baseline_bucket.bucket_name),
                "PIPELINE_NAME": codebuild.BuildEnvironmentVariable(value=pipeline_name),
                "STRIDE_WORKERS": codebuild.BuildEnvironmentVariable(value=str(STRIDE_WORKERS)),
                "STRIDE_DEADLINE_SECONDS": codebuild.BuildEnvironmentVariable(
                    value=str(STRIDE_DEADLINE_SECONDS)),
            },
            timeout=cdk.Duration.minutes(THREAT_TIMEOUT_MINUTES),
        )
        tm_asset.grant_read(threat)
        input_asset.grant_read(threat)
        policy_asset.grant_read(threat)
        threat.add_to_role_policy(iam.PolicyStatement(
            sid="BedrockInvokeAnthropicOnly",
            actions=["bedrock:InvokeModel"],
            resources=[
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.anthropic.*",
                "arn:aws:bedrock:*::foundation-model/anthropic.*",
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.openai.*",
                "arn:aws:bedrock:*::foundation-model/openai.*",
            ]))

        # ---- Package (SAM → packaged.yaml for the deploy tail)
        # Explicit artifact bucket so the package project can know its name
        # (cloudformation package uploads CodeUri zips into it).
        artifacts = s3.Bucket(
            self,
            "PipelineArtifacts",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        package = codebuild.PipelineProject(
            self, "PackageApp",
            project_name=f"agentic-gates-tier1{suffix}-package",
            build_spec=PACKAGE_BUILD_SPEC,
            environment=env,
            environment_variables={
                "PKG_BUCKET": codebuild.BuildEnvironmentVariable(value=artifacts.bucket_name),
            },
            timeout=cdk.Duration.minutes(10),
        )
        artifacts.grant_read_write(package)

        unit_tests = None
        if deploy_kind == "sam":
            unit_tests = codebuild.PipelineProject(
                self, "UnitTests",
                project_name=f"agentic-gates-tier1{suffix}-tests",
                build_spec=UNIT_TEST_BUILD_SPEC,
                environment=env,
                timeout=cdk.Duration.minutes(5),
            )

        # ---- The road's deploy: build + `cdk deploy` this repo's dashboard.
        dash_deploy = None
        if deploy_kind == "cdk":
            dash_deploy = codebuild.PipelineProject(
                self, "DashboardDeploy",
                project_name=f"agentic-gates-tier1{suffix}-dashboard-deploy",
                build_spec=DASHBOARD_DEPLOY_BUILD_SPEC,
                environment=codebuild.BuildEnvironment(
                    build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5,
                    compute_type=codebuild.ComputeType.MEDIUM,   # npm ci + vite build
                ),
                environment_variables={
                    # The board reads GitHub with a read-only token; without this
                    # the redeployed dashboard would silently fall back to
                    # anonymous reads and 404 on the private repos.
                    "GH_TOKEN_SECRET": codebuild.BuildEnvironmentVariable(
                        value=self.node.try_get_context("github_token_secret")
                        or "agentic-gates/github-read"),
                    # The dashboard's own context (repositories, site link,
                    # sign-in domain prefix, optional custom domain); see
                    # dashboard/README.md. None of these values is a secret.
                    **{name: codebuild.BuildEnvironmentVariable(value=value)
                       for name, value in dash_env.items()},
                },
                timeout=cdk.Duration.minutes(30),
            )
            # cdk deploy works by assuming the bootstrap roles. Scoped to that
            # role-name prefix rather than "*": this project's own IAM-002 rule
            # rejects a wildcard resource, and it is right to.
            dash_deploy.add_to_role_policy(iam.PolicyStatement(
                sid="AssumeCdkBootstrapRoles",
                actions=["sts:AssumeRole"],
                resources=[f"arn:aws:iam::{self.account}:role/cdk-hnb659fds-*"]))
            # `cdk deploy` reads the bootstrap version from SSM before it starts.
            dash_deploy.add_to_role_policy(iam.PolicyStatement(
                sid="ReadCdkBootstrapVersion",
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    f"arn:aws:ssm:*:{self.account}:parameter/cdk-bootstrap/hnb659fds/version",
                ]))

        # ---- Optional AWS Continuum scan (advisory). One switch:
        # -c enable_continuum=true adds it; unset or false leaves every part of
        # it out (continuum.py), so an off synth matches a stack without it.
        # You create the integration and environment; the stack only scans.
        scan = None
        if continuum.enabled(self.node.try_get_context(continuum.CONTEXT_KEY)):
            skip = continuum.region_skip_reason(self.region)
            if skip:
                cdk.Annotations.of(self).add_warning_v2("ContinuumSkipped", skip)
            else:
                scan_bucket, scan_env_id = continuum.required_context(self.node)
                scan = continuum.ContinuumScan(self, "Continuum", pipeline_name=pipeline_name,
                                               build_environment=env,
                                               source_bucket=scan_bucket,
                                               environment_id=scan_env_id,
                                               pin=self._pin, pin_pyenv=PIN_PYENV,
                                               gate_python_env=GATE_PYTHON_ENV,
                                               fetch_pinned=fetch_pinned)

        gh_repo = self.node.try_get_context("github_repo") or ""
        conn_arn = self.node.try_get_context("connection_arn") or ""
        # Optional: a rendered findings board. When absent the approval link
        # deep-links to the S3 object instead, so the sample works either way.
        dashboard_url = self.node.try_get_context("dashboard_url") or ""
        source_out = codepipeline.Artifact("Source")
        review_out = codepipeline.Artifact("ReviewReports")
        threat_out = codepipeline.Artifact("ThreatReports")
        packaged_out = codepipeline.Artifact("Packaged")

        if source == "github":
            source_action = cpactions.CodeStarConnectionsSourceAction(
                action_name="Source",
                variables_namespace="SourceVariables",
                owner=gh_repo.split("/")[0],
                repo=gh_repo.split("/")[1],
                branch=context["github_branch"],
                connection_arn=conn_arn,
                output=source_out,
                code_build_clone_output=True,
            )
        else:
            source_action = cpactions.CodeCommitSourceAction(
                action_name="Source",
                variables_namespace="SourceVariables",
                repository=repo,
                branch="main",
                output=source_out,
                code_build_clone_output=True,  # gates need git history
            )

        # What Deploy does, chosen by kind. Both deploying kinds sit behind the
        # same human Approval, because both ship something a bad commit can break
        # - and for the road that something is the operator dashboard.
        # A gate-only trio (none) has no Deploy stage, so it gets no deploy role.
        deploy_actions = []
        if deploy_kind == "cdk":
            deploy_actions = [
                cpactions.CodeBuildAction(
                    action_name="DeployDashboard", project=dash_deploy,
                    input=source_out),
            ]
        elif deploy_kind == "sam":
            app_stack = f"agentic-gates-demo-app{suffix}"
            deploy_role = self._app_deploy_role(app_stack)
            # Lambda reads the packaged function code from the artifact bucket
            # with the caller's (this role's) credentials.
            artifacts.grant_read(deploy_role)
            deploy_actions = [
                cpactions.CloudFormationCreateReplaceChangeSetAction(
                    action_name="CreateChangeSet",
                    stack_name=f"agentic-gates-demo-app{suffix}",
                    change_set_name="pipeline-changes",
                    template_path=packaged_out.at_path("packaged.yaml"),
                    # Live-demo domain injected at deploy time so the repo
                    # template stays generic (no ARNs in git).
                    parameter_overrides={
                        k: v for k, v in {
                            "Revision": "#{SourceVariables.CommitId}",
                            "DomainName": self.node.try_get_context("site_domain"),
                            "CertificateArn": self.node.try_get_context("site_cert"),
                            "HostedZoneId": self.node.try_get_context("site_zone"),
                        }.items() if v
                    } or None,
                    # CloudFormation acts as this role, scoped to what the
                    # artifact's template.yaml creates (see _app_deploy_role).
                    admin_permissions=False,
                    deployment_role=deploy_role,
                    cfn_capabilities=[
                        cdk.CfnCapabilities.ANONYMOUS_IAM,
                        cdk.CfnCapabilities.NAMED_IAM,
                        cdk.CfnCapabilities.AUTO_EXPAND,
                    ],
                    run_order=1,
                ),
                cpactions.CloudFormationExecuteChangeSetAction(
                    action_name="ExecuteChangeSet",
                    stack_name=f"agentic-gates-demo-app{suffix}",
                    change_set_name="pipeline-changes",
                    run_order=2,
                ),
            ]

        pipeline = codepipeline.Pipeline(
            self,
            "Pipeline",
            pipeline_name=pipeline_name,
            pipeline_type=codepipeline.PipelineType.V2,
            artifact_bucket=artifacts,
            stages=[
                codepipeline.StageProps(
                    stage_name="Source",
                    # GitHub variant: synth with -c github_repo=owner/name
                    #   -c connection_arn=arn:aws:codeconnections:... -c github_branch=...
                    # after authorizing the CodeConnection once in the console;
                    # the CodeCommit variant needs -c source=codecommit. Neither
                    # is a default (deploy_context.py).
                    # Gates are source-agnostic: both actions do a full clone.
                    actions=[source_action],
                ),
                codepipeline.StageProps(
                    stage_name="AutomatedGates",
                    actions=[
                        cpactions.CodeBuildAction(
                            action_name="Review", project=gate, input=source_out,
                            outputs=[review_out], variables_namespace="ReviewGate",
                            environment_variables={
                                "PIPELINE_EXECUTION_ID": codebuild.BuildEnvironmentVariable(
                                    value="#{codepipeline.PipelineExecutionId}"),
                                "SOURCE_REVISION": codebuild.BuildEnvironmentVariable(
                                    value="#{SourceVariables.CommitId}"),
                            }),
                        cpactions.CodeBuildAction(
                            action_name="Deterministic", project=det, input=source_out),
                        cpactions.CodeBuildAction(
                            action_name="ThreatModel", project=threat, input=source_out,
                            outputs=[threat_out],
                            environment_variables={
                                "PIPELINE_EXECUTION_ID": codebuild.BuildEnvironmentVariable(
                                    value="#{codepipeline.PipelineExecutionId}"),
                                "SOURCE_REVISION": codebuild.BuildEnvironmentVariable(
                                    value="#{SourceVariables.CommitId}"),
                            }),
                    ] + ([] if deploy_kind != "sam" else [
                        cpactions.CodeBuildAction(
                            action_name="UnitTests", project=unit_tests, input=source_out),
                        # `sam package` reads template.yaml, which only the
                        # artifact has. The road deploys a CDK app instead, so it
                        # skips this action and its packaged artifact entirely.
                        cpactions.CodeBuildAction(
                            action_name="Package", project=package, input=source_out,
                            outputs=[packaged_out]),
                    ]) + ([scan.action(source_out)] if scan else []),
                ),
            ] + ([] if gate_only else [
                codepipeline.StageProps(
                    stage_name="Approval",
                    actions=[cpactions.ManualApprovalAction(
                        action_name="Approve",
                        additional_information=(
                            "Agent verdict: #{ReviewGate.VERDICT} "
                            "(blocking findings: #{ReviewGate.BLOCKING}). "
                            "Compared with: #{ReviewGate.BASELINE_KIND} "
                            "(approved_baseline means an operator-approved starting "
                            "commit, not a reviewed release). "
                            "All automated gates passed. The review link opens the "
                            "findings for THIS commit "
                            "(#{SourceVariables.CommitId})."
                            + (continuum.ContinuumScan.APPROVAL_NOTE if scan else "")),
                        # Pin the link to this execution's revision instead of the
                        # bucket root, so an approver lands on the findings rather
                        # than hunting for a <commit>/ prefix. With a dashboard
                        # configured the board renders them (it already accepts
                        # ?commit=<sha>); without one, fall back to a deep link to
                        # the exact S3 object rather than the bucket.
                        external_entity_link=(
                            f"{dashboard_url.rstrip('/')}/?commit="
                            "#{SourceVariables.CommitId}"
                            if dashboard_url else
                            f"https://{self.region}.console.aws.amazon.com/s3/object/"
                            f"{reports.bucket_name}?region={self.region}"
                            "&prefix=#{SourceVariables.CommitId}/findings.json"),
                    )],
                ),
                codepipeline.StageProps(
                    stage_name="Deploy",
                    actions=deploy_actions,
                ),
            ]),
        )

        for project in (gate, threat):
            project.add_to_role_policy(iam.PolicyStatement(
                sid="ReadOwnReleaseHistory",
                actions=["codepipeline:ListPipelineExecutions"],
                resources=[f"arn:aws:codepipeline:{self.region}:{self.account}:{pipeline_name}"],
            ))
            # Read-only, and only the one object. Release approvers write it;
            # the pipeline never does (deploy/README.md, "Approved starting
            # commit"). S3 answers a missing object with NoSuchKey only to a
            # caller allowed to list the bucket, and with AccessDenied to anyone
            # else; the buildspec treats AccessDenied as an error. So listing is
            # allowed too, but only for this one key name as the prefix.
            project.add_to_role_policy(iam.PolicyStatement(
                sid="ReadApprovedBaseline",
                actions=["s3:GetObject", "s3:GetObjectVersion"],
                resources=[baseline_bucket.arn_for_objects(APPROVED_BASELINE_KEY)],
            ))
            project.add_to_role_policy(iam.PolicyStatement(
                sid="TellApprovedBaselineMissing",
                actions=["s3:ListBucket"],
                resources=[baseline_bucket.bucket_arn],
                conditions={"StringEquals": {"s3:prefix": APPROVED_BASELINE_KEY}},
            ))

        # The full-clone artifact hands each CodeBuild action a git reference,
        # so every gate project needs pull on the guarded repo.
        for project in (gate, det, threat, package, dash_deploy, unit_tests):
            if project is not None:
                repo.grant_pull(project)
        cdk.Tags.of(self).add("project", "sample-agentic-cicd-gates")

        cdk.CfnOutput(self, "RepoCloneUrlHttp", value=repo.repository_clone_url_http)
        cdk.CfnOutput(self, "PipelineName", value=pipeline.pipeline_name)
        cdk.CfnOutput(self, "ReportsBucketName", value=reports.bucket_name)
        cdk.CfnOutput(self, "BaselineBucketName", value=baseline_bucket.bucket_name,
                      description="Holds approved-baseline.json, the approved starting "
                                  "commit (deploy/README.md)")

    def _pin(self, asset: s3_assets.Asset, var: str) -> dict:
        """CodeBuild env vars that pin `asset` for fetch_pinned(var, ...).

        The SHA-256 is taken from the staged copy in the cloud assembly, which
        is what cdk-assets uploads (a directory is zipped from it). The version
        comes from S3 HeadObject at deploy time, once per asset content: a
        bucket without versioning returns no VersionId, and the deploy fails.
        Later writes to the same key do not move the pin. It moves only when
        this resource runs again: a new asset content, a new `pin_refresh`
        context value (deploy/README.md, re-pin), or a CDK upgrade that changes
        the provider. Each time, the hash still guards the bytes.
        """
        staged = pathlib.Path(asset.asset_path)
        if not staged.is_absolute():
            staged = pathlib.Path(cdk.Stage.of(self).outdir).resolve() / staged
        sha256 = (hashlib.sha256(staged.read_bytes()).hexdigest() if staged.is_file()
                  else tree_sha256(staged))
        refresh = str(self.node.try_get_context("pin_refresh") or "")
        if refresh and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", refresh):
            raise ValueError("-c pin_refresh must be 1-64 letters, digits, '.', '_' or '-'")
        version = cr.AwsCustomResource(
            self, f"{asset.node.id}Version",
            on_update=cr.AwsSdkCall(
                service="S3", action="headObject",
                parameters={"Bucket": asset.s3_bucket_name, "Key": asset.s3_object_key},
                physical_resource_id=cr.PhysicalResourceId.of(
                    f"{asset.asset_hash}-{refresh}" if refresh else asset.asset_hash),
                output_paths=["VersionId"]),
            role=self._pin_role,
            install_latest_aws_sdk=False,
        )
        return {
            f"{var}_BUCKET": codebuild.BuildEnvironmentVariable(value=asset.s3_bucket_name),
            f"{var}_KEY": codebuild.BuildEnvironmentVariable(value=asset.s3_object_key),
            f"{var}_VERSION": codebuild.BuildEnvironmentVariable(
                value=version.get_response_field("VersionId")),
            f"{var}_SHA256": codebuild.BuildEnvironmentVariable(value=sha256),
        }

    def _app_deploy_role(self, app_stack: str) -> iam.Role:
        """CloudFormation service role for the artifact's SAM stack.

        Scoped to the resources the artifact's template.yaml creates: two named
        Lambda functions, their SAM-generated roles, an HTTP API, the CodeDeploy
        application and group, one alarm, the CloudFront distribution and cache
        policy, and optional Route 53 records. Roles may only be created under
        the stack's name prefix, may only receive the two AWS managed policies
        SAM attaches, and may only be passed to Lambda or CodeDeploy. Inline
        role policies remain possible because the template declares one; the
        deterministic lane and the reviewers check template.yaml for wildcards
        before this role ever runs. Adapting the sample to another template
        means extending this role to match it.
        """
        a, r = self.account, self.region
        functions = ["agentic-gates-demo-hello", "CodeDeployHook_agentic-gates-pretraffic"]
        # HelloFn's DeploymentPreference (Type: Canary10Percent5Minutes).
        canary_config = "CodeDeployDefault.LambdaCanary10Percent5Minutes"
        fn_arns = [f"arn:aws:lambda:{r}:{a}:function:{n}" for n in functions]
        role_arn = f"arn:aws:iam::{a}:role/{app_stack}-*"
        role = iam.Role(
            self, "AppDeployRole",
            assumed_by=iam.ServicePrincipal("cloudformation.amazonaws.com"),
            description=f"CloudFormation service role for {app_stack} (least privilege)")
        role.add_to_policy(iam.PolicyStatement(
            sid="SamTransform",
            actions=["cloudformation:CreateChangeSet"],
            resources=[f"arn:aws:cloudformation:{r}:aws:transform/Serverless-2016-10-31",
                       f"arn:aws:cloudformation:{r}:aws:transform/LanguageExtensions"]))
        role.add_to_policy(iam.PolicyStatement(
            sid="AppFunctions",
            actions=["lambda:CreateFunction", "lambda:DeleteFunction", "lambda:Get*",
                     "lambda:List*", "lambda:UpdateFunctionCode",
                     "lambda:UpdateFunctionConfiguration", "lambda:PublishVersion",
                     "lambda:CreateAlias", "lambda:UpdateAlias", "lambda:DeleteAlias",
                     "lambda:AddPermission", "lambda:RemovePermission",
                     "lambda:TagResource", "lambda:UntagResource",
                     "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency",
                     "lambda:PutRuntimeManagementConfig", "lambda:PutFunctionRecursionConfig",
                     "lambda:PutFunctionCodeSigningConfig",
                     "lambda:DeleteFunctionCodeSigningConfig",
                     "lambda:PutProvisionedConcurrencyConfig",
                     "lambda:DeleteProvisionedConcurrencyConfig"],
            resources=fn_arns + [f"{x}:*" for x in fn_arns]))
        role.add_to_policy(iam.PolicyStatement(
            sid="AppRoles",
            actions=["iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole",
                     "iam:UpdateRoleDescription",
                     "iam:UpdateAssumeRolePolicy", "iam:TagRole", "iam:UntagRole",
                     "iam:ListRoleTags", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                     "iam:GetRolePolicy", "iam:ListRolePolicies",
                     "iam:ListAttachedRolePolicies"],
            resources=[role_arn]))
        role.add_to_policy(iam.PolicyStatement(
            sid="AppRoleManagedPolicies",
            actions=["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
            resources=[role_arn],
            conditions={"ArnEquals": {"iam:PolicyARN": [
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"]}}))
        role.add_to_policy(iam.PolicyStatement(
            sid="PassAppRoles",
            actions=["iam:PassRole"],
            resources=[role_arn],
            conditions={"StringEquals": {"iam:PassedToService": [
                "lambda.amazonaws.com", "codedeploy.amazonaws.com"]}}))
        role.add_to_policy(iam.PolicyStatement(
            sid="AppHttpApi",
            # TagResource/UntagResource: the HTTP API stage handler checks them
            # (seen in a test deploy) although IAM Access Analyzer lists them
            # as unknown actions.
            actions=["apigateway:GET", "apigateway:POST", "apigateway:PUT",
                     "apigateway:PATCH", "apigateway:DELETE", "apigateway:TagResource",
                     "apigateway:UntagResource"],
            resources=[f"arn:aws:apigateway:{r}::/apis", f"arn:aws:apigateway:{r}::/apis/*",
                       f"arn:aws:apigateway:{r}::/tags/*"]))
        role.add_to_policy(iam.PolicyStatement(
            sid="AppCanary",
            actions=["codedeploy:CreateApplication", "codedeploy:DeleteApplication",
                     "codedeploy:GetApplication", "codedeploy:UpdateApplication",
                     "codedeploy:CreateDeploymentGroup", "codedeploy:UpdateDeploymentGroup",
                     "codedeploy:DeleteDeploymentGroup", "codedeploy:GetDeploymentGroup",
                     "codedeploy:ListDeploymentGroups", "codedeploy:CreateDeployment",
                     "codedeploy:GetDeployment", "codedeploy:ListDeployments",
                     "codedeploy:StopDeployment",
                     "codedeploy:RegisterApplicationRevision",
                     "codedeploy:GetApplicationRevision", "codedeploy:TagResource",
                     "codedeploy:UntagResource", "codedeploy:ListTagsForResource"],
            resources=[f"arn:aws:codedeploy:{r}:{a}:application:{app_stack}-*",
                       f"arn:aws:codedeploy:{r}:{a}:deploymentgroup:{app_stack}-*/*"]))
        # CreateDeployment also needs GetDeploymentConfig on the group's config,
        # which is the one the template's DeploymentPreference names.
        role.add_to_policy(iam.PolicyStatement(
            sid="AppCanaryConfig",
            actions=["codedeploy:GetDeploymentConfig"],
            resources=[f"arn:aws:codedeploy:{r}:{a}:deploymentconfig:{canary_config}"]))
        role.add_to_policy(iam.PolicyStatement(
            sid="AppAlarm",
            actions=["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms",
                     "cloudwatch:DescribeAlarms",
                     "cloudwatch:TagResource", "cloudwatch:UntagResource",
                     "cloudwatch:ListTagsForResource"],
            resources=[f"arn:aws:cloudwatch:{r}:{a}:alarm:{app_stack}-*"]))
        # No ACM permission: the CloudFront distribution handler reads the
        # certificate itself, so the role never calls ACM.
        # distribution/* and cache-policy/* are not a shortcut: CloudFront picks
        # each ID when it creates the resource, so no ARN can name it before
        # this role creates it. The deterministic lane reports this statement,
        # and agent/tests/test_tier1_baseline.py accepts exactly that finding.
        role.add_to_policy(iam.PolicyStatement(
            sid="AppCdn",
            actions=["cloudfront:CreateDistribution",
                     "cloudfront:UpdateDistribution", "cloudfront:DeleteDistribution",
                     "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig",
                     "cloudfront:TagResource", "cloudfront:UntagResource",
                     "cloudfront:ListTagsForResource", "cloudfront:CreateCachePolicy",
                     "cloudfront:UpdateCachePolicy", "cloudfront:DeleteCachePolicy",
                     "cloudfront:GetCachePolicy", "cloudfront:GetCachePolicyConfig"],
            resources=[f"arn:aws:cloudfront::{a}:distribution/*",
                       f"arn:aws:cloudfront::{a}:cache-policy/*"]))
        zone = self.node.try_get_context("site_zone")
        if zone:
            role.add_to_policy(iam.PolicyStatement(
                sid="AppDnsRecords",
                actions=["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets",
                         "route53:GetHostedZone"],
                resources=[f"arn:aws:route53:::hostedzone/{zone}"]))
            role.add_to_policy(iam.PolicyStatement(
                sid="AppDnsChanges", actions=["route53:GetChange"],
                resources=["arn:aws:route53:::change/*"]))
            # No route53:ListHostedZones (it has no resource-level form): the
            # template names its zone by HostedZoneId, and records were
            # created, updated and deleted without it in a test deploy.
        return role
