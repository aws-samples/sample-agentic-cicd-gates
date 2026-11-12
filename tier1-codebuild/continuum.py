"""Optional AWS Continuum scan for Tier 1, behind one switch.

AWS Continuum for code vulnerabilities (generally available Oct 22, 2026, in
us-east-1 and us-west-2) scans a whole code base, checks which findings are
exploitable, and proposes fixes. It does a different job from this sample's
reviewer, which judges ONE change against the team's rules and can block it.
So the Continuum action here is ADVISORY: it runs beside the gates, reports
what Continuum found, and its findings never change the verdict or block a
release. Like any pipeline action, though, the action itself can still fail (a
CodeBuild-level failure or the project timeout) and fail the stage.

One switch turns it on:

    -c enable_continuum=true

It is OFF by default. Off (the default, or -c enable_continuum=false)
synthesizes none of the following: the ContinuumScan action, its CodeBuild
project and role, or the grants they carry. The rest of the stack is
unchanged, so an off synth is byte-for-byte a stack without this file.

You own the Continuum integration and environment, not this stack. Create the
S3 integration (pointing it at a bucket you own) and the environment once, in
the console or CLI, then pass their identifiers:

    -c enable_continuum=true \\
    -c continuum_source_bucket=<the bucket your S3 integration reads> \\
    -c continuum_environment_id=<your environment id>

The stack adds only the advisory action: it uploads the revision being
released to <bucket>/code/ and asks your environment to scan it. It creates no
integration, environment, bucket or role, and the scan project's only grants
are PutObject on that bucket's code/ prefix and the three code-scan calls on
that one environment. So the stack holds no account-wide write permission and
its own deterministic lane (checks.py) passes with the switch on or off.

Give the stack an explicit env Region (us-east-1 or us-west-2); outside those
two the switch is ignored with a synth warning, so the pipeline deploys and
runs without Continuum instead of failing.

Cost: a monthly context fee per protected line of code plus a fee per unit of
security work (https://aws.amazon.com/continuum/pricing/ — check it yourself;
rates change). Create the environment with manual-only scans, so it scans when
the pipeline asks and not also on a schedule.
"""
import pathlib
from typing import Callable

import aws_cdk as cdk
from aws_cdk import (
    aws_codebuild as codebuild,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as cpactions,
    aws_iam as iam,
    aws_s3_assets as s3_assets,
)
from constructs import Construct

CONTEXT_KEY = "enable_continuum"
BUCKET_KEY = "continuum_source_bucket"
ENVIRONMENT_KEY = "continuum_environment_id"
SUPPORTED_REGIONS = ("us-east-1", "us-west-2")
# The first boto3 we tested with a `continuum` client. The review gate keeps
# its own older pin; this action installs its own so the two never collide.
BOTO_PIN = "1.43.123"
SCAN_WAIT_SECONDS = 15 * 60
CODE_PREFIX = "code/"

_ON = ("true", "1", "on", "yes")
_OFF = ("false", "0", "off", "no")


def enabled(value) -> bool:
    """The switch: unset means OFF; anything but a clear on/off is refused."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _ON:
        return True
    if text in _OFF:
        return False
    raise ValueError(f"-c {CONTEXT_KEY}={value!r}: use true or false")


def region_skip_reason(region: str) -> str | None:
    """Why Continuum is left out in this Region, or None when it can run."""
    if cdk.Token.is_unresolved(region):
        return ("AWS Continuum needs a known Region to decide whether it is "
                "available; give the stack an explicit env region. Skipping it.")
    if region not in SUPPORTED_REGIONS:
        return (f"AWS Continuum for code vulnerabilities is available in "
                f"{' and '.join(SUPPORTED_REGIONS)}, not {region}. "
                "Skipping the ContinuumScan action; the other gates are unchanged.")
    return None


def required_context(node) -> tuple[str, str]:
    """The identifiers the switch needs, or a ValueError naming what is missing.

    There is no default: the integration and environment belong to your
    account, so you must create them and pass their ids. A forgotten value
    stops synth here rather than deploying a scan that points nowhere.
    """
    bucket = node.try_get_context(BUCKET_KEY)
    environment_id = node.try_get_context(ENVIRONMENT_KEY)
    missing = [key for key, value in ((BUCKET_KEY, bucket), (ENVIRONMENT_KEY, environment_id))
               if not value]
    if missing:
        raise ValueError(
            f"-c {CONTEXT_KEY}=true needs {' and '.join('-c ' + m + '=<value>' for m in missing)}: "
            "create the Continuum S3 integration and environment yourself, then pass "
            f"-c {BUCKET_KEY}=<the bucket your integration reads> and "
            f"-c {ENVIRONMENT_KEY}=<your environment id>. The stack creates neither.")
    return str(bucket), str(environment_id)


def scan_build_spec(pin_pyenv: str, fetch_tools: str) -> codebuild.BuildSpec:
    """The scan buildspec, hardened like every other gate: pyenv pinned outside
    the checkout, every Python command run `python -I`, the tools asset fetched
    at its pinned S3 version + SHA-256 (not by key), and reports/ emptied first.

    `pin_pyenv` is the stack's PIN_PYENV; `fetch_tools` is the stack's
    fetch_pinned("CONTINUUM_TOOLS", ...) command. Passed in so this module does
    not import tier1_stack (which imports this one)."""
    return codebuild.BuildSpec.from_object({
        "version": "0.2",
        "env": {"exported-variables": ["CONTINUUM_SUMMARY"]},
        "phases": {
            "install": {
                "runtime-versions": {"python": "3.12"},
                # Advisory: an install failure is reported by the script (which
                # then has no continuum client), not turned into a failed release.
                "commands": [
                    pin_pyenv,
                    f"python -I -m pip install --quiet boto3=={BOTO_PIN} botocore=={BOTO_PIN}"
                    " || echo 'CONTINUUM (advisory): could not install the scan dependencies'",
                ],
            },
            "build": {
                "commands": [
                    # Fetch the scan tool at its pinned S3 version + SHA-256. A
                    # key alone is not a pin (the shared asset bucket is writable
                    # by other deploy roles); a mismatch stops the action.
                    fetch_tools,
                    # The candidate checkout is cwd and may ship its own reports/.
                    "rm -rf reports && mkdir reports",
                    # python -I: a json.py / argparse.py in the checkout cannot be
                    # imported in place of the library with this action's role.
                    "python -I /tmp/continuum-tools/continuum_scan.py"
                    " --region $AWS_REGION --bucket $CONTINUUM_BUCKET"
                    " --environment-id $CONTINUUM_ENVIRONMENT_ID"
                    " --revision $SOURCE_REVISION --execution-id $PIPELINE_EXECUTION_ID"
                    " --wait-seconds $CONTINUUM_WAIT_SECONDS --report reports/continuum.json"
                    " || true",
                    # Isolated too: this value goes verbatim into the approval note.
                    "export CONTINUUM_SUMMARY=\"$(python -I -c \"import json;"
                    "print(json.load(open('reports/continuum.json'))['summary'])\""
                    " 2>/dev/null || echo 'no report; see the build log')\"",
                    'echo "CONTINUUM (advisory): $CONTINUUM_SUMMARY"',
                ],
            },
        },
        "artifacts": {"files": ["reports/**/*"]},
    })


class ContinuumScan(Construct):
    """The advisory scan CodeBuild project. No integration, environment or bucket."""

    def __init__(self, scope: Construct, cid: str, *, pipeline_name: str,
                 build_environment: codebuild.BuildEnvironment,
                 source_bucket: str, environment_id: str,
                 pin: Callable[[s3_assets.Asset, str], dict],
                 pin_pyenv: str, gate_python_env: dict,
                 fetch_pinned: Callable[..., str]) -> None:
        super().__init__(scope, cid)
        stack = cdk.Stack.of(self)
        account, region = stack.account, stack.region
        # The one environment this action may touch, named in context. The
        # wildcard sits UNDER the named environment, so it is scoped, not an
        # account-wide `environments/*`.
        environment_arn = f"arn:aws:continuum:{region}:{account}:environments/{environment_id}"

        tools = s3_assets.Asset(self, "ScanTools",
                                path=str(pathlib.Path(__file__).parent / "continuum_tools"))
        # The stack pins the asset to one S3 version + SHA-256 (it owns the
        # AssetPinRole), and hands back the fetch_pinned env vars.
        tools_pin = pin(tools, "CONTINUUM_TOOLS")
        fetch_tools = fetch_pinned("CONTINUUM_TOOLS", "continuum scan tools",
                                   "/tmp/continuum-tools.zip", "/tmp/continuum-tools")
        self.project = codebuild.PipelineProject(
            self, "ScanProject",
            project_name=f"{pipeline_name}-continuum",
            build_spec=scan_build_spec(pin_pyenv, fetch_tools),
            environment=build_environment,
            environment_variables={
                **tools_pin,
                **{k: codebuild.BuildEnvironmentVariable(value=v)
                   for k, v in gate_python_env.items()},
                "CONTINUUM_BUCKET": codebuild.BuildEnvironmentVariable(value=source_bucket),
                "CONTINUUM_ENVIRONMENT_ID": codebuild.BuildEnvironmentVariable(value=environment_id),
                "CONTINUUM_WAIT_SECONDS": codebuild.BuildEnvironmentVariable(
                    value=str(SCAN_WAIT_SECONDS)),
            },
            timeout=cdk.Duration.minutes(SCAN_WAIT_SECONDS // 60 + 10),
        )
        tools.grant_read(self.project)
        # It may add the revision's source zip under code/ of the one bucket the
        # integration reads, and nothing else on S3 (a wildcard under a named
        # bucket is scoped).
        self.project.add_to_role_policy(iam.PolicyStatement(
            sid="UploadSourceZip", actions=["s3:PutObject"],
            resources=[f"arn:aws:s3:::{source_bucket}/{CODE_PREFIX}*"]))
        # It may start and read a scan only on the one named environment.
        self.project.add_to_role_policy(iam.PolicyStatement(
            sid="ScanThisEnvironmentOnly",
            actions=["continuum:CreateCodeScan", "continuum:GetCodeScan",
                     "continuum:ListCodeIssues"],
            resources=[environment_arn, f"{environment_arn}/*"]))

    def action(self, source: codepipeline.Artifact) -> cpactions.CodeBuildAction:
        return cpactions.CodeBuildAction(
            action_name="ContinuumScan", project=self.project, input=source,
            outputs=[codepipeline.Artifact("ContinuumReports")],
            variables_namespace="ContinuumScan",
            environment_variables={
                "PIPELINE_EXECUTION_ID": codebuild.BuildEnvironmentVariable(
                    value="#{codepipeline.PipelineExecutionId}"),
                "SOURCE_REVISION": codebuild.BuildEnvironmentVariable(
                    value="#{SourceVariables.CommitId}"),
            })

    # Shown to the approver after the gate verdict, only when this action exists.
    APPROVAL_NOTE = (" Continuum (advisory, never blocks): "
                     "#{ContinuumScan.CONTINUUM_SUMMARY}.")
