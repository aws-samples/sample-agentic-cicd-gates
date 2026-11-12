"""Tier 2 — AgentCore Runtime-hosted reviewer behind a CodePipeline Lambda gate.

What changes vs Tier 1: the agent moves OUT of pipeline compute into
Bedrock AgentCore Runtime (per-invoke microVM session isolation, its own execution
role, built-in observability). The pipeline-side gate shrinks to a thin Lambda that
holds NO model permissions — enforced with an explicit IAM Deny, not just absence.

Deploy from tier2-agentcore/infra with the stack's complete context (the full
commands are in deploy/README.md); synth refuses implicit or partial source
context. One command, wrapped here:
    CDK_DOCKER=finch npx -y aws-cdk@2.1144.0 deploy Tier2PipelineStack
      -c stack_id=Tier2PipelineStack -c name_suffix=
      -c github_repo=OWNER/REPO -c connection_arn=ARN -c github_branch=main
"""
import pathlib
import sys

import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    Stack,
    aws_bedrockagentcore as agentcore,
    aws_codecommit as codecommit,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as cpactions,
    aws_ecr_assets as ecr_assets,
    aws_iam as iam,
    aws_lambda as lambda_,
)
from constructs import Construct

# One definition of the source-context rules for Tier 1 and Tier 2.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tier1-codebuild"))
from deploy_context import GITHUB_KEYS, source_kind  # noqa: E402

DEMO_REPO_NAME = "agentic-gates-demo"  # created by Tier1PipelineStack — deploy that first


class Tier2PipelineStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)

        # A second instance of this stack gates the ROAD itself (this repo),
        # so every physical name takes a suffix. Empty by default = today.
        suffix = self.node.try_get_context("name_suffix") or ""
        demo_repo_name = f"{DEMO_REPO_NAME}{suffix}"
        # Refuse implicit or partial source context before anything is built,
        # as Tier 1 does: a redeploy that forgot -c github_repo or
        # -c connection_arn used to switch this pipeline to the CodeCommit demo
        # repo, and the branch was fixed to main. GitHub now needs all three of
        # github_repo, connection_arn and github_branch; CodeCommit needs
        # -c source=codecommit (and reads main, as before).
        context = {key: self.node.try_get_context(key) for key in ("source", *GITHUB_KEYS)}
        source = source_kind(context, "Tier 2", "its stack_id and name_suffix")

        # ---- Reviewer container image (shared agent core, arm64 per Runtime contract)
        image = ecr_assets.DockerImageAsset(
            self,
            "ReviewerImage",
            directory="../..",  # repo root: Dockerfile copies agent/reviewer + handler
            file="tier2-agentcore/runtime/Dockerfile",
            platform=ecr_assets.Platform.LINUX_ARM64,
        )

        # ---- Runtime execution role: the ONLY principal with model access
        runtime_role = iam.Role(
            self,
            "RuntimeExecutionRole",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            description="AgentCore Runtime execution role for the reviewer agent",
        )
        image.repository.grant_pull(runtime_role)
        runtime_role.add_to_policy(iam.PolicyStatement(
            sid="EcrAuth", actions=["ecr:GetAuthorizationToken"], resources=["*"]))
        runtime_role.add_to_policy(iam.PolicyStatement(
            sid="Logs",
            actions=["logs:CreateLogGroup", "logs:CreateLogStream",
                     "logs:PutLogEvents", "logs:DescribeLogGroups",
                     "logs:DescribeLogStreams"],
            resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/bedrock-agentcore/*"]))
        runtime_role.add_to_policy(iam.PolicyStatement(
            sid="Telemetry",
            actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords",
                     "cloudwatch:PutMetricData"],
            resources=["*"]))
        runtime_role.add_to_policy(iam.PolicyStatement(
            sid="WorkloadIdentity",
            actions=["bedrock-agentcore:GetWorkloadAccessToken"],
            resources=[f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:workload-identity-directory/*"]))
        runtime_role.add_to_policy(iam.PolicyStatement(
            sid="BedrockInvokeAnthropicOnly",
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=[
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.anthropic.*",
                "arn:aws:bedrock:*::foundation-model/anthropic.*",
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.openai.*",
                "arn:aws:bedrock:*::foundation-model/openai.*",
            ]))

        # ---- The AgentCore Runtime itself (DEFAULT endpoint is auto-created)
        runtime = agentcore.CfnRuntime(
            self,
            "ReviewerRuntime",
            agent_runtime_name=f"agentic_gates_reviewer{suffix.replace('-', '_')}",
            description="Two-stage diff reviewer (same core as Tier 1) on AgentCore Runtime",
            agent_runtime_artifact=agentcore.CfnRuntime.AgentRuntimeArtifactProperty(
                container_configuration=agentcore.CfnRuntime.ContainerConfigurationProperty(
                    container_uri=image.image_uri)),
            network_configuration=agentcore.CfnRuntime.NetworkConfigurationProperty(
                network_mode="PUBLIC"),
            protocol_configuration="HTTP",
            role_arn=runtime_role.role_arn,
        )
        # The control plane validates ECR pull access at create time by assuming
        # the execution role — wait for the role's DefaultPolicy, not just the role.
        runtime.node.add_dependency(runtime_role)

        # ---- Thin pipeline gate: zero model permissions, provably
        repo = codecommit.Repository.from_repository_name(self, "DemoRepo", demo_repo_name)
        state_bucket = s3.Bucket(
            self, "GateState",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            # The accepted-review baseline is security state: keep earlier
            # versions so an overwrite can be audited and rolled back.
            versioned=True,
            lifecycle_rules=[s3.LifecycleRule(
                noncurrent_version_expiration=cdk.Duration.days(365))],
        )

        gate_fn = lambda_.Function(
            self,
            "GateFn",
            function_name=f"agentic-gates-tier2{suffix}-gate",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="lambda_handler.handler",
            timeout=cdk.Duration.minutes(15),
            memory_size=256,
            code=lambda_.Code.from_asset(
                "../gate",
                # Bytecode a local test run leaves in gate/ is not source. Keep it
                # out of the asset hash, and copy only the named files into the
                # bundle (bundling reads the directory itself, not a filtered
                # copy), so every checkout of one commit deploys the same zip.
                # --no-compile: pip's .pyc files embed install-time mtimes, so
                # they differed on every build, and Lambda never used them (the
                # asset zip dates every entry 1980-01-01, so they read as stale).
                exclude=["__pycache__", "*.pyc"],
                bundling=cdk.BundlingOptions(
                    image=lambda_.Runtime.PYTHON_3_12.bundling_image,
                    platform="linux/arm64",
                    command=["bash", "-c",
                             "pip install --quiet --no-compile -r requirements.txt -t /asset-output "
                             "&& cp lambda_handler.py requirements.txt /asset-output/"],
                ),
            ),
            environment={"RUNTIME_QUALIFIER": "DEFAULT",
                         "STATE_BUCKET": state_bucket.bucket_name},
        )
        state_bucket.grant_read_write(gate_fn)
        gate_fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadChangeFromCodeCommit",
            actions=["codecommit:GetCommit", "codecommit:GetDifferences",
                     "codecommit:GetBlob", "codecommit:GetFile"],
            resources=[repo.repository_arn]))
        gate_fn.add_to_role_policy(iam.PolicyStatement(
            sid="InvokeReviewerRuntime",
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resources=[runtime.attr_agent_runtime_arn,
                       f"{runtime.attr_agent_runtime_arn}/runtime-endpoint/*"]))
        gate_fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReportBackToPipeline",
            actions=["codepipeline:PutJobSuccessResult",
                     "codepipeline:PutJobFailureResult"],
            resources=["*"]))  # these two actions do not support resource scoping
        # Separation of duties, stated as policy rather than convention:
        gate_fn.add_to_role_policy(iam.PolicyStatement(
            sid="DenyDirectModelAccess",
            effect=iam.Effect.DENY,
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=["*"]))
        gate_fn.add_to_role_policy(iam.PolicyStatement(
            sid="DenyUserTokenMinting",  # hardening
            effect=iam.Effect.DENY,
            actions=["bedrock-agentcore:GetWorkloadAccessTokenForUserId"],
            resources=["*"]))

        # ---- Pipeline on the SAME demo repo as Tier 1 (side-by-side demo)
        source_out = codepipeline.Artifact("Source")
        if source == "github":
            gh_repo = context["github_repo"]
            src_action = cpactions.CodeStarConnectionsSourceAction(
                action_name="Source",
                owner=gh_repo.split("/")[0],
                repo=gh_repo.split("/")[1],
                branch=context["github_branch"],
                connection_arn=context["connection_arn"],
                output=source_out,
            )
        else:
            src_action = cpactions.CodeCommitSourceAction(
                action_name="Source", repository=repo, branch="main",
                output=source_out)

        pipeline = codepipeline.Pipeline(
            self,
            "Pipeline",
            pipeline_name=f"agentic-gates-tier2{suffix}",
            pipeline_type=codepipeline.PipelineType.V2,
            enable_key_rotation=True,   # artifact-bucket KMS key rotates yearly
            stages=[
                codepipeline.StageProps(
                    stage_name="Source",
                    actions=[src_action],
                ),
                codepipeline.StageProps(
                    stage_name="AgentReviewGate",
                    actions=[cpactions.LambdaInvokeAction(
                        action_name="Review",
                        lambda_=gate_fn,
                        inputs=[source_out],
                        user_parameters={
                            "repository": demo_repo_name,
                            "runtime_arn": runtime.attr_agent_runtime_arn,
                            # Resolved per run; the gate logs it so the dashboard
                            # can bind the report to this execution.
                            "pipeline_execution_id": "#{codepipeline.PipelineExecutionId}",
                        })],
                ),
            ],
        )

        cdk.CfnOutput(self, "RuntimeArn", value=runtime.attr_agent_runtime_arn)
        cdk.CfnOutput(self, "PipelineName", value=pipeline.pipeline_name)
        cdk.CfnOutput(self, "GateFunctionName", value=gate_fn.function_name)
