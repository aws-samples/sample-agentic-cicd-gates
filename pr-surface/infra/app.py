"""PR-surface auth — GitHub OIDC provider + least-privilege reviewer role.

No static API keys anywhere: the Actions job presents a GitHub OIDC
token; STS trusts it only for pull_request runs of the named repositories; the
role can only invoke Bedrock on Anthropic and OpenAI models and validate IAM
policies.

Deploy:  npx -y aws-cdk@2.1144.0 deploy -c repo=OWNER/REPO[,OWNER/REPO]
"""
import aws_cdk as cdk
from aws_cdk import Stack, aws_iam as iam
from constructs import Construct

GITHUB_OIDC_URL = "https://token.actions.githubusercontent.com"


class PrReviewerAuthStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)
        # Comma-separated so one role can serve every repo whose PRs this panel
        # gates. The framework repo gates its OWN pull requests, so it needs the
        # trust too - a single-repo value silently AccessDenied'd it.
        repos = [r.strip() for r in (self.node.try_get_context("repo") or "").split(",")
                 if r.strip()]
        if not repos or any(r.count("/") != 1 for r in repos):
            raise ValueError("pass -c repo=OWNER/REPO[,OWNER/REPO]: the repositories "
                             "whose pull requests may assume the reviewer role")

        provider = iam.OpenIdConnectProvider(
            self, "GitHubOidc",
            url=GITHUB_OIDC_URL,
            client_ids=["sts.amazonaws.com"],
        )

        subs: list[str] = []
        for repo in repos:
            owner, name = repo.split("/", 1)
            # Pull-request runs only: the workflow runs on pull_request, so no
            # push, tag or environment context may assume this role. Two
            # patterns per repo because GitHub's sub claim can embed numeric
            # ids (repo:owner@<ownerId>/name@<repoId>:...); the legacy
            # repo:owner/name:... form is kept for older deployments.
            # Hardened option: pin the exact ids instead of '@*'.
            subs += [f"repo:{repo}:pull_request", f"repo:{owner}@*/{name}@*:pull_request"]

        role = iam.Role(
            self, "PrReviewerRole",
            role_name="agentic-gates-pr-reviewer",
            max_session_duration=cdk.Duration.hours(1),
            assumed_by=iam.WebIdentityPrincipal(
                provider.open_id_connect_provider_arn,
                conditions={
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                    # Pull-request runs of these repos only, nothing else.
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": subs},
                },
            ),
            description="Bedrock-only reviewer role for GitHub Actions in "
                        + ", ".join(repos),
        )
        role.add_to_policy(iam.PolicyStatement(
            sid="BedrockInvokeAnthropicOnly",
            actions=["bedrock:InvokeModel"],
            resources=[
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.anthropic.*",
                "arn:aws:bedrock:*::foundation-model/anthropic.*",
                f"arn:aws:bedrock:*:{self.account}:inference-profile/us.openai.*",
                "arn:aws:bedrock:*::foundation-model/openai.*",
            ]))
        role.add_to_policy(iam.PolicyStatement(
            # Deterministic lane parity: checks.py calls ValidatePolicy on
            # inline IAM policies in the PR's templates. The API is read-only,
            # stateless, and has NO resource-level permissions, so Resource
            # must be "*" — blast radius narrowed to the reviewer's region per
            # IAM-002 remediation (Security Review Agent finding, 2026-08-18).
            sid="AccessAnalyzerValidatePolicyOnly",
            actions=["access-analyzer:ValidatePolicy"],
            resources=["*"],
            conditions={"StringEquals": {"aws:RequestedRegion": "us-west-2"}}))

        cdk.CfnOutput(self, "ReviewerRoleArn", value=role.role_arn)


app = cdk.App()
PrReviewerAuthStack(app, "PrReviewerAuthStack",
                    env=cdk.Environment(region="us-west-2"))
app.synth()
