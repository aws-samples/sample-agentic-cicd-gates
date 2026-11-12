"""Operator dashboard for the agentic CI/CD gates sample.

    viewer -- CloudFront (default domain, or an optional custom domain)
                |-- default  -> HTTP API $default (public) -> DashboardFn
                |               serves the SPA shell and GET /auth-config
                `-- /api/*   -> HTTP API ANY /api, /api/{proxy+}
                                JWT authorizer (Cognito user pool) -> DashboardFn

The board shows pipeline state, review findings and build-log excerpts read
from this account, so every /api route requires a Cognito access token. The SPA
shell carries no data and stays public. Users sign in with Cognito managed
login (authorization code grant with PKCE). Self sign-up is off: an
administrator creates each user.

Context keys (all optional; see dashboard/README.md):
    artifact_repo        OWNER/NAME of the application repository on GitHub
    gates_repo           OWNER/NAME of this gates repository on GitHub
    site_url             https:// link to the deployed application
    github_token_secret  Secrets Manager secret NAME holding a read-only token
    auth_domain_prefix   Cognito managed-login domain prefix (globally unique)
    dashboard_domain     custom domain name for the dashboard
    dashboard_zone_id    Route 53 hosted zone id for dashboard_domain
    dashboard_zone_name  Route 53 hosted zone name for dashboard_domain

The account and Region come from the deploy environment (CDK_DEFAULT_ACCOUNT,
CDK_DEFAULT_REGION). Deploy with dashboard/deploy.sh.
"""
import os
import pathlib
import re

import aws_cdk as cdk
from aws_cdk import (
    Stack,
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_authorizers as authorizers,
    aws_apigatewayv2_integrations as integrations,
    aws_certificatemanager as acm,
    aws_cloudfront as cf,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
    aws_iam as iam,
    aws_secretsmanager as sm,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_route53 as r53,
    aws_route53_targets as r53t,
)
from constructs import Construct

# Prefix-scoped: the handler reads every tier pipeline of this sample.
PIPELINE_PREFIX = "agentic-gates-"
# Each Tier 1 stack owns a reports bucket with a CloudFormation-generated name.
REPORTS_BUCKET_ARN = "arn:aws:s3:::tier1pipelinestack*-reportsbucket*"
TIER2_LOG_GROUP = "/aws/lambda/agentic-gates-tier2*"

GH_TOKEN_SECRET_CTX = "github_token_secret"
DOMAIN_KEYS = ("dashboard_domain", "dashboard_zone_id", "dashboard_zone_name")
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$")
PREFIX_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _ctx(scope: Construct, key: str) -> str:
    return str(scope.node.try_get_context(key) or "").strip()


def custom_domain(scope: Construct) -> dict | None:
    """The three dashboard_* keys together, or None. Partial context is refused."""
    values = {k: _ctx(scope, k) for k in DOMAIN_KEYS}
    given = [k for k, v in values.items() if v]
    if not given:
        return None
    if len(given) != len(DOMAIN_KEYS):
        missing = [k for k in DOMAIN_KEYS if k not in given]
        raise ValueError("a custom dashboard domain also needs "
                         + ", ".join(f"-c {k}=..." for k in missing))
    return values


def _zone(scope: Construct, domain: dict) -> r53.IHostedZone:
    return r53.HostedZone.from_hosted_zone_attributes(
        scope, "Zone", hosted_zone_id=domain["dashboard_zone_id"],
        zone_name=domain["dashboard_zone_name"])


class DashboardCertStack(Stack):
    """CloudFront certificates must live in us-east-1. Only for a custom domain."""

    def __init__(self, scope: Construct, cid: str, domain: dict, **kw) -> None:
        super().__init__(scope, cid, **kw)
        self.cert = acm.Certificate(
            self, "Cert", domain_name=domain["dashboard_domain"],
            validation=acm.CertificateValidation.from_dns(_zone(self, domain)))


class DashboardStack(Stack):
    def __init__(self, scope: Construct, cid: str, domain: dict | None = None,
                 cert: acm.ICertificate | None = None, **kw) -> None:
        super().__init__(scope, cid, **kw)
        root = pathlib.Path(__file__).resolve().parents[1]
        region = self.region

        repos = {k: _ctx(self, k) for k in ("artifact_repo", "gates_repo")}
        for key, value in repos.items():
            if value and not REPO_RE.match(value):
                raise ValueError(f"-c {key}={value!r}: expected OWNER/NAME")
        site_url = _ctx(self, "site_url")
        if site_url and not site_url.startswith("https://"):
            raise ValueError("-c site_url must be an https:// URL")
        gh_secret = _ctx(self, GH_TOKEN_SECRET_CTX)
        prefix = _ctx(self, "auth_domain_prefix")
        if prefix and not PREFIX_RE.match(prefix):
            raise ValueError("-c auth_domain_prefix: lowercase letters, digits and "
                             "hyphens, at most 63 characters")
        # Cognito prefixes are global. The account id makes the default unique.
        prefix = prefix or f"agentic-gates-dash-{self.account}"

        # ---- Sign-in: Cognito user pool with managed login -------------------
        pool = cognito.UserPool(
            self, "Users",
            self_sign_up_enabled=False,           # administrators create users
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True, mutable=True)),
            password_policy=cognito.PasswordPolicy(
                min_length=12, require_lowercase=True, require_uppercase=True,
                require_digits=True, require_symbols=True,
                temp_password_validity=cdk.Duration.days(3)),
            # Required: managed login walks each user through authenticator-app
            # setup at first sign-in. With optional MFA it never prompts, and
            # this SPA has no MFA-setup screen, so users would have none.
            mfa=cognito.Mfa.REQUIRED,
            mfa_second_factor=cognito.MfaSecondFactor(otp=True, sms=False),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            feature_plan=cognito.FeaturePlan.ESSENTIALS,
            # Kept on stack deletion so users are not lost by accident.
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        login_domain = pool.add_domain(
            "Login",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=prefix),
            managed_login_version=cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN)

        # ---- Data function ---------------------------------------------------
        fn = lambda_.Function(
            self, "DashboardFn",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            memory_size=512,
            timeout=cdk.Duration.seconds(20),
            log_group=logs.LogGroup(
                self, "DashboardFnLogs", retention=logs.RetentionDays.ONE_WEEK,
                removal_policy=cdk.RemovalPolicy.DESTROY),
            environment={
                "ARTIFACT_REPO": repos["artifact_repo"],
                "GATES_REPO": repos["gates_repo"],
                "SITE_URL": site_url,
                # Optional read-only GitHub credential, passed as a secret NAME
                # so the value never lands in the function's configuration.
                **({"GITHUB_TOKEN_SECRET": gh_secret} if gh_secret else {}),
            },
            code=lambda_.Code.from_asset(str(root / "infra" / ".asset")),
        )
        if gh_secret:
            sm.Secret.from_secret_name_v2(
                self, "GitHubToken", gh_secret).grant_read(fn)

        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadPipelineState",
            actions=["codepipeline:GetPipelineState",
                     "codepipeline:ListPipelineExecutions",
                     "codepipeline:ListActionExecutions"],
            resources=[
                f"arn:aws:codepipeline:{region}:{self.account}:{PIPELINE_PREFIX}*",
                f"arn:aws:codepipeline:{region}:{self.account}:{PIPELINE_PREFIX}*/*",
            ]))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadFindingsReports",
            actions=["s3:GetObject"],
            resources=[f"{REPORTS_BUCKET_ARN}/*"]))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadTierStackOutputs",
            # The reports bucket name is read from the Tier 1 stack outputs, so
            # no account-wide s3:ListAllMyBuckets is needed.
            actions=["cloudformation:DescribeStacks"],
            resources=[
                f"arn:aws:cloudformation:{region}:{self.account}:stack/Tier1PipelineStack/*",
                f"arn:aws:cloudformation:{region}:{self.account}:stack/Tier1PipelineStackRoad/*",
            ]))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadDemoHealthResources",
            actions=["cloudformation:ListStackResources"],
            resources=[f"arn:aws:cloudformation:{region}:{self.account}:stack/agentic-gates-demo-app/*"]))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadDemoAliasRevision",
            actions=["lambda:GetAlias", "lambda:GetFunctionConfiguration"],
            resources=[f"arn:aws:lambda:{region}:{self.account}:function:agentic-gates-demo-hello",
                       f"arn:aws:lambda:{region}:{self.account}:function:agentic-gates-demo-hello:*"]))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadDemoAlarms",
            actions=["cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory"],
            resources=[f"arn:aws:cloudwatch:{region}:{self.account}:alarm:agentic-gates-demo-app-*"]))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadDemoDeployments",
            actions=["codedeploy:ListDeployments", "codedeploy:GetDeployment",
                     "codedeploy:ListDeploymentTargets", "codedeploy:GetDeploymentTarget"],
            resources=[f"arn:aws:codedeploy:{region}:{self.account}:application:agentic-gates-demo-app-*",
                       f"arn:aws:codedeploy:{region}:{self.account}:deploymentgroup:agentic-gates-demo-app-*/*"],
            conditions={"StringEquals": {"aws:RequestedRegion": region}}))
        fn.add_to_role_policy(iam.PolicyStatement(
            sid="ReadGateLogs",
            # DescribeLogStreams + GetLogEvents let the reader walk the newest
            # stream backwards; FilterLogEvents alone pages oldest-first.
            actions=["logs:FilterLogEvents", "logs:DescribeLogStreams",
                     "logs:GetLogEvents"],
            resources=[
                f"arn:aws:logs:{region}:{self.account}:log-group:{TIER2_LOG_GROUP}:*",
                f"arn:aws:logs:{region}:{self.account}:log-group:/aws/codebuild/agentic-gates-tier1-*:*",
                f"arn:aws:logs:{region}:{self.account}:log-group:/aws/codebuild/agentic-gates-tier3-*:*",
            ]))

        # ---- HTTP API ----------------------------------------------------------
        integration = integrations.HttpLambdaIntegration("Fn", fn)
        # $default (the SPA shell and /auth-config) is public: it carries no data.
        api = apigwv2.HttpApi(self, "DashboardApi", default_integration=integration)
        api_host = cdk.Fn.select(2, cdk.Fn.split("/", api.api_endpoint))

        # ---- CloudFront --------------------------------------------------------
        origin = origins.HttpOrigin(api_host)
        no_host = cf.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER
        # CloudFront strips Authorization from GET requests unless the header is
        # in the cache key, and a caching-disabled policy cannot name headers.
        # This policy keys on Authorization with a zero default TTL; the handler
        # also answers every /api response with cache-control: no-store, so
        # nothing is cached and one user's response can never serve another.
        api_cache = cf.CachePolicy(
            self, "ApiForwardAuthorization",
            comment="Forward Authorization to the API; responses are not cached",
            default_ttl=cdk.Duration.seconds(0),
            min_ttl=cdk.Duration.seconds(0),
            max_ttl=cdk.Duration.seconds(1),
            header_behavior=cf.CacheHeaderBehavior.allow_list("Authorization"),
            query_string_behavior=cf.CacheQueryStringBehavior.all(),
            cookie_behavior=cf.CacheCookieBehavior.none())
        dist = cf.Distribution(
            self, "Dist",
            **({"domain_names": [domain["dashboard_domain"]], "certificate": cert}
               if domain else {}),
            comment="Agentic gates operator dashboard",
            minimum_protocol_version=cf.SecurityPolicyProtocol.TLS_V1_2_2021,
            default_behavior=cf.BehaviorOptions(
                origin=origin,
                viewer_protocol_policy=cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cf.CachePolicy.CACHING_DISABLED,
                origin_request_policy=no_host,
                response_headers_policy=cf.ResponseHeadersPolicy.SECURITY_HEADERS),
            additional_behaviors={
                "/api*": cf.BehaviorOptions(
                    origin=origin,
                    viewer_protocol_policy=cf.ViewerProtocolPolicy.HTTPS_ONLY,
                    allowed_methods=cf.AllowedMethods.ALLOW_GET_HEAD,
                    cache_policy=api_cache,
                    origin_request_policy=no_host,
                    response_headers_policy=cf.ResponseHeadersPolicy.SECURITY_HEADERS),
            })

        base_url = (f"https://{domain['dashboard_domain']}/" if domain
                    else f"https://{dist.distribution_domain_name}/")

        # ---- App client: public, authorization code + PKCE -------------------
        client = pool.add_client(
            "Spa",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_srp=True),
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.COGNITO],
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True,
                                         implicit_code_grant=False),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL],
                callback_urls=[base_url],
                logout_urls=[base_url]),
            access_token_validity=cdk.Duration.minutes(60),
            id_token_validity=cdk.Duration.minutes(60),
            # Cognito always issues a refresh token for the code grant. The SPA
            # discards it; the shortest validity Cognito allows limits exposure.
            refresh_token_validity=cdk.Duration.minutes(60),
            prevent_user_existence_errors=True,
            enable_token_revocation=True)
        cognito.CfnManagedLoginBranding(
            self, "LoginBranding",
            user_pool_id=pool.user_pool_id,
            client_id=client.user_pool_client_id,
            use_cognito_provided_values=True)

        # Every /api route requires a valid access token for this client.
        jwt = authorizers.HttpUserPoolAuthorizer(
            "CognitoJwt", pool, user_pool_clients=[client])
        for path in ("/api", "/api/{proxy+}"):
            api.add_routes(path=path, methods=[apigwv2.HttpMethod.ANY],
                           integration=integration, authorizer=jwt)

        # Non-secret values the SPA needs to start sign-in (GET /auth-config).
        fn.add_environment("AUTH_REGION", region)
        fn.add_environment("AUTH_DOMAIN_URL", login_domain.base_url())
        fn.add_environment("AUTH_CLIENT_ID", client.user_pool_client_id)
        fn.add_environment("DASHBOARD_URL", base_url)

        if domain:
            zone_name = domain["dashboard_zone_name"].rstrip(".")
            record = domain["dashboard_domain"].rstrip(".")
            r53.ARecord(
                self, "Alias", zone=_zone(self, domain),
                record_name=record.removesuffix(f".{zone_name}") if record != zone_name else None,
                target=r53.RecordTarget.from_alias(r53t.CloudFrontTarget(dist)))

        cdk.CfnOutput(self, "DashboardUrl", value=base_url)
        cdk.CfnOutput(self, "DistributionId", value=dist.distribution_id)
        cdk.CfnOutput(self, "UserPoolId", value=pool.user_pool_id)
        cdk.CfnOutput(self, "SignInDomain", value=login_domain.base_url())


def build(app: cdk.App) -> DashboardStack:
    """Add DashboardStack to the app, plus DashboardCertStack in us-east-1 when
    the context names a custom domain. Returns the dashboard stack."""
    account = os.environ.get("CDK_DEFAULT_ACCOUNT")
    region = os.environ.get("CDK_DEFAULT_REGION")
    env = cdk.Environment(account=account, region=region)
    domain = custom_domain(app)
    cert = None
    if domain:
        if not (account and region):
            raise ValueError("a custom domain needs a concrete deploy environment "
                             "(CDK_DEFAULT_ACCOUNT and CDK_DEFAULT_REGION)")
        cert = DashboardCertStack(
            app, "DashboardCertStack", domain=domain,
            env=cdk.Environment(account=account, region="us-east-1"),
            cross_region_references=True).cert
    return DashboardStack(app, "DashboardStack", domain=domain, cert=cert, env=env,
                          cross_region_references=bool(domain))


if __name__ == "__main__":
    app = cdk.App()
    build(app)
    app.synth()
