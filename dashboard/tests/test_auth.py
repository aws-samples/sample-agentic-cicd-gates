"""Sign-in and access control: the handler fails closed, the template guards /api."""
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from test_evidence import h

ROOT = Path(__file__).resolve().parents[1]
CLAIMS = {"authorizer": {"jwt": {"claims": {"sub": "user-1", "client_id": "client"}}}}


def call(path, request_context=None, **extra):
    event = {"rawPath": path, "queryStringParameters": None, **extra}
    if request_context is not None:
        event["requestContext"] = request_context
    return h.lambda_handler(event, None)


class HandlerAuthTests(unittest.TestCase):
    def test_api_without_token_is_401(self):
        with patch.object(h, "build_snapshot") as build:
            for path in ("/api/snapshot", "/api", "/api/anything"):
                for ctx in (None, {}, {"authorizer": {}}, {"authorizer": {"jwt": {}}},
                            {"authorizer": {"jwt": {"claims": {}}}},
                            {"authorizer": {"jwt": {"claims": {"sub": ""}}}}):
                    with self.subTest(path=path, ctx=ctx):
                        result = call(path, ctx)
                        self.assertEqual(result["statusCode"], 401)
                        self.assertEqual(result["headers"]["cache-control"], "no-store")
        build.assert_not_called()

    def test_api_ignores_legacy_shared_key(self):
        """A ?k= query string or cookie is not a credential any more."""
        with patch.object(h, "build_snapshot") as build:
            result = call("/api/snapshot", None, cookies=["dk=anything"])
            result_q = h.lambda_handler({"rawPath": "/api/snapshot",
                                         "queryStringParameters": {"k": "anything"}}, None)
        self.assertEqual(result["statusCode"], 401)
        self.assertEqual(result_q["statusCode"], 401)
        build.assert_not_called()

    def test_api_with_verified_claims_serves_snapshot_uncached(self):
        with patch.object(h, "build_snapshot", return_value={"ok": True}):
            result = call("/api/snapshot", CLAIMS)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["headers"]["cache-control"], "no-store")
        self.assertEqual(json.loads(result["body"]), {"ok": True})

    def test_unknown_api_path_is_404_after_auth(self):
        self.assertEqual(call("/api/other", CLAIMS)["statusCode"], 404)

    def test_auth_config_is_public_and_non_secret(self):
        env = {"AUTH_REGION": "us-west-2",
               "AUTH_DOMAIN_URL": "https://example.auth.us-west-2.amazoncognito.com",
               "AUTH_CLIENT_ID": "client123"}
        with patch.dict(os.environ, env), patch.object(h, "DASHBOARD_URL", "https://d.example.com/"):
            result = call("/auth-config")
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"]), {
            "region": "us-west-2",
            "domain": "https://example.auth.us-west-2.amazoncognito.com",
            "client_id": "client123", "redirect_uri": "https://d.example.com/"})

    def test_spa_shell_is_public(self):
        with patch.object(h, "_static", return_value={"statusCode": 200, "headers": {}}) as static:
            self.assertEqual(call("/")["statusCode"], 200)
        static.assert_called_once_with("/")

    def test_no_shared_key_logic_remains(self):
        source = (ROOT / "app" / "handler.py").read_text()
        for needle in ("DASH_KEY", "EVENTS_URL", "set-cookie", "events_url"):
            self.assertNotIn(needle, source)
        self.assertFalse((ROOT / "app" / "stream.mjs").exists())


def _synth(context: dict):
    """Synthesize the dashboard app in-process and return {stack id: template}."""
    import aws_cdk as cdk
    (ROOT / "infra" / ".asset").mkdir(exist_ok=True)   # staged by deploy.sh
    spec = importlib.util.spec_from_file_location("dashboard_app", ROOT / "infra" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    env = {"CDK_DEFAULT_ACCOUNT": "111122223333", "CDK_DEFAULT_REGION": "us-west-2"}
    with patch.dict(os.environ, env):
        app = cdk.App(context=context)
        mod.build(app)
        assembly = app.synth()
    return {s.stack_name: s.template for s in assembly.stacks}


def _of(template, kind):
    return {k: r for k, r in template["Resources"].items() if r["Type"] == kind}


class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain = _synth({"artifact_repo": "example-org/sample-app",
                            "gates_repo": "example-org/sample-gates"})
        cls.custom = _synth({"dashboard_domain": "dash.example.com",
                             "dashboard_zone_id": "Z0000000EXAMPLE",
                             "dashboard_zone_name": "example.com",
                             "auth_domain_prefix": "example-dash"})

    def test_every_api_route_requires_the_jwt_authorizer(self):
        for name, stacks in (("plain", self.plain), ("custom", self.custom)):
            t = stacks["DashboardStack"]
            routes = _of(t, "AWS::ApiGatewayV2::Route")
            (auth_id, auth), = _of(t, "AWS::ApiGatewayV2::Authorizer").items()
            self.assertEqual(auth["Properties"]["AuthorizerType"], "JWT")
            self.assertEqual(auth["Properties"]["JwtConfiguration"]["Audience"],
                             [{"Ref": next(iter(_of(t, "AWS::Cognito::UserPoolClient")))}])
            keys = {r["Properties"]["RouteKey"]: r["Properties"] for r in routes.values()}
            self.assertEqual(set(keys), {"$default", "ANY /api", "ANY /api/{proxy+}"}, name)
            for key, props in keys.items():
                if key != "$default":
                    self.assertEqual(props["AuthorizationType"], "JWT", key)
                    self.assertEqual(props["AuthorizerId"], {"Ref": auth_id}, key)

    def test_no_function_url_or_stream_remains(self):
        for stacks in (self.plain, self.custom):
            for t in stacks.values():
                self.assertFalse(_of(t, "AWS::Lambda::Url"))
                self.assertFalse(_of(t, "AWS::CloudFront::OriginAccessControl"))
                for perm in _of(t, "AWS::Lambda::Permission").values():
                    self.assertNotEqual(perm["Properties"]["Principal"], "cloudfront.amazonaws.com")
                for fn in _of(t, "AWS::Lambda::Function").values():
                    self.assertNotEqual(fn["Properties"].get("Handler"), "stream.handler")

    def test_user_pool_and_client(self):
        t = self.plain["DashboardStack"]
        (pool,), (client,) = _of(t, "AWS::Cognito::UserPool").values(), \
            _of(t, "AWS::Cognito::UserPoolClient").values()
        p = pool["Properties"]
        self.assertTrue(p["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"])
        self.assertEqual(p["UsernameAttributes"], ["email"])
        self.assertEqual(p["MfaConfiguration"], "ON")
        self.assertEqual(p["EnabledMfas"], ["SOFTWARE_TOKEN_MFA"])
        pw = p["Policies"]["PasswordPolicy"]
        self.assertEqual(pw["MinimumLength"], 12)
        for k in ("RequireLowercase", "RequireUppercase", "RequireNumbers", "RequireSymbols"):
            self.assertTrue(pw[k], k)
        self.assertEqual(p["AccountRecoverySetting"]["RecoveryMechanisms"],
                         [{"Name": "verified_email", "Priority": 1}])
        c = client["Properties"]
        self.assertFalse(c["GenerateSecret"])
        self.assertEqual(c["AllowedOAuthFlows"], ["code"])
        self.assertEqual(c["AllowedOAuthScopes"], ["openid", "email"])
        self.assertEqual(c["PreventUserExistenceErrors"], "ENABLED")
        self.assertEqual((c["AccessTokenValidity"], c["IdTokenValidity"]), (60, 60))
        self.assertIn("DistB3B78991", json.dumps(c["CallbackURLs"]))
        (domain,) = _of(t, "AWS::Cognito::UserPoolDomain").values()
        self.assertEqual(domain["Properties"]["Domain"], "agentic-gates-dash-111122223333")

    def test_cloudfront_security_headers_and_api_behavior(self):
        t = self.plain["DashboardStack"]
        (dist,) = _of(t, "AWS::CloudFront::Distribution").values()
        cfg = dist["Properties"]["DistributionConfig"]
        behaviors = [cfg["DefaultCacheBehavior"], *cfg["CacheBehaviors"]]
        self.assertEqual([b.get("PathPattern") for b in cfg["CacheBehaviors"]], ["/api*"])
        for b in behaviors:
            self.assertEqual(b["ResponseHeadersPolicyId"], "67f7725c-6f97-4210-82d7-5512b31e9d03")
        self.assertNotIn("Aliases", cfg)
        (policy,) = _of(t, "AWS::CloudFront::CachePolicy").values()
        pc = policy["Properties"]["CachePolicyConfig"]
        self.assertEqual(pc["DefaultTTL"], 0)
        self.assertEqual(pc["ParametersInCacheKeyAndForwardedToOrigin"]["HeadersConfig"]["Headers"],
                         ["Authorization"])
        self.assertNotIn("DashboardCertStack", self.plain)
        self.assertFalse(_of(t, "AWS::Route53::RecordSet"))

    def test_custom_domain_adds_certificate_and_alias(self):
        self.assertIn("DashboardCertStack", self.custom)
        t = self.custom["DashboardStack"]
        (record,) = _of(t, "AWS::Route53::RecordSet").values()
        self.assertEqual(record["Properties"]["Name"], "dash.example.com.")
        (client,) = _of(t, "AWS::Cognito::UserPoolClient").values()
        self.assertEqual(client["Properties"]["CallbackURLs"], ["https://dash.example.com/"])
        (domain,) = _of(t, "AWS::Cognito::UserPoolDomain").values()
        self.assertEqual(domain["Properties"]["Domain"], "example-dash")

    def test_partial_custom_domain_is_refused(self):
        with self.assertRaises(ValueError):
            _synth({"dashboard_domain": "dash.example.com"})

    def test_handler_receives_repositories_and_no_secrets(self):
        t = self.plain["DashboardStack"]
        (fn,) = [f for f in _of(t, "AWS::Lambda::Function").values()
                 if f["Properties"].get("Handler") == "handler.lambda_handler"]
        env = fn["Properties"]["Environment"]["Variables"]
        self.assertEqual(env["ARTIFACT_REPO"], "example-org/sample-app")
        self.assertEqual(env["GATES_REPO"], "example-org/sample-gates")
        self.assertEqual(set(env), {"ARTIFACT_REPO", "GATES_REPO", "SITE_URL", "AUTH_REGION",
                                    "AUTH_DOMAIN_URL", "AUTH_CLIENT_ID", "DASHBOARD_URL"})


if __name__ == "__main__":
    unittest.main()
