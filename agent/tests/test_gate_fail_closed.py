"""Fail-closed regressions for the deterministic, threat-model and PR-surface lanes.

Each case is a bypass an AWS Continuum scan reported (2026-11-06) against the
vendored copy of these files: a policy the wildcard lane let through, a
threat-model input that read as covered, or output hygiene in the PR surface.
"""
import json
import time
from pathlib import Path

import pytest
import yaml

from reviewer import rules as rules_mod


@pytest.fixture
def checks(load_module):
    return load_module("deterministic/checks.py")


@pytest.fixture
def tm(load_module):
    return load_module("threat-model/validate.py")


def _template(checks, text):
    return yaml.load(text, Loader=checks._CfnLoader)  # nosec B506 - SafeLoader subclass


def _findings(checks, text):
    template = _template(checks, text)
    out = checks.check_managed_policies(template)
    for name, doc, _ in checks._iter_policies(template):
        out += checks.check_wildcards(name, doc, template)
    return out


ROLE = """
Resources:
  Fn:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: p
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
{stmt}
"""


@pytest.mark.parametrize("stmt,expected", [
    ("                Action: !Sub '*'\n                Resource: !Ref Bucket", "Action:'*'"),
    ("                Action: !Ref ActionParam\n                Resource: x", "not a static literal"),
    ("                Action: s3:GetObject\n                Resource: !If [C, '*', !Ref B]\n"
     "                NotResource: x", "NotResource"),
    ("                Action: [!If [Prod, 'iam:PassRole', 'iam:*']]\n                Resource: x",
     "service-wide wildcard iam:*"),
    ("                Action: iam:*\n                Resource: arn:aws:iam::111122223333:role/x",
     "service-wide wildcard iam:*"),
    ("                NotAction: s3:DeleteBucket\n                Resource: '*'", "NotAction"),
    ("                Action: kms:Decrypt\n                Resource: !Sub '*'",
     "sensitive actions with Resource:'*'"),
    ("                Action: s3:GetObject\n                Resource: !Join ['', ['*']]",
     "sensitive actions with Resource:'*'"),
])
def test_wildcards_behind_intrinsics_dates_and_not_elements_block(checks, stmt, expected):
    # The unquoted YAML date made json.dumps raise, and the policy was skipped.
    found = _findings(checks, ROLE.format(stmt=stmt))
    assert any("[BLOCKING]" in f and expected in f for f in found), found


def test_ordinary_scoped_policy_still_passes(checks):
    # A wildcard under a named resource is scoped (the artifact template's shape);
    # a type plus a wildcard (x/*, role/*) is account-wide and blocks.
    stmt = ("                Action: codedeploy:PutLifecycleEventHookExecutionStatus\n"
            "                Resource: !Sub arn:aws:codedeploy:${AWS::Region}:${AWS::AccountId}"
            ":deploymentgroup:my-app/*")
    assert _findings(checks, ROLE.format(stmt=stmt)) == []


def test_artifact_template_shape_passes(checks, tmp_path):
    # The shipped artifact template must stay green under the stricter lane.
    artifact = checks.pathlib.Path(__file__).resolve().parents[3] / "sample-agentic-cicd-artifact"
    template = artifact / "template.yaml"
    if not template.exists():
        pytest.skip("artifact repo is not checked out beside this one")
    assert _findings(checks, template.read_text()) == []


@pytest.mark.parametrize("principal,condition,blocks", [
    ("'*'", None, True),
    ("{AWS: '*'}", None, True),
    ("{AWS: ['arn:aws:iam::111122223333:root', '*']}", None, True),
    ("{AWS: '*'}", "{StringEquals: {'aws:PrincipalOrgID': o-abc}}", False),
    ("{Service: lambda.amazonaws.com}", None, False),
])
def test_principal_wildcard_in_trust_and_resource_policies(checks, principal, condition, blocks):
    cond = f"\n            Condition: {condition}" if condition else ""
    text = f"""
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {principal}
            Action: sts:AssumeRole{cond}
  K:
    Type: AWS::KMS::Key
    Properties:
      KeyPolicy:
        Statement:
          - Effect: Allow
            Principal: {principal}
            Action: kms:Decrypt
            Resource: arn:aws:kms:us-west-2:111122223333:key/k{cond}
"""
    found = [f for f in _findings(checks, text) if "Principal:'*'" in f]
    assert len(found) == (2 if blocks else 0), found


def test_not_principal_and_admin_managed_policies_block(checks):
    text = """
Resources:
  B:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            NotPrincipal: {AWS: arn:aws:iam::111122223333:root}
            Action: s3:GetObject
            Resource: arn:aws:s3:::b/*
  Role:
    Type: AWS::IAM::Role
    Properties:
      ManagedPolicyArns: [arn:aws:iam::aws:policy/AdministratorAccess]
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Policies: [AdministratorAccess, AWSLambdaBasicExecutionRole]
"""
    found = _findings(checks, text)
    assert any("NotPrincipal" in f for f in found)
    assert sum("admin-level managed policy AdministratorAccess" in f for f in found) == 2
    assert not any("AWSLambdaBasicExecutionRole" in f for f in found)


def test_missing_or_empty_boundaries_fail(tm, tmp_path):
    model = {"threats": [{"statement": "TB-DATA spoofing"}]}
    assert tm.boundary_coverage(model, tmp_path / "missing.yaml")
    empty = tmp_path / "b.yaml"
    empty.write_text("boundaries: []\n")
    assert tm.boundary_coverage(model, empty)


def test_boundary_coverage_counts_only_threat_statements(tm, tmp_path):
    path = tmp_path / "b.yaml"
    path.write_text("boundaries:\n  - {id: TB-DATA, name: Function to datastore}\n")
    covered = {"threats": [{"statement": "Through [TB-DATA] a caller with a forged session "
                                         "token reads rows that belong to another tenant",
                            "stride": ["I"], "mitigations": ["row-level auth"]}]}
    elsewhere = {"applicationInfo": {"description": "TB-DATA"},
                 "threats": [{"statement": "TB-DATAX is a different boundary"}]}
    assert tm.boundary_coverage(covered, path) == []
    assert any("TB-DATA'" in e for e in tm.boundary_coverage(elsewhere, path))
    # Continuum, 2026-11-07: a statement of boundary tokens documents nothing.
    stuffed = {"threats": [{"statement": "TB-DATA Function to datastore TB-DATA threat",
                            "stride": ["S"], "mitigations": ["m"]}]}
    assert any("TB-DATA'" in e for e in tm.boundary_coverage(stuffed, path))


@pytest.mark.parametrize("path", ["main.tf", "infra/app.py", "cdk.json", "serverless.yml",
                                  "svc/terraform/vpc.tf", "template.yaml", "a/b/cdk.json"])
def test_root_level_infra_files_count_as_infra_changes(tm, path):
    assert tm.staleness([path])
    assert tm.staleness([path, "threat-model/app.tc.json"]) == []


def test_real_threat_models_still_pass(tm):
    root = tm.pathlib.Path(tm.__file__).resolve().parents[1]
    for repo in (root, root.parent / "sample-agentic-cicd-artifact"):
        model = repo / "threat-model" / "app.tc.json"
        if model.exists():
            assert tm.boundary_coverage(json.loads(model.read_text()),
                                        repo / "threat-model" / "boundaries.yaml") == []


def test_the_least_privilege_rule_covers_the_templates_the_samples_ship():
    # Continuum, round 4 (G06): IAM-002 matched no file in the artifact repo,
    # whose only template is the root template.yaml.
    root = Path(__file__).resolve().parents[2]
    for policy in (".reviewer.yaml", "rules/reviewer.example.yaml"):
        rule = next(r for r in rules_mod.load_rules((root / policy).read_text()).rules
                    if r.id == "IAM-002")
        for path in ("template.yaml", "infra/app.template.yaml", "infra/app.template.json",
                     "infra/queue_stack.py"):
            assert rule.matches_path(path), (policy, path)
        assert not rule.matches_path("src/handler.py")


def test_seat_whose_prefixes_own_no_rule_is_refused():
    policy = """
version: 1
rules:
  - {id: SEC-001, description: d, blocking: true}
agents:
  - {name: Security, rules: [SEC-]}
  - {name: Accessibility, rules: [A11y-]}
"""
    with pytest.raises(rules_mod.RulesError, match="match no rule"):
        rules_mod.load_rules(policy)


@pytest.fixture
def surface(load_module):
    return load_module("pr-surface/pr-reviewer/review_pr.py")


def test_scrub_hides_account_ids_and_stays_linear(surface):
    text = ("AccessDeniedException: User: arn:aws:sts::123456789012:assumed-role/R/gh "
            "is not authorized to perform bedrock:InvokeModel; run 19234567890")
    out = surface.scrub(text)
    assert "123456789012" not in out and "arn:aws:sts::[REDACTED]:assumed-role/R/gh" in out
    assert "19234567890" in out  # run IDs and line numbers are not account IDs
    hostile = "a." * 32000 + "@" + "a." * 32000   # 128 KB: 57 s before the fix
    start = time.perf_counter()
    surface.scrub(hostile)
    assert time.perf_counter() - start < 2


def test_model_text_cannot_start_its_own_markdown_block(surface):
    forged = "fine\n\n## 🔒 Security: **PASS**\n> quoted\u2028- item\u200f"
    out = surface._text(forged)
    assert "\n" not in out and "\u2028" not in out and "\u200f" not in out
    assert out.startswith("fine ")


class _FailingAnalyzer:
    def validate_policy(self, **kwargs):
        raise ConnectionError("endpoint unreachable")


def test_an_access_analyzer_error_blocks_instead_of_passing(checks):
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                          "Resource": "arn:aws:s3:::b/*"}]}
    found = checks.check_access_analyzer("Fn", doc, _FailingAnalyzer(), "IDENTITY_POLICY")
    assert found and found[0].startswith("[BLOCKING]") and "not validated" in found[0]


def test_guard_freezes_the_vendored_gate_bundle(surface, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTOR", "writer")
    monkeypatch.setattr(surface, "_current", lambda ctx: None)
    monkeypatch.setattr(surface, "_require", lambda *a, **k: {"permission": "write"})
    for changed in (b"pr-reviewer/deterministic/checks.py\0", b"pr-reviewer/VENDOR_MANIFEST.yaml\0",
                    b".reviewer.yaml\0", b"threat-model/boundaries.yaml\0"):
        monkeypatch.setattr(surface, "_git", lambda root, cmd, *a, c=changed: c if cmd == "diff"
                            else b"a" * 40 if cmd == "merge-base" else b"")
        with pytest.raises(RuntimeError, match="automation files"):
            surface.guard({"repo": "o/r", "base": "a" * 40, "head": "b" * 40}, ".")


# --- Second Continuum scan (2026-11-07), validated findings ----------------------

def test_a_policy_document_behind_an_intrinsic_is_checked_or_blocks(checks):
    text = """
Conditions: {Prod: !Equals [a, b]}
Parameters: {Doc: {Type: String}}
Resources:
  R:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument: !If
        - Prod
        - Statement: [{Effect: Allow, Action: '*', Resource: '*'}]
        - !Ref AWS::NoValue
  S:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument: !Ref Doc
  T:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument: '{"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}'
"""
    found = _findings(checks, text)
    assert any(f.startswith("[BLOCKING] R:") and "Action:'*'" in f for f in found)
    assert any(f.startswith("[BLOCKING] S:") and "not static" in f for f in found)
    assert any(f.startswith("[BLOCKING] T:") and "iam:*" in f for f in found)


@pytest.mark.parametrize("condition,scoped", [
    ("{StringEquals: {'aws:PrincipalOrgID': o-abc123}}", True),
    ("{StringLike: {'aws:PrincipalOrgID': '*'}}", False),
    ("{StringNotEquals: {'aws:PrincipalOrgID': o-abc123}}", False),
    ("{StringEqualsIfExists: {'aws:SourceArn': 'arn:aws:s3:::b'}}", False),
    ("{'ForAllValues:StringEquals': {'aws:PrincipalOrgID': [o-abc123]}}", False),
    ("{Null: {'aws:PrincipalOrgID': 'false'}}", False),
    ("{StringEquals: {'aws:username': 'aws:PrincipalOrgID'}}", False),
    # A wildcard anywhere in the value, or a value of the wrong shape, scopes nothing.
    ("{StringLike: {'aws:PrincipalOrgID': 'o-*'}}", False),
    ("{ArnLike: {'aws:PrincipalArn': 'arn:aws:iam::*:*'}}", False),
    ("{StringEquals: {'aws:PrincipalAccount': '12'}}", False),
    ("{StringEquals: {'aws:SourceAccount': !Ref AWS::AccountId}}", True),
])
def test_principal_star_needs_a_real_scoping_condition(checks, condition, scoped):
    text = f"""
Resources:
  B:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: '*'
            Action: s3:GetObject
            Resource: arn:aws:s3:::b/*
            Condition: {condition}
"""
    found = [f for f in _findings(checks, text) if "Principal:'*'" in f]
    assert bool(found) is not scoped, found


def test_unresolvable_resource_and_principal_fail_closed(checks):
    text = """
Parameters:
  Wide: {Type: String, Default: '*'}
  Open: {Type: String}
Resources:
  Fn:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [{Effect: Allow, Principal: {AWS: !Ref Open}, Action: sts:AssumeRole}]
      Policies:
        - PolicyName: p
          PolicyDocument:
            Statement:
              - {Effect: Allow, Action: s3:GetObject, Resource: !Ref Wide}
              - {Effect: Allow, Action: kms:Decrypt, Resource: !Sub '${Wide}'}
              - {Effect: Allow, Action: s3:PutObject, Resource: !Ref Open}
              - {Effect: Allow, Action: s3:GetObject, Resource: !GetAtt Bucket.Arn}
  Bucket: {Type: AWS::S3::Bucket}
"""
    found = _findings(checks, text)
    assert sum("Resource:'*'" in f for f in found) == 2
    assert sum("cannot be resolved" in f and "Resource" in f for f in found) == 1
    assert any("(trust)" in f and "Principal" in f for f in found)


def test_policy_shapes_outside_the_old_list_are_checked(checks):
    text = """
Conditions: {Prod: !Equals [a, b]}
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Policies:
        - !If [Prod, {Statement: [{Effect: Allow, Action: '*', Resource: '*'}]}, !Ref AWS::NoValue]
        - S3CrudPolicy: {BucketName: '*'}
        - S3ReadPolicy: {BucketName: !Ref Bucket}
  Topic:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Statement: [{Effect: Allow, Principal: '*', Action: sns:Publish, Resource: '*'}]
  Queue:
    Type: Custom::Thing
    Properties:
      QueuePolicyText: {Statement: [{Effect: Allow, Action: 'iam:*', Resource: x}]}
  Bucket: {Type: AWS::S3::Bucket}
"""
    found = _findings(checks, text)
    assert any(f.startswith("[BLOCKING] Fn:") and "Action:'*'" in f for f in found)
    assert any("S3CrudPolicy" in f for f in found)
    assert not any("S3ReadPolicy" in f for f in found)
    assert any("Topic" in f and "Principal:'*'" in f for f in found)
    assert any("Queue(QueuePolicyText)" in f and "iam:*" in f for f in found)


@pytest.mark.parametrize("stmt,expected", [
    # Any service's wildcard, not six of them.
    ("                Action: logs:*\n                Resource: x", "service-wide wildcard logs:*"),
    # A write on a wide resource, whatever the service.
    ("                Action: sqs:SendMessage\n                Resource: '*'",
     "write actions with Resource:'*'"),
    ("                Action: iam:PassRole\n"
     "                Resource: !Sub arn:aws:iam::${AWS::AccountId}:role/*", "account-wide"),
    ("                Action: dynamodb:PutItem\n"
     "                Resource: arn:aws:dynamodb:us-west-2:111122223333:table/*", "account-wide"),
    ("                Action: s3:PutObject\n                Resource: arn:aws:s3:::*", "account-wide"),
    ("                Action: sqs:SendMessage\n"
     "                Resource: arn:aws:sqs:us-west-2:*:q", "account-wide"),
    # Reads on a non-sensitive service, '*'-only writes, and named resources pass.
    ("                Action: ec2:DescribeInstances\n                Resource: '*'", None),
    ("                Action: xray:PutTraceSegments\n                Resource: '*'", None),
    # The deterministic lane's own calls: no resource type, they read only their input.
    ("                Action: [access-analyzer:ValidatePolicy, inspector-scan:ScanSbom]\n"
     "                Resource: '*'", None),
    # Their services' other writes still need a named resource.
    ("                Action: access-analyzer:CreateAnalyzer\n                Resource: '*'",
     "write actions with Resource:'*'"),
    ("                Action: inspector-scan:*\n                Resource: '*'",
     "service-wide wildcard inspector-scan:*"),
    ("                Action: s3:GetObject\n                Resource: arn:aws:s3:::b/*", None),
    ("                Action: logs:PutLogEvents\n"
     "                Resource: arn:aws:logs:us-west-2:111122223333:log-group:/app/x:*", None),
])
def test_wide_resources_and_any_service_wildcard(checks, stmt, expected):
    found = _findings(checks, ROLE.format(stmt=stmt))
    if expected is None:
        assert found == []
    else:
        assert any("[BLOCKING]" in f and expected in f for f in found), found


def test_hidden_policy_properties_and_more_admin_policies_block(checks):
    text = """
Parameters: {Doc: {Type: String}, Arn: {Type: String}}
Resources:
  Thing:
    Type: Custom::Thing
    Properties:
      ThingPolicy: !Ref Doc
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      RedrivePolicy: {deadLetterTargetArn: x, maxReceiveCount: 3}
  Role:
    Type: AWS::IAM::Role
    Properties:
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/job-function/SystemAdministrator
        - arn:aws:iam::aws:policy/AmazonS3FullAccess
        - !Ref Arn
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Policies: [AmazonDynamoDBFullAccess, AWSLambdaBasicExecutionRole]
"""
    found = _findings(checks, text)
    assert any(f.startswith("[BLOCKING] Thing(ThingPolicy):") and "not static" in f
               for f in found), found
    assert not any("Queue" in f for f in found)
    for name in ("SystemAdministrator", "AmazonS3FullAccess", "AmazonDynamoDBFullAccess"):
        assert any(f"admin-level managed policy {name}" in f for f in found), name
    assert any("Role:" in f and "cannot be resolved" in f for f in found)
    assert not any("AWSLambdaBasicExecutionRole" in f for f in found)


def test_nested_and_included_templates_must_be_checked_too(checks, tmp_path):
    text = """
Resources:
  Child:
    Type: AWS::CloudFormation::Stack
    Properties: {TemplateURL: nested.yaml}
  App:
    Type: AWS::Serverless::Application
    Properties: {Location: {ApplicationId: arn:aws:serverlessrepo:x, SemanticVersion: 1.0.0}}
  Inc:
    Fn::Transform: {Name: AWS::Include, Parameters: {Location: 's3://bucket/policy.yaml'}}
"""
    main = tmp_path / "template.yaml"
    nested = tmp_path / "nested.yaml"
    template = _template(checks, text)
    found = checks.check_template_references(template, str(main), [str(main)])
    assert [f.split(":")[0] for f in found] == ["[BLOCKING] Child", "[BLOCKING] App",
                                                "[BLOCKING] Inc"], found
    found = checks.check_template_references(template, str(main), [str(main), str(nested)])
    assert not any("Child" in f for f in found) and len(found) == 2


def test_resources_in_a_foreach_loop_are_checked_and_unreadable_ones_block(checks):
    # Continuum, round 4 (G01): a Fn::ForEach entry is a list, so everything it
    # generated was skipped by every check.
    text = """
Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Roles:
    - Name
    - [A, B]
    - Role${Name}:
        Type: AWS::IAM::Role
        Properties:
          ManagedPolicyArns: [arn:aws:iam::aws:policy/AdministratorAccess]
          Policies:
            - PolicyName: p
              PolicyDocument:
                Statement: [{Effect: Allow, Action: '*', Resource: '*'}]
  Odd: [not, a, resource]
"""
    found = _findings(checks, text)
    assert any("Fn::ForEach::Roles/Role${Name}" in f and "Action:'*'" in f for f in found)
    assert any("admin-level managed policy AdministratorAccess" in f for f in found)
    assert any(f.startswith("[BLOCKING] Odd:") and "cannot read" in f for f in found)


@pytest.mark.parametrize("stmt,blocks", [
    # G02: read-named actions that return credentials, on any service.
    ("                Action: ec2:GetPasswordData\n                Resource: '*'", True),
    ("                Action: lambda:GetFunction\n                Resource: '*'", True),
    ("                Action: ec2:Get*\n                Resource: '*'", True),
    ("                Action: ec2:DescribeInstances\n                Resource: '*'", False),
    # AWS accepts it only on '*', and it reads nothing alone.
    ("                Action: ecr:GetAuthorizationToken\n                Resource: '*'", False),
])
def test_credential_returning_reads_are_sensitive(checks, stmt, blocks):
    found = _findings(checks, ROLE.format(stmt=stmt))
    assert any("sensitive actions with Resource:'*'" in f for f in found) is blocks, found


@pytest.mark.parametrize("principal,condition,blocks", [
    # G03: sts:ExternalId names no caller, and a template makes it public.
    ("'*'", "{StringEquals: {'sts:ExternalId': abc123}}", "Principal:'*'"),
    # G07: a literal account cannot be told apart from a stranger's.
    ("{AWS: 'arn:aws:iam::444455556666:root'}", None, "trusts AWS account 444455556666"),
    ("{AWS: '444455556666'}", None, "trusts AWS account 444455556666"),
    ("{AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'}", None, None),
    ("{AWS: 'arn:aws:iam::444455556666:root'}",
     "{StringEquals: {'aws:PrincipalOrgID': o-abc123}}", None),
    ("{Service: lambda.amazonaws.com}", None, None),
])
def test_trust_needs_a_named_caller_not_an_external_id_or_a_literal_account(
        checks, principal, condition, blocks):
    cond = f"\n            Condition: {condition}" if condition else ""
    text = f"""
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {principal}
            Action: sts:AssumeRole{cond}
"""
    found = _findings(checks, text)
    if blocks is None:
        assert found == [], found
    else:
        assert any(f.startswith("[BLOCKING] R(trust):") and blocks in f for f in found), found


def test_a_glob_that_matches_nothing_fails_unless_allowed(checks, tmp_path, monkeypatch, capsys):
    for extra, code in (([], 1), (["--allow-no-templates"], 0)):
        monkeypatch.setattr(checks.sys, "argv", [
            "checks.py", "--templates", str(tmp_path / "missing.yaml"), "--repo-root",
            str(tmp_path), "--skip-access-analyzer", *extra])
        (tmp_path / "pr-reviewer").mkdir(exist_ok=True)
        (tmp_path / "pr-reviewer" / "VENDOR_MANIFEST.yaml").write_text("files:\n")
        assert checks.main() == code
    assert "no templates matched" in capsys.readouterr().out


def test_guard_refuses_criss_cross_history_and_gitattributes(surface, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTOR", "writer")
    monkeypatch.setattr(surface, "_current", lambda ctx: None)
    monkeypatch.setattr(surface, "_require", lambda *a, **k: {"permission": "write"})
    ctx = {"repo": "o/r", "base": "a" * 40, "head": "b" * 40}
    monkeypatch.setattr(surface, "_git", lambda root, cmd, *a: (
        b"c" * 40 + b"\n" + b"d" * 40 + b"\n") if cmd == "merge-base" else b"src/a.py\0")
    with pytest.raises(RuntimeError, match="2 merge bases"):
        surface.guard(ctx, ".")
    for changed in (b".gitattributes\0", b"src/.gitattributes\0"):
        monkeypatch.setattr(surface, "_git", lambda root, cmd, *a, c=changed: (
            b"c" * 40) if cmd == "merge-base" else c if cmd == "diff" else b"")
        with pytest.raises(RuntimeError, match="automation files"):
            surface.guard(ctx, ".")


@pytest.mark.parametrize("response,allowed", [
    ({"permission": "write", "role_name": "write"}, True),
    ({"permission": "write", "role_name": "maintain"}, True),
    ({"permission": "admin", "role_name": "admin"}, True),
    ({"permission": "read", "role_name": "triage"}, False),
    # Continuum, round 4 (G08): the allow-list named triage, which cannot push code.
    ({"permission": "triage"}, False),
    ({"permission": "write", "role_name": "triage"}, False),
])
def test_only_roles_that_can_push_unlock_credentialed_jobs(surface, monkeypatch, response,
                                                           allowed):
    monkeypatch.setenv("GITHUB_ACTOR", "someone")
    monkeypatch.delenv("GITHUB_TRIGGERING_ACTOR", raising=False)
    monkeypatch.setattr(surface, "_current", lambda ctx: None)
    monkeypatch.setattr(surface, "_require", lambda *a, **k: dict(response))
    monkeypatch.setattr(surface, "_git", lambda root, cmd, *a: (
        b"c" * 40) if cmd == "merge-base" else b"")
    try:
        surface.guard({"repo": "o/r", "base": "a" * 40, "head": "b" * 40}, ".")
        error = ""
    except (RuntimeError, ValueError) as exc:
        error = str(exc)
    assert ("permission" not in error) is allowed, error


@pytest.mark.parametrize("diff,numstat,refused", [
    (b"diff --git a/src/app.py b/src/app.py\nBinary files a/src/app.py and b/src/app.py differ\n",
     b"-\t-\tsrc/app.py\0", True),
    (b"diff --git a/x.js b/x.js\nBinary files /dev/null and b/x.js differ\n",
     b"-\t-\tx.js\0", True),
    (b"diff --git a/s/a.mp3 b/s/a.mp3\nBinary files a/s/a.mp3 and b/s/a.mp3 differ\n",
     b"-\t-\ts/a.mp3\0", False),
    # git C-quotes an unusual name in the diff text; numstat -z does not quote it.
    (b'diff --git "a/src/a\\tb.py" "b/src/a\\tb.py"\n'
     b'Binary files "a/src/a\\tb.py" and "b/src/a\\tb.py" differ\n',
     b"-\t-\tsrc/a\tb.py\0", True),
    (b"diff --git a/src/ok.py b/src/ok.py\n+x\n", b"1\t0\tsrc/ok.py\0", False),
])
def test_a_text_file_shown_as_binary_is_not_reviewed_blind(surface, monkeypatch, tmp_path,
                                                          diff, numstat, refused):
    policy = tmp_path / ".reviewer.yaml"
    policy.write_text("version: 1\nrules:\n  - {id: SEC-001, description: d, blocking: true}\n"
                      "agents:\n  - {name: Security, rules: [SEC-]}\n")
    import reviewer.bedrock_reviewer as core
    monkeypatch.setattr(surface, "_git", lambda *a: numstat if "--numstat" in a else diff)
    monkeypatch.setattr(core, "review_panel", lambda *a, **k: [])
    ctx = {"repo": "o/r", "pr": "1", "base": "a" * 40, "head": "b" * 40, "run": "1",
           "attempt": "1"}
    if refused:
        with pytest.raises(ValueError, match="Binary files"):
            surface.analyze(ctx, ".", policy)
    else:
        surface.analyze(ctx, ".", policy)


def test_model_text_cannot_open_a_list_rule_or_autolink(surface):
    for raw in ("- item", "+ item", "1. item", "=== ", "see https://evil.example/x",
                "www.evil.example"):
        out = surface._text(raw)
        assert not out.startswith(("-", "+", "=", "1.")), out
        assert "https://" not in out and "www." not in out, out
    code = surface._code("ok\u202e\x1b[31m\x00\ttab\nline")
    assert "\u202e" not in code and "\x1b" not in code and "\x00" not in code
    assert "\ttab\nline" in code


@pytest.mark.parametrize("compare,dismissed", [
    ({"status": "ahead", "files": [{"filename": "src/app.py"}]}, 1),
    ({"status": "diverged", "files": [{"filename": "src/app.py"}]}, 0),
    ({"status": "ahead", "files": []}, 0),
])
def test_only_a_real_forward_revision_withdraws_a_block(surface, monkeypatch, compare, dismissed):
    from types import SimpleNamespace
    agent = SimpleNamespace(name="Security")
    ctx = {"repo": "o/r", "pr": "7", "head": "b" * 40, "run": "200", "attempt": "1"}
    old = dict(ctx, head="c" * 40, run="199")
    review = {"id": 5, "user": dict(surface.BOT), "state": "CHANGES_REQUESTED",
              "commit_id": "c" * 40,
              "body": surface._marker(old, agent) + "\n## Security: **FAIL**\n\nold"}
    calls = []

    def require(method, path, payload=None):
        calls.append((method, path))
        return compare if "/compare/" in path else {}

    monkeypatch.setattr(surface, "_require", require)
    monkeypatch.setattr(surface, "_current", lambda ctx: None)
    surface._dismiss_stale_blocks(ctx, agent, [review])
    assert sum(m == "PUT" for m, _ in calls) == dismissed


def test_staleness_needs_a_real_model_edit_and_more_infra_paths(tm):
    model = {"threats": [{"id": "T-1", "statement": "s", "stride": ["S"], "mitigations": ["m"]}]}
    for path in ("deploy/stack-canary.yaml", "appspec.yml", "samconfig.toml",
                 "env/prod.tfvars", "infra.yaml", "Dockerfile"):
        assert tm.staleness([path]), path
    assert tm.staleness(["template.yaml", "threat-model/README.md"])
    assert tm.staleness(["template.yaml", "threat-model/app.tc.json"], model, dict(model))
    edited = {"threats": model["threats"] + [dict(model["threats"][0], id="T-2")]}
    assert tm.staleness(["template.yaml", "threat-model/app.tc.json"], edited, model) == []


def test_a_gutted_model_fails(tm, tmp_path):
    full = {"threats": [{"id": "T-1", "statement": "TB-DATA x", "stride": ["S"],
                         "mitigations": ["m"]},
                        {"id": "T-2", "statement": "TB-DATA y", "stride": ["T"],
                         "mitigations": ["n"]}]}
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"threats": [{"id": "T-1", "statement": "TB-DATA"}]}))
    _, errors = tm.load_model(path)
    assert any("stride" in e for e in errors)
    gutted = {"threats": [full["threats"][0]]}
    assert tm.removed_threats(gutted, full) and tm.removed_threats(full, full) == []
    # Gutting under the same id counts too; rewording and adding do not.
    for change in ({"stride": []}, {"statement": "x"}, {"mitigations": []}):
        weaker = {"threats": [dict(full["threats"][0], **change), full["threats"][1]]}
        assert any("weakened" in e for e in tm.removed_threats(weaker, full)), change
    reworded = {"threats": [dict(full["threats"][0], statement="TB-DATA reworded",
                                 mitigations=["m2", "m3"]), full["threats"][1]]}
    assert tm.removed_threats(reworded, full) == []


def test_renamed_or_differently_named_infra_counts(tm):
    for path in ("Template.YAML", "template.yml", "app.template.json", "serverless.yaml",
                 "buildspec.yml", "infra/tier1_stack.py", "docker-compose.yaml", "net.hcl"):
        assert tm.staleness([path]), path
    assert tm.staleness(["src/app.py", "README.md"]) == []


# Round 6 (threat-model/validate.py)

def test_git_quoted_non_ascii_infra_paths_still_count_as_infra(tm):
    # #2: git C-quotes a non-ASCII name, so "infra/maín.tf" arrives quoted and octal-escaped.
    for quoted in ('"infra/ma\\303\\255n.tf"', '"deploy/a\\tb.yaml"'):
        assert tm.staleness([quoted]), quoted
    assert tm.staleness(['"src/caf\\303\\251.py"']) == []


def test_duplicate_threat_ids_fail_and_cannot_hide_a_gutted_threat(tm, tmp_path):
    # #3: a gutted T-1 followed by a pristine copy under the same id.
    good = {"id": "T-1", "statement": "A caller [TB-DATA] reads rows", "stride": ["I"],
            "mitigations": ["Row-level authorization on every query"]}
    gutted = dict(good, stride=["S"], mitigations=["Accepted for the demo"])
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"threats": [gutted, good]}))
    _, errors = tm.load_model(path)
    assert any("unique" in e and "T-1" in e for e in errors), errors
    found = tm.removed_threats({"threats": [gutted, good]}, {"threats": [good]})
    assert any("weakened" in e and "T-1" in e for e in found), found


def test_boundary_coverage_needs_a_tag_and_more_than_filler(tm, tmp_path):
    # #4: one statement of boundary tokens plus ten filler words covered every boundary.
    path = tmp_path / "b.yaml"
    path.write_text("boundaries:\n  - {id: TB-DATA, name: Function to datastore}\n"
                    "  - {id: TB-EDGE, name: Viewer to edge}\n")
    for statement in ("[TB-DATA] [TB-EDGE] the and of to a in is it that this with",
                      "TB-DATA TB-EDGE caller forged session token reads rows other tenant "
                      "data leak",
                      "A caller crossing the Function to datastore and Viewer to edge boundaries "
                      "reads rows of another tenant through a forged session token"):
        model = {"threats": [{"statement": statement, "stride": ["I"], "mitigations": ["m"]}]}
        errors = tm.boundary_coverage(model, path)
        assert any("TB-DATA'" in e for e in errors) and any("TB-EDGE'" in e for e in errors), \
            statement
    tagged = {"threats": [{"statement": "A caller [TB-EDGE] with a forged session token reads "
                                        "rows that belong to another tenant [TB-DATA]",
                           "stride": ["I"], "mitigations": ["m"]}]}
    assert tm.boundary_coverage(tagged, path) == []


def test_mitigation_text_cannot_be_gutted_or_left_as_a_placeholder(tm, tmp_path):
    # #6: the count and STRIDE set stayed the same while every mitigation became "n/a".
    base = {"threats": [{"id": "T-1", "statement": "A caller [TB-DATA] reads rows",
                         "stride": ["I"], "mitigations": ["Parameterized queries (SEC-001)",
                                                          "Row-level authorization"]}]}
    for mitigations in (["n/a", "none"], ["Parameterized queries (SEC-001)", "Logged"]):
        head = {"threats": [dict(base["threats"][0], mitigations=mitigations)]}
        assert any("weakened" in e for e in tm.removed_threats(head, base)), mitigations
    extended = {"threats": [dict(base["threats"][0], mitigations=[
        "Parameterized queries (SEC-001) in every handler", "row-level  authorization"])]}
    assert tm.removed_threats(extended, base) == []
    for placeholder in ("", "n/a", "None.", "-", "TBD", "Not applicable", 7):
        path = tmp_path / "m.json"
        path.write_text(json.dumps({"threats": [dict(base["threats"][0],
                                                     mitigations=["Row-level authorization",
                                                                  placeholder])]}))
        _, errors = tm.load_model(path)
        assert any("placeholder" in e for e in errors), placeholder


# Round 6 (pr-surface/pr-reviewer/review_pr.py)

def test_a_credential_split_by_an_invisible_character_is_still_redacted(surface):
    # scrub() ran before the control/bidi strip, so the strip rejoined the key.
    key = "AKIAABCDEFGHIJKLMNOP"
    for mark in ("\x01", "\x7f", "\u200e", "\u202a", "\u2066"):
        split = f"leaked {key[:9]}{mark}{key[9:]} and gh{mark}p_{'a' * 24}"
        for out in (surface._text(split), surface._code(split)):
            assert key not in out and "ghp" not in out and "REDACTED" in out, repr(out)
    quoted = ('{"aws_secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCY", '
              "'password': hunter2hunter2}")
    out = surface.scrub(quoted)
    assert "wJalrXUtnFEMI" not in out and "hunter2" not in out, out


def _moved_file_repo(tmp_path):
    """A repo whose head moves one file unchanged (a 100%-similarity rename)."""
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
            capture_output=True, check=True, text=True).stdout.strip()

    git("init", "-q")
    (repo / "notes.txt").write_text("".join(f"payload line {i}\n" for i in range(20)))
    git("add", "-A")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (repo / "src").mkdir()
    git("mv", "notes.txt", "src/run.py")
    git("commit", "-qm", "move")
    return repo, base, git("rev-parse", "HEAD")


def test_a_moved_file_reaches_the_review_panel_in_full(surface, monkeypatch, tmp_path):
    repo, base, head = _moved_file_repo(tmp_path)
    policy = tmp_path / ".reviewer.yaml"
    policy.write_text("version: 1\nrules:\n  - {id: SEC-001, description: d, blocking: true}\n"
                      "agents:\n  - {name: Security, rules: [SEC-]}\n")
    import reviewer.bedrock_reviewer as core
    seen = []
    monkeypatch.setattr(core, "review_panel", lambda diff, *a, **k: seen.append(diff) or [])
    ctx = {"repo": "o/r", "pr": "1", "base": base, "head": head, "run": "1", "attempt": "1"}
    surface.analyze(ctx, repo, policy)
    assert "+payload line 19" in seen[0] and "similarity index" not in seen[0], seen[0]


def test_the_pipeline_review_diff_shows_a_moved_file_in_full(load_module, tmp_path):
    prep = load_module("pipeline_tools/prepare_review.py")
    repo, base, head = _moved_file_repo(tmp_path)
    policy = tmp_path / "approved.yaml"
    policy.write_text("version: 1\n")
    prep.dry_run(base, head, policy, tmp_path / "out", str(repo))
    diff = (tmp_path / "out" / "change.diff").read_text()
    assert "+payload line 19" in diff and "similarity index" not in diff, diff


# Round 6 (deterministic/checks.py)

GITHUB = ("{Federated: !Sub 'arn:aws:iam::${AWS::AccountId}:oidc-provider/"
          "token.actions.githubusercontent.com'}")
SUB = "{StringEquals: {'token.actions.githubusercontent.com:sub': 'repo:o/r:ref:refs/heads/main'}}"


@pytest.mark.parametrize("principal,condition,blocks", [
    # #5: with no subject, an audience only or a wildcard subject, any GitHub
    # workflow on the internet can assume the role.
    (GITHUB, None, "token.actions.githubusercontent.com:sub"),
    (GITHUB, "{StringEquals: {'token.actions.githubusercontent.com:aud': sts.amazonaws.com}}",
     "token.actions.githubusercontent.com:sub"),
    (GITHUB, "{StringLike: {'token.actions.githubusercontent.com:sub': 'repo:o/*'}}",
     "token.actions.githubusercontent.com:sub"),
    (GITHUB, "{StringLike: {'token.actions.githubusercontent.com:sub': 'repo:*'}}",
     "token.actions.githubusercontent.com:sub"),
    (GITHUB, "{StringLike: {'token.actions.githubusercontent.com:sub': 'repo:o/r*:pull_request'}}",
     "token.actions.githubusercontent.com:sub"),
    # One named repository, any ref or event in it (AWS's GitHub guidance), and
    # this sample's own pr-surface pattern with wildcarded immutable ids.
    (GITHUB, "{StringLike: {'token.actions.githubusercontent.com:sub': 'repo:o/r:*'}}", None),
    (GITHUB, "{StringLike: {'token.actions.githubusercontent.com:sub': "
             "['repo:o/r:pull_request', 'repo:o@*/r@*:pull_request']}}", None),
    (GITHUB, SUB, None),
    ("{Federated: !Ref Oidc}", None, "(a provider resource)"),
    ("{Federated: !Ref Oidc}", SUB, None),
    ("{Federated: 'arn:aws:iam::444455556666:oidc-provider/token.actions.githubusercontent.com'}",
     SUB, "trusts AWS account 444455556666"),
    ("{CanonicalUser: 79a59df900b949e55d96a1e698fbaced}", None, "CanonicalUser"),
])
def test_federated_and_canonical_user_principals_must_be_scoped(checks, principal, condition,
                                                                 blocks):
    cond = f"\n            Condition: {condition}" if condition else ""
    text = f"""
Resources:
  Oidc: {{Type: AWS::IAM::OIDCProvider}}
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {principal}
            Action: sts:AssumeRoleWithWebIdentity{cond}
"""
    found = _findings(checks, text)
    if blocks is None:
        assert found == [], found
    else:
        assert any(f.startswith("[BLOCKING] R(trust):") and blocks in f for f in found), found


def test_managed_policies_and_sam_templates_off_the_allowlist_block(checks):
    # #7: SecretsManagerReadWrite is secretsmanager:* on '*', and VPCAccessPolicy
    # takes no argument, so neither was ever questioned.
    text = """
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecretsManagerReadWrite
        - arn:aws:iam::111122223333:policy/AWSLambdaBasicExecutionRole
        - !Sub arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        - !Ref Mine
  Mine:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument: {Statement: [{Effect: Allow, Action: s3:GetObject, Resource: 'arn:aws:s3:::b/*'}]}
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Policies: [AWSXRayDaemonWriteAccess, VPCAccessPolicy: {}, S3ReadPolicy: {BucketName: b}]
"""
    found = _findings(checks, text)
    assert any("Role:" in f and "SecretsManagerReadWrite" in f for f in found), found
    assert sum("AWSLambdaBasicExecutionRole" in f for f in found) == 1   # the customer copy
    assert any("Fn:" in f and "VPCAccessPolicy" in f for f in found), found
    assert len(found) == 3 and all(f.startswith("[BLOCKING]") for f in found), found


class _RecordingAnalyzer:
    def __init__(self):
        self.calls = []

    def validate_policy(self, **kwargs):
        self.calls.append(kwargs)
        return {"findings": []}


def test_an_inert_intrinsic_cannot_turn_off_access_analyzer(checks, tmp_path, monkeypatch,
                                                           capsys):
    # #8: Sid: !Sub s1 resolves to the same literal, and used to skip the layer.
    template = tmp_path / "template.yaml"
    template.write_text("""
Parameters: {Team: {Type: String}}
Resources:
  Bucket: {Type: AWS::S3::Bucket}
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - {Sid: !Sub s1, Effect: Allow, Principal: {Service: lambda.amazonaws.com},
             Action: sts:AssumeRole}
  Read:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {Service: cloudfront.amazonaws.com}
            Action: s3:GetObject
            Resource: !Sub '${Bucket.Arn}/*'
            Condition: {StringEquals: {'aws:SourceAccount': !Ref AWS::AccountId}}
  Tagged:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: ec2:DescribeInstances
            Resource: '*'
            Condition: {StringEquals: {'aws:ResourceTag/team': !Ref Team}}
""")
    (tmp_path / "pr-reviewer").mkdir()
    (tmp_path / "pr-reviewer" / "VENDOR_MANIFEST.yaml").write_text("files:\n")
    analyzer = _RecordingAnalyzer()
    monkeypatch.setattr(checks.boto3, "client", lambda *a, **k: analyzer)
    monkeypatch.setattr(checks.sys, "argv", ["checks.py", "--templates", str(template),
                                             "--repo-root", str(tmp_path)])
    assert checks.main() == 1
    sent = {json.dumps(c.get("validatePolicyResourceType")): json.loads(c["policyDocument"])
            for c in analyzer.calls}
    assert len(analyzer.calls) == 2, analyzer.calls
    trust = sent['"AWS::IAM::AssumeRolePolicyDocument"']
    assert trust["Statement"][0]["Sid"] == "s1"
    bucket = sent["null"]   # a bucket policy is no role trust policy
    assert "${" not in json.dumps(bucket) and "Fn::" not in json.dumps(bucket)
    out = capsys.readouterr().out
    assert "[BLOCKING] Tagged: an intrinsic in the policy cannot be resolved" in out, out
    assert sum("[BLOCKING]" in line for line in out.splitlines()) == 1, out


def test_permission_resources_are_checked_as_the_grants_they_make(checks):
    # #9: these grant access through properties no policy-name rule finds.
    text = """
Resources:
  Fn: {Type: AWS::Serverless::Function}
  L: {Type: AWS::Lambda::LayerVersion}
  B: {Type: AWS::Events::EventBus}
  Open:
    Type: AWS::Lambda::Permission
    Properties: {Action: lambda:InvokeFunction, FunctionName: !Ref Fn, Principal: '*'}
  Foreign:
    Type: AWS::Lambda::Permission
    Properties: {Action: lambda:InvokeFunction, FunctionName: !Ref Fn, Principal: '444455556666'}
  Scoped:
    Type: AWS::Lambda::Permission
    Properties: {Action: lambda:InvokeFunction, FunctionName: !Ref Fn, Principal: s3.amazonaws.com,
                 SourceAccount: !Ref AWS::AccountId, SourceArn: 'arn:aws:s3:::b'}
  Layer:
    Type: AWS::Lambda::LayerVersionPermission
    Properties: {Action: lambda:GetLayerVersion, LayerVersionArn: !Ref L, Principal: '*'}
  OrgLayer:
    Type: AWS::Lambda::LayerVersionPermission
    Properties: {Action: lambda:GetLayerVersion, LayerVersionArn: !Ref L, Principal: '*',
                 OrganizationId: o-abc123}
  Bus:
    Type: AWS::Events::EventBusPolicy
    Properties:
      StatementId: s
      Statement: {Effect: Allow, Principal: '*', Action: events:PutEvents, Resource: !GetAtt B.Arn}
  OrgBus:
    Type: AWS::Events::EventBusPolicy
    Properties: {StatementId: s, Action: events:PutEvents, Principal: '*',
                 Condition: {Type: StringEquals, Key: 'aws:PrincipalOrgID', Value: o-abc123}}
  Glue:
    Type: AWS::Glue::ResourcePolicy
    Properties:
      PolicyInJson:
        Statement: [{Effect: Allow, Principal: {AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'},
                     Action: 'glue:*', Resource: '*'}]
"""
    found = _findings(checks, text)
    blocked = {f.split(":")[0].removeprefix("[BLOCKING] ") for f in found}
    assert blocked == {"Open(Permission)", "Foreign(Permission)",
                       "Layer(LayerVersionPermission)", "Bus(EventBusPolicy)",
                       "Glue(ResourcePolicy)"}, found
