"""Deterministic lane — runs BESIDE the agent, not instead of it.

Checks synthesized/committed CloudFormation templates:
  1. wildcard-IAM (blocking) — the deterministic twin of agent rule IAM-002,
     demonstrating layering: Action:"*", sensitive service-wide wildcards
     (iam:*), sensitive actions on Resource:"*", Allow with NotAction /
     NotResource / NotPrincipal, Principal:"*" without a scoping Condition, a
     web-identity (OIDC) principal without a wildcard-free subject Condition, a
     CanonicalUser principal, managed policies and SAM policy templates outside
     a short allowlist, and actions hidden behind intrinsics. Lambda and layer
     permissions, EventBridge bus policies and Glue resource policies are read
     as the grants they make.
  2. Access Analyzer ValidatePolicy on every inline IAM policy found, with its
     intrinsics resolved (ERROR/SECURITY_WARNING findings, an API error and an
     intrinsic that cannot be resolved are blocking; suggestions advisory).
  3. A nested stack, SAM application or AWS::Include must point at a template
     this lane also checked (blocking otherwise).

Usage: python checks.py --templates 'sample-app/template.yaml' [--skip-access-analyzer]
Exit 0 = pass, 1 = blocking findings.
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import hashlib
import json
import pathlib
import re
import sys

import boto3
import yaml


class _CfnLoader(yaml.SafeLoader):
    """Tolerate CloudFormation short-form intrinsics (!Ref, !GetAtt, !Sub...)."""


def _unknown(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{tag_suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"Fn::{tag_suffix}": loader.construct_sequence(node)}
    return {f"Fn::{tag_suffix}": loader.construct_mapping(node)}


_CfnLoader.add_multi_constructor("!", _unknown)


# !Ref in YAML short form loads as Fn::Ref (see _CfnLoader); JSON uses Ref.
REF = ("Ref", "Fn::Ref")


def _branches(value) -> list:
    """Every value an !If can take (both branches, recursively); AWS::NoValue is none."""
    if isinstance(value, dict) and len(value) == 1:
        (key, arg), = value.items()
        if key == "Fn::If" and isinstance(arg, list) and len(arg) == 3:
            return _branches(arg[1]) + _branches(arg[2])
        if key in REF and arg == "AWS::NoValue":
            return []
    return [value]


def _as_document(doc):
    """A policy document as a mapping, or None when it is not static."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    return doc if isinstance(doc, dict) and "Statement" in doc else None


def _statements(policy_doc) -> tuple[list, bool]:
    """(statements, complete). complete is False when part of the document is an
    intrinsic or shape no check can read, so the caller fails closed."""
    stmts, complete = [], True
    for branch in _branches(policy_doc):
        doc = _as_document(branch)
        if doc is None:
            complete = False
            continue
        raw = doc.get("Statement")
        for item in _branches(raw) if not isinstance(raw, list) else raw:
            for s in _branches(item) if not isinstance(item, list) else item:
                if isinstance(s, dict) and not (len(s) == 1 and next(iter(s)).startswith(
                        ("Fn::", "Ref"))):
                    stmts.append(s)
                else:
                    complete = False
    return stmts, complete


# Services whose READS are sensitive too. Any write on a wide resource blocks,
# whatever the service; this list only adds reads (s3:GetObject on '*').
SENSITIVE_SERVICES = ("iam", "sts", "s3", "kms", "secretsmanager", "ssm", "dynamodb", "*")
READ_VERBS = ("get", "list", "describe", "batchget", "head")
# Writes AWS accepts only on Resource "*" (they name no resource).
# ecr:GetAuthorizationToken is here, not in CREDENTIAL_READS: AWS accepts it
# only on "*", and the token reads nothing by itself (a pull still needs
# ecr:BatchGetImage on a named repository). access-analyzer:ValidatePolicy and
# inspector-scan:ScanSbom have no resource type, and each only reads the
# document it is sent (a policy, an SBOM); this lane's own role calls both.
RESOURCE_STAR_ONLY = ("xray:puttracesegments", "xray:puttelemetryrecords",
                      "cloudwatch:putmetricdata", "ecr:getauthorizationtoken",
                      "access-analyzer:validatepolicy", "inspector-scan:scansbom")
# Read-named actions that return credentials or secrets: sensitive whatever the
# service, including through a wildcard (ec2:Get*).
CREDENTIAL_READS = ("ec2:getpassworddata", "lambda:getfunction", "cloudformation:gettemplate",
                    "redshift:getclustercredentials", "redshift:getclustercredentialswithiam",
                    "redshift-serverless:getcredentials", "cognito-identity:getopenidtoken",
                    "cognito-identity:getopenidtokenfordeveloperidentity",
                    "cognito-identity:getcredentialsforidentity",
                    "lightsail:getinstanceaccessdetails", "glue:getconnection",
                    "glue:getconnections", "codeartifact:getauthorizationtoken",
                    "sso:getrolecredentials")
ADMIN_MANAGED_POLICIES = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")
# The only AWS managed policies a workload may attach: a function's own logs and
# traces. Every other one blocks, since the lane cannot read what it grants.
# shortcut: an allowlist by name, not an expansion of each policy's document;
# vendor the documents and run check_wildcards on them when more are needed.
ALLOWED_MANAGED_POLICIES = ("AWSLambdaBasicExecutionRole", "AWSXRayDaemonWriteAccess")
# SAM policy templates that grant only on the resource their arguments name
# (an argument of '*' or one that cannot be resolved still blocks). Any other
# template blocks, including argument-less ones such as VPCAccessPolicy.
ALLOWED_SAM_TEMPLATES = ("S3ReadPolicy", "S3WritePolicy", "S3CrudPolicy", "DynamoDBReadPolicy",
                         "DynamoDBWritePolicy", "DynamoDBCrudPolicy", "SQSSendMessagePolicy",
                         "SQSPollerPolicy", "SNSPublishMessagePolicy", "LambdaInvokePolicy",
                         "KMSDecryptPolicy", "AWSSecretsManagerGetSecretValuePolicy",
                         "EventBridgePutEventsPolicy", "StepFunctionsExecutionPolicy")
# A Condition on one of these keys narrows Principal "*" to known callers.
# sts:ExternalId is not one: it names no caller, and in a template it is public.
PRINCIPAL_SCOPING_KEYS = ("aws:principalorgid", "aws:principalaccount", "aws:principalarn",
                          "aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid",
                          "aws:sourcevpc", "aws:sourcevpce")
# What a concrete value of a scoping key looks like; anything else scopes nothing.
SCOPE_SHAPES = {"aws:principalorgid": r"o-[a-z0-9]+", "aws:sourceorgid": r"o-[a-z0-9]+",
                "aws:principalaccount": r"\d{12}", "aws:sourceaccount": r"\d{12}",
                "aws:principalarn": r"arn:.+", "aws:sourcearn": r"arn:.+",
                "aws:sourcevpc": r"vpc-[0-9a-f]+", "aws:sourcevpce": r"vpce-[0-9a-f]+"}
# Resource-policy properties that are not named PolicyDocument.
RESOURCE_POLICY_PROPS = ("KeyPolicy", "RepositoryPolicyText", "ResourcePolicy", "AccessPolicies")
# Resources the SAM transform adds; a !Ref to one names a concrete resource.
SAM_GENERATED = ("ServerlessDeploymentApplication", "ServerlessRestApi", "ServerlessHttpApi")


CONCRETE = "<resource>"   # a !Ref to a resource, a pseudo parameter, or a !GetAtt


def _sam_generated(name: str, template: dict) -> bool:
    transform = template.get("Transform")
    if "AWS::Serverless-2016-10-31" not in (transform if isinstance(transform, list)
                                            else [transform]):
        return False
    return name in SAM_GENERATED or any(name.startswith(r)   # HelloFnRole, HelloFnAlias
                                        for r in (template.get("Resources") or {}))


def _strings(value, template=None) -> list:
    """The literal strings a policy value can take; None means 'not static'.

    Resolves the intrinsics that hide a literal (!Sub "*", !If, !Join of
    literals, a !Ref to a parameter's Default) so they cannot dodge the
    wildcard checks. A !Ref to one of the template's resources, a pseudo
    parameter or a !GetAtt names one concrete resource (CONCRETE). A parameter
    with no Default, or an intrinsic this cannot resolve, is None.
    """
    tpl = template or {}
    params = tpl.get("Parameters") or {}

    def ref(name):
        if name in params:
            default = (params[name] or {}).get("Default")
            return None if default is None else str(default)
        if (name.startswith("AWS::") or name in (tpl.get("Resources") or {})
                or _sam_generated(name, tpl)):
            return CONCRETE
        return None

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, template)]
    if isinstance(value, dict) and len(value) == 1:
        (key, arg), = value.items()
        if key in REF and arg == "AWS::NoValue":
            return []
        if key in REF and isinstance(arg, str):
            return [ref(arg.split(".")[0])]
        if key == "Fn::GetAtt":
            return [CONCRETE]
        if key == "Fn::Sub":
            text, local = (arg[0], arg[1]) if isinstance(arg, list) and len(arg) == 2 \
                else (arg, {})
            if not isinstance(text, str) or not isinstance(local, dict):
                return [None]
            names = {}
            for name in re.findall(r"\$\{([^}!]+)\}", text):
                got = _strings(local[name], template) if name in local else \
                    [ref(name.split(".")[0])]
                names[name] = got[0] if len(got) == 1 else None
            if any(v is None for v in names.values()):
                return [None]
            return [re.sub(r"\$\{([^}!]+)\}",
                           lambda m: "*" if names[m[1]] == "*" else
                           (m[0] if names[m[1]] == CONCRETE else names[m[1]]), text)]
        if key == "Fn::If" and isinstance(arg, list) and len(arg) == 3:
            return _strings(arg[1], template) + _strings(arg[2], template)
        if key == "Fn::Join" and isinstance(arg, list) and len(arg) == 2 \
                and isinstance(arg[0], str) and isinstance(arg[1], list):
            parts = [_strings(p, template) for p in arg[1]]
            if all(len(p) == 1 and isinstance(p[0], str) for p in parts):
                return [arg[0].join(p[0] for p in parts)]
    return [None]


def _hidden(value) -> bool:
    """True when an intrinsic hides the value (!Ref, !Sub, !ImportValue, ...)."""
    return isinstance(value, dict) and len(value) == 1 and \
        str(next(iter(value))).startswith(("Fn::", "Ref"))


def _policy_property(key: str, value) -> bool:
    """A resource property that holds a policy document, whatever it is called.

    A *Policy or *PolicyText property is a policy when it reads as one, or when
    an intrinsic hides its value: that one is checked, and fails closed as not
    static. A readable value with no Statement (RedrivePolicy, LifecyclePolicy)
    is some other setting."""
    if key.endswith("PolicyDocument") or key in RESOURCE_POLICY_PROPS:
        return True
    return key.endswith(("Policy", "PolicyText")) and any(
        _as_document(b) is not None or _hidden(b) for b in _branches(value))


def _given(fields: dict) -> dict:
    """The fields a template sets; a property it omits is no part of the grant."""
    return {k: v for k, v in fields.items() if v is not None and v != {}}


def _lambda_permission(p: dict) -> dict:
    return {"Statement": [_given({
        "Principal": p.get("Principal"), "Action": p.get("Action"),
        "Resource": p.get("FunctionName"), "Condition": _given({
            "StringEquals": _given({"aws:SourceAccount": p.get("SourceAccount"),
                                    "aws:PrincipalOrgID": p.get("PrincipalOrgID")}),
            "ArnLike": _given({"aws:SourceArn": p.get("SourceArn")})})})]}


def _layer_permission(p: dict) -> dict:
    return {"Statement": [_given({
        "Principal": p.get("Principal"), "Action": p.get("Action"),
        "Resource": p.get("LayerVersionArn"), "Condition": _given({
            "StringEquals": _given({"aws:PrincipalOrgID": p.get("OrganizationId")})})})]}


def _event_bus_policy(p: dict) -> dict:
    if "Statement" in p:
        return {"Statement": [p["Statement"]]}
    c = p.get("Condition")                  # the older form: {Type, Key, Value}
    return {"Statement": [_given({
        "Principal": p.get("Principal"), "Action": p.get("Action"),
        "Condition": {c.get("Type"): {c.get("Key"): c.get("Value")}}
        if isinstance(c, dict) else None})]}


# Resource types that grant a principal access through properties not named like
# a policy, and the policy each grant amounts to, so check_wildcards reads its
# Principal, Action, Resource and Condition like any other. The second field is
# the ValidatePolicy type: None for a statement the lane builds from properties,
# which is no document Access Analyzer can read. A type not listed here is not
# failed closed; _policy_property still finds its *Policy properties.
PERMISSION_TYPES = {
    "AWS::Lambda::Permission": (_lambda_permission, None),
    "AWS::Lambda::LayerVersionPermission": (_layer_permission, None),
    "AWS::Events::EventBusPolicy": (_event_bus_policy, None),
    "AWS::Glue::ResourcePolicy": (lambda p: p.get("PolicyInJson"), "RESOURCE_POLICY"),
}


def _resources(template: dict):
    """(name, resource) for every resource, including each one an
    AWS::LanguageExtensions Fn::ForEach loop generates; (name, None) for an
    entry no check can read, which check_managed_policies blocks on."""
    def walk(entries, prefix):
        for name, res in entries.items() if isinstance(entries, dict) else ():
            if (str(name).startswith("Fn::ForEach::") and isinstance(res, list)
                    and len(res) == 3 and isinstance(res[2], dict)):
                yield from walk(res[2], f"{prefix}{name}/")   # [id, collection, body]
            else:
                yield f"{prefix}{name}", res if isinstance(res, dict) else None
    yield from walk(template.get("Resources"), "")


def _iter_policies(template: dict):
    for name, res in _resources(template):
        props = (res.get("Properties") if isinstance(res, dict) else None) or {}
        kind = str(res.get("Type")) if isinstance(res, dict) else ""
        pols = props.get("Policies") or []
        for entry in pols if isinstance(pols, list) else [pols]:
            for pol in _branches(entry):
                if isinstance(pol, str):
                    continue                     # managed or SAM policy name
                if isinstance(pol, dict) and "PolicyDocument" in pol:
                    yield name, pol["PolicyDocument"], "IDENTITY_POLICY"
                elif isinstance(pol, dict) and len(pol) == 1 and \
                        not next(iter(pol)).startswith(("Fn::", "Ref", "Statement")):
                    continue                     # SAM policy template: check_managed_policies
                else:                            # SAM inline policy, or an unreadable entry
                    yield name, pol, "IDENTITY_POLICY"
        for key, value in props.items():
            if key == "AssumeRolePolicyDocument":
                # Trust policies carry Principal and no Resource — they validate
                # as RESOURCE_POLICY, not IDENTITY_POLICY (else false ERRORs).
                yield f"{name}(trust)", value, "RESOURCE_POLICY"
            elif key == "PolicyDocument":
                # Only an IAM policy is an identity policy: a bucket, topic or queue
                # policy names a Principal, which ValidatePolicy rejects in one.
                yield name, value, "IDENTITY_POLICY" if kind.startswith("AWS::IAM::") \
                    else "RESOURCE_POLICY"
            elif _policy_property(key, value):
                yield f"{name}({key})", value, "RESOURCE_POLICY"
        if kind in PERMISSION_TYPES:
            build, ptype = PERMISSION_TYPES[kind]
            yield f"{name}({kind.rsplit('::', 1)[-1]})", build(props), ptype


def _admin_policy(ref: str) -> bool:
    """Admin-level or service-wide-write managed policies, by full path and name.
    job-function/ policies are for people, never for a workload's role."""
    name = ref.rsplit("/", 1)[-1]
    return ("job-function/" in ref or name in ADMIN_MANAGED_POLICIES
            or name.endswith("FullAccess") or "Administrator" in name)


def check_managed_policies(template: dict) -> list[str]:
    """Managed policies (by ARN or SAM name) and SAM policy templates. The lane
    cannot read what they grant, so only the allowlisted ones pass, and a SAM
    template given '*' or an unresolvable argument blocks too."""
    out = []
    for name, res in _resources(template):
        if res is None:
            # Nothing the lane cannot read passes: it may hold any IAM.
            out.append(f"[BLOCKING] {name}: a Resources entry the lane cannot read (not a "
                       f"resource mapping or a Fn::ForEach loop)")
            continue
        props = res.get("Properties") or {}
        pols = props.get("Policies") or []
        entries = [p for e in (pols if isinstance(pols, list) else [pols]) for p in _branches(e)]
        attached = _strings(props.get("ManagedPolicyArns") or [], template) + \
            [p for p in entries if isinstance(p, str)]
        for ref in attached:
            if ref is None:
                out.append(f"[BLOCKING] {name}: attaches a managed policy whose ARN cannot "
                           f"be resolved (a parameter with no Default, or an intrinsic)")
            elif ref == CONCRETE:
                # shortcut: a !Ref or !GetAtt is taken to be a policy this template
                # defines (its document is checked there); resolve the target's Type
                # if a template attaches a policy some other resource returns.
                continue
            elif _admin_policy(ref):
                out.append(f"[BLOCKING] {name}: attaches admin-level managed policy "
                           f"{ref.rsplit('/', 1)[-1]}")
            elif ref.rsplit("/", 1)[-1] not in ALLOWED_MANAGED_POLICIES or (
                    ref.startswith("arn:") and not re.match(
                        r"arn:([\w-]+|\$\{AWS::Partition\}):iam::aws:policy/", ref)):
                out.append(f"[BLOCKING] {name}: attaches managed policy "
                           f"{ref.rsplit('/', 1)[-1]}, whose permissions this lane cannot "
                           f"read; write the statements it needs as an inline policy")
        for pol in entries:
            if isinstance(pol, dict) and len(pol) == 1:
                (tmpl, args), = pol.items()
                if tmpl.startswith(("Fn::", "Ref", "Statement")) or tmpl == "PolicyDocument":
                    continue
                if tmpl not in ALLOWED_SAM_TEMPLATES:
                    out.append(f"[BLOCKING] {name}: SAM policy template {tmpl} is not on the "
                               f"lane's allowlist; write the statements it needs as an "
                               f"inline policy")
                    continue
                values = _strings(list(args.values()), template) if isinstance(args, dict) \
                    else []
                if "*" in values or None in values:
                    out.append(f"[BLOCKING] {name}: SAM policy template {tmpl} gets '*' or "
                               f"a value that cannot be resolved; name the resource")
    return out


def _principal_wildcard(principal, template=None) -> bool:
    values = _strings(list(principal.values()), template) if isinstance(principal, dict) \
        else _strings(principal, template)
    return "*" in values or None in values


def _matched(condition, template=None):
    """(key, values) for each Condition a caller must match. Negated operators,
    ...IfExists (true when the key is absent), Null and ForAllValues (true on an
    empty set) require nothing."""
    if not isinstance(condition, dict):
        return
    for operator, pairs in condition.items():
        op = "Null" if operator is None else str(operator)   # YAML reads Null: as None
        base = op.split(":", 1)[-1]
        if ("Not" in base or base.endswith("IfExists") or base == "Null"
                or op.startswith("ForAllValues:") or not isinstance(pairs, dict)):
            continue
        for key, value in pairs.items():
            yield str(key).lower(), _strings(value, template)


def _scopes_caller(condition, template=None) -> bool:
    """True when a Condition narrows the caller: a positive match operator on a
    scoping key, with a concrete value. A bare '*' value scopes nothing."""
    return any(key in PRINCIPAL_SCOPING_KEYS and values and all(
        _concrete_value(key, v) for v in values) for key, values in _matched(condition, template))


def _web_identity_providers(principal, template=None) -> list[str]:
    """The OIDC providers a Federated principal trusts, by the host their claims
    are keyed on ('' when a !Ref names a provider resource). A SAML provider
    belongs to an account and is scoped like any account ARN."""
    if not isinstance(principal, dict):
        return []
    hosts = []
    for value in _strings(principal.get("Federated", []), template):
        if not isinstance(value, str) or value == "*" or ":saml-provider/" in value:
            continue                        # '*' and None: _principal_wildcard blocks them
        if "oidc-provider/" in value:
            hosts.append(value.split("oidc-provider/", 1)[1].lower())
        else:                               # accounts.google.com, or a provider resource
            hosts.append("" if value == CONCRETE or value.startswith("arn:") or "${" in value
                         else value.lower())
    return hosts


# A GitHub Actions subject names one repository once it starts repo:<owner>/<name>
# with both written out; each may carry an @<id>, wildcarded or not, and the
# rest (event, ref, environment) may be a wildcard. AWS's GitHub guidance and
# this sample's own pr-surface role (repo:<owner>@*/<name>@*:pull_request) use
# that shape. repo:org/* or a bare * still match any repository.
GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"
GITHUB_REPO_SUBJECT = re.compile(r"repo:[^*?/@:]+(?:@[^/:]*)?/[^*?/@:]+(?:@[^/:]*)?(?::|$)")


def _names_subjects(host: str, value) -> bool:
    if not isinstance(value, str) or not value or value == CONCRETE:
        return False
    if host == GITHUB_OIDC_HOST and GITHUB_REPO_SUBJECT.match(value):
        return True
    return not any(c in value for c in "*?")


def _scopes_subject(condition, host: str, template=None) -> bool:
    """True when a Condition names subjects of the provider: a positive match on
    <host>:sub whose values have no wildcard (for GitHub: no wildcard before the
    repository is named). Any workflow, app or user the provider issues a token
    to matches a wildcard (repo:org/*) or no condition.
    shortcut: the subject claim only; accept a provider's own scoping claim (a
    Cognito identity pool's :aud) when a template trusts one."""
    return any((key == f"{host}:sub" if host else key.endswith(":sub")) and values and all(
        _names_subjects(key[:-len(":sub")], v) for v in values)
        for key, values in _matched(condition, template))


def _concrete_value(key: str, value) -> bool:
    """One identifier, with no wildcard anywhere (o-* or arn:aws:iam::*:* match
    many callers), in the shape the key takes; a !Ref or !GetAtt is concrete."""
    if not isinstance(value, str) or not value or "*" in value or "?" in value:
        return False
    if value == CONCRETE or re.fullmatch(r"\$\{[^}]+\}", value):
        return True
    shape = SCOPE_SHAPES.get(key)   # a key with no declared shape scopes nothing
    return shape is not None and re.fullmatch(shape, value) is not None


def _named_accounts(principal, template=None) -> list[str]:
    """Literal 12-digit AWS accounts a Principal trusts, under any key (AWS, a
    Federated provider ARN, ...). This account is named with ${AWS::AccountId};
    a literal one cannot be told apart from a stranger's."""
    values = list(principal.values()) if isinstance(principal, dict) else principal
    return sorted({m for v in _strings(values, template) if isinstance(v, str)
                   for m in re.findall(r"(?<!\d)\d{12}(?!\d)", v)})


def _wide(resource: str) -> bool:
    """A Resource that names no particular resource: '*', an ARN with a wildcard
    partition, service or account, or one whose resource part is a wildcard or a
    type plus a wildcard (arn:aws:iam::${AWS::AccountId}:role/*, ...:table/*).
    A wildcard under a named resource (bucket/*, deploymentgroup:app/*) is scoped."""
    if resource == "*":
        return True
    if not resource.startswith("arn:"):
        return False
    parts = re.sub(r"\$\{[^}]*\}", "X", resource).split(":", 5)   # ${AWS::AccountId}
    if len(parts) < 6 or any(c in parts[i] for i in (1, 2, 4) for c in "*?"):
        return True
    head, *rest = re.split(r"[/:]", parts[5], 1)
    if parts[2] == "s3" or not rest:            # bucket[/key], or no resource type
        return any(c in head for c in "*?")
    return any(c in head for c in "*?") or not rest[0].strip("*?/:")


def _read_only(action: str) -> bool:
    return action.split(":", 1)[-1].startswith(READ_VERBS) or action in RESOURCE_STAR_ONLY


def check_wildcards(name: str, doc, template=None) -> list[str]:
    out = []
    stmts, complete = _statements(doc)
    if not complete:
        out.append(f"[BLOCKING] {name}: policy document is not static (an intrinsic or a "
                   f"shape the check cannot read); write the document as plain YAML")
    for s in stmts:
        # Anything that is not literally Deny is treated as Allow (fail closed).
        effect = _strings(s.get("Effect"), template)
        if effect and all(e == "Deny" for e in effect):
            continue
        actions = _strings(s.get("Action", []), template)
        resources = _strings(s.get("Resource", []), template)
        literal = [a.lower() for a in actions if isinstance(a, str)]
        if None in actions or any("${" in a or a == CONCRETE for a in literal):
            out.append(f"[BLOCKING] {name}: Action is not a static literal (CFN "
                       f"intrinsic); write actions as plain strings")
        if "*" in literal:
            out.append(f"[BLOCKING] {name}: statement allows Action:'*'")
        wide = sorted({a for a in literal if a.endswith(":*")})   # any service
        if wide:
            out.append(f"[BLOCKING] {name}: service-wide wildcard {', '.join(wide)}")
        sensitive = any(a.split(":")[0] in SENSITIVE_SERVICES
                        or any(fnmatch.fnmatchcase(c, a) for c in CREDENTIAL_READS)
                        for a in literal)
        risky = sensitive or not all(_read_only(a) for a in literal)
        what = "sensitive actions" if sensitive else "write actions"
        broad = [r for r in resources if isinstance(r, str) and _wide(r)]
        if broad and risky:
            where = "Resource:'*'" if "*" in broad else f"an account-wide Resource {broad[0]}"
            out.append(f"[BLOCKING] {name}: {what} with {where}; name the resource")
        if None in resources and risky:
            out.append(f"[BLOCKING] {name}: {what} on a Resource that cannot be "
                       f"resolved (a parameter with no Default, or an intrinsic)")
        for element in ("NotAction", "NotResource", "NotPrincipal"):
            if element in s:
                out.append(f"[BLOCKING] {name}: Allow with {element} grants everything "
                           f"not listed; list what is allowed instead")
        if "Principal" in s and _principal_wildcard(s["Principal"], template) \
                and not _scopes_caller(s.get("Condition"), template):
            out.append(f"[BLOCKING] {name}: allows Principal:'*' (or one that cannot be "
                       f"resolved) without a Condition that scopes the caller "
                       f"(aws:PrincipalOrgID, aws:SourceArn, ...)")
        accounts = _named_accounts(s["Principal"], template) if "Principal" in s else []
        if accounts and not _scopes_caller(s.get("Condition"), template):
            out.append(f"[BLOCKING] {name}: trusts AWS account {', '.join(accounts)} named "
                       f"in the template; use ${{AWS::AccountId}} for this account, or "
                       f"scope the caller (aws:PrincipalOrgID) for a partner account")
        # shortcut: a Service principal passes with no aws:SourceAccount/SourceArn
        # (a confused deputy on a resource policy); require one when a template
        # grants a service access to a bucket, queue or topic.
        principal = s.get("Principal")
        if isinstance(principal, dict) and "CanonicalUser" in principal:
            out.append(f"[BLOCKING] {name}: trusts a CanonicalUser principal, which no "
                       f"Condition here can tie to a known account; use an AWS principal "
                       f"(an origin access control for CloudFront)")
        for host in _web_identity_providers(principal, template):
            if not _scopes_subject(s.get("Condition"), host, template):
                claim = f"{host or '<provider>'}:sub"
                out.append(f"[BLOCKING] {name}: trusts web-identity provider "
                           f"{host or '(a provider resource)'} without a Condition on {claim} "
                           f"naming its subjects (for GitHub, repo:<owner>/<name> written "
                           f"out; elsewhere, no wildcard); anyone the provider issues "
                           f"a token to can assume it")
    return out


def _template_references(template: dict):
    """(where, location) for every other template this one pulls in: nested
    stacks, SAM applications and AWS::Include transforms."""
    for name, res in _resources(template):
        if not isinstance(res, dict):
            continue
        props = res.get("Properties") or {}
        if res.get("Type") == "AWS::CloudFormation::Stack":
            yield name, props.get("TemplateURL")
        elif res.get("Type") == "AWS::Serverless::Application":
            yield name, props.get("Location")

    def walk(node, where):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("Fn::Transform", "Transform"):
                    for t in value if isinstance(value, list) else [value]:
                        if isinstance(t, dict) and t.get("Name") == "AWS::Include":
                            yield where, (t.get("Parameters") or {}).get("Location")
                yield from walk(value, key if where == "template" and key != "Resources"
                                else where)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value, where)
    yield from walk(template, "template")


def check_template_references(template: dict, path: str, scanned) -> list[str]:
    """A policy in a nested or included template deploys too, so that template
    must be one this lane checked. Nothing checked is not a pass."""
    checked = {pathlib.Path(p).resolve() for p in scanned}
    here = pathlib.Path(path).resolve().parent
    out = []
    for where, location in _template_references(template):
        for value in _strings(location, template):
            if not (isinstance(value, str) and "://" not in value
                    and (here / value).resolve() in checked):
                out.append(f"[BLOCKING] {where}: pulls in template {value or location!r}, "
                           f"which this lane did not check; add it to --templates or "
                           f"inline it")
    return out


# Stand-ins ValidatePolicy accepts for a value known only at deploy time. Each
# names one resource, as the wildcard check reads CONCRETE: a '*' here would be
# rejected in a Principal and flag iam:PassRole on a role the template names.
DEPLOY_TIME = {"AWS::Partition": "aws", "AWS::URLSuffix": "amazonaws.com",
               "AWS::AccountId": "123456789012", "AWS::Region": "us-east-1"}
DEPLOY_ARN = "arn:aws:iam::123456789012:role/deploy-time-value"


def _for_analyzer(node, template, stand_ins: list):
    """The policy with every intrinsic resolved, for ValidatePolicy; None when a
    value cannot be (a parameter with no Default, a function _strings does not
    read). A literal stays itself (!Sub 's1' is 's1'), an !If keeps both
    branches, and a value known only at deploy time (a resource of this
    template, a pseudo parameter) gets a stand-in, counted in stand_ins."""
    if isinstance(node, list):
        out = []
        for item in node:
            got = _for_analyzer(item, template, stand_ins)
            if got is None:
                return None
            out += got if _hidden(item) and isinstance(got, list) else [got]
        return out
    if isinstance(node, dict) and not _hidden(node):
        out = {}
        for key, value in node.items():
            if _branches(value):                     # [] is AWS::NoValue: no key
                out[key] = _for_analyzer(value, template, stand_ins)
                if out[key] is None:
                    return None
        principal, condition = out.get("Principal"), out.get("Condition")
        if isinstance(principal, dict) and principal.get("Federated") == DEPLOY_ARN:
            # A !Ref to an OIDC provider: name it by the host its :sub key uses
            # (a statement without one already blocks in check_wildcards).
            keys = [str(k) for pairs in (condition.values() if isinstance(condition, dict)
                                         else ()) if isinstance(pairs, dict) for k in pairs]
            host = next((k.rsplit(":", 1)[0] for k in keys if k.lower().endswith(":sub")),
                        "deploy-time-value")
            principal["Federated"] = f"arn:aws:iam::123456789012:oidc-provider/{host}"
        return out
    if not _hidden(node):
        return node
    (key, arg), = node.items()
    if key in REF and isinstance(arg, str) and arg in DEPLOY_TIME:
        stand_ins.append(arg)
        return DEPLOY_TIME[arg]
    branches = _branches(node)
    if branches != [node]:                           # an !If
        got = [_for_analyzer(b, template, stand_ins) for b in branches]
        if any(g is None for g in got):
            return None
        flat = [v for g in got for v in (g if isinstance(g, list) else [g])]
        return flat[0] if len(flat) == 1 else flat
    values = _strings(node, template)
    if None in values:
        return None

    def stand_in(m):
        stand_ins.append(m[0])
        return DEPLOY_TIME.get(m[1]) or (DEPLOY_ARN if m.start() == 0 else "deploy-time-value")
    out = [re.sub(r"\$\{([^}!]+)\}|" + re.escape(CONCRETE), stand_in, v) for v in values]
    return out[0] if len(out) == 1 else out


def check_access_analyzer(name: str, doc: dict, client, policy_type: str,
                          template=None) -> list[str]:
    stand_ins: list = []
    resolved = _for_analyzer(doc, template, stand_ins)
    if resolved is None:
        # Fail closed, as on an API error: a skipped validation is never a pass.
        return [f"[BLOCKING] {name}: an intrinsic in the policy cannot be resolved (a "
                f"parameter with no Default, or a function this lane does not read), so "
                f"Access Analyzer could not validate it"]
    out = [f"[advisory] {name}: contains CFN intrinsics — Access Analyzer validated it "
           f"with placeholders for {len(stand_ins)} deploy-time value(s) (wildcard check "
           f"still applied)"] if stand_ins else []
    try:
        kwargs = {"policyDocument": json.dumps(resolved, default=str), "policyType": policy_type}
        if policy_type == "RESOURCE_POLICY" and name.endswith("(trust)"):
            # A role trust policy has an implicit Resource (the role itself). Any
            # other resource policy names its Resource and would fail this syntax.
            kwargs["validatePolicyResourceType"] = "AWS::IAM::AssumeRolePolicyDocument"
        resp = client.validate_policy(**kwargs)
        for f in resp.get("findings", []):
            level = f["findingType"]
            tag = "[BLOCKING]" if level in ("ERROR", "SECURITY_WARNING") else "[advisory]"
            out.append(f"{tag} {name}: AccessAnalyzer {level}: {f['findingDetails']}")
    except Exception as exc:  # noqa: BLE001 — reported, never raised
        # Fail closed: an unvalidated policy is not a passing one. Use
        # --skip-access-analyzer to run the lane without the API on purpose.
        out.append(f"[BLOCKING] {name}: ValidatePolicy unavailable ({type(exc).__name__}); "
                   f"the policy was not validated")
    return out


def check_single_reviewer_core(root: pathlib.Path) -> list[str]:
    """One reviewer core, or the build fails.

    The PR surface used to ship a vendored copy of `reviewer/` beside
    review_pr.py. Python puts a script's own directory ahead of PYTHONPATH, so
    that copy SHADOWED the real core even though the workflow pointed PYTHONPATH
    at it — and it had drifted 100 lines, which is how a seat came to report an
    error message that had already been deleted from the core. A fork that
    silently wins is worse than no fork, so its existence is now a build
    failure rather than a convention.
    """
    canonical = root / "agent" / "reviewer"
    out = []
    if not canonical.exists():
        # An ARTIFACT repo has no agent/ - its vendored bundle IS the reviewer,
        # and the thing worth checking there is that it still matches what the
        # paved road published. That check lives in the artifact repo as
        # pr-reviewer/verify_vendor.py and runs before its review; duplicating
        # it here would just guess at another repo's layout.
        manifest = next(root.rglob("VENDOR_MANIFEST.yaml"), None)
        if manifest is None:
            out.append("[BLOCKING] no reviewer core and no VENDOR_MANIFEST.yaml — this "
                       "repo has neither the canonical reviewer nor a pinned copy of it")
        return out
    for path in root.rglob("reviewer/__init__.py"):
        if any(part in {"cdk.out", ".venv", "node_modules", "__pycache__", ".asset"}
               for part in path.parts):
            continue
        pkg = path.parent
        if pkg.resolve() != canonical.resolve():
            out.append(f"[BLOCKING] duplicate reviewer core at {pkg.relative_to(root)} — "
                       f"import it from agent/ instead of vendoring it, or generate it "
                       f"with scripts/vendor_reviewer.sh for an EXTERNAL repo")
    return out


def check_panel_config_mirror(root: pathlib.Path) -> list[str]:
    """Verify the policy bundle packaged by dashboard/deploy.sh against its source.

    The handler loads panel_policy.json, so searching Python source for names
    or models checks a redundant description instead of the deployed input.
    Compare the full agent/rule metadata and the digest of the original policy;
    rule blocking flags, scopes, model settings, additions and removals all
    participate. This is an offline build invariant, not a live AWS policy check.
    """
    dashboard = root / "dashboard" / "app"
    if not dashboard.exists():
        return []  # Guarded artifact repositories need not ship this dashboard.
    rules_file = root / ".reviewer.yaml"
    bundle_file = dashboard / "panel_policy.json"
    fix = "regenerate with .venv/bin/python dashboard/scripts/bundle_policy.py"
    try:
        raw = rules_file.read_bytes()
        cfg = yaml.safe_load(raw)
        bundle = json.loads(bundle_file.read_text())
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"[BLOCKING] cannot validate dashboard policy bundle "
                f"({type(exc).__name__}); {fix}"]
    if not isinstance(cfg, dict) or not isinstance(bundle, dict):
        return [f"[BLOCKING] dashboard policy source/bundle must be objects; {fix}"]
    out = []
    for field in ("agents", "rules"):
        expected = cfg.get(field)
        if not isinstance(expected, list) or not expected:
            out.append(f"[BLOCKING] .reviewer.yaml has no valid {field} metadata")
        elif bundle.get(field) != expected:
            out.append(f"[BLOCKING] dashboard policy bundle {field} differ from "
                       f".reviewer.yaml; {fix}")
    if bundle.get("sha256") != hashlib.sha256(raw).hexdigest():
        out.append(f"[BLOCKING] dashboard policy bundle source digest is stale; {fix}")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Deterministic IaC checks")
    p.add_argument("--templates", required=True, help="glob of CFN/SAM templates")
    p.add_argument("--skip-access-analyzer", action="store_true")
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--repo-root", default=".",
                   help="root for the single-core and panel-mirror invariants")
    p.add_argument("--allow-no-templates", action="store_true",
                   help="a repo that deploys no template (the paved road itself); "
                        "without it, a glob that matches nothing fails")
    args = p.parse_args()

    findings: list[str] = []
    root = pathlib.Path(args.repo_root).resolve()
    findings += check_single_reviewer_core(root)
    findings += check_panel_config_mirror(root)
    client = None if args.skip_access_analyzer else boto3.client(
        "accessanalyzer", region_name=args.region)
    paths = sorted(glob.glob(args.templates, recursive=True))
    if not paths:
        # Nothing scanned is not a pass: a moved or renamed template would
        # otherwise turn this lane green while checking nothing.
        if not args.allow_no_templates:
            findings.append(f"[BLOCKING] no templates matched {args.templates}; "
                            f"pass --allow-no-templates if this repo deploys none")
        blocking = [f for f in findings if "[BLOCKING]" in f]
        for f in findings:
            print(f)
        print(f"DETERMINISTIC LANE: {'FAIL' if blocking else 'PASS'} "
              f"(no templates matched {args.templates}; "
              f"{len(blocking)} blocking / {len(findings)} total)")
        return 1 if blocking else 0
    for path in paths:
        # _CfnLoader subclasses yaml.SafeLoader; it only maps !Ref-style tags to dicts.
        template = yaml.load(pathlib.Path(path).read_text(), Loader=_CfnLoader)  # nosec B506
        findings += [f"{path} :: {m}" for m in check_managed_policies(template or {})]
        findings += [f"{path} :: {m}"
                     for m in check_template_references(template or {}, path, paths)]
        for name, doc, ptype in _iter_policies(template or {}):
            # Every policy gets the wildcard check, even one that JSON cannot
            # encode as-is (an unquoted YAML date such as Version: 2012-10-17).
            findings += [f"{path} :: {m}" for m in check_wildcards(name, doc, template)]
            readable = _as_document(doc)
            if client and readable is not None and ptype:
                findings += [f"{path} :: {m}" for m in
                             check_access_analyzer(name, readable, client, ptype, template)]

    blocking = [f for f in findings if "[BLOCKING]" in f]
    for f in findings:
        print(f)
    print(f"DETERMINISTIC LANE: {'FAIL' if blocking else 'PASS'} "
          f"({len(blocking)} blocking / {len(findings)} total)")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
