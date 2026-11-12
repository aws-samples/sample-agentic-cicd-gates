"""Tier 1's synth context, refused when it is implicit or partial.

A redeploy that forgets part of the stack's context must stop at synth instead
of quietly changing what the live pipeline does. Before this check a missing
`github_branch` silently became "main", a missing repository or connection
silently switched the source to the CodeCommit demo repository, and a missing
site_* key silently dropped the application's custom domain from every later
release. Kept free of CDK imports so the rules are unit-tested directly.
"""

GITHUB_KEYS = ("github_repo", "connection_arn", "github_branch")
SITE_KEYS = ("site_domain", "site_cert", "site_zone")
KEYS = ("source", *GITHUB_KEYS, *SITE_KEYS)
# deploy_kind=cdk: the dashboard's own context, handed to dashboard/deploy.sh as
# environment variables (context key -> variable name).
DASHBOARD_DOMAIN_KEYS = ("dashboard_domain", "dashboard_zone_id", "dashboard_zone_name")
DASHBOARD_ENV = {
    "artifact_repo": "ARTIFACT_REPO",
    "gates_repo": "GATES_REPO",
    "site_url": "SITE_URL",
    "auth_domain_prefix": "AUTH_DOMAIN_PREFIX",
    "dashboard_domain": "DASHBOARD_DOMAIN",
    "dashboard_zone_id": "DASHBOARD_ZONE_ID",
    "dashboard_zone_name": "DASHBOARD_ZONE_NAME",
}


class ContextError(ValueError):
    """The synth context does not say completely what to deploy."""


def source_kind(context: dict, stack: str = "Tier 1",
                saved: str = "its site_*, dashboard_url and other values") -> str:
    """'github' or 'codecommit'; nothing is chosen by default.

    Tier 2 (tier2-agentcore/infra/tier2_stack.py) applies the same rules and
    names itself and its own saved context in the message.
    """
    choice = str(context.get("source") or "").lower()
    given = [k for k in GITHUB_KEYS if context.get(k)]
    if choice not in ("", "github", "codecommit"):
        raise ContextError(f"-c source={choice}: choose github or codecommit")
    if choice == "codecommit":
        if given:
            raise ContextError("-c source=codecommit cannot be combined with "
                               + ", ".join(f"-c {k}" for k in given))
        return "codecommit"
    if not given:
        raise ContextError(
            f"{stack} has no source context. To update an existing stack, repeat its "
            "complete saved context (-c github_repo=OWNER/REPO -c connection_arn=ARN "
            f"-c github_branch=BRANCH and {saved}; "
            "see deploy/README.md). To create a stack that reads the CodeCommit demo "
            "repository, say so with -c source=codecommit.")
    missing = [k for k in GITHUB_KEYS if not context.get(k)]
    if missing:
        raise ContextError("a GitHub source also needs " + ", ".join(f"-c {k}=..." for k in missing)
                           + "; nothing defaults (a missing branch used to mean main, and a "
                           "missing repository or connection the CodeCommit demo repo)")
    return "github"


def check_site(context: dict) -> None:
    """The application's custom domain takes all three site_* values or none."""
    given = [k for k in SITE_KEYS if context.get(k)]
    if given and len(given) != len(SITE_KEYS):
        missing = [k for k in SITE_KEYS if k not in given]
        raise ContextError("a custom domain also needs "
                           + ", ".join(f"-c {k}=..." for k in missing)
                           + "; without all three the domain would be dropped")


def dashboard_env(context: dict) -> dict:
    """Environment for dashboard/deploy.sh from Tier 1 context; empty values left out.

    `gates_repo` defaults to `github_repo`: with deploy_kind=cdk the pipeline's
    source IS the gates repository. The dashboard's custom domain takes all three
    dashboard_* values or none, like the application's site_* values.
    """
    given = [k for k in DASHBOARD_DOMAIN_KEYS if context.get(k)]
    if given and len(given) != len(DASHBOARD_DOMAIN_KEYS):
        missing = [k for k in DASHBOARD_DOMAIN_KEYS if k not in given]
        raise ContextError("a custom dashboard domain also needs "
                           + ", ".join(f"-c {k}=..." for k in missing))
    values = {k: str(context.get(k) or "").strip() for k in DASHBOARD_ENV}
    if not values["gates_repo"]:
        values["gates_repo"] = str(context.get("github_repo") or "").strip()
    return {DASHBOARD_ENV[k]: v for k, v in values.items() if v}
