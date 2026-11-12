#!/usr/bin/env bash
# Build and deploy the operator dashboard (DashboardStack, plus
# DashboardCertStack in us-east-1 only when a custom domain is given).
#
# The account and Region come from your AWS credentials and configuration
# (cdk sets CDK_DEFAULT_ACCOUNT / CDK_DEFAULT_REGION). Optional settings, as
# environment variables; each becomes the CDK context key named beside it:
#   ARTIFACT_REPO        artifact_repo        OWNER/NAME of the application repo
#   GATES_REPO           gates_repo           OWNER/NAME of this gates repo
#   SITE_URL             site_url             https:// link to the deployed application
#   GH_TOKEN_SECRET      github_token_secret  Secrets Manager secret NAME (read-only GitHub token)
#   AUTH_DOMAIN_PREFIX   auth_domain_prefix   Cognito managed-login domain prefix
#   DASHBOARD_DOMAIN     dashboard_domain     custom domain (needs the next two as well)
#   DASHBOARD_ZONE_ID    dashboard_zone_id    Route 53 hosted zone id
#   DASHBOARD_ZONE_NAME  dashboard_zone_name  Route 53 hosted zone name
# Extra arguments are passed to `cdk deploy`.
set -euo pipefail
cd "$(dirname "$0")"

echo "== build web =="
(cd web && npm ci --no-fund --no-audit && npm run build)

echo "== stage lambda asset =="
../.venv/bin/python scripts/bundle_policy.py
rm -rf infra/.asset && mkdir -p infra/.asset/web
cp app/handler.py app/evidence.py app/health.py app/panel_policy.json infra/.asset/
cp -r web/dist/* infra/.asset/web/

echo "== deploy =="
cd infra
CTX=()
add() {  # add <context key> <value>; empty values are left out
  if [ -n "$2" ]; then CTX+=(-c "$1=$2"); echo "   $1=$2"; fi
}
add artifact_repo "${ARTIFACT_REPO:-}"
add gates_repo "${GATES_REPO:-}"
add site_url "${SITE_URL:-}"
add github_token_secret "${GH_TOKEN_SECRET:-}"
add auth_domain_prefix "${AUTH_DOMAIN_PREFIX:-}"
add dashboard_domain "${DASHBOARD_DOMAIN:-}"
add dashboard_zone_id "${DASHBOARD_ZONE_ID:-}"
add dashboard_zone_name "${DASHBOARD_ZONE_NAME:-}"
[ -n "${GH_TOKEN_SECRET:-}" ] || echo "   github_token_secret=<unset: anonymous GitHub reads>"
npx -y aws-cdk@2.1144.0 deploy --all --require-approval never ${CTX[@]+"${CTX[@]}"} "$@"
