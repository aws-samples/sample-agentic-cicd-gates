# Operator dashboard

The dashboard shows one revision's path through the sample's release
pipelines. It reads, from your AWS account:

- CodePipeline state and execution history for the `agentic-gates-*` pipelines
- review findings that Tier 1 writes to its reports bucket
- excerpts of CodeBuild and Lambda logs from the gate projects
- deployment health for the sample application (CodeDeploy, CloudWatch alarms,
  the Lambda alias)

It also reads pull requests and their checks from GitHub.

The full view (`Full dashboard`) also has a Tier 3 column, for a Kiro headless
harness that this release does not include. Without that pipeline, the column
reports it as not found.

**This is restricted content.** Pipeline state, findings and build-log excerpts
can reveal code, configuration and weaknesses. Only the account's operators
should get dashboard users.

## Architecture

```
browser ── CloudFront (security headers; TLS)
             ├── default  → HTTP API $default (public) → Lambda
             │              SPA shell and GET /auth-config
             └── /api*    → HTTP API ANY /api, ANY /api/{proxy+}
                            JWT authorizer (Cognito user pool) → Lambda
                            GET /api/snapshot
browser ── Cognito managed login (password, then required TOTP MFA)
```

- **Amazon Cognito** holds the users. Self sign-up is off, so an administrator
  creates each user. Users sign in with their email address, a password of at
  least 12 characters that uses all character classes, and a code from an
  authenticator app (TOTP). MFA is required. Account recovery is by email.
- The single-page app (SPA) signs in with the **authorization code grant and
  PKCE** through a public app client (no client secret). It keeps only the
  access token and its expiry in `sessionStorage`. Tokens last 60 minutes. The
  SPA discards the ID and refresh tokens that Cognito also returns, so after an
  hour it sends the user through managed login again (which skips the password
  while the managed-login session lasts).
- **Amazon API Gateway (HTTP API)** checks the access token with a JWT
  authorizer on every `/api` route. The issuer is the user pool and the
  audience is the app client. The Lambda function also refuses any `/api`
  request that arrives without verified token claims (HTTP 401), so a route
  misconfiguration fails closed.
- The SPA shell and `GET /auth-config` are public because they carry no
  account data. `/auth-config` returns only the Region, the Cognito domain URL,
  the app client id and the redirect URL.
- **AWS Lambda** (Python) reads the account with a role scoped to the sample's
  resource names. It holds no secrets; an optional read-only GitHub token is
  read from AWS Secrets Manager by name at run time.
- **Amazon CloudFront** serves everything over HTTPS and adds the managed
  security-headers response policy. API responses are not cached. CloudFront
  forwards the `Authorization` header to the API through a cache policy that
  includes it with a zero TTL, and the function marks every API response
  `no-store`.
- The board refreshes by polling `/api/snapshot` every 5 seconds with
  `Authorization: Bearer <access token>`. There is no streaming endpoint,
  because browser `EventSource` cannot send that header and tokens must not
  travel in URLs.

The HTTP API's own `execute-api` URL is also reachable. It enforces the same
JWT authorizer, so it exposes nothing that CloudFront does not.

## Deploy

Prerequisites: AWS credentials for the target account, Node.js 22 or later,
Python 3.12, and a CDK-bootstrapped account and Region
(`npx aws-cdk@2.1144.0 bootstrap`; also bootstrap `us-east-1` if you use a
custom domain). From the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
export AWS_REGION=us-west-2               # the Region of your pipelines
export ARTIFACT_REPO=example-org/sample-agentic-cicd-artifact
export GATES_REPO=example-org/sample-agentic-cicd-gates
bash dashboard/deploy.sh
```

`deploy.sh` builds the web app, stages the Lambda asset and runs `cdk deploy`.
The account and Region come from your credentials and configuration. It turns
these optional environment variables into CDK context:

| Variable | Context key | Meaning |
|---|---|---|
| `ARTIFACT_REPO` | `artifact_repo` | `OWNER/NAME` of the application repository on GitHub. Empty: its PR panel says it is not configured. |
| `GATES_REPO` | `gates_repo` | `OWNER/NAME` of this gates repository on GitHub. |
| `SITE_URL` | `site_url` | `https://` link to the deployed application, shown as **Live site**. |
| `GH_TOKEN_SECRET` | `github_token_secret` | Name of a Secrets Manager secret that holds a read-only GitHub token. Without it the board reads GitHub anonymously, which works for public repositories only. |
| `AUTH_DOMAIN_PREFIX` | `auth_domain_prefix` | Prefix of the Cognito managed-login domain. It must be globally unique. Default: `agentic-gates-dash-<account id>`. |
| `DASHBOARD_DOMAIN` | `dashboard_domain` | Optional custom domain, for example `dashboard.example.com`. |
| `DASHBOARD_ZONE_ID` | `dashboard_zone_id` | Route 53 hosted zone id for that domain. |
| `DASHBOARD_ZONE_NAME` | `dashboard_zone_name` | Route 53 hosted zone name, for example `example.com`. |

Without a custom domain the dashboard uses its CloudFront domain
(`https://dXXXXXXXXXXXXX.cloudfront.net/`). With one, give all three
`DASHBOARD_*` values. The deploy then adds `DashboardCertStack` in `us-east-1`
for the certificate (CloudFront requires that Region) and an alias record in
your hosted zone. The Cognito callback and sign-out URLs follow the dashboard
URL either way.

The stack outputs `DashboardUrl`, `UserPoolId` and `SignInDomain`.

Tier 1 can deploy the dashboard as its release (`deploy_kind=cdk`). It passes
the same context keys from its own context to `deploy.sh` as the variables
above; see [deploy/README.md](../deploy/README.md).

## Create the first user

Self sign-up is off. Create each operator as an administrator:

```bash
POOL_ID=$(aws cloudformation describe-stacks --stack-name DashboardStack \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)
aws cognito-idp admin-create-user --user-pool-id "$POOL_ID" \
  --username operator@example.com \
  --user-attributes Name=email,Value=operator@example.com Name=email_verified,Value=true \
  --desired-delivery-mediums EMAIL
```

Cognito emails a temporary password, valid for three days. Open `DashboardUrl`,
sign in, and set a new password. Managed login then shows a QR code: add it to
an authenticator app and enter the code it shows. Every later sign-in asks for
a code. Remove access with `aws cognito-idp admin-disable-user` or
`admin-delete-user`. If a user loses their authenticator, delete and recreate
the user; Cognito has no administrator action that resets TOTP.

## Security notes

- Give users only to people who operate the account.
- For internet-facing use, attach an AWS WAF web ACL to the CloudFront
  distribution (for example the AWS managed common rule set and a rate-based
  rule). This sample does not create one.
- MFA is required. Keep it required when you adapt the stack: with optional
  MFA, managed login never prompts users to set it up, and this app has no
  setup screen of its own.
- The user pool is retained when you delete the stack, so users are not lost
  by accident. Delete it yourself when you no longer need it.
- Cognito's default email sender has a low daily limit. Configure Amazon SES
  for the user pool if you create many users.

## Views

The root URL opens the presenter overview. Use `?present=0` for the full
dashboard, `focus=pr` or `focus=release` for a focused view, and `stage=1`
for enlarged PR presentation. Stage has an Exit link and supports Escape.
Both views preserve selections when switching between them. **Sign out**
clears the stored token and ends the Cognito session.

`repo=artifact|road`, `commit=<sha>`, `execution=<pipeline-execution-id>`,
`pr=<number>`, and `closed=1` compose with these views. A revision selects its
newest execution; an execution ID pins that specific run, including an older
run of the same revision. `review=<review-id>` selects a published PR report.
`review_build=<CodeBuild-build-id>` selects a review attempt inside the selected
pipeline execution. The interface clears incompatible selectors when switching
repository, revision, PR, or execution. These parameters survive the sign-in
round trip.

The main flow is the selected repository's **Tier 1 CodeBuild pipeline**.
GitHub PR reviews are shown beside it with their own head revision. PR reporting
is explicitly distinguished from deployment enforcement; this UI does not
assert that GitHub branch protection is configured. The health panel reads
execution-bound deployment and rollback evidence and separately labels current
alarm and alias observations. Unavailable or expired evidence remains explicit.

## Inspect a failed review after a later pass

1. Select the PR, including closed PRs when needed. Its current-head result
   remains separate from historical reports.
2. Expand **Review history** and choose the earlier failed report. Inspect its
   head SHA, workflow attempt, submitted time, GitHub state, complete findings
   and error detail. **Source report** contains the full published text,
   including continuation parts and suggested code.
3. Choose the later passing report. The earlier failure remains in history.
   A dismissed GitHub review retains its original verdict and explanation.
4. For pipeline reviews, choose **Pipeline execution**, expand **Review
   attempts**, and select the relevant build. Earlier failed attempts stay
   distinct from the current report, including retries inside one execution.

Long reports have keyboard-focusable scroll regions in both views. Stage does
not hide expanded explanations. Deep links preserve the selected report or
build. Missing parts, retrieval errors and unknown IDs do not substitute a
different report or turn missing evidence into PASS.

## Evidence contract

- Pipeline actions, failures and CodeBuild logs belong to one pipeline execution.
  A revision absent from retained history never falls back to another revision.
  Revision selection resolves the newest execution of that SHA, including retries.
- Tier 1 writes a separate
  `executions/<pipeline-execution-id>/builds/<CodeBuild-build-id>/findings.json`
  archive before updating the execution/SHA convenience keys and returning the
  gate result. Conditional writes prevent the uploader from replacing an
  existing attempt. These reports remain subject to the configured retention
  policy; this is not S3 Object Lock or a promise against administrative deletion.
- The reader prefers that exact build archive. The mutable execution convenience
  key requires affirmative matching build identity. SHA-only reports cannot
  identify an attempt and are not used as historical proof.
  Contradictory execution/build metadata or `review_input.head_revision` is
  rejected. The actual policy digest and baseline remain in `review_evidence`.
- If a Tier 1 S3 report is missing, unavailable, or unbound, the exact action's
  CodeBuild stream can recover the aggregate report printed by `review_cli.py`.
  Pretty JSON spanning multiple log events/pages is supported. There is no
  moving one-hour or 30-day cutoff on exact-stream reads.
- Tier 3 reads only the selected action's CodeBuild stream. Tier 2's shared
  Lambda logs must carry matching execution/build provenance; a time window
  alone is insufficient. Old unbound Lambda reports remain unavailable.
- `review_evidence` distinguishes `passed`, `blocked`, `blocked_error`,
  `reviewing`, `not_reviewed`, `missing`, `unavailable`, and `expired`.
  `expired` requires an explicit elapsed `expires_at`; neither a 403 nor an
  absent object proves expiry. Retrieval/page-limit failures never imply PASS.
- `execution_started` dates the run. The browser's received timestamp dates the
  connection data. Current PR reviews are restricted to the selected head and
  latest verified workflow attempt. Queued reruns invalidate old same-head
  current reviews but leave them in history.
- Published PR history requires the configured publisher identity and a matching
  v2 repository/PR/reviewer/head/run/attempt marker. Parts are joined without
  truncating findings. Unmarked legacy or unverified-author reports are not
  promoted to trusted reports. Incomplete marked reports remain inspectable with
  missing/unavailable publication evidence.
- A requested build must belong to a real Review action of the selected primary
  execution before any archive or log read. Exact execution selection does not
  imply an exact corresponding attempt in the independent Tier 2/3 pipelines.

## Execution-bound health evidence

The presenter view reads the selected application deployment's CodeDeploy and
CloudWatch evidence. A candidate is identified by the selected CloudFormation
action interval, application/deployment group, Lambda alias and the candidate
version's `DEMO_REVISION`. Missing or ambiguous identity stays unavailable. A
candidate rejected before deployment is **Not reached**, not a missing alarm.

The expanded health panel separates historical deployment/rollback results from
the alarm and live alias observed now. A green alarm today does not prove an old
deployment was healthy. Alarm history is scoped to the selected action interval;
CodeDeploy's explicit rollback relationship identifies its recovery. Lambda
rollback target metadata retains the failed AppSpec's version pair, so the
restoration target is the original deployment's current version, not the
rollback record's misleading `targetVersion`.

The dashboard has read-only access to the sample application stack's resources,
its alarm, function alias/version configuration and CodeDeploy
application/group. Historical CloudWatch transitions have a retention limit and
are not reconstructed from today's alarm state.

## Local validation (no AWS or model calls)

From the repository root:

```sh
.venv/bin/python dashboard/scripts/bundle_policy.py
.venv/bin/python -m pytest dashboard/tests -q
node --experimental-strip-types --test dashboard/tests/state.test.ts
npm --prefix dashboard/web ci && npm --prefix dashboard/web run build
```

`dashboard/tests/test_auth.py` checks that the handler answers 401 without
verified token claims, and synthesizes the stacks to check that every `/api`
route requires the JWT authorizer.

Browser regression (Playwright CLI installed):

```sh
npm --prefix dashboard/web run dev -- --host 127.0.0.1 --port 5178
# Separate shell, from dashboard/tests:
playwright-cli -s=dashboard-worker open about:blank --browser=chrome
playwright-cli -s=dashboard-worker run-code --filename=browser-check.js
playwright-cli -s=dashboard-worker run-code --filename=browser-history-check.js
playwright-cli -s=dashboard-worker close
```

Browser checks use clearly labeled **local test fixtures**. They mock
`/auth-config` and `/api/snapshot`, store a fixture access token, and check that
every snapshot request carries it. They exercise 1920×1080 plus a narrower
viewport, deep links, view switching, polling refreshes and missing, expired or
blocked evidence. Screenshots are QA artifacts, not evidence of real GitHub or
AWS results.
