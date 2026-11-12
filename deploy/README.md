# Deploy the sample in your own account

Start with **Tier 1 CodeBuild and the GitHub PR workflow**. Tier 2 is an
optional review-execution alternative, not additional release stages. These
instructions describe the current CDK source; successful deployment of v2 must
be verified in your account.

## Prerequisites and source selection

Use Python 3.12, Node.js/npm, AWS CLI credentials for the intended account, and a
CDK-bootstrapped environment. The checked-in CDK entrypoints select **us-west-2**;
changing only `AWS_REGION` does not port the stacks. Verify model/profile access
for your approved `.reviewer.yaml` and the matching IAM permissions. Model IDs in
the sample are configuration examples, not an availability promise.

For the SAM application path, the source repository needs `template.yaml`, its
application files, `tests/`, `.reviewer.yaml`, `threat-model/app.tc.json` and
`threat-model/boundaries.yaml`. The companion `sample-agentic-cicd-artifact`
repository has that shape; this gates repository does not have a root SAM app.
Use your own copy of the artifact repository, or another repository you are
authorized to deploy.

Choose one source:

- **GitHub:** create and authorize a CodeConnections connection for your source
  repository. Supply **both** `github_repo` and `connection_arn`, plus
  `github_branch` for Tier 1. The action supplies a full Git clone.
- **CodeCommit:** omit every GitHub flag and pass `-c source=codecommit`.
  Tier 1 creates
  `agentic-gates-demo<name_suffix>` and reads `main` with full-clone output. Seed
  it with your approved artifact source after inspecting the stack's
  `RepoCloneUrlHttp` output.

CodeCommit returned to full General Availability and reopened to new customers
on **2025-11-24** ([AWS announcement](https://aws.amazon.com/blogs/devops/aws-codecommit-returns-to-general-availability/)).
It is a supported source option. No roadmap feature is required for this sample.
The stack currently creates its CodeCommit repository even when GitHub is selected.

## Primary path: CDK with complete context

From your gates checkout, prepare the pinned Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# With credentials already selected for your intended account:
aws sts get-caller-identity
npx -y aws-cdk@2.1144.0 bootstrap aws://YOUR_ACCOUNT_ID/us-west-2
```

Use Bash for the array below. Set `TARGET_REPO`, `CONNECTION_ARN`, `SOURCE_BRANCH`
and `APPROVED_POLICY` in your shell first; the policy path must be absolute.
Set `SITE_DOMAIN`, `SITE_ZONE`, `SITE_CERT` and `DASHBOARD_URL` to your own values
if used. For a new stack without custom endpoints, leave those four unset.
For an existing stack, preserve its exact source, identity and optional settings.

```bash
# From the gates repository root, in Bash:
: "${TARGET_REPO:?Set owner/repository for your artifact source}"
: "${CONNECTION_ARN:?Set your authorized CodeConnections ARN}"
: "${SOURCE_BRANCH:?Set the source branch}"
: "${APPROVED_POLICY:?Set an absolute path to the approved reviewer policy}"
CTX=(
  -c stack_id=Tier1PipelineStack
  -c name_suffix=
  -c deploy_kind=sam
  -c "github_repo=$TARGET_REPO"
  -c "connection_arn=$CONNECTION_ARN"
  -c "github_branch=$SOURCE_BRANCH"
  -c "review_policy_file=$APPROVED_POLICY"
  -c report_retention_days=120
  -c "site_domain=${SITE_DOMAIN:-}"
  -c "site_zone=${SITE_ZONE:-}"
  -c "site_cert=${SITE_CERT:-}"
  -c "dashboard_url=${DASHBOARD_URL:-}"
)
cd tier1-codebuild
# --method template compares templates with the read-only lookup role. A plain
# `cdk diff` defaults to --method auto, which creates a CloudFormation change
# set with the deploy role, so it is not read-only.
npx -y aws-cdk@2.1144.0 diff Tier1PipelineStack --method template "${CTX[@]}"
# Inspect the diff, IAM and asset changes before deploying:
npx -y aws-cdk@2.1144.0 deploy Tier1PipelineStack "${CTX[@]}"
```

For CodeCommit, replace the three GitHub source entries and their shell checks
with `-c source=codecommit`; the source branch is fixed to `main`. Keep the
remaining context. For additional stack instances, change both the command's
stack ID and `stack_id`, and give `name_suffix` a distinct value.

Synth refuses implicit or partial context
([`tier1-codebuild/deploy_context.py`](../tier1-codebuild/deploy_context.py)), so
a redeploy that forgets a flag stops instead of changing the live pipeline: a
GitHub source needs all of `github_repo`, `connection_arn` and `github_branch`
(no branch defaults to `main`); a custom domain needs all three `site_*` values;
and a stack with no source context stops instead of selecting CodeCommit. For an
existing stack, the diff must show only the changes you intend. A change to gate
tooling alone (`agent/`, `pipeline_tools/`, `threat-model/`, `deterministic/` or
a buildspec) shows up only in the CodeBuild projects and, for each changed
asset, in its `<asset>Version` custom resource (for example
`AgentPackageVersion`), which is replaced to pin the new version. A review policy
change shows up the same way, in `ReviewPolicyVersion`. If the `Pipeline`
resource or an IAM resource appears too, stop and find out why before deploying.
One expected IAM change: a `deploy_kind=none` trio deployed before gate-only
trios stopped getting a deploy role shows its unused `AppDeployRole` and that
role's policy being deleted. No Deploy stage ever used that role.

Custom domains map to the application's `DomainName`, `HostedZoneId` and
`CertificateArn` parameters. CloudFront's certificate must be in **us-east-1**.
Supply domain, zone and certificate together when using a custom domain.
An empty `dashboard_url` leaves the approval link pointing to the S3 report.
`review_policy_file` defaults to this checkout's `../.reviewer.yaml` from the CDK
app directory. The explicit flag makes the deployed policy choice reviewable.
Policy/tool changes require a separate pipeline deployment; a source commit alone
does not update deployed gate assets.

The deployment pins every S3 asset the gate builds fetch: the review policy and
the agent, review-input, deterministic and threat-model packages. For each, it
records the uploaded object's S3 version and a SHA-256 of its content in the
CodeBuild projects that fetch it (`<NAME>_VERSION` and `<NAME>_SHA256`, for
example `REVIEW_POLICY_VERSION`). The policy is hashed as a file. A package is
zipped only at publish time, so it is hashed as a tree after unzip: the SHA-256
of the `sha256sum` lines for all its files. Each build fetches exactly the
pinned version and stops on a missing version, a failed read or a hash
mismatch, before anything from the asset runs. The objects are in the CDK
bootstrap asset bucket, and the default `cdk bootstrap` template turns on
versioning there; without versioning there is no version to pin, and the deploy
or the build stops. A later write to the same key does not change the pinned
version. A pin moves only when its custom resource runs again: new asset
content, a new `pin_refresh` value (below), or a CDK upgrade that changes the
custom-resource provider. Each time, the hash still guards the bytes.

**Re-pin after a pinned version is gone.** The bootstrap bucket expires
noncurrent object versions (after 30 days in the current bootstrap template). A
pinned version becomes noncurrent only when someone overwrites or deletes its
key; `cdk deploy` does neither, because each key is a hash of the content. So a
build that stops with `NoSuchVersion` means something wrote the bucket: find out
what first. Then re-pin with unchanged rules and tooling:

1. Check the key named in the build's environment:
   `aws s3api head-object --bucket <asset bucket> --key <key>`. If the key is
   gone, the next `cdk deploy` uploads it again. If the key exists but builds
   stop on the hash, its current version holds other bytes, and `cdk deploy`
   will not replace them: cdk-assets checks only that the key exists. Save a copy
   for the investigation, then delete that version:
   `aws s3api delete-object --bucket <asset bucket> --key <key> --version-id <its VersionId>`.
   Check again: an earlier version with the synthesized bytes is now current, or
   the key is gone and the next deploy uploads it.
2. Add `-c pin_refresh=<new value>` (letters, digits, `.`, `_` or `-`; today's
   date works) to the stack's complete saved context, then run `cdk diff` and
   `cdk deploy` as above. Every asset's `<asset>Version` custom resource reads
   the current version again.
3. Keep the value in the saved context. Changing or dropping it later re-pins
   again, which is harmless.

Re-pinning cannot make a build accept other bytes: if the current object is not
what was synthesized, the hash check still stops the build. The stack does not
re-pin on every deploy, because that would make every `cdk diff` show a change.
It does not change the expiry rule either: that rule belongs to the account's
bootstrap stack, which every CDK app in the account shares.

Tier 1's review compares the candidate with the last successful pipeline release
completed before the current execution began. With no prior success it uses an
[approved starting commit](#approved-starting-commit) if one is stored, and
otherwise reviews the full tree. Failures do not advance that release baseline.
Missing history/revisions, identity mismatch, a malformed approval file or a diff
above 3,000,000 UTF-8 bytes stops preparation.

A diff larger than one 100,000-byte review chunk is reviewed in chunks, never
truncated. `prepare_review.py` splits it into whole file sections in diff order
(an oversized file into whole hunks, an oversized hunk at line boundaries with
recomputed `@@` headers) and writes `chunk-plan.json`. `review_cli.py`
re-verifies that the plan reproduces the diff, runs every seat over every chunk
in its scope with the unchanged two-stage review, and folds each seat back into
one verdict: a blocking finding in any chunk fails; an error, truncation,
timeout or unreviewed chunk is the seat's error verdict (BLOCKED_ERROR for a
seat that owns blocking rules); a plan that fails verification is BLOCKED_ERROR.
A chunk whose review ended in an error (never FAIL) is reviewed once more while
the deadline allows; its row records both attempts.
Chunks run on 8 worker threads under an 82-minute deadline inside the Review
action's 90-minute timeout; the advisory STRIDE pass runs per chunk under a
12-minute deadline inside the ThreatModel action's 20-minute timeout. The
arithmetic is in `tier1-codebuild/tier1_stack.py`.

A chunked PASS means every chunk passed on its own; the report's
`chunking.note` says so. A flow from a source in one chunk to a sink in another
is not traced, and the 25-finding cap applies per chunk call. Deltas of 100,001
to 400,000 bytes, which used to get one call per seat, are now chunked too.

Before writing any input, `prepare_review.py` also stops the gate when bytes
would not all reach a reviewer: the rendered diff must match git's own list of
changed files, file for file and in order; a carriage return inside a line is
refused; a change to any `.gitattributes` file is refused; and a file that git
renders only as `Binary files ... differ` must be a deletion or an image, web
font or MP3 (`BINARY_EXTENSIONS`). The remaining binary files, which no model
reads, are listed with their sizes in `review_input.chunk_plan.binary_sections`
of `findings.json`.

To see a candidate's plan without any AWS or model call:

```bash
python pipeline_tools/prepare_review.py --dry-run --repo ARTIFACT_CHECKOUT \
  --base LAST_RELEASED_SHA --head HEAD --rules .reviewer.yaml --output /tmp/review-input-dry-run
(cd agent && python review_cli.py --dry-run --diff /tmp/review-input-dry-run/change.diff \
  --rules ../.reviewer.yaml --chunk-plan /tmp/review-input-dry-run/chunk-plan.json) \
  > /tmp/review-input-dry-run/schedule.json
```

Before approving, check the execution's `findings.json` against that dry run.
The check is read-only and prints `EVIDENCE: PASS` only for a complete PASS
over exactly the expected range, plan, policy and binary files:

```bash
python pipeline_tools/check_evidence.py --findings findings.json \
  --dry-run /tmp/review-input-dry-run --schedule /tmp/review-input-dry-run/schedule.json \
  --rules .reviewer.yaml --baseline LAST_RELEASED_SHA --head CANDIDATE_SHA \
  --expect-binary PATH_OF_EACH_EXPECTED_BINARY
```

## Approved starting commit

Tier 1 normally compares a candidate with its last successful release. Without
one it reviews the whole tree, and a tree above 3,000,000 bytes stops the gate
before any model call. An approved starting commit gives the gate a reviewed
point to compare with instead.

Use it when:

- the first release of a codebase is larger than the review limit;
- the pipeline has run but its history has no successful release;
- the last success is older than CodePipeline's 12-month execution history, so
  the gate would otherwise fall back to a full-tree review again.

The approval is a trust decision made by people, not a PASS. The gate records it
in `review_input` of `findings.json` and in the approval prompt
(`Compared with: approved_baseline`). Only the change since that commit is
reviewed; the commit itself is not reviewed again by the gate.

### Procedure

1. Pick the commit. It must be on the branch the pipeline builds: the gate refuses
   a commit that is not the candidate or one of its ancestors. Do not pick the
   revision that is failing review just to get past the gate.
2. Review the whole repository at that commit once, outside the gate, with the
   same rules (the deployed `review_policy_file`). For example, run Tier 1's own
   tooling from the empty tree in chunks, or a human review against the same rules.
3. Someone other than the author of that code approves the review.
4. Put every finding in a backlog with an owner. The approval does not make
   findings go away.
5. Write the approval file. Exactly these keys, nothing else, at most 16 KB:

   ```json
   {
     "version": 1,
     "commit": "<40-character lowercase commit SHA>",
     "approved_by": "<who approved>",
     "approved_at": "2026-10-31T09:00:00Z",
     "reviewed": "<what was reviewed and where, for example a link to the review>"
   }
   ```

   `approved_at` is UTC and ends in `Z`. A missing, empty or unknown key, another
   `version`, a short or upper-case SHA, or a file that is not JSON stops the gate.
6. Upload it create-only to the stack's `BaselineBucketName` output:

   ```bash
   aws s3api put-object --bucket <BaselineBucket> --key approved-baseline.json \
     --body approved-baseline.json --if-none-match '*'
   ```

   Record the commit, the returned `VersionId` and the file's SHA-256
   (`shasum -a 256 approved-baseline.json`) in your change record.
7. Retry the blocked execution. Keep the failed run as evidence.

To replace the file later, upload a new version only over the one you checked:

```bash
aws s3api head-object --bucket <BaselineBucket> --key approved-baseline.json   # note the ETag
aws s3api put-object --bucket <BaselineBucket> --key approved-baseline.json \
  --body approved-baseline.json --if-match '<current ETag>'
```

The bucket is versioned, so every version is kept; replaced versions expire
after 365 days. The bucket is retained when the stack is deleted.

### Who can write it

Only release approvers should be able to write `approved-baseline.json`. The
pipeline only reads it: the Review and ThreatModel roles may get that one object
and check whether it exists, and nothing else in the bucket. Grant write access in
your own IAM or bucket policy; the stack grants none.

### Which baseline the gate uses

1. The last successful release in the pipeline history, as before. If an approval
   file exists, the gate records `approved_baseline_used: false` and the file's
   hash and version, and does not use it.
2. Only when the history has no eligible successful release: the approved
   starting commit. `baseline_kind` is `approved_baseline`, and `review_input`
   records `approved_by`, `approved_at`, `reviewed`, `approval_sha256` and
   `approval_version_id`. The commit must exist in the repository and be the
   candidate or an ancestor of it; otherwise the gate stops.
3. Otherwise the full tree, as before.

If the object does not exist, the gate goes on without it. Any other read error,
such as access denied or a missing bucket, stops the gate.
`check_evidence.py` accepts only `last_successful_release`, so it refuses
evidence from a run compared with an approved starting commit; check that run's
`review_input` by hand against your change record.

## Other deployment modes and alternatives

| Choice | Context and scope |
|---|---|
| SAM application (primary) | `deploy_kind=sam`: review, deterministic, threat-model, unit tests and package; approval; native CloudFormation change-set actions; artifact's CodeDeploy canary |
| Gates only | `deploy_kind=none` (legacy `gate_only` also works): no approval or deploy stage |
| Framework dashboard | `deploy_kind=cdk`, with this gates repository as the source: after approval, a CodeBuild action runs `dashboard/deploy.sh` (`cdk deploy`). Optional context, passed to the script as environment variables: `artifact_repo`, `gates_repo` (defaults to `github_repo`), `site_url`, `github_token_secret`, `auth_domain_prefix`, and `dashboard_domain` + `dashboard_zone_id` + `dashboard_zone_name` together or not at all. See [dashboard/README.md](../dashboard/README.md). This trio deploys CDK apps and has no `template.yaml`, so its deterministic lane runs only the repository checks (`--allow-no-templates`) |
| AgentCore reviewer | Separate Tier 2 review-only pipeline; runtime image and gate Lambda must be deployed together; explicit baseline initialization required |

Optional GitHub-source examples, from the gates root with the variables above:

```bash
# Tier 2 takes Tier 1's source keys and refuses partial context the same way.
# Set TIER2_BRANCH to the branch its pipeline reads; diff with the same flags first.
T2=(-c stack_id=Tier2PipelineStack -c name_suffix= -c "github_repo=$TARGET_REPO"
    -c "connection_arn=$CONNECTION_ARN" -c "github_branch=${TIER2_BRANCH:?}")
(cd tier2-agentcore/infra && CDK_DOCKER=finch npx -y aws-cdk@2.1144.0 diff Tier2PipelineStack \
  --method template "${T2[@]}")
(cd tier2-agentcore/infra && CDK_DOCKER=finch npx -y aws-cdk@2.1144.0 deploy Tier2PipelineStack \
  "${T2[@]}")

```

Tier 2 imports Tier 1's CodeCommit repository identity; deploy the matching Tier 1
stack first and preserve matching suffixes if used. Like Tier 1, its synth stops
for a GitHub source without all of `github_repo`, `connection_arn` and
`github_branch`, and for a stack with no source context (`-c source=codecommit`
selects the demo repo, on `main`). Its ARM64 bundling requires Docker-compatible
tooling (`CDK_DOCKER=finch` is supported). A tooling-only Tier 2 update should
change only the gate function's code and the runtime's container image; if the
`Pipeline` or an IAM resource appears in the diff, find out why first. Before the
first review, follow the [Tier 2 initialization
procedure](../tier2-agentcore/README.md): archive an independently approved
commit, record its SHA/hash/approval, and create-only upload the baseline. Missing
state blocks; seeding is not a PASS. Audit pre-v2 state because the old handler
could have advanced it after rejection, and record what its history never
reviewed. After each deploy, run the zero-model smoke check
(`tier2-agentcore/runtime/smoke.py`) before pushing to the source branch. To roll
back, revert the runtime image only (`tier2-agentcore/infra/runtime_rollback.py`)
or stop the gate stage's inbound transition; never restore a pre-v2 template while
a delta is waiting for review ([Rolling back a
deploy](../tier2-agentcore/README.md#rolling-back-a-deploy)).

## CloudFormation template status

For template review, run `cdk synth` from `tier1-codebuild` with the **same complete
context array** used for deployment. The offline tests synthesize Tier 1 for each
`deploy_kind` and run `deterministic/checks.py` on the result. They accept one
finding: `AppDeployRole` (`sam` only) manages CloudFront distributions and cache
policies on `distribution/*` and `cache-policy/*`, because CloudFront picks each ID
when it creates the resource. CDK deployment publishes the referenced
assets. A standalone CloudFormation deployment requires publishing the exact
cloud assembly's assets and using its matching generated template; the old
`cdk publish-assets` example is not a valid sample setup command.

## PR workflow and deployment boundaries

Follow [the PR setup guide](../pr-surface/README.md), using the current
[`.github/workflows/agentic-review.yml`](../.github/workflows/agentic-review.yml)
and the companion artifact's v2 `.github` workflow. The legacy
`pr-surface/agentic-review.yml` is not compatible with the v2 runner interface.
The checks report results. Your repository needs verified rulesets, human
review, protected tooling and restricted OIDC trust before those checks can be
described as merge enforcement.

Inspect IAM before adoption. The SAM change-set action runs as `AppDeployRole`,
scoped to the resources the artifact's `template.yaml` creates; extend it if you
change that template. The PR role trusts only pull-request runs of the
repositories you pass with `-c repo=`. Deterministic scanning still has documented
advisory/unavailable paths. These sample choices are not a production-hardening
certification.

## Cost, retention and teardown

See [cost accounting](../docs/cost.md) for dated evaluation evidence and the
services to include. The report bucket defaults to a **120-day lifecycle**, but
destroying the stack uses `DESTROY` and automatic object deletion. Export needed
evidence first; lifecycle retention is not protection from stack deletion.
The Tier 1 baseline bucket (`BaselineBucketName`) is retained on stack deletion
because it holds approval records; delete it yourself when you no longer need them.

When intentionally removing your own installation, inspect the actual stack IDs,
reuse their synth context, and remove optional Tier 2/3 stacks before Tier 1.
The SAM application stack (`agentic-gates-demo-app<suffix>`) is created by the
pipeline and must be deleted separately. Inspect retained source repositories,
logs, ECR images, bootstrap assets, domains and separately
provisioned secrets for your chosen cleanup policy. `make destroy` is not complete
teardown.
