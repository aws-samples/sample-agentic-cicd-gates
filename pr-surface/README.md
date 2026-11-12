# GitHub pull-request reviews

The v2 PR flow reports specialist findings where developers review code. Its
checks report results. A red check or
`REQUEST_CHANGES` review is not proof that merging is prevented; protection and
bypass behavior must be verified on the actual destination repository.

## Authoritative workflow and setup

The implementation is [`.github/workflows/agentic-review.yml`](../.github/workflows/agentic-review.yml)
for this gates repository, plus `.github/workflows/agentic-review.yml` in the
companion `sample-agentic-cicd-artifact` checkout. Both v2
workflows target `main`; choose explicit release branches when adapting them.

1. Select the correct v2 workflow for the repository layout. This repository uses
   `agent/reviewer` and `pr-surface/pr-reviewer/review_pr.py`; the artifact uses
   a generated `pr-reviewer/` bundle and its base-branch vendor verifier.
2. Review and stage the complete v2 tooling and approved `.reviewer.yaml` on the
   trusted PR **base branch** before opening feature PRs. The guard
   requires `WORKFLOW_CONTRACT = 2`; it never falls back to head tooling. Bootstrap
   and `.github/` changes require separate maintainer handling.
3. For an external artifact repository, run `scripts/vendor_reviewer.sh` from an
   approved gates checkout. Inspect its generated manifest and destination policy
   before accepting them; the script replaces `.reviewer.yaml`. Keep the artifact's
   own threat-model data, boundary policy and vendor verifier.
4. Provision/review the OIDC role and set the repository variable
   `REVIEWER_ROLE_ARN`. With the root Python virtualenv prepared, an explicit
   repository selection avoids inheriting the auth stack's demo defaults:

   ```bash
   : "${TARGET_REPO:?Set owner/repository}"
   (cd pr-surface/infra && npx -y aws-cdk@2.1144.0 deploy PrReviewerAuthStack \
     -c "repo=$TARGET_REPO")
   # Set REVIEWER_ROLE_ARN from the inspected ReviewerRoleArn stack output:
   : "${REVIEWER_ROLE_ARN:?Set the role ARN for this repository}"
   gh variable set REVIEWER_ROLE_ARN --repo "$TARGET_REPO" --body "$REVIEWER_ROLE_ARN"
   ```

   The role stack creates a GitHub OIDC provider; reconcile an existing provider
   before deploying into an account that already has one. Current trust patterns
   cover repository workflow contexts, not only this review workflow. The role's
   Bedrock resources cover Anthropic/OpenAI profiles and models; Access Analyzer
   is region-conditioned to `us-west-2`. Verify access for the selected models and
   repository review-writing settings. No static AWS keys are needed.
5. Run a same-repository feature PR after bootstrap. Inspect the exact base/head
   SHA, workflow run/attempt, retained report, reviewer comments and check results.
   Apply and verify merge protection separately before calling the checks required.

## Execution and credential boundaries

| Job | What it does |
|---|---|
| `guard` | Rejects credentialed fork review, invalid/stale PR identity, unauthorized original/rerun actors, `.github/` changes, symlinks and submodules. Uses immutable base tooling. |
| `analyze` | Runs base reviewer code and rules against the base-to-head merge-base diff. Bedrock access through an OIDC session; no GitHub write token. |
| `review` | Downloads only the trusted analysis job's immutable artifact ID; validates identity, policy and complete reviewer set; recomputes verdicts and publishes. No AWS/OIDC permission, head checkout or model invocation. |
| `deterministic` | Runs base checker tooling on head data, with an Access Analyzer-only session policy. |
| `threat-model` | Runs the base validator and boundary policy against the head threat model and merge-base changed-file list. No model credentials or advisory STRIDE invocation in these v2 PR workflows. |
| Artifact `tests` only | Runs exact-head Python unit tests on a separate fresh runner with read-only contents, no AWS/write credentials and no artifact handoff to the publisher. |

Base tooling and head data are sibling directories; Python runs isolated with
`-I`, and checkouts do not persist credentials. Reports bind repository, PR,
base/head SHAs, run ID/attempt, policy digest, configured reviewers, findings,
counts and errors. The `review` job fails for missing/malformed/stale evidence,
failed guard/analysis, publication failures and blocking verdicts. Infrastructure
failure before report creation remains unavailable evidence, not an empty PASS.

The workflow definition itself comes from `pull_request` context. A same-repository
writer who can replace that workflow can remove an in-workflow guard. Base-ref
loading therefore needs protected workflow/tooling changes and restricted IAM
trust; it does not supply those controls by itself. Credentialed fork review and
`merge_group` are not implemented. Artifact unit tests can run on forks with their
reduced permissions.

## Reviewer output and errors

Reviewers, model settings, thinking presets, rule prefixes and optional input
`file_patterns` come from the base `.reviewer.yaml`. The current Security and
Accessibility scopes include blocking rules; Code Quality and Architecture rules
are advisory. The Bedrock adapter tries a second thinking format only when a
model rejects the first, at the same level and token room. It never retries
with less reasoning after an empty answer: that seat fails by its `fail_mode`.
The report labels thinking as configured.
The [strict findings contract](../agent/README.md) rejects unknown
rules, malformed values and out-of-scope findings. Confidence filtering and
rule metadata determine the verdict, but probabilistic findings and scores can
still miss or misclassify defects.

- `PASS` and advisory results publish `COMMENT`; the bot never sends `APPROVE`.
- `FAIL` and `BLOCKED_ERROR` publish `REQUEST_CHANGES` and fail the check.
- Advisory-only errors remain `ADVISORY_ERROR` under open error policy. They are
  incomplete reviews, not PASS, and cannot dismiss an earlier block.
- Each reviewer publishes complete findings in the review body. Up to 20 eligible
  findings also receive inline comments. A GitHub 422 retries body-only; long
  reports use continuation reviews without dropping findings.
- A completed PASS can dismiss only older blocks carrying this bot's verified
  identity and exact v2 repository/PR/reviewer marker. Human objections, other
  reviewers and unmarked legacy reviews remain. Current SHAs are rechecked around
  writes, but GitHub provides no atomic compare-and-swap for dismissal.

Input/report limits are 1 MB/2 MB, with finite history/API/job bounds. Exceeding
those limits errors rather than truncating evidence into PASS. Analysis artifacts
are retained for **seven days**; this is not immutable long-term audit storage.
Rendered-output filtering is best-effort and does not replace secret scanning.

## Coverage differs by repository and execution path

The gates workflow's deterministic job checks repository invariants; there is no
root deployed template and no cfn-guard step. The artifact workflow checks its
SAM template and uses a checksum-verified cfn-guard 3.2.1 release; download,
extraction and validation errors fail that check. Access Analyzer validates each
policy with its deploy-time values replaced by placeholders; an Access Analyzer
error, or a value the lane cannot resolve, blocks. Neither PR workflow
runs Inspector SBOM scanning; that remains best-effort on Tier 1. Dependency-alert
settings require separate repository configuration.

Tier 1 uses deployment-pinned reviewer policy and a last-successful-release delta.
PR review uses immutable event **base-SHA policy/tooling** and a merge-base diff.
The threat-model check detects declared coverage/staleness, not semantic
completeness. These paths complement each other; they are not full-gate parity.

## Make the checks required in your repository

The workflow reports results; it does not make them required. Configure and
verify protection on your own repository. Public visibility alone establishes
no control.

- Require `review`, `deterministic` and `threat-model`; also require `tests` for
  the artifact. Verify actual check contexts and their source app. Prefer an
  organization-controlled required workflow where available.
- Require independent human approval and ownership review for workflows, reviewer
  code/rules, manifests, checks, threat-model policy and ownership configuration.
  Restrict direct pushes, force pushes, deletion and bypasses; invalidate stale
  approvals. Do not give the review bot merge or release authority.
- Keep workflow tokens read-only by default, fork secrets/write-token forwarding
  disabled, and OIDC trust scoped to the approved repository and trusted workflow
  context. Review the supplied broad repository subject patterns before reuse.
- Verify failing findings/tests, model errors, missing/malformed reports, a fixed
  revision, retained human objections and an actually rejected merge attempt.
  Record exact SHA/run evidence before claiming enforcement.

Past pull-request runs are examples, not proof of merge protection on your
repository. Live model evaluation limits are in [docs/cost.md](../docs/cost.md).
