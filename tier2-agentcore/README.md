# Tier 2 — AgentCore Runtime-hosted reviewer

The **same reviewer core** as Tier 1 moves out of pipeline compute into Amazon Bedrock
AgentCore Runtime. The pipeline keeps only a thin Lambda gate.

## Why this is the production shape

| Property | Tier 1 (CodeBuild) | Tier 2 (AgentCore) |
|---|---|---|
| Agent isolation | shared build container | per-invoke microVM session |
| Model permissions | pipeline compute role | **runtime execution role only** — the gate Lambda carries an explicit IAM **Deny** on `bedrock:InvokeModel` |
| Observability | build logs | AgentCore OTEL traces + CloudWatch |
| Gate latency | adds CodeBuild container start-up to each gate | ≈40s for a clean commit (one run) |
| Versioning | S3 asset per deploy | runtime versions + endpoint qualifiers |

The Tier 2 latency is one observed run on 2026-08-17 in us-west-2 (see the
verification note under [Local smoke test](#local-smoke-test-no-deploy-needed)).
It is not a performance guarantee; your times depend on diff size, model and Region.

## Layout

- `runtime/` — container for AgentCore Runtime (HTTP contract: `GET /ping`,
  `POST /invocations` on 8080). `handler.py` wraps `agent/reviewer` with
  `BedrockAgentCoreApp`. The image also copies Tier 1's `pipeline_tools/review_chunks.py`
  and `agent/review_cli.py` beside it, for deltas larger than one chunk. Its pip
  dependencies are pinned to the image deployed on 2026-08-20, and its base image
  by digest to the one it was tested on. **Must bind `0.0.0.0`** —
  the SDK's host auto-detect can fall back to loopback, which the Runtime's health
  probe can't reach. `smoke.py` (not in the image) is the zero-model deploy check.
- `gate/` — CodePipeline Lambda action. Compares the source artifact ZIP with
  the accepted snapshot in S3, reads `.reviewer.yaml` only from that baseline, calls
  `bedrock-agentcore:InvokeAgentRuntime`, maps the verdict to
  `PutJobSuccessResult`/`PutJobFailureResult`. Every path ends in a PutJob*Result —
  the action never wedges.
- `infra/` — CDK stack: ARM64 image asset → ECR, `AWS::BedrockAgentCore::Runtime`,
  gate Lambda, pipeline `agentic-gates-tier2` on the same demo repo as Tier 1.
  `runtime_rollback.py` writes a template that reverts only the runtime image.

## Baseline and initialization

The existing key `tier2/last-reviewed-source.zip` now means **last accepted
review snapshot**. Only a well-formed, error-free `PASS`, with every reviewer
also reporting `PASS`, can advance it. `FAIL`, `BLOCKED_ERROR`, `ADVISORY_ERROR`,
unknown verdicts, malformed reports and review/storage errors block the action
and retain the previous baseline. In particular, even an advisory reviewer error
blocks Tier 2: the missing evidence must not disappear from the next delta.
Findings from advisory rules are permitted in an otherwise valid PASS.

There is no automatic first-run seed and no fallback to the current change's
rules. `NoSuchKey` produces `BASELINE_MISSING`; access denial, missing bucket,
timeouts and other errors remain storage failures. Missing/corrupt policy in the
baseline blocks. Neither path silently creates a successful review.

An operator must initialize a new baseline explicitly:

1. Select a specific commit that has been independently reviewed and approved,
   including its `.reviewer.yaml`. If no approved revision exists, complete that
   review first. Do not use the revision currently failing review as a shortcut.
2. Archive that exact commit with files at ZIP root. Record the commit SHA, ZIP
   SHA-256 and review/approval evidence in the operator's change record.
3. Upload it once with create-only semantics to the correct stack's state bucket.
   This is a privileged trust decision, not a pipeline PASS.
4. Retry the blocked pipeline revision. Its changes are reviewed against that
   independently approved baseline. Keep the original failed run as evidence.

Example operator commands (replace the explicit placeholders; not run by tests):

```bash
git archive --format=zip --output=/tmp/tier2-approved-source.zip <APPROVED_COMMIT_SHA>
unzip -p /tmp/tier2-approved-source.zip .reviewer.yaml
shasum -a 256 /tmp/tier2-approved-source.zip
aws s3api put-object --bucket <STATE_BUCKET> \
  --key tier2/last-reviewed-source.zip \
  --body /tmp/tier2-approved-source.zip --if-none-match '*'
```

Existing deployments need a baseline audit before rollout: the previous handler
advanced state after rejected reviews. Verify the ZIP against an independently
approved revision. If it is untrusted, stop executions, preserve a copy and its
provenance, and restore a known approved snapshot under a separately recorded
operator change. Never delete/reseed state to make a failed revision disappear.

Proving that a baseline equals a commit (its ETag is the MD5 of that run's
pipeline source artifact; its tree equals `git archive` of the commit) is not
the same as proving the commit was reviewed. The audit record must also list,
from the gate's log, every way the baseline's history falls short of review:
a first run that seeded the whole tree in under a second with no review; runs
whose diff was cut at 400,000 characters (`diff bytes=400000`), whose rules came
from the candidate (`rules from current`), or that passed with an errored seat;
FAILs after which the old handler advanced the baseline anyway, and whether
each finding is still present at the baseline; and the files the old reader
never sent to a model (before v2: anything but `.py`, `.yaml`, `.yml`, `.json`,
`.md`, `.txt`, `.sh`, `.toml`, `.cfg`). A v2 PASS then covers the delta from that
baseline, not the tree before it. If that is not enough, review the baseline
commit's whole tree once (for example with Tier 1's tooling from the empty tree)
before relying on Tier 2, and record the owner's explicit acceptance either way.

Promotion uses S3 `IfMatch` against the ETag read before review. Concurrent state
changes fail the action rather than overwriting another review's baseline.
Use an SDK supporting conditional `PutObject`. Baseline promotion records review
acceptance, not deployment success; S3 writes and the CodePipeline result callback
are not a transaction. A callback failure after a successful promotion needs
operator reconciliation with the review logs. It shows as a result line with
`"verdict": "PASS"`, then `GATE INFRA ERROR`, and an action message starting
`gate error:`: the baseline may already be this revision, so compare the bucket's
ETag with the result line's `review_input.baseline_etag`. A retry then reviews an
empty delta and passes. Any other failure (`verdict=FAIL`, `verdict=BLOCKED_ERROR`,
or a `gate error:` with no PASS result line before it) leaves the ETag unchanged.

## Rolling back a deploy

The gate and the runtime image deploy together, and rolling back is not symmetric:

- If a deploy fails, CloudFormation returns the stack to its previous template,
  gate included. If that gate is pre-v2, do not push to the branch the pipeline
  reads until a redeploy succeeds and is verified: the old gate would review the
  next delta truncated and advance the baseline whatever the verdict.
- To stop reviews without touching the stack, disable the gate stage's inbound
  transition. Executions wait before it, nothing is reviewed and the baseline
  cannot move; `enable-stage-transition` resumes them.

  ```bash
  aws codepipeline disable-stage-transition --pipeline-name PIPELINE \
    --stage-name AgentReviewGate --transition-type Inbound --reason "Tier 2 rollback"
  ```

- To revert only the runtime image, `infra/runtime_rollback.py` writes the
  stack's current template with the previous template's image and nothing else
  (commands in its docstring). The current gate stays, and it refuses any delta
  over one chunk that comes back without chunk evidence, so under an older image
  a large delta fails closed. Keep the transition disabled until you roll forward
  unless small deltas should run.
- Never restore a whole pre-v2 template while its baseline is behind the branch
  head, that is, while a delta is waiting for review. Its gate truncates at
  400,000 characters, reads nine extensions and advances after a FAIL. If it must
  be restored, disable the inbound transition first, keep it disabled until you
  roll forward, and never retry those executions under it. `update-stack` needs
  `--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND` and
  `--parameters ParameterKey=BootstrapVersion,UsePreviousValue=true`.

## Change coverage and bounds

The ZIP reader includes the existing backend/config extensions plus
`.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`, `.html`, `.htm`, `.css`, `.scss`,
`.sass`, `.less`, `.svg`, `.vue` and `.svelte`, and text files known by name
rather than extension (`TEXT_NAMES`: `Dockerfile`, `Containerfile`, `Makefile`,
`GNUmakefile`, `LICENSE`, `LICENCE`, `NOTICE`, `.gitignore`, `.dockerignore`, in
any directory and any letter case). It produces `diff --git` sections
for additions, modifications and deletions, including quoted filenames and
missing final newlines, so scoped reviewers receive their changed files.
This is a supported-text gate, not a claim to review every artifact:
binary files, other extensions and names (for example `Dockerfile.dev` or
`.diff` fixtures), and ZIP file-mode changes remain outside its coverage, and
each result lists the changed ones in `skipped_files` for an operator to read.
The per-rule and reviewer patterns still determine review scope.

Unreadable supported text fails rather than vanishing from the diff. A delta of
at most 100,000 UTF-8 bytes (one review chunk) takes the single-call path it
always has, with the same report. A larger delta, up to 2,500,000 bytes, is
reviewed in chunks with Tier 1's own code inside the same synchronous call: the
runtime plans it with `review_chunks.py`, re-verifies the plan independently and
reviews every (seat, chunk) on 16 workers with `agent/reviewer/chunked.py`, and
folds the panel into one report with `review_cli.py`. The semantics are Tier 1's:
every seat reviews every chunk in its scope (a scoped seat's in-scope files in
items of at most 30,000 bytes, `SCOPED_ITEM_BYTES`, where Tier 1 packs them up to
100,000; a single larger file section is one item); a blocking finding in any chunk fails;
a chunk whose review ended in an error is reviewed once more; and a chunk that
still errored, truncated, timed out or was not reviewed makes its seat an error
verdict (BLOCKED_ERROR for a seat owning blocking rules). Tier 2 then blocks on any
error verdict, ADVISORY_ERROR included, as before. An unplannable delta is
BLOCKED_ERROR before any model call. Deltas above 2,500,000 bytes block rather than
being truncated. What a chunked PASS does not cover is in each report's
`chunking.note`: a flow from a source in one chunk to a sink in another is not traced.

The time budget is in `gate/lambda_handler.py`. The Lambda (900 s) and a
synchronous `InvokeAgentRuntime` (15 minutes) are both hard limits. The gate waits
840 s for the report and calls only with 870 s left; in the chunked path the
runtime stops waiting for chunk reviews at 720 s and fails every unfinished chunk
closed, so its report arrives before the read timeout. The single-call path (one
chunk or less) has no deadline: its four seats run one after another (302 s for
98,971 bytes of code on 2026-10-02), and a call that outlasted 840 s would end as a
gate error with no baseline change. Either way the action never wedges. One
reviewer call may take up to 1,126 s (the 64,000-token cap at 60 tokens/s), more
than these limits allow, so Tier 2 cannot always wait for it. That is safe because
a review cut off this way fails closed and never passes; Tier 1, with 82 minutes,
always has room for it.

Wall time is at least the review work divided by 16 workers and at least the
slowest single review plus its retry, which cannot be split. On Tier 1's measured
rates, 2,500,000 bytes of illustrated assets is ~126 s of work, but 2,500,000 bytes
of code is ~480 s before stragglers and retries and is likely to reach the
deadline; about 1,000,000 bytes of code leaves room. The slowest seat measured
(Accessibility, Fable 5) took 244.5 s for one 22,887-byte item, which is why scoped
items are capped at 30,000 bytes. A review that runs out of time is BLOCKED_ERROR
with a complete report, and the baseline stays where it was: retry it, or fix the
cause; never reseed. A pushed delta can only grow, so split a large change into
smaller fast-forward pushes before it reaches the branch, not after.

Before the baseline advances, the gate checks that the PASS covers what it sent. A
chunked report must name the same diff (`chunking.diff_sha256`, `diff_bytes`), must
not have reached its deadline, and must account for every scheduled chunk review
as a completed PASS; a delta over one chunk without chunk evidence is refused.
Every logged result carries the gate's `review_input`: job, pipeline execution and
runtime session IDs (the dashboard shows a Tier 2 report only when its
`pipeline_execution_id` matches the run),
source and baseline ZIP hashes, the baseline ETag, the policy hash, diff size and
hash, and `skipped_files`, the changed files outside those extensions and names that no
model read, with `bytes` and `previous_bytes` (up to 500 listed; the totals are
always complete). The same `review_input` is logged before the call, so a refusal
or a failed call still leaves it.

## Deploy

Deploy Tier 1 first (it owns the demo repo). Then:

Use the deployment command and all required context flags documented in
[`deploy/README.md`](../deploy/README.md). Synth refuses implicit or partial
source context with Tier 1's rules (`tier1-codebuild/deploy_context.py`): a GitHub
source needs `github_repo`, `connection_arn` and `github_branch` (the stack used
to fix the branch to `main`; pass `-c github_branch=main` to keep reading it), and
the CodeCommit demo repo needs `-c source=codecommit`. A redeploy that forgets a
flag stops instead of switching the pipeline to CodeCommit.
Rebuild both the gate Lambda and the AgentCore runtime image so the shared
validator, the chunked review and the gate's checks match; one stack deploy does
both. The runtime image is `linux/arm64`; `CDK_DOCKER=finch` is supported.

Known CFN gotcha (handled in the stack): the AgentCore control plane validates ECR pull
access at create time by assuming the execution role, so the runtime must depend on the
role's **DefaultPolicy**, not just the role (`runtime.node.add_dependency(runtime_role)`).

## Deployed smoke test (no model call)

Run this after every deploy, and before anything is pushed to the branch the
pipeline reads. The DEFAULT endpoint must be `READY` on the new runtime version
with no `targetVersion` pending, and the check must print `SMOKE: PASS`. The
payload's only seat is scoped to a path nothing matches, so the runtime plans and
verifies a chunked review and schedules no model call (`runtime/smoke.py`).

```bash
python runtime/smoke.py > /tmp/tier2-smoke-payload.json
aws bedrock-agentcore-control get-agent-runtime-endpoint --agent-runtime-id RUNTIME_ID \
  --endpoint-name DEFAULT --query '[status,liveVersion,targetVersion]'
aws bedrock-agentcore invoke-agent-runtime --agent-runtime-arn RUNTIME_ARN --qualifier DEFAULT \
  --runtime-session-id "deploy-smoke-$(uuidgen)" --content-type application/json \
  --accept application/json --payload fileb:///tmp/tier2-smoke-payload.json \
  /tmp/tier2-smoke-report.json
python runtime/smoke.py --check /tmp/tier2-smoke-report.json
```

The smoke test does not exercise the gate Lambda. Check that separately: the
deployed function's `lambda_handler.py` must be byte-identical to the commit's.

## Local smoke test (no deploy needed)

```bash
finch build --platform linux/arm64 -f runtime/Dockerfile -t reviewer-smoke ../..
eval $(aws configure export-credentials --format env)
finch run -d --name reviewer-smoke -p 127.0.0.1:8080:8080 \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -e AWS_REGION=us-west-2 reviewer-smoke
curl http://127.0.0.1:8080/ping
# POST {"diff": ..., "rules_yaml": ..., "deadline_seconds": 720} to /invocations
# → GateResult JSON. A diff over 100,000 bytes needs deadline_seconds (above 780 is capped).
```

Verified 2026-08-17 (us-west-2): clean commit passed in ~40s; SQL-injection commit
blocked with pipeline summary `verdict=FAIL blocking=1 ... | SEC-001 src/db.py:6`;
revert passed. Both tiers reviewed the same commits side-by-side on the shared repo.

## Review panel

The gate is panel-aware: `.reviewer.yaml` in the accepted baseline defines the
reviewers, models, rule ownership and input scopes. `runtime/handler.py` runs
every configured reviewer, preserves the worst actual verdict including errors,
and returns findings with per-finding `agent` attribution plus an
`agents[]` summary. Config and schema notes: `pr-surface/README.md`.
