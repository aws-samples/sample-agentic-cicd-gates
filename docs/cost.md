# Evaluation observations and cost accounting

The sample's original target was less than $1 per gated run. That is a design
target, not a measured v2 price or a pricing commitment. Separate model inference,
CI execution and application/dashboard hosting when estimating your workload.

## Live evaluation — 2026-11-06

Runs of `evals/run_panel_evals.py` on 2026-11-06 (Pacific time), in `us-west-2`,
after the panel moved to newer models. The current panel ran twice; the previous
panel ran once on the same day as a baseline. All runs used the same cases. The
runs' logs and per-case results are operator evidence and are not included in
this repository.

| Observation | Current panel, run 1 | Current panel, run 2 | Previous panel |
|---|---|---|---|
| Cases that met every criterion (verdict, expected findings, no labeled false positive, no error) | **25/25** | **25/25** | **25/25** |
| Expected findings found | 17/17 | 17/17 | 17/17 |
| Labeled false positives | 0 | 0 | 0 |
| Review errors | 0 | 0 | 0 |
| Model calls | 100 | 100 | 99 |
| Elapsed time for the suite | 101 s (5 workers) | 101 s (5 workers) | 127 s (3 workers) |
| Estimated inference, at the rates below | $1.22 | $1.20 | $1.52 |

Every reviewer returned the same verdict, the same findings and the same
blocking count on every case in all three runs. Three more runs that day gave
the same results: one more of the current panel ($1.13), and two with the
Architecture Review Agent still on `us.anthropic.claude-opus-4-8` ($1.35 and
$1.37). The Architecture Review Agent also ran alone on the 25 cases, twice on
`us.anthropic.claude-sonnet-5-5` and once on `us.anthropic.claude-opus-4-8`,
with the same result on every case.

Per model, current panel, run 2:

| Model | Calls | Input tokens | Output tokens |
|---|---:|---:|---:|
| `us.anthropic.claude-opus-5-5` | 34 | 55,310 | 8,404 |
| `us.openai.gpt-6.1-sol` | 29 | 20,881 | 3,169 |
| `us.anthropic.claude-sonnet-5-5` | 30 | 34,310 | 1,942 |
| `us.anthropic.claude-fable-5-1` | 7 | 14,352 | 7,846 |

Small synthetic runs are not representative production accuracy, a general
false-positive rate, real pull-request latency or proof that several models
outperform one. The currency figures are estimates, not a billing reconciliation.

## Live evaluation — 2026-10-30

Two full runs with the previous panel (`us.anthropic.claude-opus-5`,
`us.openai.gpt-5.6-sol`, `us.anthropic.claude-opus-4-8`,
`us.anthropic.claude-fable-5`), with the runner's default five workers: 25/25
cases met every criterion in both runs, 17/17 expected findings, no labeled false
positives, no review errors, 99 model calls, 87 s per suite. The runner's prices at
the time gave $1.23 and $1.24 a run. At the rates below the same tokens cost
$1.45 and $1.46: the earlier `us.openai.gpt-5.6-sol` rate of $1.25 / $10.00 was
too low.

An earlier run on 2026-10-02, before parser and prompt fixes, met all criteria
on 23 of 25 cases: Security missed a secondary SEC-002 finding in `vuln.diff`,
and Architecture returned invalid JSON (`ADVISORY_ERROR`) on `injection.diff`.

## Historical illustrative estimates — August 2026

The earlier documentation recorded these observations and assumptions in
`us-west-2`. They predate the stricter parser, corrected scoring, expanded suite
and revised pipeline. They are retained for context, not reused as v2 results.

| Historical record | Original basis | What it does not establish |
|---|---|---|
| August 17 single-model build-out day | 60 Sonnet invocations; 38,898 input and 6,336 output tokens; about 1,300 input / 210 output tokens averaged over an assumed 30 two-call reviews | A representative real-PR distribution or complete pipeline bill |
| August 17 infrastructure worksheet | Illustrative totals of about $0.06 for Tier 1 and $0.03 for Tier 2, using assumed short runs, three SMALL gate builds and 30-day report retention | Current v2 cost: the SAM path now has five parallel CodeBuild actions and defaults to 120-day report retention |
| August 17 three-reviewer suite | Reported 18/18 verdicts and about $0.38 estimated inference cost over 18 synthetic cases | Corrected-score accuracy, four-reviewer performance or a real-PR price |
| August 19 four-reviewer suite | Reported 21/21 verdicts and about $0.78 estimated inference cost over 21 synthetic cases | Current 25-case results, general four-cent PR pricing or infrastructure-inclusive cost |

## Rates used by the panel runner

USD per million tokens, for the US geographic cross-Region inference profiles
(`us.` model IDs) this sample calls: Standard tier, short context, `us-west-2`,
checked 2026-11-06. US geographic profiles cost 10% more than global (`global.`)
profiles. Rates change; these are a dated snapshot, not a rate card.

| Model ID | Input | Output | Used by |
|---|---:|---:|---|
| `us.anthropic.claude-opus-5-5` | 4.40 | 22.00 | Security Review Agent |
| `us.openai.gpt-6.1-sol` | 2.20 | 11.00 | Code Quality Review Agent |
| `us.anthropic.claude-fable-5-1` | 11.00 | 55.00 | Accessibility Review Agent |
| `us.anthropic.claude-sonnet-5-5` | 2.20 | 11.00 | Architecture Review Agent; default model; advisory STRIDE agent |
| `us.anthropic.claude-opus-5` | 5.50 | 27.50 | Previous Security model |
| `us.anthropic.claude-opus-4-8` | 5.50 | 27.50 | Previous Architecture model |
| `us.openai.gpt-5.6-sol` | 4.40 | 22.00 | Previous Code Quality model |
| `us.anthropic.claude-fable-5` | 11.00 | 55.00 | Previous Accessibility model |

Unknown models are reported as `unpriced`, not free. Consult
[Bedrock pricing](https://aws.amazon.com/bedrock/pricing/) and the relevant
region/model/inference mode before estimating a new run.

## Measure your own execution

For each retained run, record repository and revision, policy digest, baseline,
reviewer configuration, actual verdicts/errors, token usage, retries and execution
IDs. Compare repeated runs on representative changes, including clean changes and
known defects. Preserve misses and incomplete reviews alongside successful cases.

Estimate inference as `input_tokens × input_rate / 1,000,000 + output_tokens ×
output_rate / 1,000,000`, using current applicable rates and supported usage fields.
File scoping, empty scoped diffs, validation calls, reasoning output, retries and
refusals affect usage. A missing usage record is not proof of zero cost.

Add the services actually used:

- CodeBuild action durations and compute types, CodePipeline executions, and
  GitHub Actions usage/retention for PR reviews.
- Optional AgentCore Runtime, Lambda, ECR, Kiro plan/API and Secrets Manager costs.
  The two alternative pipelines do not contain all Tier 1 release actions, so
  their gate-only totals are not like-for-like deployment totals.
- S3 artifacts/reports, CloudWatch logs/alarms, optional advisory STRIDE calls,
  source hosting and scanning charges where applicable.
- The separately deployed application's CloudFront/API Gateway/Lambda usage,
  dashboard, DNS and any other selected hosting services.

Parallel actions still incur their own usage. Compare estimates with account
billing; do not infer zero idle cost or free inference from an absent line item.
See [deployment setup and teardown](../deploy/README.md) for resource scope.
