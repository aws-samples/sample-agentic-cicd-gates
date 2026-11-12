# Tier 1 — CodeBuild-hosted review gate

The agent harness runs **inside the pipeline's own build compute** (CodeBuild), calling
Amazon Bedrock for inference through a least-privilege role.

## What gets deployed

- CodeCommit repo `agentic-gates-demo` (the guarded demo repo — Tier 2 reuses it)
- CodePipeline `agentic-gates-tier1`: Source (full-clone) → AgentReviewGate (CodeBuild)
- The buildspec lives in the **stack**, not the guarded repo — a change can't edit its own gate
- Every gate build runs Python isolated (`python -I`, with `PYTHONSAFEPATH=1` and
  `PYTHONNOUSERSITE=1` as a second guard) and pins the pyenv interpreter from `/`, so no
  file in the checkout (a `json.py`, a `.python-version`) is imported or picks the Python
- Rules and tooling deployed as CDK S3 assets, never read from the guarded repo. Every
  asset a build fetches (the rules, `.reviewer.yaml` or `review_policy_file`, and the
  agent, review-input, deterministic and threat-model packages) is pinned to one S3
  version and a SHA-256, and a build stops if either does not match
- CodeBuild roles: Bedrock invoke limited to Anthropic and OpenAI models and their `us.*`
  inference profiles (review and threat model); read on the whole CDK asset bucket
  (`Asset.grant_read`), so the pins, not IAM, fix which bytes a build uses; pull on the
  one repo

## Deploy

```bash
python -m venv ../.venv && ../.venv/bin/pip install -r ../requirements.txt
# A NEW stack that reads the CodeCommit demo repo, from this directory:
npx -y aws-cdk@2.1144.0 deploy -c source=codecommit
```

The source is never chosen by default: synth stops without `-c source=codecommit`
or the complete GitHub context (`github_repo`, `connection_arn` and
`github_branch`), and a custom domain needs all three `site_*` values
([`deploy_context.py`](deploy_context.py)). To update an existing stack, repeat
its complete saved context as shown in [deploy/README.md](../deploy/README.md).

Optional: add `-c enable_continuum=true` (in `us-east-1` or `us-west-2`) to run
the advisory AWS Continuum code scan beside the gates. It is off by default and
its findings never block the release (a CodeBuild failure or the project timeout
still fails the stage, like any action); see the repository README, "Optional:
AWS Continuum code scan in this pipeline" ([continuum.py](continuum.py)).

## Run the demo

```bash
# seed clean code + rules, push → pipeline passes
# push a SQL-injection change → gate FAILS the build with SEC-001 + suggested fix
# git revert → pipeline green again
```

Verified 2026-08-17 (us-west-2): clean seed passed; vuln commit blocked with
`SEC-001 src/db.py:6 conf=97` (`VERDICT=FAIL blocking=1 discovered=2`, one candidate
suppressed below the confidence floor — the two-stage validation working); revert passed.
Gate latency ≈65s including CodeBuild provisioning.

## Review panel

The gate is panel-aware: `.reviewer.yaml` in the demo repo configures three
personas (Security Review Agent 🛡️ Opus 5.5 security · Code Quality Review Agent ⚡ GPT 6.1 robustness · Architecture Review Agent 📐
Sonnet 5.5 design, advisory). `review_cli.py` runs every persona over the diff,
folds the worst verdict into the exported `VERDICT`/`BLOCKING` variables, and
writes one findings.json with per-finding `agent` attribution plus an
`agents[]` summary. Config and schema notes: `pr-surface/README.md`.
