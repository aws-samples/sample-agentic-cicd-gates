# evals

Both runners default to the demo's root `.reviewer.yaml`, which includes
`SEC-003`; use `--rules /path/to/approved-rules.yaml` to evaluate another policy.
The older example policy in `rules/` does not include SEC-003.

`run_panel_evals.py` evaluates each configured reviewer under its own rule
prefixes. The case verdict is the worst actual reviewer verdict, preserving
`BLOCKED_ERROR` and `ADVISORY_ERROR`. Errors never earn verdict-accuracy credit.
Exit zero requires correct verdicts, no expected-finding misses, no labeled
false positives, and no errors. A required finding with no owning reviewer is
a miss. An empty rule-prefix list means the reviewer owns all rules.

`run_evals.py` evaluates the selected single model against the entire ruleset;
it does not silently inherit only the first panel member's rule scope or model.
It uses that member's thinking preset. Its exit status also includes verdicts,
errors, expected findings and labeled false positives.

The suite now has 25 illustrative cases, including four SEC-003 cases:

| Case | Expected | Purpose |
|---|---|---|
| `xss-innerhtml.diff` | FAIL, SEC-003 | URL input into a DOM HTML sink |
| `xss-reflected-html.diff` | FAIL, SEC-003 | Query input in a Python HTML response |
| `xss-textcontent.diff` | PASS, no SEC-003 | Safe DOM text assignment |
| `xss-escaped-html.diff` | PASS, no SEC-003 | Escaped input in an HTML text node |

The scoring is also covered offline with mocked model outcomes. The latest live
runs are recorded in [docs/cost.md](../docs/cost.md): two full panel runs on
2026-10-30 (Pacific time) each met all criteria on 25 of 25 cases. When you run
the suite, keep the rules and commit, individual results, misses, false
positives, errors and token usage with the result. The script's token price
table is a configured estimate, and its totals exclude pipeline infrastructure.

Offline regressions (no model calls):

```bash
.venv/bin/python -m pytest -q agent/tests
```

Live evaluations, only when separately authorized:

```bash
.venv/bin/python evals/run_panel_evals.py --rules .reviewer.yaml
.venv/bin/python evals/run_evals.py --rules .reviewer.yaml --only xss-innerhtml.diff
```

## Rule catch test (SEC-900)

`SEC-900` in `.reviewer.yaml` came from AWS Continuum's first scan of the
`sample-agentic-cicd-artifact` repository, which found 19 issues. To test the
rule, the authors took the files behind those issues, as they were before the
fixes. On each run date, the Security Review Agent alone reviewed them once
without the rule and once with it. Each file was reviewed whole, as a new-file
diff, in seven groups: the artifact's vendored copy of this repository's gate
tooling (`pr-reviewer/`: rule checks, threat-model validator, vendor check, PR
reviewer and review core), its pull-request workflow, one site script, and the
application's Python, page and template files.

| Run | Security model | Without SEC-900 | With SEC-900 |
|---|---|---|---|
| 2026-11-06 | Claude Opus 5 | 0 of 19 | 7, and part of 2 more |
| 2026-11-07 | Claude Opus 5.5 | 0 of 19 | 5, and part of 1 more |

On November 7, with the rule added, the 25-case suite still met all criteria,
and no verdict changed. Two runs over 19 issues are a small sample, not an accuracy measure,
so `SEC-900` stays advisory.
