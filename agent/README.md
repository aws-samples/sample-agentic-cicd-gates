# agent

The shared parser accepts `{"findings":[]}` as a valid completed response.
Every nonempty finding must have a known rule ID, an in-scope repository-relative
path (at most 4096 characters), a nonnegative integer line, a nonempty message
(at most 2000 characters), and integer confidence from 0 to 100. Booleans and
numeric strings do not count as integers. `suggested_code` is null or a string
of at most 2000 characters. Rule severity and blocking status remain authoritative;
model-provided values for those fields are ignored.

Unknown IDs, malformed rows, out-of-scope paths and excess findings invalidate
the entire response; they are never silently dropped or truncated. The configured
`max_findings` must be an integer from 1 to 1000. Discovery may omit confidence
because the separate scoring call must provide exactly one valid score for every
candidate. Missing, duplicate, out-of-range or malformed scores are errors.

Reviewers owning blocking rules fail closed on contract/model errors, including
reviewers whose empty rule-prefix list means "all rules." Advisory-only reviewers
still follow `fail_mode`. Panel reports retain `ADVISORY_ERROR` and `BLOCKED_ERROR`
instead of presenting them as successful findings-free reviews. Tier 2 requires
every reviewer to finish without error before advancing its accepted baseline.

These checks validate the response contract, not the truth or completeness of
model findings. Empty valid findings can still represent missed defects.

`review_cli.py --chunk-plan` reviews a delta larger than one chunk with
[`reviewer/chunked.py`](reviewer/chunked.py): the plan must reproduce the diff,
every seat reviews every chunk in its scope through the same `review_diff`, the
`max_findings` cap and confidence floor apply per call, and each seat folds back
into one result. A chunk whose review ends in an error (never one that ends in
FAIL) is reviewed once more while the deadline allows, and its row records both
attempts. Any chunk that still has no completed review, or whose last attempt
failed, truncated or timed out, makes the seat its error verdict, never PASS;
kept findings are de-duplicated on rule, path and line.

What a chunked PASS does not mean is written into every chunked report
(`chunking.note`). Chunked review loses context across chunk boundaries: a flow
from a source in one chunk to a sink in another is not traced. The 25-finding
cap applies per chunk call, so a seat can report more than 25 findings in total,
and a delta of 100,001 to 400,000 bytes that once had one call per seat (and
failed its contract above 25 findings) is now chunked. Scoped views split lines
at LF only, so file content cannot fake a `diff --git` header for a scoped seat.

Run focused tests without credentials, Kiro, model calls or deployments:

```bash
.venv/bin/python -m pytest -q agent/tests
```

The test fixtures reject network connections and AWS client creation unless a
test supplies a fake client.
