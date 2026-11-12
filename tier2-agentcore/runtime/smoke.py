"""Zero-model smoke test of a deployed Tier 2 runtime's chunked path.

The payload is a 1,500-line added file (over one 100,000-byte chunk) and a
one-seat policy scoped to a path nothing matches. The runtime therefore plans
the delta, verifies the plan and folds a chunked report while scheduling no
review, so no model is called. Only an image with this repository's chunked
path answers it as checked below; the 2026-08-20 image answers without any
`chunking` block. Nothing here calls AWS.

    python tier2-agentcore/runtime/smoke.py > /tmp/tier2-smoke-payload.json
    aws bedrock-agentcore invoke-agent-runtime --agent-runtime-arn RUNTIME_ARN \\
      --qualifier DEFAULT --runtime-session-id "deploy-smoke-$(uuidgen)" \\
      --content-type application/json --accept application/json \\
      --payload fileb:///tmp/tier2-smoke-payload.json /tmp/tier2-smoke-report.json
    python tier2-agentcore/runtime/smoke.py --check /tmp/tier2-smoke-report.json

`--check` prints `SMOKE: PASS ...` and exits 0, or prints why and exits 1.
"""
import argparse
import hashlib
import json
import sys

SCOPED_ITEM_BYTES = 30_000  # runtime/handler.py; a different value is a different image
LINES = 1_500
RULES_YAML = """version: 1
agents:
  - name: Smoke
    rules: [SMK-]
    file_patterns: ['nothing-matches/**']
rules:
  - id: SMK-001
    description: deploy smoke test; no file is in scope
    blocking: true
"""


def payload() -> dict:
    body = "".join(f"+const smoke{i} = {i}; // {'.' * 60}\n" for i in range(LINES))
    diff = ("diff --git a/smoke/only.js b/smoke/only.js\nnew file mode 100644\n"
            f"--- /dev/null\n+++ b/smoke/only.js\n@@ -0,0 +1,{LINES} @@\n" + body)
    return {"diff": diff, "rules_yaml": RULES_YAML, "deadline_seconds": 60}


def check(report, sent: dict) -> list[str]:
    """Every reason the report is not the expected zero-review chunked PASS."""
    if not isinstance(report, dict):
        return ["the response is not a JSON object"]
    problems = []
    chunking = report.get("chunking")
    if not isinstance(chunking, dict):
        return ["no chunking block: this is not the chunked runtime (old image or wrong endpoint?)"]
    diff = sent["diff"].encode("utf-8")
    expected = {"mode": "chunked", "reviews_scheduled": 0, "reviews_completed": 0,
                "deadline_reached": False, "scoped_item_bytes": SCOPED_ITEM_BYTES,
                "diff_bytes": len(diff), "diff_sha256": hashlib.sha256(diff).hexdigest()}
    for key, want in expected.items():
        if chunking.get(key) != want:
            problems.append(f"chunking.{key} is {chunking.get(key)!r}, expected {want!r}")
    if report.get("verdict") != "PASS" or report.get("error"):
        problems.append(f"verdict {report.get('verdict')!r}, error {report.get('error')!r}")
    agents = report.get("agents")
    if (not isinstance(agents, list) or len(agents) != 1 or agents[0].get("verdict") != "PASS"
            or agents[0].get("error") or agents[0].get("chunks") != []):
        problems.append(f"agents {agents!r}: expected one PASS seat with no chunk reviews")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", metavar="REPORT", help="check a runtime's answer to the payload")
    args = parser.parse_args(argv)
    sent = payload()
    if not args.check:
        json.dump(sent, sys.stdout)
        return 0
    with open(args.check, encoding="utf-8") as fh:
        try:
            report = json.load(fh)
        except ValueError as exc:
            print(f"SMOKE: FAIL - the response is not JSON: {exc}")
            return 1
    problems = check(report, sent)
    if problems:
        print("SMOKE: FAIL - " + "; ".join(problems))
        return 1
    print(f"SMOKE: PASS chunked path, {report['chunking']['chunks']} chunk(s), 0 model reviews, "
          f"scoped items {SCOPED_ITEM_BYTES}, diff sha256 {report['chunking']['diff_sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
