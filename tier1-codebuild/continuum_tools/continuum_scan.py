"""Advisory AWS Continuum scan of the revision this pipeline run is releasing.

Zips the checked-out revision, uploads it as the environment's S3 source,
starts a Continuum code scan, waits a bounded time, and reports the issues
Continuum lists. ADVISORY: it always exits 0. Findings, errors and timeouts
are written to the report and the build log; they never change the gate
verdict, which belongs to the reviewer and the fixed rules.

Outside us-east-1 and us-west-2 it makes no AWS call and reports SKIPPED.
"""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import zipfile

SUPPORTED_REGIONS = ("us-east-1", "us-west-2")
SOURCE_KEY = "code/source.zip"
TERMINAL = ("SUCCEEDED", "FAILED")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
POLL_SECONDS = 15


def console_url(region: str, environment_id: str) -> str:
    return (f"https://console.aws.amazon.com/continuum/home?region={region}"
            f" (environment {environment_id})")


def summarize(issues: list[dict]) -> tuple[dict, str]:
    counts = {s: 0 for s in SEVERITIES}
    for issue in issues:
        sev = (issue.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    shown = [f"{counts[s]} {s}" for s in SEVERITIES if counts[s]]
    # ListCodeIssues has no per-scan filter, so these are the environment's
    # cumulative OPEN issues, not only this commit's.
    text = f"{len(issues)} open issue(s) in the environment" + (
        f" ({', '.join(shown)})" if shown else "")
    return counts, text


def archive(source_dir: str, out: str) -> None:
    """Zip every tracked file at HEAD, listed by `git ls-files`.

    Not `git archive`: that honours a committed `.gitattributes export-ignore`,
    so a change under review could hide a file from the scan while the reviewer
    still sees it. `ls-files` lists the whole tracked tree regardless.
    """
    names = subprocess.run(["git", "-C", source_dir, "ls-files", "-z", "--cached"],
                           check=True, capture_output=True).stdout.split(b"\0")
    base = pathlib.Path(source_dir)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for raw in names:
            if not raw:
                continue
            name = raw.decode()
            path = base / name
            if path.is_file() and not path.is_symlink():
                zf.write(path, name)


def list_issues(client, environment_id: str) -> list[dict]:
    issues, token = [], None
    while True:
        kw = {"environmentId": environment_id, "maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = client.list_code_issues(**kw)
        issues += page.get("items", [])
        token = page.get("nextToken")
        if not token:
            return issues


def run(args, client=None, s3=None, sleep=time.sleep, clock=time.monotonic) -> dict:
    report = {"tool": "aws-continuum", "advisory": True, "region": args.region,
              "environment_id": args.environment_id, "revision": args.revision,
              "pipeline_execution_id": args.execution_id}
    if args.region not in SUPPORTED_REGIONS:
        report.update(status="SKIPPED_REGION", summary=(
            f"skipped: AWS Continuum is available in {' and '.join(SUPPORTED_REGIONS)}, "
            f"not {args.region}"))
        return report
    try:
        if client is None or s3 is None:
            import boto3
            client = client or boto3.client("continuum", region_name=args.region)
            s3 = s3 or boto3.client("s3", region_name=args.region)
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = pathlib.Path(tmp) / "source.zip"
            archive(args.source_dir, str(zip_path))
            s3.put_object(Bucket=args.bucket, Key=SOURCE_KEY, Body=zip_path.read_bytes(),
                          Metadata={"revision": args.revision or "",
                                    "pipeline-execution": args.execution_id or ""})
        try:
            params = {"environmentId": args.environment_id}
            if args.execution_id:          # the pipeline always passes one; keep it idempotent
                params["clientToken"] = args.execution_id[:128]
            scan = client.create_code_scan(**params)["scan"]
        except client.exceptions.ServiceQuotaExceededException:
            scan = None
        if scan is None:
            report.update(status="SCAN_BUSY", scan_status="ALREADY_RUNNING")
        else:
            report["scan_run_id"] = scan["scanRunId"]
            deadline = clock() + args.wait_seconds
            while scan["status"] not in TERMINAL and clock() < deadline:
                sleep(POLL_SECONDS)
                scan = client.get_code_scan(environmentId=args.environment_id,
                                            scanRunId=scan["scanRunId"])["scan"]
            report["scan_status"] = scan["status"]
            if scan.get("failureMessage"):
                report["failure"] = {"stage": scan.get("failureStage"),
                                     "message": scan["failureMessage"]}
            report["status"] = ("SCAN_" + scan["status"]) if scan["status"] in TERMINAL \
                else "SCAN_STILL_RUNNING"
        issues = list_issues(client, args.environment_id)
        counts, text = summarize(issues)
        report["counts"] = counts
        report["issues"] = [{k: i.get(k) for k in ("name", "severity", "status", "phase")}
                            for i in issues[:50]]
        state = {"SCAN_SUCCEEDED": "scan succeeded", "SCAN_FAILED": "scan failed",
                 "SCAN_STILL_RUNNING": "scan still running",
                 "SCAN_BUSY": "a scan was already running"}[report["status"]]
        report["summary"] = f"{state}; {text}; details in the Continuum console"
        report["note"] = ("Continuum keeps validating issues and writing patches after a scan "
                          "ends; see " + console_url(args.region, args.environment_id))
    except Exception as exc:   # advisory: report, never fail the release
        report.update(status="ERROR", error=f"{type(exc).__name__}: {exc}"[:500],
                      summary=f"error ({type(exc).__name__}); see the build log")
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--region", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--environment-id", required=True)
    p.add_argument("--revision", default="")
    p.add_argument("--execution-id", default="")
    p.add_argument("--wait-seconds", type=int, default=900)
    p.add_argument("--source-dir", default=".")
    p.add_argument("--report", default="reports/continuum.json")
    args = p.parse_args(argv)
    report = run(args)
    path = pathlib.Path(args.report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"CONTINUUM (advisory): {report['status']}: {report['summary']}")
    for issue in report.get("issues", [])[:10]:
        print(f"  - [{issue.get('severity')}] {issue.get('name')} ({issue.get('status')})")
    if report.get("error"):
        print(f"  error: {report['error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
