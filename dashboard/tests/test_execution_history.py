"""Exact execution selection and retained reports."""
import io
import json
import unittest
from unittest.mock import patch

import test_evidence as fixtures
from test_evidence import h, SHA, OTHER
from test_execution_lookup import summary


class ExecutionHistoryTests(unittest.TestCase):
    setUp = fixtures.EvidenceTests.setUp

    def snapshot(self, execution_id=None, commit=None, repo=None):
        with patch.object(h, "_reports_bucket", return_value="retained-reports"), \
             patch.object(h, "_pr_surface", return_value={"open": []}), \
             patch.object(h, "_exec_for", return_value=None), \
             patch.object(h, "_health") as health:
            health.read.return_value = {"state": "unavailable", "observed_at": "original-observation"}
            return h.build_snapshot(commit_sha=commit, repo_key=repo, execution_id=execution_id)

    def retained_reports(self):
        self.cp.list_pipeline_executions.return_value = {"pipelineExecutionSummaries": [
            summary(SHA, "new-pass"), {**summary(SHA, "old-fail"), "status": "Failed"}]}
        self.cp.get_pipeline_state.return_value = {"stageStates": [
            {"stageName": "AutomatedGates", "actionStates": [{"actionName": "Review"}]}]}
        def actions(**kwargs):
            execution = kwargs["filter"]["pipelineExecutionId"]
            return {"actionExecutionDetails": [{
                "stageName": "AutomatedGates", "actionName": "Review",
                "status": "Failed" if execution == "old-fail" else "Succeeded",
                "actionExecutionId": execution,
                "output": {"executionResult": {
                    "externalExecutionId": f"agentic-gates-tier1-review:{execution}"}}}]}
        self.cp.list_action_executions.side_effect = actions
        def report(**kwargs):
            execution = kwargs["Key"].split("/")[1]
            failed = execution == "old-fail"
            doc = fixtures.report(execution_id=execution, revision=SHA)
            if failed:
                doc.update(verdict="FAIL", stats={"blocking": 1, "total": 1},
                           findings=[{"agent": h.PERSONAS[0], "rule_id": "SEC-003",
                                      "path": "src/handler.py", "line": 37,
                                      "message": "Complete retained failure reason. " * 50,
                                      "blocking": True}])
                doc["agents"][0]["verdict"] = "FAIL"
            return {"Body": io.BytesIO(json.dumps(doc).encode())}
        self.s3.get_object.side_effect = report

    def test_same_sha_failed_and_passed_runs_are_distinct_and_reports_stay_bound(self):
        self.retained_reports()
        old = self.snapshot("old-fail")
        new = self.snapshot("new-pass")
        self.assertEqual([r["execution_id"] for r in old["executions"]], ["new-pass", "old-fail"])
        self.assertEqual(len(old["commits"]), 1)
        self.assertEqual(old["execution"], "old-fail")
        self.assertEqual(old["execution_status"], "Failed")
        self.assertFalse(old["live"])
        self.assertEqual(old["review_evidence"]["tier1"]["state"], "blocked")
        self.assertGreater(len(old["failures"][0]["gate_reason"][0]), 420)
        self.assertEqual(new["review_evidence"]["tier1"]["state"], "passed")
        self.assertTrue(new["live"])
        self.assertEqual(old["selected_execution"], "old-fail")
        self.assertIsNone(old["selected_commit"])
        self.assertEqual(old["commit"]["sha"], SHA)
        self.assertEqual([c.kwargs["Key"] for c in self.s3.get_object.call_args_list],
                         ["executions/old-fail/builds/agentic-gates-tier1-review:old-fail/findings.json",
                          "executions/new-pass/builds/agentic-gates-tier1-review:new-pass/findings.json"])
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)
        self.assertIn("No cross-pipeline execution binding", old["pipelines"]["agentic-gates-tier2"]["error"])
        self.assertEqual(old["review_evidence"]["tier2"]["state"], "unavailable")

    def test_current_commit_only_selection_still_uses_newest_retry(self):
        self.retained_reports()
        snap = self.snapshot(commit=SHA)
        self.assertEqual(snap["execution"], "new-pass")
        self.assertIsNone(snap["selected_execution"])
        self.assertEqual(snap["selected_commit"], SHA)

    def test_failure_reasons_include_complete_findings_and_both_error_levels(self):
        self.retained_reports()
        base = self.s3.get_object.side_effect
        agent_error = "Provider diagnostic " * 40
        report_error = "Review runner diagnostic " * 40
        def errors(**kwargs):
            doc = json.loads(base(**kwargs)["Body"].read())
            doc["agents"][1]["error"] = agent_error
            doc["error"] = report_error
            return {"Body": io.BytesIO(json.dumps(doc).encode())}
        self.s3.get_object.side_effect = errors
        snap = self.snapshot("old-fail")
        reasons = snap["failures"][0]["gate_reason"]
        self.assertEqual(len(reasons), 3)
        self.assertIn("Complete retained failure reason.", reasons[0])
        self.assertTrue(reasons[1].endswith(agent_error))
        self.assertTrue(reasons[2].endswith(report_error))
        self.assertNotEqual(snap["review_evidence"]["tier1"]["state"], "passed")

    def test_execution_lookup_does_not_stop_at_another_run_of_same_sha(self):
        self.retained_reports()
        self.cp.list_pipeline_executions.side_effect = [
            {"pipelineExecutionSummaries": [summary(SHA, "new-pass")], "nextToken": "older"},
            {"pipelineExecutionSummaries": [summary(SHA, "old-fail")], "nextToken": "unneeded"},
            RuntimeError("must not read beyond selected execution")]
        snap = self.snapshot("old-fail", SHA)
        self.assertEqual(snap["execution"], "old-fail")
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)

    def test_unknown_execution_is_not_replaced_by_newest_pass(self):
        self.retained_reports()
        snap = self.snapshot("unknown")
        self.assertEqual(snap["selection_state"], "not_found")
        self.assertIn("requested execution ID", snap["selection_error"])
        self.assertIsNone(snap["execution"])
        self.assertIsNone(snap["findings"]["tier1"])
        self.s3.get_object.assert_not_called()

    def test_unavailable_history_keeps_execution_selector_and_actual_error(self):
        self.retained_reports()
        self.cp.list_pipeline_executions.side_effect = RuntimeError("ThrottlingException")
        snap = self.snapshot("old-fail")
        self.assertEqual(snap["selection_state"], "unavailable")
        self.assertEqual(snap["selected_execution"], "old-fail")
        self.assertIn("ThrottlingException", snap["selection_error"])
        self.assertEqual(snap["executions"], [])
        self.assertIsNone(snap["execution"])

    def test_found_execution_without_revision_is_unavailable_not_not_found(self):
        self.retained_reports()
        self.cp.list_pipeline_executions.return_value = {
            "pipelineExecutionSummaries": [{"pipelineExecutionId": "old-fail", "status": "Failed"}]}
        snap = self.snapshot("old-fail")
        self.assertEqual(snap["selection_state"], "unavailable")
        self.assertIn("no source revision", snap["selection_error"])
        self.assertIsNone(snap["execution"])

    def test_conflicting_commit_and_execution_do_not_mix_evidence(self):
        self.retained_reports()
        snap = self.snapshot("old-fail", OTHER)
        self.assertEqual(snap["selection_state"], "unavailable")
        self.assertIn("does not match", snap["selection_error"])
        self.assertIsNone(snap["commit"])
        self.assertIsNone(snap["execution"])
        self.s3.get_object.assert_not_called()
        self.cp.list_action_executions.assert_not_called()

    def test_execution_lookup_is_scoped_to_selected_repository_pipeline(self):
        self.retained_reports()
        self.cp.list_pipeline_executions.return_value = {"pipelineExecutionSummaries": []}
        snap = self.snapshot("old-fail", repo="road")
        self.assertEqual(snap["selection_state"], "not_found")
        self.assertEqual(self.cp.list_pipeline_executions.call_args.kwargs["pipelineName"],
                         "agentic-gates-tier1-road")

    def test_snapshot_cache_key_keeps_distinct_retry_selections(self):
        self.retained_reports()
        with patch.object(h.time, "time", return_value=100):
            old = self.snapshot("old-fail")
            new = self.snapshot("new-pass")
            cached_old = self.snapshot("old-fail")
        self.assertIs(cached_old, old)
        self.assertIsNot(new, old)
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)
        self.assertEqual(cached_old["health"]["observed_at"], "original-observation")

    def test_overwritten_convenience_report_cannot_replace_missing_old_execution_report(self):
        from botocore.exceptions import ClientError
        self.retained_reports()
        new_doc = fixtures.report(execution_id="new-pass", revision=SHA)
        self.s3.get_object.side_effect = [
            ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject"),
            {"Body": io.BytesIO(json.dumps(new_doc).encode())}]
        with patch.object(h, "_build_report", return_value=None):
            snap = self.snapshot("old-fail")
        self.assertEqual(snap["review_evidence"]["tier1"]["state"], "unavailable")
        self.assertIsNone(snap["findings"]["tier1"])

    def test_http_handler_forwards_execution_selector(self):
        with patch.object(h, "build_snapshot", return_value={}) as build:
            result = h.lambda_handler({"rawPath": "/api/snapshot",
                "requestContext": {"authorizer": {"jwt": {"claims": {"sub": "user-1"}}}},
                "queryStringParameters": {"execution": "old-fail", "commit": SHA, "review_build": "old-build",
                                          "repo": "artifact", "pr": "7"}}, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(build.call_args.kwargs["execution_id"], "old-fail")
        self.assertEqual(build.call_args.kwargs["review_build"], "old-build")
        self.assertEqual(build.call_args.args[:3], (SHA, 7, "artifact"))

if __name__ == "__main__":
    unittest.main()


class ConsoleSelectionTests(unittest.TestCase):
    """Deep links retain selected execution identity."""

    def test_execution_console_link_is_not_the_latest_pipeline_view(self):
        """A historical action opens its exact execution in the console."""
        url = h._console("agentic-gates-tier1-road", "selected-run")
        self.assertIn("/executions/selected-run/visualization?", url)
        self.assertNotIn("/view?", url)

    def test_console_identifiers_are_url_encoded(self):
        """Unexpected identifier delimiters cannot alter the console path."""
        self.assertIn("run%2Fname%3Fx%3D1", h._console("p", "run/name?x=1"))
