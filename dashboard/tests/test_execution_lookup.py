"""Execution lookup limits and honest selection states; no network calls."""
import unittest
from unittest.mock import patch

import test_evidence as fixtures
from test_evidence import h, SHA, OTHER


def summary(sha, execution):
    return {"pipelineExecutionId": execution, "status": "Succeeded",
            "sourceRevisions": [{"revisionId": sha}]}


class ExecutionLookupTests(unittest.TestCase):
    setUp = fixtures.EvidenceTests.setUp

    def snapshot(self):
        with patch.object(h, "_pipeline_view", return_value=({"stages": []}, None, None)), \
             patch.object(h, "_exec_for", return_value=None), \
             patch.object(h, "_execution_findings", return_value=(None, {"state": "unavailable"})), \
             patch.object(h, "_health") as health, \
             patch.object(h, "_pr_surface", return_value={"open": []}):
            health.read.return_value = {"state": "unavailable", "observed_at": "actual-observation"}
            return h.build_snapshot(commit_sha=SHA)

    def test_target_on_first_page_avoids_unneeded_history_and_selects_latest_retry(self):
        self.cp.list_pipeline_executions.side_effect = [
            {"pipelineExecutionSummaries": [summary(SHA, "new-retry"), summary(SHA, "old")],
             "nextToken": "unneeded"},
            RuntimeError("older history throttled"),
        ]
        self.assertEqual(h._exec_for("p", SHA), "new-retry")
        self.cp.list_pipeline_executions.assert_called_once()
        self.assertNotIn("p_executions", h._last_errors)

    def test_empty_page_is_followed_but_pages_after_match_are_not(self):
        self.cp.list_pipeline_executions.side_effect = [
            {"pipelineExecutionSummaries": [], "nextToken": "second"},
            {"pipelineExecutionSummaries": [summary(SHA, "selected")], "nextToken": "unneeded"},
            RuntimeError("must not read"),
        ]
        self.assertEqual(h._exec_for("p", SHA), "selected")
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)
        self.assertEqual(self.cp.list_pipeline_executions.call_args.kwargs["nextToken"], "second")

    def test_new_same_sha_retry_is_not_pinned_to_cached_identity(self):
        self.cp.list_pipeline_executions.side_effect = [
            {"pipelineExecutionSummaries": [summary(SHA, "first")]},
            {"pipelineExecutionSummaries": [summary(SHA, "retry"), summary(SHA, "first")]},
        ]
        self.assertEqual(h._exec_for("p", SHA), "first")
        self.assertEqual(h._exec_for("p", SHA), "retry")

    def test_absence_requires_successful_exhaustion_not_first_page_miss(self):
        self.cp.list_pipeline_executions.side_effect = [
            {"pipelineExecutionSummaries": [summary(OTHER, "other")], "nextToken": "second"},
            {"pipelineExecutionSummaries": []},
        ]
        snap = self.snapshot()
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)
        self.assertEqual(snap["selection_state"], "not_found")
        self.assertEqual(snap["selection_error"], "No retained execution found for requested revision")
        self.assertIsNone(snap["execution"])

    def test_throttle_after_partial_history_is_unavailable_not_absent(self):
        from botocore.exceptions import ClientError
        self.cp.list_pipeline_executions.side_effect = [
            {"pipelineExecutionSummaries": [summary(OTHER, "other")], "nextToken": "second"},
            ClientError({"Error": {"Code": "ThrottlingException", "Message": "rate limited"}},
                        "ListPipelineExecutions"),
        ]
        snap = self.snapshot()
        self.assertEqual(snap["selection_state"], "unavailable")
        self.assertIn("ThrottlingException", snap["selection_error"])
        self.assertIn("agentic-gates-tier1_executions", snap["degraded"])
        self.assertEqual(snap["commits"], [])
        self.assertIsNone(snap["commit"])
        self.assertIsNone(snap["execution"])
        self.assertIsNone(snap["findings"]["tier1"])

    def test_repeated_token_is_unavailable_not_absent(self):
        self.cp.list_pipeline_executions.return_value = {
            "pipelineExecutionSummaries": [], "nextToken": "again"}
        snap = self.snapshot()
        self.assertEqual(snap["selection_state"], "unavailable")
        self.assertIn("pagination token repeated", snap["selection_error"])
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)

    def test_page_budget_remains_bounded(self):
        from evidence import IncompleteEvidence
        self.cp.list_pipeline_executions.side_effect = [
            {"nextToken": "one"}, {"nextToken": "two"}, {"nextToken": "three"}]
        with self.assertRaisesRegex(IncompleteEvidence, "exceeds 2 pages"):
            h._execution_summaries("p", SHA, max_pages=2)
        self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)

    def test_retry_after_failure_clears_error_and_selects_real_execution(self):
        self.cp.list_pipeline_executions.side_effect = [
            RuntimeError("unavailable"),
            {"pipelineExecutionSummaries": [summary(SHA, "recovered")]},
        ]
        self.assertEqual(self.snapshot()["selection_state"], "unavailable")
        h._cache.clear()
        recovered = self.snapshot()
        self.assertEqual(recovered["selection_state"], "selected")
        self.assertEqual(recovered["execution"], "recovered")
        self.assertIsNone(recovered["selection_error"])
        self.assertNotIn("agentic-gates-tier1_executions", recovered["degraded"])

    def test_slow_snapshot_can_be_reused_without_retimestamping_health(self):
        self.cp.list_pipeline_executions.return_value = {
            "pipelineExecutionSummaries": [summary(SHA, "selected")]}
        # First assembly takes 10 seconds: reuse must be measured from completion.
        with patch.object(h.time, "time", side_effect=[100, 110, 111, 114, 116]):
            first = self.snapshot()
            cached = self.snapshot()
            self.assertIs(cached, first)
            self.assertEqual(self.cp.list_pipeline_executions.call_count, 1)
            self.assertEqual(cached["health"]["observed_at"], "actual-observation")
            self.assertEqual(cached["generated_at"], first["generated_at"])
            refreshed = self.snapshot()
            self.assertIsNot(refreshed, first)
            self.assertEqual(self.cp.list_pipeline_executions.call_count, 2)


if __name__ == "__main__":
    unittest.main()
