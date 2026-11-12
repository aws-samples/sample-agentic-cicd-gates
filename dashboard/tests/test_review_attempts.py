"""In-place Review retries keep current and selected historical builds isolated."""
import io
import json
import unittest
from unittest.mock import patch
from botocore.exceptions import ClientError

import test_evidence as fixtures
from test_evidence import h, SHA
from test_execution_lookup import summary

EXECUTION = "one-execution"
NEW = "agentic-gates-tier1-review:new-build"
OLD = "agentic-gates-tier1-review:old-build"


def document(build, verdict="PASS"):
    doc = fixtures.report(execution_id=EXECUTION, build_id=build, revision=SHA, verdict=verdict)
    if verdict == "FAIL":
        doc["agents"][0]["verdict"] = "FAIL"
    return doc


def key(build):
    return f"executions/{EXECUTION}/builds/{build}/findings.json"


class ReviewAttemptTests(unittest.TestCase):
    def setUp(self):
        fixtures.EvidenceTests.setUp(self)
        self.cp.list_pipeline_executions.return_value = {
            "pipelineExecutionSummaries": [summary(SHA, EXECUTION)]}
        self.cp.get_pipeline_state.return_value = {"stageStates": [{
            "name": "ignored", "stageName": "AutomatedGates",
            "actionStates": [{"actionName": "Review"}]}]}
        self.rows = [{
            "pipelineExecutionId": EXECUTION, "actionExecutionId": action,
            "stageName": "AutomatedGates", "actionName": "Review", "status": status,
            "startTime": "2026-10-03T01:00:00Z" if action == "new-action" else "2026-10-03T00:00:00Z",
            "lastUpdateTime": "2026-10-03T01:02:00Z" if action == "new-action" else "2026-10-03T00:02:00Z",
            "output": {"executionResult": {"externalExecutionId": build,
                       "externalExecutionUrl": f"https://fixture.invalid/build/{action}"}},
        } for action, build, status in [("new-action", NEW, "Succeeded"), ("old-action", OLD, "Failed")]]
        self.cp.list_action_executions.return_value = {"actionExecutionDetails": self.rows}
        self.objects = {key(NEW): document(NEW),
                        key(OLD): document(OLD, "FAIL"),
                        f"executions/{EXECUTION}/findings.json": document(NEW)}
        self.read_keys = []
        def get(**kwargs):
            path = kwargs["Key"]
            self.read_keys.append(path)
            if path not in self.objects:
                raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
            return {"Body": io.BytesIO(json.dumps(self.objects[path]).encode())}
        self.s3.get_object.side_effect = get

    def snapshot(self, build=None):
        with patch.object(h, "_reports_bucket", return_value="bucket"), \
             patch.object(h, "_pr_surface", return_value={"open": []}), \
             patch.object(h, "_health") as health:
            health.read.return_value = {"state": "unavailable", "observed_at": "actual-observation"}
            return h.build_snapshot(execution_id=EXECUTION, review_build=build)

    def test_old_failure_remains_separate_after_same_execution_pass(self):
        snap = self.snapshot(OLD)
        self.assertEqual(snap["execution_status"], "Succeeded")
        self.assertEqual(snap["findings"]["tier1"]["verdict"], "PASS")
        self.assertEqual(snap["review_evidence"]["tier1"]["state"], "passed")
        self.assertEqual(snap["review_attempt"]["report"]["verdict"], "FAIL")
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "blocked")
        self.assertEqual(snap["selected_review_build"], OLD)
        self.assertEqual([(a["build_id"], a["is_current"], a["status"]) for a in snap["review_attempts"]],
                         [(NEW, True, "Succeeded"), (OLD, False, "Failed")])
        self.assertEqual(snap["review_attempts"][1]["action_execution_id"], "old-action")
        self.assertEqual(snap["review_attempts_evidence"]["state"], "available")
        self.assertEqual(self.read_keys, [key(NEW), key(OLD)])
        self.cp.list_action_executions.assert_called_once()

    def test_reversed_rows_still_choose_new_pass_and_preserve_old_failure(self):
        self.rows.reverse()
        snap = self.snapshot(OLD)
        self.assertEqual(snap["findings"]["tier1"]["verdict"], "PASS")
        self.assertEqual(snap["review_attempt"]["report"]["verdict"], "FAIL")
        self.assertEqual([(a["build_id"], a["is_current"]) for a in snap["review_attempts"]],
                         [(NEW, True), (OLD, False)])
        self.assertEqual(snap["pipelines"]["agentic-gates-tier1"]["stages"][0]["status"], "Succeeded")
        self.cp.list_action_executions.assert_called_once()

    def test_later_old_update_or_stale_live_pointer_does_not_override_new_start(self):
        self.rows[1]["lastUpdateTime"] = "2026-10-03T02:00:00Z"
        self.cp.get_pipeline_state.return_value["stageStates"][0]["actionStates"][0]["latestExecution"] = {
            "actionExecutionId": "old-action"}
        self.rows.reverse()
        snap = self.snapshot()
        self.assertEqual(snap["findings"]["tier1"]["verdict"], "PASS")
        self.assertEqual([a["build_id"] for a in snap["review_attempts"] if a["is_current"]], [NEW])

    def test_missing_or_tied_starts_leave_current_unknown_but_exact_attempt_readable(self):
        for start in [None, "2026-10-03T01:00:00Z", "not-a-date", "2026-10-03T02:00:00"]:
            with self.subTest(start=start):
                h._cache.clear()
                self.rows[1]["startTime"] = start
                snap = self.snapshot(OLD)
                self.assertIsNone(snap["findings"]["tier1"])
                self.assertEqual(snap["review_evidence"]["tier1"]["state"], "unavailable")
                self.assertEqual(snap["review_attempts_evidence"]["state"], "unavailable")
                self.assertFalse(any(a["is_current"] for a in snap["review_attempts"]))
                self.assertEqual(snap["review_attempt"]["report"]["verdict"], "FAIL")
                if start is None:
                    self.assertNotIn("started", next(a for a in snap["review_attempts"] if a["build_id"] == OLD))

    def test_matching_live_id_can_resolve_missing_timestamps_only_within_execution(self):
        for row in self.rows:
            row.pop("startTime")
        live = {"actionExecutionId": "foreign-action"}
        self.cp.get_pipeline_state.return_value["stageStates"][0]["actionStates"][0]["latestExecution"] = live
        snap = self.snapshot()
        self.assertIsNone(snap["findings"]["tier1"])
        self.assertFalse(any(a["is_current"] for a in snap["review_attempts"]))
        h._cache.clear()
        live["actionExecutionId"] = "new-action"
        self.rows.reverse()
        snap = self.snapshot()
        self.assertEqual(snap["findings"]["tier1"]["verdict"], "PASS")
        self.assertEqual([a["build_id"] for a in snap["review_attempts"] if a["is_current"]], [NEW])
        self.assertTrue(all("started" not in a for a in snap["review_attempts"]))

    def test_metadata_listing_does_not_fetch_old_reports_without_selection(self):
        snap = self.snapshot()
        self.assertEqual(len(snap["review_attempts"]), 2)
        self.assertNotIn("review_attempt", snap)
        self.assertIsNone(snap["selected_review_build"])
        self.assertEqual(self.read_keys, [key(NEW)])

    def test_selecting_current_attempt_reuses_current_report(self):
        snap = self.snapshot(NEW)
        self.assertIs(snap["review_attempt"]["report"], snap["findings"]["tier1"])
        self.assertEqual(self.read_keys, [key(NEW)])

    def test_foreign_build_is_not_fetched(self):
        foreign = "agentic-gates-tier1-road-review:foreign"
        snap = self.snapshot(foreign)
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "unavailable")
        self.assertIsNone(snap["review_attempt"]["report"])
        self.assertEqual(self.read_keys, [key(NEW)])  # only the normal current read
        self.logs.filter_log_events.assert_not_called()

    def test_unknown_build_selector_alone_never_becomes_a_storage_path(self):
        result = h._selected_review_attempt(
            {"name": "agentic-gates-tier1", "execution_id": EXECUTION, "review_attempts": []},
            SHA, "../foreign", None, {})
        self.assertEqual(result["evidence"]["state"], "unavailable")
        self.s3.get_object.assert_not_called()
        self.logs.filter_log_events.assert_not_called()

    def test_mutable_new_pass_cannot_replace_old_failure_and_exact_logs_recover_it(self):
        del self.objects[key(OLD)]
        self.logs.filter_log_events.return_value = {"events": [{"message": json.dumps(document(OLD, "FAIL"))}]}
        snap = self.snapshot(OLD)
        self.assertEqual(snap["review_attempt"]["report"]["verdict"], "FAIL")
        self.assertEqual(snap["review_attempt"]["evidence"]["source"], f"CodeBuild log: {OLD}")
        self.assertEqual(self.logs.filter_log_events.call_args.kwargs["logStreamNames"], ["old-build"])
        self.assertEqual(self.read_keys, [key(NEW), key(OLD), f"executions/{EXECUTION}/findings.json"])

    def test_execution_identity_without_build_identity_cannot_prove_an_attempt(self):
        del self.objects[key(OLD)]
        self.objects[f"executions/{EXECUTION}/findings.json"].pop("build_id")
        snap = self.snapshot(OLD)
        self.assertIsNone(snap["review_attempt"]["report"])
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "unavailable")
        self.assertEqual(snap["findings"]["tier1"]["verdict"], "PASS")

    def test_compatible_execution_key_requires_matching_build_identity(self):
        del self.objects[key(OLD)]
        self.objects[f"executions/{EXECUTION}/findings.json"] = document(OLD, "FAIL")
        snap = self.snapshot(OLD)
        self.assertEqual(snap["review_attempt"]["report"]["verdict"], "FAIL")
        self.assertEqual(snap["review_attempt"]["evidence"]["source"],
                         f"s3://bucket/executions/{EXECUTION}/findings.json")
        self.logs.filter_log_events.assert_not_called()

    def test_expired_build_archive_is_not_replaced_by_mutable_pass(self):
        self.objects[key(OLD)]["expires_at"] = "2020-01-01T00:00:00Z"
        snap = self.snapshot(OLD)
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "expired")
        self.assertIsNone(snap["review_attempt"]["report"])
        self.assertEqual(self.read_keys, [key(NEW), key(OLD)])

    def test_missing_attempt_archive_and_log_stays_missing(self):
        del self.objects[key(OLD)]
        del self.objects[f"executions/{EXECUTION}/findings.json"]
        snap = self.snapshot(OLD)
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "missing")
        self.assertIsNone(snap["review_attempt"]["report"])

    def test_wrong_build_identity_inside_archive_is_rejected(self):
        self.objects[key(OLD)] = document(NEW)
        snap = self.snapshot(OLD)
        self.assertIsNone(snap["review_attempt"]["report"])
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "unavailable")

    def test_missing_build_metadata_is_explicit_and_does_not_authorize_requested_id(self):
        self.rows[1]["output"] = {}
        snap = self.snapshot(OLD)
        self.assertEqual([a["build_id"] for a in snap["review_attempts"]], [NEW])
        self.assertEqual(snap["review_attempts_evidence"]["state"], "unavailable")
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "unavailable")
        self.assertEqual(self.read_keys, [key(NEW)])
        self.logs.filter_log_events.assert_not_called()

    def test_action_history_error_prevents_archive_or_log_selection(self):
        self.cp.list_action_executions.side_effect = RuntimeError("ThrottlingException")
        snap = self.snapshot(OLD)
        self.assertEqual(snap["review_attempts_evidence"]["state"], "unavailable")
        self.assertIn("ThrottlingException", snap["review_attempt"]["evidence"]["reason"])
        self.assertEqual(self.read_keys, [])
        self.logs.filter_log_events.assert_not_called()
        self.cp.list_action_executions.assert_called_once()

    def test_foreign_execution_action_record_does_not_authorize_build(self):
        self.rows[1]["pipelineExecutionId"] = "different-execution"
        snap = self.snapshot(OLD)
        self.assertEqual(snap["review_attempts"], [])
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "unavailable")
        self.assertEqual(self.read_keys, [])

    def test_live_build_fallback_requires_matching_action_identity(self):
        self.rows[0]["output"] = {}
        live = {"actionExecutionId": "different-action", "externalExecutionId": NEW}
        self.cp.get_pipeline_state.return_value["stageStates"][0]["actionStates"][0]["latestExecution"] = live
        snap = self.snapshot(NEW)
        self.assertEqual(snap["review_attempt"]["evidence"]["state"], "unavailable")
        self.assertEqual(self.read_keys, [])
        h._cache.clear()
        live["actionExecutionId"] = "new-action"
        snap = self.snapshot(NEW)
        self.assertEqual(snap["review_attempt"]["report"]["verdict"], "PASS")

    def test_attempt_selector_is_part_of_snapshot_cache_key(self):
        with patch.object(h.time, "time", return_value=100):
            old = self.snapshot(OLD)
            current = self.snapshot(NEW)
            cached = self.snapshot(OLD)
        self.assertIs(old, cached)
        self.assertIsNot(current, old)
        self.assertEqual(current["review_attempt"]["report"]["verdict"], "PASS")
        self.assertEqual(old["review_attempt"]["report"]["verdict"], "FAIL")
        self.assertEqual(self.cp.list_action_executions.call_count, 2)


if __name__ == "__main__":
    unittest.main()
