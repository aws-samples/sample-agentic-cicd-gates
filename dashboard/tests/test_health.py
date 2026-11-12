"""Health evidence must identify the deployment, not borrow today's green alarm."""
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from health import HealthReader, paged


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.cfn, self.cd, self.cw, self.fn = [Mock() for _ in range(4)]
        self.reader = HealthReader(self.cfn, self.cd, self.cw, self.fn, "us-west-2")
        self.now = datetime.now(timezone.utc)
        self.start = self.now - timedelta(minutes=10)
        self.end = self.now - timedelta(minutes=2)
        self.pipeline = {"execution_id": "run-a", "stages": [{"name": "Deploy", "actions": [
            {"name": "ExecuteChangeSet", "status": "Succeeded",
             "started": self.start.isoformat(), "when": self.end.isoformat()}]}]}
        self.reader.resources["stack"] = {"function": "fn", "alarm": "alarm",
                                            "application": "app", "group": "group"}
        self.fn.get_alias.return_value = {"FunctionVersion": "70"}
        self.fn.get_function_configuration.side_effect = lambda **kw: {
            "Environment": {"Variables": {"DEMO_REVISION": {
                "68": "old", "69": "selected", "70": "new"}[kw["Qualifier"]]}}}
        self.cw.describe_alarms.return_value = {"MetricAlarms": [{
            "AlarmName": "alarm", "StateValue": "OK", "StateReason": "Current zero errors",
            "StateUpdatedTimestamp": self.now}]}
        self.cw.describe_alarm_history.return_value = {"AlarmHistoryItems": [{
            "Timestamp": self.start + timedelta(minutes=3),
            "HistorySummary": "OK to ALARM",
            "HistoryData": json.dumps({"newState": {"stateValue": "ALARM"}})}]}
        self.cd.list_deployments.return_value = {"deployments": ["d-a"]}
        self.deployments = {"d-a": {
            "deploymentId": "d-a", "applicationName": "app", "deploymentGroupName": "group",
            "createTime": self.start + timedelta(seconds=1), "completeTime": self.end,
            "status": "Succeeded"}}
        self.cd.get_deployment.side_effect = lambda **kw: {
            "deploymentInfo": self.deployments[kw["deploymentId"]]}
        self.cd.list_deployment_targets.return_value = {"targetIds": ["target"]}
        self.cd.get_deployment_target.side_effect = lambda **kw: {"deploymentTarget": {
            "lambdaTarget": {"lambdaFunctionInfo": {
                "functionName": "fn", "functionAlias": "live", "currentVersion": "68",
                "targetVersion": "69"}}}}

    def test_completed_historical_deployment_keeps_current_alias_separate(self):
        r = self.reader.read(self.pipeline, "selected", "stack")
        self.assertEqual(r["state"], "completed")
        self.assertEqual(r["deployment"]["target_version"], "69")
        self.assertEqual(r["current"]["version"], "70")
        self.assertFalse(r["current"]["matches_selected_revision"])
        self.assertEqual(r["alarms"][0]["state"], "OK")
        self.assertEqual(r["alarms"][0]["transitions"][0]["state"], "ALARM")
        self.assertEqual(self.cw.describe_alarm_history.call_args.kwargs["EndDate"], self.end)

    def test_alarm_rollback_uses_recorded_relationship_despite_alarm_ok_now(self):
        self.deployments["d-a"].update(status="Stopped", errorInformation={"code": "ALARM_ACTIVE"},
                                        rollbackInfo={"rollbackDeploymentId": "d-rollback"})
        self.deployments["d-rollback"] = {
            **self.deployments["d-a"], "status": "Succeeded", "creator": "codeDeployRollback",
            "rollbackInfo": {"rollbackTriggeringDeploymentId": "d-a"}}
        self.cd.list_deployments.return_value = {"deployments": ["d-rollback", "d-a"]}
        r = self.reader.read(self.pipeline, "selected", "stack")
        self.assertEqual(r["state"], "rolled_back")
        self.assertEqual(r["label"], "Alarm rollback succeeded")
        self.assertEqual(r["rollback"]["target_version"], "68")
        self.assertEqual(r["current"]["version"], "70")

    def test_rollback_relationship_cannot_point_at_another_execution(self):
        self.deployments["d-a"]["rollbackInfo"] = {"rollbackDeploymentId": "d-rollback"}
        self.deployments["d-rollback"] = {
            **self.deployments["d-a"], "creator": "codeDeployRollback",
            "rollbackInfo": {"rollbackTriggeringDeploymentId": "some-other-run"}}
        self.assertEqual(self.reader.read(self.pipeline, "selected", "stack")["state"], "unavailable")

    def test_unknown_revision_cannot_borrow_a_deployment(self):
        r = self.reader.read(self.pipeline, "different", "stack")
        self.assertEqual(r["state"], "unavailable")
        self.assertNotIn("deployment", r)

    def test_outside_action_interval_is_not_same_execution(self):
        self.deployments["d-a"]["createTime"] = self.start - timedelta(seconds=1)
        self.assertEqual(self.reader.read(self.pipeline, "selected", "stack")["state"], "unavailable")

    def test_two_matching_candidates_are_ambiguous_not_green(self):
        self.cd.list_deployments.return_value = {"deployments": ["d-a", "d-b"]}
        self.deployments["d-b"] = dict(self.deployments["d-a"])
        self.assertEqual(self.reader.read(self.pipeline, "selected", "stack")["state"], "unavailable")

    def test_deployment_not_reached_is_not_missing_cloudwatch(self):
        self.pipeline["stages"][0]["actions"][0]["status"] = "NotStarted"
        r = self.reader.read(self.pipeline, "selected", "stack")
        self.assertEqual(r["state"], "not_started")
        self.assertEqual(r["label"], "Not reached")
        self.cw.describe_alarms.assert_not_called()

    def test_alarm_read_error_is_visible(self):
        self.cw.describe_alarms.side_effect = RuntimeError("AccessDenied")
        r = self.reader.read(self.pipeline, "selected", "stack")
        self.assertEqual(r["state"], "unavailable")
        self.assertIn("AccessDenied", r["errors"][0])

    def test_target_starting_has_current_observations_without_invented_deployment(self):
        self.pipeline["stages"][0]["actions"][0]["status"] = "InProgress"
        self.cd.list_deployments.return_value = {"deployments": []}
        r = self.reader.read(self.pipeline, "selected", "stack")
        self.assertEqual(r["label"], "Deployment starting")
        self.assertNotIn("deployment", r)

    def test_other_target_is_not_applicable(self):
        self.assertEqual(self.reader.read(self.pipeline, "selected")["state"], "not_applicable")

    def test_uppercase_cloudwatch_pagination_and_repeat_detection(self):
        call = Mock(side_effect=[{"items": [], "NextToken": "next"}, {"items": [1]}])
        self.assertEqual(paged(call, "items", "NextToken"), [1])
        self.assertEqual(call.call_args.kwargs, {"NextToken": "next"})
        with self.assertRaises(ValueError):
            paged(Mock(return_value={"items": [], "NextToken": "repeat"}), "items", "NextToken")


if __name__ == "__main__":
    unittest.main()
