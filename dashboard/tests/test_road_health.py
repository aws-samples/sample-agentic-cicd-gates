"""Road deployments use their own selected CodeBuild action, never Troy health."""
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from unittest.mock import Mock

from health import HealthReader


class RoadHealthTests(unittest.TestCase):
    def setUp(self):
        """Create isolated service mocks and one selected road deployment."""
        self.services = [Mock() for _ in range(4)]
        self.reader = HealthReader(*self.services, "us-west-2")
        self.target = {
            "key": "road", "health_kind": "codebuild", "deploy_target": "this board",
            "deploy_action": "DeployDashboard",
            "deploy_project": "agentic-gates-tier1-road-dashboard-deploy",
            "pipeline": "agentic-gates-tier1-road",
        }
        self.action = {
            "name": "DeployDashboard", "status": "Succeeded", "provider": "CodeBuild",
            "action_execution_id": "selected-action",
            "external_id": self.target["deploy_project"] + ":selected-build",
            "started": "2026-10-07T10:00:00Z", "when": "2026-10-07T10:05:00Z",
            "url": "https://console.aws.amazon.com/codebuild/selected-build",
        }
        self.pipeline = {"name": "agentic-gates-tier1-road", "execution_id": "selected-run",
                         "stages": [{"name": "Deploy", "actions": [self.action]}]}

    def read(self):
        """Read health evidence for the configured road deployment fixture."""
        return self.reader.read(self.pipeline, "selected-revision", target=self.target)

    def test_success_bound_to_selected_build_is_not_a_claim_of_runtime_health(self):
        """Keep build success distinct from an unobserved runtime-health result."""
        result = self.read()
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["repo"], "road")
        self.assertEqual(result["execution_id"], "selected-run")
        self.assertEqual(result["revision"], "selected-revision")
        self.assertEqual(result["deployment"]["id"], self.action["external_id"])
        self.assertIn("runtime health probes", result["reason"])
        self.assertNotIn("current", result)
        self.assertEqual(result["alarms"], [])
        for service in self.services:
            self.assertEqual(service.mock_calls, [])

    def test_each_selected_action_status_remains_distinct(self):
        """Preserve not-started, failure, in-progress and unavailable outcomes."""
        for status, state in [("NotStarted", "not_started"), ("Failed", "failed"),
                              ("Abandoned", "failed"), ("InProgress", "observing"),
                              ("Unavailable", "unavailable")]:
            with self.subTest(status=status):
                self.action["status"] = status
                self.assertEqual(self.read()["state"], state)

    def test_wrong_target_build_is_refused(self):
        """Reject build identities from another deployment project."""
        self.action["external_id"] = "agentic-gates-tier1-review:foreign-build"
        self.assertEqual(self.read()["state"], "unavailable")
        self.assertNotIn("deployment", self.read())

    def test_wrong_pipeline_is_refused(self):
        """Reject a deployment action from another repository pipeline."""
        self.pipeline["name"] = "agentic-gates-tier1"
        self.assertEqual(self.read()["state"], "unavailable")

    def test_partial_identity_cannot_become_a_green_deployment(self):
        """Require complete action and build identity before reporting completion."""
        for key in ["action_execution_id", "started", "provider", "external_id"]:
            with self.subTest(key=key):
                value = self.action.pop(key)
                self.assertEqual(self.read()["state"], "unavailable")
                self.action[key] = value

    def test_failed_selection_never_uses_a_deployment(self):
        """Do not expose a deployment when its execution lookup failed."""
        self.pipeline["error"] = "Requested execution was not found"
        self.assertEqual(self.read()["state"], "unavailable")

    def test_missing_deploy_action_is_unavailable(self):
        """Surface a missing deployment action as unavailable evidence."""
        self.pipeline["stages"] = []
        self.assertEqual(self.read()["state"], "unavailable")

    def test_same_revision_retry_uses_each_executions_own_build(self):
        """Keep same-revision retries bound to their separate builds."""
        old = self.read()
        self.pipeline["execution_id"] = "new-run"
        self.action["external_id"] = self.target["deploy_project"] + ":new-build"
        new = self.read()
        self.assertNotEqual(old["execution_id"], new["execution_id"])
        self.assertNotEqual(old["deployment"]["id"], new["deployment"]["id"])
