"""Read actual deployment/CloudWatch evidence without confusing past and present."""
from datetime import datetime, timezone
import json
import time
from urllib.parse import quote


def timestamp(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def iso(value):
    return timestamp(value).isoformat() if value else None


def paged(call, key, token_key="nextToken", **kwargs):
    result, token, seen = [], None, set()
    for _ in range(20):
        page = call(**kwargs, **({token_key: token} if token else {}))
        result.extend(page.get(key, []))
        token = page.get(token_key)
        if not token:
            return result
        if token in seen:
            raise ValueError("Repeated health evidence pagination token")
        seen.add(token)
    raise ValueError("Health evidence pagination incomplete")


class HealthReader:
    def __init__(self, cfn, deploy, cloudwatch, functions, region):
        self.cfn, self.deploy, self.cw, self.functions = cfn, deploy, cloudwatch, functions
        self.region = region
        self.cache = {}
        self.resources = {}

    def console(self, deployment_id):
        return (f"https://{self.region}.console.aws.amazon.com/codesuite/codedeploy/"
                f"deployments/{quote(deployment_id)}?region={self.region}")

    def resource_ids(self, stack):
        if stack not in self.resources:
            rows = paged(self.cfn.list_stack_resources, "StackResourceSummaries",
                         "NextToken", StackName=stack)
            by_name = {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in rows}
            by_type = {r["ResourceType"]: r["PhysicalResourceId"] for r in rows}
            self.resources[stack] = {
                "function": by_name["HelloFn"],
                "alarm": by_name["HelloErrorsAlarm"],
                "application": by_type["AWS::CodeDeploy::Application"],
                "group": by_type["AWS::CodeDeploy::DeploymentGroup"],
            }
        return self.resources[stack]

    def target(self, deployment_id, function):
        ids = paged(self.deploy.list_deployment_targets, "targetIds", deploymentId=deployment_id)
        matches = []
        for target_id in ids:
            response = self.deploy.get_deployment_target(
                deploymentId=deployment_id, targetId=target_id)
            info = response["deploymentTarget"].get("lambdaTarget", {}).get("lambdaFunctionInfo", {})
            if info.get("functionName") == function and info.get("functionAlias") == "live":
                matches.append(info)
        if len(matches) != 1:
            raise ValueError("Expected exactly one matching Lambda alias deployment target")
        return matches[0]

    def read(self, pipeline, revision, stack=None, target=None):
        """Read the selected target's execution-bound deployment and health evidence."""
        if target and target.get("health_kind") == "codebuild":
            return self.read_codebuild(pipeline, revision, target)
        action = next((a for s in pipeline.get("stages", []) if s["name"] == "Deploy"
                       for a in s["actions"] if a["name"] == "ExecuteChangeSet"), None)
        key = (pipeline.get("execution_id"), revision, stack, json.dumps(action, sort_keys=True))
        cached = self.cache.get(key)
        if cached and time.monotonic() - cached[0] < 15:
            return cached[1]
        now = datetime.now(timezone.utc)
        result = {
            "state": "unavailable", "label": "Evidence unavailable",
            "reason": "", "execution_id": pipeline.get("execution_id"),
            "revision": revision, "observed_at": now.isoformat(), "alarms": [], "errors": [],
        }
        try:
            if not stack:
                result.update(state="not_applicable", label="Different deployment target",
                              reason="This repository does not deploy the Troy Lambda alias.")
            elif pipeline.get("error") or not pipeline.get("execution_id"):
                raise ValueError("Selected pipeline execution evidence is unavailable")
            elif not action or action.get("status") == "NotStarted":
                result.update(state="not_started", label="Not reached",
                              reason="This execution did not reach the deployment action; it has no canary health result.")
            elif action.get("status") == "Unavailable" or not action.get("started"):
                raise ValueError("Deployment action identity or start time is unavailable")
            else:
                self.populate(result, action, revision, self.resource_ids(stack), now)
        except Exception as exc:
            result.update(state="unavailable", label="Evidence unavailable",
                          reason="Could not complete the selected deployment's health evidence.")
            result["errors"].append(f"{type(exc).__name__}: {str(exc)[:240]}")
        self.cache[key] = (time.monotonic(), result)
        if len(self.cache) > 32:
            self.cache.pop(next(iter(self.cache)))
        return result

    def read_codebuild(self, pipeline, revision, target):
        """Describe the selected CDK build, without inventing a Lambda canary."""
        result = {
            "state": "unavailable", "label": "Evidence unavailable",
            "reason": "", "execution_id": pipeline.get("execution_id"),
            "revision": revision, "repo": target["key"],
            "service": "AWS CodeBuild", "target": target["deploy_target"],
            "kind": "codebuild", "observed_at": datetime.now(timezone.utc).isoformat(),
            "alarms": [], "errors": [],
        }
        try:
            if pipeline.get("error") or not pipeline.get("execution_id") or not revision:
                raise ValueError("Selected pipeline execution and revision are required")
            if pipeline.get("name") != target.get("pipeline"):
                raise ValueError("Selected pipeline belongs to another deployment target")
            actions = [a for s in pipeline.get("stages", []) if s["name"] == "Deploy"
                       for a in s["actions"] if a["name"] == target["deploy_action"]]
            if len(actions) != 1:
                raise ValueError("Selected pipeline's dashboard deployment action is unavailable")
            action = actions[0]
            if action.get("status") == "NotStarted":
                result.update(state="not_started", label="Not reached",
                              reason="This execution did not reach the dashboard deployment action.")
                return result
            build_id = action.get("external_id", "")
            prefix = target["deploy_project"] + ":"
            if not (isinstance(build_id, str) and build_id.startswith(prefix)
                    and len(build_id) > len(prefix) and action.get("action_execution_id")
                    and action.get("started")):
                raise ValueError("Deployment build identity is missing or belongs to another target")
            if action.get("provider") != "CodeBuild":
                raise ValueError("Selected deployment action is not an AWS CodeBuild action")
            status = action.get("status")
            states = {"Succeeded": ("completed", "Deployment succeeded"),
                      "Failed": ("failed", "Deployment failed"),
                      "Abandoned": ("failed", "Deployment abandoned"),
                      "InProgress": ("observing", "Deployment in progress")}
            if status not in states:
                raise ValueError("Selected deployment action status is unavailable")
            state, label = states[status]
            result.update(
                state=state, label=label,
                reason=f"{target['deploy_action']} {status.lower()} for the selected execution. "
                       "This records the dashboard deployment build; runtime health probes "
                       "and a Lambda canary are not configured for this target.",
                binding="Repository + pipeline execution + revision + action execution + CodeBuild build",
                deployment={"id": build_id, "status": status, "service": "AWS CodeBuild",
                            "action_execution_id": action["action_execution_id"],
                            "started": iso(action["started"]),
                            "completed": iso(action.get("when")) if status != "InProgress" else None,
                            "url": action.get("url") or pipeline.get("console")},
            )
        except (KeyError, TypeError, ValueError) as exc:
            result.update(state="unavailable", label="Evidence unavailable",
                          reason="Could not bind dashboard deployment evidence to this selection.")
            result["errors"].append(str(exc))
        return result

    def populate(self, result, action, revision, resources, now):
        start = timestamp(action["started"])
        end = now if action["status"] == "InProgress" else timestamp(action["when"])
        if end < start:
            raise ValueError("Invalid deployment action time interval")
        fn = resources["function"]
        alias = self.functions.get_alias(FunctionName=fn, Name="live")
        config = self.functions.get_function_configuration(FunctionName=fn, Qualifier=alias["FunctionVersion"])
        live_revision = config.get("Environment", {}).get("Variables", {}).get("DEMO_REVISION")
        result["current"] = {
            "alias": "live", "version": alias["FunctionVersion"], "revision": live_revision,
            "weights": alias.get("RoutingConfig", {}).get("AdditionalVersionWeights", {}),
            "matches_selected_revision": bool(revision and live_revision == revision),
        }
        alarms = self.cw.describe_alarms(AlarmNames=[resources["alarm"]])["MetricAlarms"]
        if len(alarms) != 1:
            raise ValueError("Configured CloudWatch alarm was not returned")
        alarm = alarms[0]
        history = paged(self.cw.describe_alarm_history, "AlarmHistoryItems", "NextToken",
                        AlarmName=alarm["AlarmName"], HistoryItemType="StateUpdate",
                        StartDate=start, EndDate=end)
        transitions = []
        for item in history:
            data = json.loads(item.get("HistoryData", "{}"))
            transitions.append({
                "at": iso(item["Timestamp"]),
                "state": data.get("newState", {}).get("stateValue", "UNKNOWN"),
                "summary": item.get("HistorySummary", ""),
            })
        result["alarms"] = [{
            "name": alarm["AlarmName"], "state": alarm["StateValue"],
            "reason": alarm.get("StateReason", ""), "updated": iso(alarm.get("StateUpdatedTimestamp")),
            "url": (f"https://{self.region}.console.aws.amazon.com/cloudwatch/home?region={self.region}"
                    f"#alarmsV2:alarm/{quote(alarm['AlarmName'], safe='')}"),
            "transitions": sorted(transitions, key=lambda t: t["at"]),
        }]
        ids = paged(self.deploy.list_deployments, "deployments",
                    applicationName=resources["application"], deploymentGroupName=resources["group"],
                    createTimeRange={"start": start, "end": end})
        matches = []
        for deployment_id in ids:
            info = self.deploy.get_deployment(deploymentId=deployment_id)["deploymentInfo"]
            # Lambda rollback target metadata retains the failed AppSpec's
            # current/target pair. It must not become a second candidate release.
            if (info.get("creator") == "codeDeployRollback" or
                    info.get("rollbackInfo", {}).get("rollbackTriggeringDeploymentId")):
                continue
            # Do not trust service-side range filtering alone.
            if not start <= timestamp(info["createTime"]) <= end:
                continue
            if info.get("applicationName") != resources["application"] or info.get("deploymentGroupName") != resources["group"]:
                continue
            target = self.target(deployment_id, fn)
            candidate = self.functions.get_function_configuration(
                FunctionName=fn, Qualifier=str(target["targetVersion"]))
            candidate_revision = candidate.get("Environment", {}).get("Variables", {}).get("DEMO_REVISION")
            if not revision or candidate_revision != revision:
                continue
            matches.append((deployment_id, info, target))
        if not matches and action["status"] == "InProgress":
            result.update(state="observing", label="Deployment starting",
                          reason="The selected CloudFormation action is running; no matching CodeDeploy traffic shift has started yet.")
            return
        if len(matches) != 1:
            raise ValueError(f"Expected one deployment matching action interval, application, alias and revision; found {len(matches)}")
        deployment_id, info, target = matches[0]
        alarm_triggered = info.get("errorInformation", {}).get("code") == "ALARM_ACTIVE"
        result["binding"] = "Selected action time interval + CodeDeploy application/group + Lambda alias + candidate DEMO_REVISION."
        result["deployment"] = {
            "id": deployment_id, "status": info["status"], "url": self.console(deployment_id),
            "original_version": str(target["currentVersion"]), "target_version": str(target["targetVersion"]),
            "started": iso(info.get("createTime")), "completed": iso(info.get("completeTime")),
            "alarm_triggered": alarm_triggered,
        }
        rollback_id = info.get("rollbackInfo", {}).get("rollbackDeploymentId")
        if rollback_id:
            rollback = self.deploy.get_deployment(deploymentId=rollback_id)["deploymentInfo"]
            rollback_target = self.target(rollback_id, fn)
            if (rollback.get("applicationName") != resources["application"] or
                    rollback.get("deploymentGroupName") != resources["group"] or
                    rollback.get("creator") != "codeDeployRollback" or
                    rollback.get("rollbackInfo", {}).get("rollbackTriggeringDeploymentId") != deployment_id):
                raise ValueError("Rollback identity differs from selected deployment")
            # A successful automatic rollback restores the original version.
            # AWS retains targetVersion=failed candidate even on this rollback's
            # Lambda target record, so displaying that as the restored version
            # would be wrong. Current alias evidence remains separately labelled.
            result["rollback"] = {"id": rollback_id, "status": rollback["status"],
                                  "url": self.console(rollback_id),
                                  "target_version": str(target["currentVersion"])}
            if rollback["status"] == "Succeeded":
                result.update(state="rolled_back",
                              label="Alarm rollback succeeded" if alarm_triggered else "Rollback succeeded",
                              reason="The selected deployment rolled back. Current alarm and live-alias readings below are observed now, not historical health claims.")
            else:
                result.update(state="observing", label="Rollback " + rollback["status"],
                              reason="The selected deployment is being recovered; inspect the linked rollback.")
        elif info["status"] == "Succeeded":
            result.update(state="completed", label="Deployment completed",
                          reason="CodeDeploy completed this candidate. The alarm state and live alias below are current observations, not a guarantee of application health.")
        elif info["status"] in ("Failed", "Stopped"):
            result.update(state="failed", label="Deployment " + info["status"].lower(),
                          reason=info.get("errorInformation", {}).get("message", "Inspect the selected deployment failure."))
        else:
            result.update(state="observing", label="Canary in progress",
                          reason="The selected traffic shift is active. Observe the current alarm and alias weights below.")
        if (now - start).days >= 30:
            result["errors"].append("Historical CloudWatch alarm transitions may be outside the 30-day retention window.")
