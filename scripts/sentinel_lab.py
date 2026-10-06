"""Guarded native-preview preparation and exact incident/run acceptance.

Plan locally by default. Deployment creates only disabled components; grant is a
separate action. This helper never enables analytics/automation/workflows and
never grants the tenant Sentinel service account permissions implicitly.
"""
from __future__ import annotations
import argparse
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import uuid
from lab_support import ROOT, assert_owned, az, private_path, save
from trial_state import begin_trial, finish_trial
import manual_executor_trial
import playbook_lab as pb
from sentinel_timing import timestamp, validate_incident_evidence, singleton
from telemetry import workspace_id

sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import ARM, AzureCLI, HTTP, Manifest, SafetyError, guid, load_json, utc_now
from stormlab.__main__ import private_root


def window(start, end):
    a, b = timestamp(start), timestamp(end)
    if not a or not b or not 0 < (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() <= 7200:
        raise SafetyError("Native trial requires an explicit positive UTC window at most two hours")
    return a, b


def planned_state(data, responder, start, end):
    m = Manifest.from_dict(data)
    start, end = window(start, end)
    ids = {key: str(uuid.uuid4()) for key in ("rule", "automation", "group_role", "invoke_role", "group_grant", "reader_grant", "invoke_grant")}
    suffix = m.lab_id.replace("-", "")[:8] + "-" + ids["rule"][:8]
    assets = [ROOT / "detections/sentinel-rule.arm.json", ROOT / "playbooks/sentinel-dispatcher.bicep",
              ROOT / "playbooks/sentinel-dispatcher.workflow.json", ROOT / "playbooks/sentinel-automation.bicep",
              ROOT / "playbooks/sentinel-dispatcher-rbac.bicep", ROOT / "playbooks/dispatcher-role-definitions.bicep"]
    state = {"schema_version": 1, "lab_id": m.lab_id, "subscription_id": m.subscription_id,
            "workspace_id": workspace_id(m), "stage": "planned", "ids": ids,
            "dispatcher_name": "storm3168-dispatcher-" + suffix, "connection_name": "storm3168-sentinel-" + suffix,
            "executor_id": responder["workflow_id"], "assignment": responder["assignment"],
            "not_before_utc": start, "not_after_utc": end, "native_delivery": "not_tested",
            "source_hashes": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in assets}}
    state["resource_ids"] = {key: item[0] for key, item in resources(m, state).items()}
    state["permission_targets"] = permission_targets(m, state)
    return state


def validate_state(m, state):
    if state.get("schema_version") != 1 or state.get("lab_id") != m.lab_id or state.get("subscription_id") != m.subscription_id or state.get("workspace_id") != workspace_id(m):
        raise SafetyError("Native state belongs to a different lab")
    window(state.get("not_before_utc"), state.get("not_after_utc"))
    keys = {"rule", "automation", "group_role", "invoke_role", "group_grant", "reader_grant", "invoke_grant"}
    if set(state.get("ids", {})) != keys:
        raise SafetyError("Native state requires all exact pre-recorded component GUIDs")
    for value in state["ids"].values():
        guid(value, "component UUID")
    if len(set(state["ids"].values())) != len(keys):
        raise SafetyError("Native component UUIDs must be distinct")
    suffix = m.lab_id.replace("-", "")[:8] + "-" + state["ids"]["rule"][:8]
    if state.get("dispatcher_name") != "storm3168-dispatcher-" + suffix or state.get("connection_name") != "storm3168-sentinel-" + suffix:
        raise SafetyError("Native state names do not match the recorded generated IDs")
    if state.get("executor_id") != pb.workflow_path({"subscription_id": m.subscription_id, "resource_group": m.resource_group, "lab_id": m.lab_id}):
        raise SafetyError("Native executor is not the exact lab responder")
    if state.get("assignment") not in m.role_assignments:
        raise SafetyError("Native target assignment is no longer manifest allowlisted")
    if state.get("resource_ids") != {key: item[0] for key, item in resources(m, state).items()} or state.get("permission_targets") != permission_targets(m, state):
        raise SafetyError("Full native resource/permission IDs differ from the recorded plan")


def resources(m, state):
    prefix = workspace_id(m) + "/providers/Microsoft.SecurityInsights/"
    return {"analytic": (prefix + "alertRules/" + state["ids"]["rule"], "2025-09-01"),
            "dispatcher": (m.rg_id + "/providers/Microsoft.Logic/workflows/" + state["dispatcher_name"], "2019-05-01"),
            "connection": (m.rg_id + "/providers/Microsoft.Web/connections/" + state["connection_name"], "2016-06-01"),
            "automation": (prefix + "automationRules/" + state["ids"]["automation"], "2025-09-01")}


def permission_targets(m, state):
    definitions = "/subscriptions/" + m.subscription_id + "/providers/Microsoft.Authorization/roleDefinitions/"
    group_role, invoke_role = definitions + state["ids"]["group_role"], definitions + state["ids"]["invoke_role"]
    assignments = [(m.rg_id, "group_grant", group_role),
                   (workspace_id(m), "reader_grant", definitions + "8d289c81-5878-46d4-8554-54e1e3d8b5cb"),
                   (state["executor_id"], "invoke_grant", invoke_role)]
    return {"role_definition_ids": [group_role, invoke_role], "role_assignments": [
        {"id": scope + "/providers/Microsoft.Authorization/roleAssignments/" + state["ids"][key],
         "scope": scope, "role_definition_id": definition, "principal_id": state.get("dispatcher_object_id")}
        for scope, key, definition in assignments]}


class NativeLab:
    def __init__(self, data, state, http, operator):
        self.data, self.m, self.state, self.http, self.operator = data, Manifest.from_dict(data), state, http, operator
        validate_state(self.m, state)

    def read(self, rid, version, *, method="GET"):
        return self.http.request(method, ARM + rid + "?api-version=" + version, {"Authorization": "Bearer " + self.operator.token("arm")})

    def object(self, rid, version, *, method="GET"):
        result = self.read(rid, version, method=method)
        if result.status != 200 or result.transport_error:
            raise SafetyError("Exact native component metadata unavailable")
        return result.data()

    def preflight(self):
        assert_owned(self.data, self.m.subscription_id)
        workspace = self.object(workspace_id(self.m), "2023-09-01")
        if str(workspace.get("id", "")).lower() != workspace_id(self.m).lower() or workspace.get("tags", {}).get("storm3168LabId") != self.m.lab_id:
            raise SafetyError("Native preview workspace identity/tag mismatch")
        onboard_id = workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/onboardingStates/default"
        onboard = self.object(onboard_id, "2024-03-01")
        if str(onboard.get("id", "")).lower() != onboard_id.lower():
            raise SafetyError("Sentinel onboarding is not verified; no implicit onboarding")
        _, responder, _ = manual_executor_trial.load_bound_state(self.data, self.state["assignment"]["id"])
        pb.check_workflow(self.data, responder, self.http, self.operator, dry_run=True, expected_state="Disabled")

    def absent(self, rid, version):
        result = self.read(rid, version)
        if result.status != 404 or result.transport_error:
            raise SafetyError("Fresh recorded native resource is not proven absent; refusing overwrite/adoption")

    def verify_components(self, *, disabled=True):
        refs = resources(self.m, self.state)
        found = {key: self.object(*value) for key, value in refs.items()}
        for key, obj in found.items():
            if str(obj.get("id", "")).lower() != refs[key][0].lower():
                raise SafetyError("Native resource ID readback mismatch")
        for key in ("dispatcher", "connection"):
            if found[key].get("tags", {}).get("storm3168LabId") != self.m.lab_id:
                raise SafetyError("Native resource lab tag mismatch")
        dispatcher = found["dispatcher"]
        identity, p = dispatcher.get("identity", {}), dispatcher.get("properties", {})
        if identity.get("type") != "SystemAssigned" or str(identity.get("tenantId", "")).lower() != self.m.tenant_id:
            raise SafetyError("Dispatcher identity type/tenant mismatch")
        object_id = guid(identity.get("principalId"), "dispatcher object ID")
        if self.state.get("dispatcher_object_id") and self.state["dispatcher_object_id"] != object_id:
            raise SafetyError("Recorded dispatcher identity changed")
        expected = {"expectedSubscriptionId": self.m.subscription_id, "labId": self.m.lab_id,
                    "resourceGroupId": self.m.rg_id, "workspaceResourceId": workspace_id(self.m),
                    "actorObjectId": self.m.actor["service_principal_object_id"], "analyticRuleResourceId": refs["analytic"][0],
                    "executorResourceId": self.state["executor_id"], "notBeforeUtc": self.state["not_before_utc"], "notAfterUtc": self.state["not_after_utc"],
                    "targetRoleAssignmentId": self.state["assignment"]["id"], "targetRoleDefinitionId": self.state["assignment"]["role_definition_id"], "targetRoleScope": self.state["assignment"]["scope"],
                    "dispatchEnabled": False, "expectedExecutorDryRun": True, "dispatchConfirmation": ""}
        if any(p.get("parameters", {}).get(key, {}).get("value") != value for key, value in expected.items()):
            raise SafetyError("Dispatcher preview configuration drift")
        if disabled and p.get("state") != "Disabled":
            raise SafetyError("Dispatcher must remain Disabled after preparation")
        rule = found["analytic"].get("properties", {})
        body = load_json(ROOT / "detections" / "sentinel-rule.arm.json")["variables"]["queryBody"]
        bindings = [f'let LabResourceGroupId = "{self.m.rg_id}";', f'let ActorObjectId = "{self.m.actor["service_principal_object_id"]}";', f'let ConfiguredLabId = "{self.m.lab_id}";']
        if not rule.get("query", "").endswith(body) or any(binding not in rule["query"] for binding in bindings) or (disabled and rule.get("enabled") is not False):
            raise SafetyError("Analytic query binding or disabled state mismatch")
        binding = found["automation"].get("properties", {})
        logic = binding.get("triggeringLogic", {})
        condition = [{"conditionType": "Property", "conditionProperties": {"propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains", "propertyValues": [refs["analytic"][0]]}}]
        if (logic.get("conditions") != condition or logic.get("triggersOn") != "Incidents" or logic.get("triggersWhen") != "Created"
                or timestamp(logic.get("expirationTimeUtc")) != timestamp(self.state["not_after_utc"])
                or (disabled and logic.get("isEnabled") is not False)
                or len(binding.get("actions", [])) != 1 or binding["actions"][0].get("actionType") != "RunPlaybook"
                or binding["actions"][0].get("actionConfiguration", {}).get("logicAppResourceId") != refs["dispatcher"][0]):
            raise SafetyError("Automation exact-rule/dispatcher binding or expiry mismatch")
        return object_id

    def deploy(self, persist):
        if self.state.get("stage") != "planned":
            raise SafetyError("Deployment was already requested; reconcile instead of repeating an upsert")
        if datetime.now(timezone.utc) >= datetime.fromisoformat(self.state["not_after_utc"]):
            raise SafetyError("Planned native preview window has expired")
        if type(self.data.get("budget_target_usd")) not in {int, float} or not 0 < self.data["budget_target_usd"] <= 10:
            raise SafetyError("Explicit bounded lab budget is required")
        expected_assets = {"detections/sentinel-rule.arm.json", "playbooks/sentinel-dispatcher.bicep", "playbooks/sentinel-dispatcher.workflow.json", "playbooks/sentinel-automation.bicep", "playbooks/sentinel-dispatcher-rbac.bicep", "playbooks/dispatcher-role-definitions.bicep"}
        if set(self.state.get("source_hashes", {})) != expected_assets or any(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != value for p, value in self.state["source_hashes"].items()):
            raise SafetyError("Native templates changed after the reviewed local plan")
        self.preflight()
        for rid, version in resources(self.m, self.state).values():
            self.absent(rid, version)
        self.state["stage"] = "deployment_requested_outcome_unverified"
        persist(self.state)
        common = {"expectedSubscriptionId": self.m.subscription_id, "labId": self.m.lab_id, "workspaceName": self.m.workspace_name}
        assignment = self.state["assignment"]
        definitions = [
            ("analytic", ROOT / "detections/sentinel-rule.arm.json", {"workspaceName": self.m.workspace_name, "labResourceGroupId": self.m.rg_id, "actorObjectId": self.m.actor["service_principal_object_id"], "labId": self.m.lab_id, "ruleId": self.state["ids"]["rule"], "enableRule": False}),
            ("dispatcher", ROOT / "playbooks/sentinel-dispatcher.bicep", {**common, "location": self.m.location, "analyticRuleId": self.state["ids"]["rule"], "dispatcherName": self.state["dispatcher_name"], "connectionName": self.state["connection_name"], "executorName": self.state["executor_id"].rsplit("/", 1)[-1], "actorObjectId": self.m.actor["service_principal_object_id"], "targetRoleAssignmentId": assignment["id"], "targetRoleDefinitionId": assignment["role_definition_id"], "targetRoleScope": assignment["scope"], "notBeforeUtc": self.state["not_before_utc"], "notAfterUtc": self.state["not_after_utc"], "dispatchEnabled": False, "expectedExecutorDryRun": True, "dispatchConfirmation": ""}),
            ("automation", ROOT / "playbooks/sentinel-automation.bicep", {**common, "analyticRuleId": self.state["ids"]["rule"], "dispatcherName": self.state["dispatcher_name"], "automationRuleId": self.state["ids"]["automation"], "expiresAtUtc": self.state["not_after_utc"], "enableAutomationRule": False})]
        for name, template, params in definitions:
            self.preflight()
            for key in (name, "connection") if name == "dispatcher" else (name,):
                self.absent(*resources(self.m, self.state)[key])
            az("deployment", "group", "create", "--subscription", self.m.subscription_id, "--resource-group", self.m.resource_group,
               "--name", "storm3168-" + name + "-" + self.state["ids"]["rule"], "--mode", "Incremental", "--template-file", str(template),
               "--parameters", *[key + "=" + (str(value).lower() if isinstance(value, bool) else str(value)) for key, value in params.items()])
        self.state["dispatcher_object_id"] = self.verify_components()
        self.state["permission_targets"] = permission_targets(self.m, self.state)
        self.state.update(stage="components_deployed_disabled_verified", native_delivery="not_tested")
        persist(self.state)

    def accept_preview(self, incident_uuid, run_name):
        self.preflight()  # Executor remains Disabled/dry-run for this acceptance.
        self.verify_components(disabled=False)
        incident_uuid = guid(incident_uuid, "incident UUID")
        if not isinstance(run_name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", run_name):
            raise SafetyError("Exact dispatcher run name required")
        rid = workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/incidents/" + incident_uuid
        incident = self.object(rid, "2025-09-01")
        alerts = self.object(rid + "/alerts", "2025-09-01", method="POST")
        validated = validate_incident_evidence(self.m, incident, alerts, incident_id=incident_uuid,
            analytic_rule_id=self.state["ids"]["rule"], not_before_utc=self.state["not_before_utc"], not_after_utc=self.state["not_after_utc"])
        run_id = resources(self.m, self.state)["dispatcher"][0] + "/runs/" + run_name
        run = self.object(run_id, "2016-06-01")
        p = run.get("properties", {})
        output = p.get("outputs", {})
        expected = {"incidentId": rid, "providerEventId": validated["event_id"], "dispatchMode": "preview_only"}
        if str(run.get("id", "")).lower() != run_id.lower() or p.get("status") != "Succeeded" or p.get("trigger", {}).get("name") != "Microsoft_Sentinel_incident":
            raise SafetyError("Native dispatcher run identity, trigger or terminal status is unverified")
        if any(output.get(key, {}).get("value") != value for key, value in expected.items()):
            raise SafetyError("Native run is not correlated to the exact incident/provider event")
        started, ended = timestamp(p.get("startTime")), timestamp(p.get("endTime"))
        event_time = timestamp(output.get("providerEventTime", {}).get("value"))
        details = validated["alert_properties"].get("additionalData", {}).get("Custom Details")
        details = json.loads(details) if isinstance(details, str) else details
        if event_time != timestamp(singleton(details, "ProviderEventTime")):
            raise SafetyError("Native run provider clock does not match the exact alert")
        if not started or not ended or not event_time or not self.state["not_before_utc"] <= event_time <= started <= ended <= self.state["not_after_utc"]:
            raise SafetyError("Native preview run/event clocks are outside the recorded trial")
        return {"schema_version": 1, "evidence_type": "native_incident_dispatcher_preview", "observed_at": utc_now(),
                "incident_id": incident_uuid, "provider_event_id": validated["event_id"], "dispatcher_run_id": run_name,
                "dispatcher_started_at": started, "dispatcher_ended_at": ended, "status": "preview_correlated",
                "executor_invoked": False, "role_removal_tested": False, "containment_tested": False,
                "shutdown_required": True, "source_acceptance_note": "Provider schema was observed for these exact IDs; repeated delivery and response remain separate trials."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--operation", choices=["plan", "deploy", "accept-preview"], default="plan")
    parser.add_argument("--subscription")
    parser.add_argument("--confirm-lab-id")
    parser.add_argument("--not-before-utc")
    parser.add_argument("--not-after-utc")
    parser.add_argument("--incident-id")
    parser.add_argument("--dispatcher-run-name")
    parser.add_argument("--output")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    private = private_root(args.manifest)
    data = load_json(args.manifest)
    model = Manifest.from_dict(data)
    state_path = private_path(str(private / "sentinel-state.json"))
    if state_path.exists():
        state = load_json(state_path)
        validate_state(model, state)
    else:
        if args.operation != "plan" or args.execute:
            raise SafetyError("Create/review the local plan first; no ID discovery or adoption")
        responder = load_json(private_path(str(private / "responder-state.json")))
        _, responder, _ = manual_executor_trial.load_bound_state(data, responder["assignment"]["id"])
        state = planned_state(data, responder, args.not_before_utc, args.not_after_utc)
        save(state_path, state)
    if args.operation == "plan" or not args.execute:
        print(json.dumps({"mode": "local_plan", "private_state": "private/sentinel-state.json", "stage": state["stage"], "cloud_mutations": False,
                          "resources": resources(model, state), "forwarding": False, "native_delivery": "not_tested"}, indent=2))
        return 0
    if args.subscription != model.subscription_id or args.confirm_lab_id != model.lab_id:
        raise SafetyError("Explicit matching subscription and lab confirmation required")
    worker = NativeLab(data, state, HTTP(), AzureCLI(model, args.subscription))
    if args.operation == "deploy":
        lease = "native-prepare-" + str(uuid.uuid4())
        begin_trial(data, lease, check_settling=False)
        complete = False
        try:
            worker.deploy(lambda value: save(state_path, value))
            complete = True
        finally:
            finish_trial(data, lease, cleanup_confirmed=complete, outcome=state["stage"])
        print(json.dumps({"status": state["stage"], "native_delivery": "not_tested", "permissions_granted": False}))
    else:
        if not args.output:
            raise SafetyError("A new private output path is required")
        output = private_path(args.output)
        if output.exists():
            raise SafetyError("Refusing to overwrite native acceptance evidence")
        result = worker.accept_preview(args.incident_id, args.dispatcher_run_name)
        save(output, result)
        print(json.dumps({"status": result["status"], "executor_invoked": False, "containment_tested": False}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Native preparation/acceptance stopped; inspect exact private state. No remote payload or callback URL is logged.", file=sys.stderr)
        raise SystemExit(1)
