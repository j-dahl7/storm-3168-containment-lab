"""Read one exact Sentinel incident/alert and join private provider clock evidence.

No alert/incident update, callback URL, credential output or inferred containment.
The incident alerts API uses POST for a read-only list operation.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from lab_support import ROOT, private_path
from telemetry import load_manifest, resolve_workspace, workspace_id, write_private
import playbook_lab

sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import ARM, AzureCLI, HTTP, Manifest, SafetyError, guid, load_json, utc_now


def timestamp(value) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|\+00:00)", value):
        raise SafetyError("Clock field is not an explicit UTC timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()


def duration(start: str | None, end: str | None) -> dict:
    if not start or not end:
        return {"status": "unavailable", "seconds": None}
    seconds = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    return {"status": "observed_clock_difference" if seconds >= 0 else "clock_order_unknown", "seconds": seconds}


def singleton(details: dict, key: str) -> str:
    values = details.get(key)
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str) or not values[0]:
        raise SafetyError("Alert custom details do not identify one exact lab event")
    return values[0]


def build_evidence(m: Manifest, incident: dict, alerts: dict, *, incident_id: str,
                   analytic_rule_id: str, activity: dict, run: dict | None = None) -> dict:
    workspace = workspace_id(m)
    expected_incident = workspace + "/providers/Microsoft.SecurityInsights/incidents/" + guid(incident_id, "incident UUID")
    expected_rule = workspace + "/providers/Microsoft.SecurityInsights/alertRules/" + guid(analytic_rule_id, "analytic rule UUID")
    props = incident.get("properties", {})
    rules = props.get("relatedAnalyticRuleIds", [])
    if (str(incident.get("id", "")).lower() != expected_incident.lower() or not isinstance(rules, list)
            or len(rules) != 1 or str(rules[0]).lower() != expected_rule.lower()):
        raise SafetyError("Incident identity or sole analytic-rule relationship does not match")
    if alerts.get("nextLink") or not isinstance(alerts.get("value"), list) or len(alerts["value"]) != 1:
        raise SafetyError("Timing export requires one attributable alert; no paginated or merged incident inference")
    alert = alerts["value"][0]
    p = alert.get("properties", {})
    if alert.get("kind") != "SecurityAlert" or str(p.get("alertType", "")).lower() != analytic_rule_id.lower():
        raise SafetyError("Alert kind or analytic-rule identity mismatch")
    details = p.get("additionalData", {}).get("Custom Details")
    details = json.loads(details) if isinstance(details, str) else details
    if not isinstance(details, dict) or singleton(details, "LabId") != m.lab_id or singleton(details, "ActorObjectId").lower() != m.actor["service_principal_object_id"]:
        raise SafetyError("Alert lab or actor custom details mismatch")
    resource = singleton(details, "ResourceId")
    if not (resource.lower() == m.rg_id.lower() or resource.lower().startswith(m.rg_id.lower() + "/providers/")) or any(x in resource for x in ("..", "%", "?", "#", "\\")):
        raise SafetyError("Alert resource is outside the exact lab group")
    event_id = guid(singleton(details, "ProviderEventId"), "provider event UUID")
    if activity.get("kind") != "provider_telemetry" or activity.get("mode") != "live_read_only":
        raise SafetyError("Activity evidence is not the read-only provider export schema")
    sources = [s for s in activity.get("sources", []) if s.get("source") == "AzureActivity"]
    if len(sources) != 1:
        raise SafetyError("Exactly one provider Activity source required")
    source = sources[0]
    selected = source.get("selection", {})
    if (str(selected.get("resource_id", "")).lower() != workspace.lower() or selected.get("ownership_required") is not True
            or source.get("status") not in {"query_completed", "query_completed_no_rows"}):
        raise SafetyError("Activity evidence workspace or collection status mismatch")
    candidates = [r for r in source.get("rows", []) if str(r.get("EventDataId", "")).lower() == event_id]
    for row in candidates:
        if str(row.get("ResourceId", "")).lower() != resource.lower() or str(row.get("ActorObjectId", "")).lower() != m.actor["service_principal_object_id"]:
            raise SafetyError("Provider event identity does not match alert custom details")
    event = candidates[0] if len(candidates) == 1 else {}
    clocks = {"provider_event": timestamp(event.get("TimeGenerated")),
              "provider_submission": timestamp(event.get("EventSubmissionTimestamp")),
              "workspace_ingestion": timestamp(event.get("WorkspaceIngestionTime")),
              "alert_time_generated": timestamp(p.get("timeGenerated")),
              "alert_available": timestamp(p.get("processingEndTime")),
              "incident_created": timestamp(props.get("createdTimeUtc")),
              "incident_last_modified": timestamp(props.get("lastModifiedTimeUtc")),
              "workflow_started": timestamp((run or {}).get("properties", {}).get("startTime")),
              "workflow_ended": timestamp((run or {}).get("properties", {}).get("endTime"))}
    pairs = {"event_to_workspace": ("provider_event", "workspace_ingestion"),
             "workspace_to_alert": ("workspace_ingestion", "alert_available"),
             "alert_to_incident": ("alert_available", "incident_created"),
             "incident_to_workflow": ("incident_created", "workflow_started"),
             "workflow_duration": ("workflow_started", "workflow_ended")}
    differences = {key: duration(clocks[a], clocks[b]) for key, (a, b) in pairs.items()}
    if differences["incident_to_workflow"]["status"] == "observed_clock_difference":
        differences["incident_to_workflow"]["status"] = "unattributed_clock_difference"
    return {"schema_version": 1, "kind": "sentinel_pipeline_clock_evidence", "mode": "live_read_only", "cloud_mutations": False,
            "observed_at": utc_now(), "lab_id": m.lab_id, "incident_id": incident_id, "analytic_rule_id": analytic_rule_id,
            "provider_event_id": event_id, "provider_match": "unique" if len(candidates) == 1 else "missing" if not candidates else "ambiguous",
            "provider_export_truncated": source.get("truncated", False), "clocks": clocks,
            "durations": differences,
            "containment": "not_proven",
            "limitations": ["Alert timeGenerated is not treated as alert publication or incident creation.",
                            "processingEndTime is alert availability; absent clocks stay unavailable.",
                            "Provider ingestion is approximate; negative differences indicate clock-order uncertainty.",
                            "A recorded workflow run is not automatically causally attributed to this incident.",
                            "Use independent fixed-token evidence for actual access loss; these timestamps do not establish containment."]}


def read(http: HTTP, operator: AzureCLI, method: str, path: str) -> dict:
    response = http.request(method, ARM + path, {"Authorization": "Bearer " + operator.token("arm")})
    if response.status != 200 or response.transport_error:
        raise SafetyError("Sentinel timing metadata is unavailable")
    return response.data()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--analytic-rule-id", required=True)
    parser.add_argument("--activity-evidence", required=True, help="Existing private/ export from telemetry.py")
    parser.add_argument("--include-recorded-responder-run", action="store_true")
    parser.add_argument("--output", required=True, help="New evidence path inside this checkout's private/")
    args = parser.parse_args(argv)
    destination = private_path(args.output)
    if destination.exists():
        raise SafetyError("Refusing to overwrite timing evidence")
    activity = load_json(private_path(args.activity_evidence))
    data, m = load_manifest(args.manifest, guid(args.subscription, "subscription"))
    if not m.actor:
        raise SafetyError("A recorded lab actor is required")
    incident_id, rule_id = guid(args.incident_id, "incident UUID"), guid(args.analytic_rule_id, "rule UUID")
    resolve_workspace(data, m, workspace_id(m), owned=True)
    http, operator = HTTP(), AzureCLI(m, args.subscription)
    base = workspace_id(m) + "/providers/Microsoft.SecurityInsights/incidents/" + incident_id
    incident = read(http, operator, "GET", base + "?api-version=2025-09-01")
    alerts = read(http, operator, "POST", base + "/alerts?api-version=2025-09-01")
    run = None
    if args.include_recorded_responder_run:
        state = load_json(private_path(str(ROOT / "private" / "responder-state.json")))
        if state.get("lab_id") != m.lab_id or state.get("workflow_id") != playbook_lab.workflow_path(data):
            raise SafetyError("Recorded responder state mismatch")
        playbook_lab.check_workflow(data, state, http, operator)
        name = state.get("last_run", {}).get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", name):
            raise SafetyError("No exact recorded responder run")
        run_id = state["workflow_id"] + "/runs/" + name
        run = read(http, operator, "GET", run_id + "?api-version=2016-06-01")
        if str(run.get("id", "")).lower() != run_id.lower():
            raise SafetyError("Workflow run identity mismatch")
    result = build_evidence(m, incident, alerts, incident_id=incident_id, analytic_rule_id=rule_id, activity=activity, run=run)
    write_private(args.output, result)
    print(json.dumps({"private_evidence_written": True, "provider_match": result["provider_match"], "cloud_mutations": False, "containment": "not_proven"}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SafetyError, RuntimeError, ValueError, OSError, KeyError, TypeError):
        print("Timing export stopped; verify exact incident/rule, private provider evidence, ownership and metadata. No remote payload is logged.", file=sys.stderr)
        raise SystemExit(1)
