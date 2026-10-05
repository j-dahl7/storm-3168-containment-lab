"""Plan or reconcile only exact recorded lab workflow runs and Sentinel incidents.

No incident sweep or queue adoption. Disable the recorded workflows, cancel only
recorded unfinished run names, prove quiescence, then close exact verified lab
incidents. Uses operator permissions; grants no access and never enables a flow.
"""
from __future__ import annotations
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys
import time
from lab_support import ROOT, assert_owned, private_path, save
import playbook_lab as pb
from sentinel_timing import timestamp, validate_incident_evidence
from telemetry import workspace_id

sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import ARM, AzureCLI, HTTP, Manifest, SafetyError, guid, load_json, utc_now
from stormlab.__main__ import private_root


def validate_receipt(m: Manifest, receipt: dict) -> None:
    if (receipt.get("schema_version") != 1 or receipt.get("lab_id") != m.lab_id
            or receipt.get("subscription_id") != m.subscription_id
            or receipt.get("workspace_id") != workspace_id(m)):
        raise SafetyError("Trial receipt does not belong to this exact lab workspace")
    guid(receipt.get("analytic_rule_id"), "analytic rule UUID")
    start, end = timestamp(receipt.get("not_before_utc")), timestamp(receipt.get("not_after_utc"))
    if not start or not end or not 0 < (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() <= 7200:
        raise SafetyError("Trial window must be positive and no longer than two hours")
    incidents, workflows = receipt.get("incident_ids"), receipt.get("workflows")
    if not isinstance(incidents, list) or len(incidents) > 10 or len(set(incidents)) != len(incidents):
        raise SafetyError("Require at most ten unique recorded incident UUIDs")
    for item in incidents:
        guid(item, "incident UUID")
    if not isinstance(workflows, list) or not 1 <= len(workflows) <= 2:
        raise SafetyError("Require one or two exact recorded workflows")
    prefix = m.rg_id + "/providers/Microsoft.Logic/workflows/"
    seen = set()
    for item in workflows:
        rid, names = item.get("resource_id"), item.get("run_names")
        if (not isinstance(rid, str) or not rid.startswith(prefix)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", rid[len(prefix):]) or rid.lower() in seen):
            raise SafetyError("Workflow is not a unique exact resource in the lab group")
        seen.add(rid.lower())
        guid(item.get("principal_id"), "recorded workflow identity")
        if item.get("kind") not in {"dispatcher", "executor"}:
            raise SafetyError("Unknown lab workflow kind")
        if (not isinstance(names, list) or len(names) > 20 or len(set(names)) != len(names)
                or any(not isinstance(n, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", n) for n in names)):
            raise SafetyError("Require at most twenty unique exact recorded run names per workflow")


class Reconciler:
    def __init__(self, data: dict, receipt: dict, http: HTTP, operator: AzureCLI, *, sleeper=time.sleep):
        self.data, self.m, self.receipt, self.http, self.operator = data, Manifest.from_dict(data), receipt, http, operator
        validate_receipt(self.m, receipt)
        self.sleep = sleeper

    def request(self, method, path, body=None, *, etag=None):
        headers = {"Authorization": "Bearer " + self.operator.token("arm")}
        if etag:
            headers["If-Match"] = etag
        return self.http.request(method, ARM + path, headers, body)

    def get(self, path, *, method="GET"):
        result = self.request(method, path)
        if result.status != 200 or result.transport_error:
            raise SafetyError("Exact reconciliation metadata is unavailable")
        return result.data()

    def check_workflow(self, item):
        assert_owned(self.data, self.m.subscription_id)
        value = self.get(item["resource_id"] + "?api-version=2019-05-01")
        identity, parameters = value.get("identity", {}), value.get("properties", {}).get("parameters", {})
        if (str(value.get("id", "")).lower() != item["resource_id"].lower()
                or value.get("tags", {}).get("storm3168LabId") != self.m.lab_id
                or identity.get("type") != "SystemAssigned" or identity.get("userAssignedIdentities")
                or str(identity.get("principalId", "")).lower() != item["principal_id"]
                or str(identity.get("tenantId", "")).lower() != self.m.tenant_id):
            raise pb.ShutdownIdentityMismatch("Recorded workflow identity or ownership changed")
        expected = {"expectedSubscriptionId": self.m.subscription_id, "resourceGroupId": self.m.rg_id,
                    "labId": self.m.lab_id, "actorObjectId": self.m.actor["service_principal_object_id"]}
        if item["kind"] == "dispatcher":
            expected.update(workspaceResourceId=workspace_id(self.m), analyticRuleResourceId=workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/alertRules/" + self.receipt["analytic_rule_id"])
            for key, field in (("notBeforeUtc", "not_before_utc"), ("notAfterUtc", "not_after_utc")):
                if timestamp(parameters.get(key, {}).get("value")) != timestamp(self.receipt[field]):
                    raise SafetyError("Dispatcher belongs to a different trial window")
        if any(str(parameters.get(k, {}).get("value", "")).lower() != v.lower() for k, v in expected.items()):
            raise SafetyError("Recorded workflow's configured lab context changed")
        return value

    def stop_workflow(self, item, result, *, timeout):
        self.check_workflow(item)
        proof = pb.ShutdownProof(item["resource_id"], self.m.lab_id, self.m.tenant_id, item["principal_id"], time.monotonic())
        pb.independent_shutdown(proof, result, self.http, self.operator, timeout=timeout,
                                before_write=lambda: self.check_workflow(item))
        state = {"workflow_id": item["resource_id"]}
        runs = pb.read_runs(state, self.http, self.operator)
        active = {name for name, status in runs.items() if status not in pb.TERMINAL}
        if active - set(item["run_names"]):
            raise SafetyError("Unrecorded unfinished runs remain; no queue entries adopted")
        result["cancelled_run_requests"] = []
        for name in sorted(active):
            current = self.check_workflow(item)
            if current.get("properties", {}).get("state") != "Disabled":
                raise SafetyError("Workflow is not verified Disabled before run cancellation")
            # Read the exact run again; a run list never supplies a new target.
            run_id = item["resource_id"] + "/runs/" + name
            run = self.get(run_id + "?api-version=2016-06-01")
            if str(run.get("id", "")).lower() != run_id.lower():
                raise SafetyError("Recorded run identity changed")
            if run.get("properties", {}).get("status") in pb.TERMINAL:
                continue
            assert_owned(self.data, self.m.subscription_id)
            cancelled = self.request("POST", run_id + "/cancel?api-version=2016-06-01")
            result["cancelled_run_requests"].append({"name": name, "acknowledged": cancelled.status in {200, 202, 204} and not cancelled.transport_error})
        deadline = time.monotonic() + timeout
        while True:
            runs = pb.read_runs(state, self.http, self.operator)
            if all(status in pb.TERMINAL for status in runs.values()):
                result["quiescent_verified"] = True
                return
            if time.monotonic() >= deadline:
                raise SafetyError("Unfinished run state remains unverified")
            self.sleep(min(3, max(0, deadline - time.monotonic())))

    def close_incident(self, incident_uuid):
        assert_owned(self.data, self.m.subscription_id)
        workspace = self.get(workspace_id(self.m) + "?api-version=2023-09-01")
        if str(workspace.get("id", "")).lower() != workspace_id(self.m).lower() or workspace.get("tags", {}).get("storm3168LabId") != self.m.lab_id:
            raise SafetyError("Incident workspace ownership is unverified")
        base = workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/incidents/" + incident_uuid
        incident = self.get(base + "?api-version=2025-09-01")
        alerts = self.get(base + "/alerts?api-version=2025-09-01", method="POST")
        validated = validate_incident_evidence(self.m, incident, alerts, incident_id=incident_uuid,
            analytic_rule_id=self.receipt["analytic_rule_id"], not_before_utc=self.receipt["not_before_utc"], not_after_utc=self.receipt["not_after_utc"])
        props = validated["incident_properties"]
        if props.get("status") == "Closed":
            return {"id": incident_uuid, "status": "already_closed_verified"}
        if props.get("status") not in {"New", "Active"}:
            raise SafetyError("Incident status is not eligible for lab closure")
        etag = incident.get("etag")
        if not isinstance(etag, str) or not 1 <= len(etag) <= 200 or any(ord(c) < 32 for c in etag):
            raise SafetyError("Incident ETag required for conditional exact-ID closure")
        body = {"title": props["title"], "severity": props["severity"], "status": "Closed", "classification": "Undetermined",
                "classificationComment": "Lab trial reconciled by exact receipt IDs; no containment conclusion."}
        for key in ("description", "owner", "labels"):
            if key in props:
                body[key] = props[key]
        assert_owned(self.data, self.m.subscription_id)
        response = self.request("PUT", base + "?api-version=2025-09-01", {"etag": etag, "properties": body}, etag=etag)
        acknowledged = response.status in {200, 201} and not response.transport_error
        current = self.get(base + "?api-version=2025-09-01")
        current_alerts = self.get(base + "/alerts?api-version=2025-09-01", method="POST")
        checked = validate_incident_evidence(self.m, current, current_alerts, incident_id=incident_uuid,
            analytic_rule_id=self.receipt["analytic_rule_id"], not_before_utc=self.receipt["not_before_utc"], not_after_utc=self.receipt["not_after_utc"])
        if checked["incident_properties"].get("status") != "Closed":
            raise SafetyError("Incident closure is unverified; no mutation retry")
        return {"id": incident_uuid, "status": "closed_observed", "write_acknowledged": acknowledged}

    def execute(self, *, confirm_lab_id, persist, timeout=60):
        if confirm_lab_id != self.m.lab_id or not 0 <= timeout <= 120:
            raise SafetyError("Exact lab confirmation and bounded timeout required")
        report = {"schema_version": 1, "lab_id": self.m.lab_id, "status": "in_progress", "workflows": [], "incidents": [], "containment": "not_proven"}
        persist(report)
        for item in self.receipt["workflows"]:
            result = {"id": item["resource_id"], "quiescent_verified": False}
            report["workflows"].append(result)
            try:
                self.stop_workflow(item, result, timeout=timeout)
            except Exception as exc:
                result.update(status="unresolved", exception_type=type(exc).__name__)
            persist(report)
        # No incident is closed while recorded automation remains active/unknown.
        if all(row["quiescent_verified"] for row in report["workflows"]):
            for incident in self.receipt["incident_ids"]:
                try:
                    report["incidents"].append(self.close_incident(incident))
                except Exception as exc:
                    report["incidents"].append({"id": incident, "status": "unresolved", "exception_type": type(exc).__name__})
                persist(report)
        report["status"] = "reconciled" if all(row["quiescent_verified"] for row in report["workflows"]) and len(report["incidents"]) == len(self.receipt["incident_ids"]) and all(row["status"] != "unresolved" for row in report["incidents"]) else "partial_reconciliation_required"
        report["observed_at"] = utc_now()
        persist(report)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--receipt", required=True, help="Private exact-ID Sentinel trial receipt; never discovered by display name")
    parser.add_argument("--output", required=True, help="New private result path")
    parser.add_argument("--subscription")
    parser.add_argument("--confirm-lab-id")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    private_root(args.manifest)
    data, receipt = load_json(args.manifest), load_json(private_path(args.receipt))
    model = Manifest.from_dict(data)
    validate_receipt(model, receipt)
    output = private_path(args.output)
    if output.exists():
        raise SafetyError("Refusing to overwrite reconciliation evidence")
    if not args.execute:
        print(json.dumps({"mode": "offline_plan", "workflows": receipt["workflows"], "incident_ids": receipt["incident_ids"], "cloud_mutations": False}, indent=2))
        return 0
    if not args.subscription or guid(args.subscription, "subscription") != model.subscription_id or args.confirm_lab_id != model.lab_id:
        raise SafetyError("Execution requires the exact subscription and lab UUID")
    result = Reconciler(data, receipt, HTTP(), AzureCLI(model, args.subscription)).execute(confirm_lab_id=model.lab_id, persist=lambda r: save(output, r))
    print(json.dumps({"status": result["status"], "private_evidence_written": True, "containment": "not_proven"}))
    return 0 if result["status"] == "reconciled" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Sentinel reconciliation stopped; inspect exact private receipts. No raw provider payload is logged.", file=sys.stderr)
        raise SystemExit(1)
