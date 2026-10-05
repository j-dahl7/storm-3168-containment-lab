"""Optional Administrative Activity Log export to the exact owned workspace.

Offline plan by default. Does not modify existing exports, including a central
workspace export; never changes Entra diagnostics. Source category is SUBSCRIPTION
WIDE; resource filtering happens later in KQL, not in the diagnostic setting.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import uuid
from lab_support import ROOT, assert_owned, private_path, save

sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import ARM, AzureCLI, HTTP, Manifest, SafetyError, guid, load_json, utc_now
from stormlab.__main__ import private_root

API = "?api-version=2021-05-01-preview"


def workspace_id(m: Manifest) -> str:
    return m.rg_id + "/providers/Microsoft.OperationalInsights/workspaces/" + m.workspace_name


def setting_id(m: Manifest, export_uuid: str) -> str:
    return f"/subscriptions/{m.subscription_id}/providers/Microsoft.Insights/diagnosticSettings/storm3168-activity-{m.lab_id}-{guid(export_uuid, 'export UUID')}"


def payload(m: Manifest) -> dict:
    return {"properties": {"workspaceId": workspace_id(m), "logs": [{"category": "Administrative", "enabled": True}], "metrics": []}}


def validate_state(m: Manifest, state: dict) -> None:
    if (not isinstance(state, dict) or state.get("lab_id") != m.lab_id or state.get("subscription_id") != m.subscription_id
            or state.get("workspace_id") != workspace_id(m) or state.get("setting_id") != setting_id(m, state.get("export_uuid"))):
        raise SafetyError("Activity export state is not the exact recorded lab setting")


class ActivityExport:
    def __init__(self, data: dict, http: HTTP, operator: AzureCLI):
        self.data, self.m, self.http, self.operator = data, Manifest.from_dict(data), http, operator

    def request(self, method: str, path: str, body: dict | None = None):
        return self.http.request(method, ARM + path, {"Authorization": "Bearer " + self.operator.token("arm")}, body)

    def owned_destination(self) -> None:
        assert_owned(self.data, self.m.subscription_id)
        response = self.request("GET", workspace_id(self.m) + "?api-version=2023-09-01")
        if response.transport_error or response.status != 200:
            raise SafetyError("Owned destination workspace cannot be verified")
        workspace = response.data()
        if (str(workspace.get("id", "")).lower() != workspace_id(self.m).lower()
                or workspace.get("tags", {}).get("storm3168LabId") != self.m.lab_id):
            raise SafetyError("Destination workspace identity/tag changed; no central-workspace fallback")

    def read_setting(self, state: dict) -> dict | None:
        validate_state(self.m, state)
        response = self.request("GET", state["setting_id"] + API)
        if response.status == 404 and not response.transport_error:
            return None
        if response.status != 200 or response.transport_error:
            raise SafetyError("Activity export existence is unknown")
        item = response.data()
        p = item.get("properties", {})
        logs = p.get("logs")
        if (str(item.get("id", "")).lower() != state["setting_id"].lower()
                or str(p.get("workspaceId", "")).lower() != workspace_id(self.m).lower()
                or not isinstance(logs, list) or len(logs) != 1
                or logs[0].get("category") != "Administrative" or logs[0].get("enabled") is not True
                or logs[0].get("categoryGroup")
                or p.get("metrics", []) or any(p.get(k) for k in ("storageAccountId", "eventHubAuthorizationRuleId", "eventHubName", "marketplacePartnerId"))):
            raise SafetyError("Recorded activity export identity, destination or categories changed")
        return item

    def perform(self, operation: str, state: dict, *, confirm_lab_id: str,
                acknowledge_subscription_wide: bool, persist) -> dict:
        if confirm_lab_id != self.m.lab_id or operation not in {"create", "remove", "status"}:
            raise SafetyError("Explicit operation and matching lab confirmation required")
        validate_state(self.m, state)
        self.owned_destination()
        current = self.read_setting(state)
        if operation == "status":
            return {"status": "present_verified" if current else "absent_verified", "cloud_mutations": False}
        if operation == "create":
            if not acknowledge_subscription_wide:
                raise SafetyError("Explicit acknowledgment of subscription-wide Administrative export required")
            if current is not None:
                raise SafetyError("Exact export ID already exists; refusing overwrite or adoption")
            budget = self.data.get("budget_target_usd")
            if type(budget) not in {float, int} or not 0 < budget <= 10:
                raise SafetyError("Creation requires a recorded positive budget target at most 10 USD; not a spending cap")
            state.update(stage="create_planned", requested_at=utc_now())
            persist(state)  # Exact ID is durable before the mutation.
            self.owned_destination()
            if self.read_setting(state) is not None:
                raise SafetyError("Setting appeared after preflight; refusing overwrite")
            result = self.request("PUT", state["setting_id"] + API, payload(self.m))
        else:
            if current is None:
                state["stage"] = "absent_verified"
                persist(state)
                return {"status": state["stage"], "cloud_mutations": False}
            self.owned_destination()
            self.read_setting(state)
            state.update(stage="remove_planned", requested_at=utc_now())
            persist(state)
            result = self.request("DELETE", state["setting_id"] + API)
        state["last_write_acknowledged"] = result.status in {200, 201, 202, 204} and not result.transport_error
        state["stage"] = "outcome_unknown"
        persist(state)
        if not state["last_write_acknowledged"]:
            raise SafetyError("Export mutation unconfirmed; reconcile recorded exact ID before retrying")
        current = self.read_setting(state)
        if (operation == "create") != (current is not None):
            raise SafetyError("Export postcondition not yet verified; no automatic mutation retry")
        state.update(stage="present_verified" if current else "absent_verified", observed_at=utc_now())
        persist(state)
        return {"status": state["stage"], "cloud_mutations": True, "subscription_wide_category": "Administrative"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "private" / "manifest.json")
    parser.add_argument("--operation", choices=["create", "status", "remove"], default="create")
    parser.add_argument("--subscription")
    parser.add_argument("--confirm-lab-id")
    parser.add_argument("--acknowledge-subscription-wide-export", action="store_true")
    parser.add_argument("--execute", action="store_true", help="Required for provider access; create/remove mutate cloud state")
    args = parser.parse_args(argv)
    private = private_root(args.manifest)
    data = load_json(args.manifest)
    m = Manifest.from_dict(data)
    path = private_path(str(private / "activity-export-state.json"))
    state = load_json(path) if path.exists() else None
    if state is not None:
        validate_state(m, state)
    if not args.execute:
        print(json.dumps({"mode": "offline_plan", "operation": args.operation, "destination": workspace_id(m),
                          "setting_id": state["setting_id"] if state else "fresh UUID generated and recorded only on explicit create",
                          "scope": "subscription-wide Administrative category; no source RG filter",
                          "existing_exports_changed": False, "entra_export_changed": False,
                          "live_validation": "not_performed"}, indent=2))
        return 0
    if not args.subscription or not args.confirm_lab_id or guid(args.subscription, "subscription") != m.subscription_id or guid(args.confirm_lab_id, "lab confirmation") != m.lab_id:
        parser.error("--execute requires exact --subscription and --confirm-lab-id")
    if state is None:
        if args.operation != "create":
            raise SafetyError("No recorded export; status/remove never discover or adopt an existing setting")
        export_uuid = str(uuid.uuid4())
        state = {"schema_version": 1, "lab_id": m.lab_id, "subscription_id": m.subscription_id,
                 "workspace_id": workspace_id(m), "export_uuid": export_uuid, "setting_id": setting_id(m, export_uuid)}
    worker = ActivityExport(data, HTTP(), AzureCLI(m, args.subscription))
    result = worker.perform(args.operation, state, confirm_lab_id=m.lab_id,
                            acknowledge_subscription_wide=args.acknowledge_subscription_wide_export,
                            persist=lambda value: save(path, value))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SafetyError, RuntimeError, ValueError, OSError, KeyError, TypeError):
        print("Activity export stopped; reconcile the exact private state and ownership. No provider error body is logged.", file=sys.stderr)
        raise SystemExit(1)
