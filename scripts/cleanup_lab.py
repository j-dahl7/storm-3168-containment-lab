"""Preview or remove exact recorded lab objects; never delete a resource group.

No network access occurs in plan mode. Execution checks live ownership before
each write, makes no mutation retries, and preserves the private manifests.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
import time
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stormlab.core import ARM, GRAPH, AzureCLI, HTTP, Manifest, Response, SafetyError, guid, load_json, utc_now
from stormlab.__main__ import private_root
from activity_export import ActivityExport, remove_recorded_export, validate_state as validate_export_state
from trial_state import assert_idle


VERSIONS = {"workflow": "2019-05-01", "assignment": "2022-04-01",
            "responder_assignment": "2022-04-01", "role_definition": "2022-04-01",
            "storage": "2023-05-01", "workspace": "2023-09-01"}
ROLE_ACTIONS = {"Microsoft.Resources/subscriptions/resourceGroups/read",
                "Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleAssignments/delete"}


@dataclass(frozen=True)
class Target:
    kind: str
    id: str
    service: str = "arm"
    metadata: dict = field(default_factory=dict)

    @property
    def path(self) -> str:
        if self.service == "graph":
            collection = {"application": "applications", "service_principal": "servicePrincipals", "group": "groups"}[self.kind]
            return f"/v1.0/{collection}/{self.id}"
        return self.id + "?api-version=" + VERSIONS[self.kind]


def equal_id(actual: object, expected: str) -> bool:
    return isinstance(actual, str) and actual.lower() == expected.lower()


def exact_role_id(value: object, prefix: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.lower().startswith(prefix.lower()):
        raise SafetyError(field_name + " must be in the recorded subscription and scope")
    suffix = value[len(prefix):]
    guid(suffix, field_name)
    return prefix + suffix.lower()


def build_plan(m: Manifest, state: dict | None = None, *, include_storage: bool = False,
               include_workspace: bool = False, confirm_storage_name: str | None = None,
               acknowledge_data_loss: bool = False, export_state: dict | None = None) -> tuple[list[Target], dict]:
    """Derive targets only from the manifest and exact responder state, never discovery."""
    if (include_storage or include_workspace) and not acknowledge_data_loss:
        raise SafetyError("Data-resource removal requires --acknowledge-data-loss after archiving needed evidence")
    if include_storage and confirm_storage_name != m.storage_account:
        raise SafetyError("--confirm-storage-name must exactly match the recorded storage account")
    if confirm_storage_name is not None and not include_storage:
        raise SafetyError("--confirm-storage-name requires --include-storage")
    targets = [Target("assignment", r["id"], metadata=r) for r in m.role_assignments]
    workflow = None
    skipped = []
    state = state or {}
    if state and state.get("lab_id") != m.lab_id:
        raise SafetyError("Responder state lab_id does not match the selected manifest")
    responder = state.get("responder_object_id")
    if responder is not None:
        responder = guid(responder, "responder object ID")
        if responder in {(m.actor or {}).get("service_principal_object_id"), (m.group or {}).get("object_id")}:
            raise SafetyError("Responder identity must be separate from the lab actor and group")
    definition = None
    if "role_definition_id" in state:
        definition = exact_role_id(state["role_definition_id"], f"/subscriptions/{m.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/", "responder role definition ID")
        if state.get("role_definition_guid") is not None and not equal_id(definition.rsplit("/", 1)[-1], guid(state["role_definition_guid"], "responder role definition GUID")):
            raise SafetyError("Responder role definition ID and GUID differ")
    else:
        skipped.append("Responder role definition: no recorded role_definition_id; GUIDs are not adopted as deployed IDs")
    if "role_assignment_id" in state:
        assignment = exact_role_id(state["role_assignment_id"], m.rg_id + "/providers/Microsoft.Authorization/roleAssignments/", "responder role assignment ID")
        if state.get("role_assignment_guid") is not None and not equal_id(assignment.rsplit("/", 1)[-1], guid(state["role_assignment_guid"], "responder role assignment GUID")):
            raise SafetyError("Responder role assignment ID and GUID differ")
        if not responder or not definition:
            raise SafetyError("Recorded responder grant requires its recorded principal and role definition IDs")
        targets.append(Target("responder_assignment", assignment, metadata={"principal_id": responder, "scope": m.rg_id, "role_definition_id": definition}))
    else:
        skipped.append("Responder role assignment: no recorded role_assignment_id")
    if definition:
        targets.append(Target("role_definition", definition))
    if "workflow_id" in state:
        expected = m.rg_id + "/providers/Microsoft.Logic/workflows/storm3168-responder-" + m.lab_id.replace("-", "")[:8]
        if not equal_id(state["workflow_id"], expected):
            raise SafetyError("Responder workflow ID is not the exact generated lab workflow")
        if not responder:
            skipped.append("Responder workflow: missing recorded responder_object_id; retained for reconciliation")
        else:
            # The workflow can still reference an assignment removed by a later
            # experiment; validate its bounded shape without adopting that grant.
            row = state.get("assignment")
            if not isinstance(row, dict) or not m.actor:
                raise SafetyError("Responder workflow requires its recorded actor assignment")
            if set(row) != {"id", "scope", "principal_id", "role_definition_id"}:
                raise SafetyError("Unexpected responder target assignment schema")
            if not equal_id(row["scope"], m.rg_id) or row["principal_id"] != m.actor["service_principal_object_id"]:
                raise SafetyError("Responder target must be the exact lab actor at the lab group")
            exact_role_id(row["id"], m.rg_id + "/providers/Microsoft.Authorization/roleAssignments/", "responder target assignment")
            exact_role_id(row["role_definition_id"], f"/subscriptions/{m.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/", "responder target definition")
            workflow = Target("workflow", expected, metadata={"principal_id": responder, "assignment": dict(row)})
            targets.append(workflow)
    else:
        skipped.append("Responder workflow: no recorded workflow_id")
    if m.actor:
        targets.extend([Target("service_principal", m.actor["service_principal_object_id"], "graph"),
                        Target("application", m.actor["application_object_id"], "graph")])
    else:
        skipped.append("Actor application/service principal: not recorded")
    if m.group:
        targets.append(Target("group", m.group["object_id"], "graph"))
    else:
        skipped.append("Security group: not recorded")
    workspace = m.rg_id + "/providers/Microsoft.OperationalInsights/workspaces/" + m.workspace_name
    retained = [{"id": m.rg_id, "reason": "Resource groups are never deleted"}]
    for enabled, kind, rid in [(include_storage, "storage", m.storage_id), (include_workspace, "workspace", workspace)]:
        if enabled:
            targets.append(Target(kind, rid))
        else:
            retained.append({"id": rid, "reason": "Retained by default; storage, ingestion, retention or enabled Sentinel charges may continue"})
    identities = [(t.service, t.id.lower()) for t in targets]
    if len(set(identities)) != len(identities):
        raise SafetyError("Cleanup targets overlap; reconcile recorded IDs")
    plan = {"schema_version": 1, "lab_id": m.lab_id, "mode": "plan", "live_validation": "not_performed",
            "operations": ([{"action": "disable_and_verify_no_active_runs", "kind": "workflow", "id": workflow.id}] if workflow else [])
                          + [{"action": "delete_and_verify_absent", "kind": t.kind, "id": t.id} for t in targets],
            "retained": retained, "skipped": skipped,
            "limitations": ["No resource-group, lock, unrecorded object or purge operations",
                            "Optional Sentinel dispatcher, connections and rules are not removed; Activity Log export is removed only when its exact separate receipt exists",
                            "Only the recorded custom responder role is removed; built-in roles are never deleted",
                            "Cleanup does not prove revocation of previously issued credentials"],
            "results": []}
    if export_state is not None:
        validate_export_state(m, export_state)
        plan["operations"].insert(0, {"action": "remove_recorded_activity_export", "kind": "activity_export", "id": export_state["setting_id"]})
    plan["limitations"].append("Read-only leftovers inventory reports unrecorded resources/grants and exact soft-deleted identities; it never adds deletion targets and may be incomplete if reads fail")
    return targets, plan


class Cleanup:
    def __init__(self, m: Manifest, targets: list[Target], http: HTTP, operator: AzureCLI,
                 *, sleeper: Callable = time.sleep, persist: Callable | None = None,
                 manifest_data: dict | None = None, export_state: dict | None = None, export_persist: Callable | None = None):
        self.m, self.targets, self.http, self.operator = m, tuple(targets), http, operator
        self.sleeper, self.persist = sleeper, persist or (lambda _: None)
        self.manifest_data, self.export_state = manifest_data, export_state
        self.export_persist = export_persist or (lambda _: None)

    def lock_inventory(self) -> dict:
        result = {}
        for scope in (self.m.rg_id, self.m.storage_id):
            response = self.call("arm", "GET", scope + "/providers/Microsoft.Authorization/locks?api-version=2016-09-01")
            value = self.object_or_absent(response)
            if value is None and scope == self.m.storage_id:
                absent = self.object_or_absent(self.call("arm", "GET", scope + "?api-version=2023-05-01"))
                if absent is None:
                    result[scope] = []
                    continue
            if value is None or not isinstance(value.get("value"), list) or value.get("nextLink"):
                raise SafetyError("Cannot establish resource-group/storage lock inventory; no cleanup writes")
            result[scope] = [{"id": x.get("id"), "level": x.get("properties", {}).get("level")} for x in value["value"]]
            if value["value"]:
                raise SafetyError("Resource-group or storage locks are present; cleanup never removes them")
        return result

    def leftovers(self) -> dict:
        """Read-only reporting. Discovery never expands the deletion allowlist."""
        result = {"complete": True, "unrecorded_resources": [], "unrecorded_identity_assignments": [], "soft_deleted_identities": []}
        allowed = {x.id.lower() for x in self.targets} | {self.m.storage_id.lower(), (self.m.rg_id + "/providers/Microsoft.OperationalInsights/workspaces/" + self.m.workspace_name).lower()}
        principals = {(self.m.actor or {}).get("service_principal_object_id"), (self.m.group or {}).get("object_id")}
        principals.update(t.metadata.get("principal_id") for t in self.targets if t.kind == "responder_assignment")
        for name, path in (("unrecorded_resources", self.m.rg_id + "/resources?api-version=2021-04-01"),
                           ("unrecorded_identity_assignments", self.m.rg_id + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()")):
            try:
                value = self.object_or_absent(self.call("arm", "GET", path))
                if value is None or not isinstance(value.get("value"), list) or value.get("nextLink"):
                    raise SafetyError("Incomplete inventory")
                result[name] = [{"id": x.get("id"), "type": x.get("type")} for x in value["value"]
                                if str(x.get("id", "")).lower() not in allowed
                                and (name == "unrecorded_resources" or x.get("properties", {}).get("principalId") in principals)]
            except Exception:
                result["complete"] = False
                result[name + "_status"] = "unknown_read_failed_or_paginated"
        for t in self.targets:
            if t.kind not in {"application", "service_principal"}:
                continue
            try:
                value = self.object_or_absent(self.call("graph", "GET", "/v1.0/directory/deletedItems/" + t.id))
                result["soft_deleted_identities"].append({"id": t.id, "kind": t.kind, "status": "present_retained_no_purge" if value else "not_found"})
            except Exception:
                result["complete"] = False
                result["soft_deleted_identities"].append({"id": t.id, "kind": t.kind, "status": "unknown"})
        return result

    def call(self, service: str, method: str, path: str) -> Response:
        if service not in {"arm", "graph"} or method != "GET":
            raise SafetyError("Metadata helper only allows service GETs")
        return self.http.request(method, (ARM if service == "arm" else GRAPH) + path,
                                 {"Authorization": "Bearer " + self.operator.token(service)})

    @staticmethod
    def object_or_absent(response: Response) -> dict | None:
        if not response.transport_error and response.status == 404:
            return None
        if response.transport_error or response.status != 200:
            raise SafetyError(f"Cannot verify cleanup metadata (HTTP {response.status}); no success inferred")
        return response.data()

    def ownership(self) -> None:
        rg = self.object_or_absent(self.call("arm", "GET", self.m.rg_id + "?api-version=2021-04-01"))
        if not rg or not equal_id(rg.get("id"), self.m.rg_id) or rg.get("tags", {}).get("storm3168LabId") != self.m.lab_id:
            raise SafetyError("Live resource-group ID or storm3168LabId ownership tag changed")
        lock = self.object_or_absent(self.call("arm", "GET", self.m.lock_id + "?api-version=2016-09-01"))
        if lock is not None:
            raise SafetyError("A lock exists at the exact lab lock ID; cleanup never removes locks. Review it and explicitly run the harness lock-remove action for a verified owned lab lock")

    def read_target(self, target: Target) -> dict | None:
        if target not in self.targets:
            raise SafetyError("Target is not in the exact cleanup plan")
        obj = self.object_or_absent(self.call(target.service, "GET", target.path))
        if obj is None:
            return None
        m = self.m
        if not equal_id(obj.get("id"), target.id):
            raise SafetyError("Cleanup resource ID mismatch")
        if target.kind in {"workflow", "storage", "workspace"}:
            if obj.get("tags", {}).get("storm3168LabId") != m.lab_id:
                raise SafetyError("Cleanup resource ownership tag missing or changed")
            expected_type = {"workflow": "Microsoft.Logic/workflows", "storage": "Microsoft.Storage/storageAccounts", "workspace": "Microsoft.OperationalInsights/workspaces"}[target.kind]
            if not equal_id(obj.get("type"), expected_type) or obj.get("name") != target.id.rsplit("/", 1)[-1]:
                raise SafetyError("Cleanup resource type or name mismatch")
        if target.kind in {"assignment", "responder_assignment"}:
            props = obj.get("properties", {})
            row = target.metadata
            if any(not equal_id(props.get(k), row[v]) for k, v in {"principalId": "principal_id", "scope": "scope", "roleDefinitionId": "role_definition_id"}.items()):
                raise SafetyError("Recorded role assignment principal, scope or definition changed")
            expected_type = "Group" if m.group and row["principal_id"] == m.group["object_id"] else "ServicePrincipal"
            # Deleted principals can legitimately resolve as Unknown on a retry;
            # IDs, scope and role remain the authoritative recorded allowlist.
            if props.get("principalType") not in {expected_type, "Unknown"}:
                raise SafetyError("Recorded role assignment principal type changed")
        elif target.kind == "role_definition":
            props = obj.get("properties", {})
            permissions = props.get("permissions", [])
            expected_name = "Storm3168 bounded role removal " + m.lab_id
            expected_description = f"Lab {m.lab_id}: read ownership/assignments and conditionally remove the configured actor role. No effective-access guarantee."
            if props.get("type") != "CustomRole" or props.get("roleName") != expected_name or props.get("description") != expected_description:
                raise SafetyError("Responder role definition ownership metadata changed")
            scopes = props.get("assignableScopes")
            if not isinstance(scopes, list) or len(scopes) != 1 or not equal_id(scopes[0], m.rg_id):
                raise SafetyError("Responder custom role has unexpected assignable scopes")
            if (len(permissions) != 1 or set(permissions[0].get("actions", [])) != ROLE_ACTIONS
                    or any(permissions[0].get(k, []) for k in ["notActions", "dataActions", "notDataActions"])):
                raise SafetyError("Responder custom role permissions changed")
        elif target.kind == "workflow":
            identity, props = obj.get("identity", {}), obj.get("properties", {})
            if identity.get("type") != "SystemAssigned" or not equal_id(identity.get("principalId"), target.metadata["principal_id"]):
                raise SafetyError("Responder managed identity changed")
            row = target.metadata["assignment"]
            expected = {"expectedSubscriptionId": m.subscription_id, "labId": m.lab_id, "resourceGroupId": m.rg_id,
                        "actorObjectId": m.actor["service_principal_object_id"], "targetRoleAssignmentId": row["id"],
                        "targetRoleScope": row["scope"], "targetRoleDefinitionId": row["role_definition_id"]}
            if any(not equal_id(props.get("parameters", {}).get(key, {}).get("value"), val) for key, val in expected.items()):
                raise SafetyError("Responder configured target changed")
        elif target.kind in {"application", "service_principal"}:
            if obj.get("displayName") != m.name_prefix or not equal_id(obj.get("appId"), m.actor["client_id"]):
                raise SafetyError("Actor exact display name or application ID changed")
            if target.kind == "application" and "storm3168LabId=" + m.lab_id not in obj.get("tags", []):
                raise SafetyError("Application ownership tag missing or changed")
            if target.kind == "service_principal":
                if obj.get("servicePrincipalType") != "Application" or not equal_id(obj.get("appOwnerOrganizationId"), m.tenant_id):
                    raise SafetyError("Service principal type or owner tenant changed")
        elif target.kind == "group":
            if obj.get("displayName") != m.name_prefix + "-access" or obj.get("description") != "storm3168LabId=" + m.lab_id or obj.get("securityEnabled") is not True or obj.get("mailEnabled") is not False:
                raise SafetyError("Group exact display name, ownership description or type changed")
        return obj

    def verify_no_active_runs(self, target: Target) -> None:
        # This read never discovers deletion targets. Fail on pagination rather
        # than guessing whether a disabled workflow still has older active runs.
        response = self.object_or_absent(self.call("arm", "GET", target.id + "/runs?api-version=2016-06-01&$top=100"))
        if response is None or not isinstance(response.get("value"), list) or response.get("nextLink"):
            raise SafetyError("Cannot prove responder has no active runs; inspect runs before cleanup")
        terminal = {"Succeeded", "Failed", "Cancelled", "Aborted", "TimedOut", "Skipped", "Faulted"}
        if any(row.get("properties", {}).get("status") not in terminal for row in response["value"]):
            raise SafetyError("Responder still has an active/unknown run; cleanup does not cancel runs automatically")

    def write(self, target: Target, method: str) -> Response:
        if target not in self.targets or method not in {"DELETE", "DISABLE"} or (method == "DISABLE" and target.kind != "workflow"):
            raise SafetyError("Mutation is outside the exact cleanup allowlist")
        self.ownership()
        current = self.read_target(target)
        if current is None:
            return Response(404)
        if method == "DELETE" and target.kind in {"workflow", "application", "service_principal", "group", "role_definition"}:
            for assignment in self.targets:
                if assignment.kind in {"assignment", "responder_assignment"} and self.read_target(assignment) is not None:
                    raise SafetyError("A recorded role assignment still exists; remove and verify recorded grants before deleting identities or their custom role")
        if target.kind == "service_principal":
            # Recheck the recorded app before deleting its SP; no name searches.
            for app in self.targets:
                if app.kind == "application":
                    self.read_target(app)
        if method == "DELETE" and target.kind == "workflow":
            if current.get("properties", {}).get("state") != "Disabled":
                raise SafetyError("Responder must be verified Disabled before removal")
            self.verify_no_active_runs(target)
        path = target.id + "/disable?api-version=2016-06-01" if method == "DISABLE" else target.path
        verb = "POST" if method == "DISABLE" else "DELETE"
        response = self.http.request(verb, (ARM if target.service == "arm" else GRAPH) + path,
                                     {"Authorization": "Bearer " + self.operator.token(target.service)})
        if response.transport_error or response.status not in {200, 202, 204, 404}:
            raise SafetyError(f"Cleanup write not acknowledged (HTTP {response.status}); reconcile exact target, never assume success")
        return response

    def wait_for(self, target: Target, *, absent: bool) -> None:
        for attempt in range(6):
            current = self.read_target(target)
            if absent and current is None:
                return
            if not absent and (current is None or current.get("properties", {}).get("state") == "Disabled"):
                return
            if attempt < 5:
                self.sleeper(2)
        raise SafetyError("Cleanup postcondition not confirmed within bounded polling; leave manifests intact and rerun only after reconciliation")

    def execute(self, plan: dict, *, subscription: str, confirm_lab_id: str) -> dict:
        if guid(subscription, "selected subscription") != self.m.subscription_id or guid(confirm_lab_id, "lab confirmation") != self.m.lab_id:
            raise SafetyError("Explicit subscription or lab confirmation mismatch")
        plan.update(mode="execute", status="preflight", live_validation="in_progress")
        self.persist(plan)
        try:
            self.ownership()
            plan["locks_checked"] = self.lock_inventory()
            # Check every candidate before the first write. Repeat fresh checks
            # immediately before each mutation to detect mid-run ownership drift.
            for target in self.targets:
                self.read_target(target)
            if self.export_state is not None:
                if self.manifest_data is None:
                    raise SafetyError("Recorded export cleanup needs the selected original manifest")
                ActivityExport(self.manifest_data, self.http, self.operator).read_setting(self.export_state)
            plan["live_validation"] = "passed"
            plan["status"] = "in_progress"
            if self.export_state is not None:
                result = remove_recorded_export(self.manifest_data, self.export_state, self.http, self.operator,
                    confirm_lab_id=self.m.lab_id, persist=self.export_persist)
                plan["results"].append({"action": "remove_recorded_activity_export", "id": self.export_state["setting_id"], **result})
                self.persist(plan)
            for target in self.targets:
                if target.kind != "workflow":
                    continue
                current = self.read_target(target)
                if current is not None:
                    if current.get("properties", {}).get("state") != "Disabled":
                        self.write(target, "DISABLE")
                        self.wait_for(target, absent=False)
                    self.verify_no_active_runs(target)
                plan["results"].append({"action": "disable", "kind": target.kind, "id": target.id,
                                        "status": "already_absent" if current is None else "disabled_no_active_runs", "observed_at": utc_now()})
                self.persist(plan)
            for target in self.targets:
                self.ownership()
                current = self.read_target(target)
                if current is None:
                    status = "already_absent"
                else:
                    plan["pending"] = {"action": "delete", "kind": target.kind, "id": target.id, "started_at": utc_now()}
                    self.persist(plan)
                    self.write(target, "DELETE")
                    self.wait_for(target, absent=True)
                    status = "absence_verified"
                plan.pop("pending", None)
                plan["results"].append({"action": "delete", "kind": target.kind, "id": target.id, "status": status, "observed_at": utc_now()})
                self.persist(plan)
            plan["leftovers"] = self.leftovers()
            plan["status"] = "completed_with_retained_resources"
        except BaseException as exc:
            plan["status"] = "stopped_reconciliation_required"
            # Error strings contain only static diagnostic text/status codes.
            plan["error"] = str(exc) if isinstance(exc, SafetyError) else "Unexpected provider metadata; reconcile before retrying"
            self.persist(plan)
            raise
        self.persist(plan)
        return plan


def load_inputs(manifest_path: Path) -> tuple[Manifest, dict | None, Path]:
    private = private_root(manifest_path)
    m = Manifest.from_dict(load_json(manifest_path))
    state_path = private / "responder-state.json"
    if state_path.resolve() != state_path:
        raise SafetyError("Responder state must be a regular path in this checkout's private directory")
    state = load_json(state_path) if state_path.exists() else None
    if state is not None and not isinstance(state, dict):
        raise SafetyError("Responder state must be an object")
    return m, state, private


def write_report(path: Path, report: dict) -> None:
    if path.resolve() != path or path.parent.resolve() != ROOT.resolve() / "private":
        raise SafetyError("Cleanup report must remain inside this checkout's private directory")
    # Credentials and service response bodies never enter this report.
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, allow_nan=False)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "private" / "manifest.json")
    parser.add_argument("--subscription", help="Required with --execute; exact manifest subscription UUID")
    parser.add_argument("--confirm-lab-id", help="Required with --execute; exact manifest lab UUID")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--include-storage", action="store_true", help="Delete the whole recorded canary account and its contents")
    parser.add_argument("--confirm-storage-name", help="Required with --include-storage; literal recorded account name")
    parser.add_argument("--include-workspace", action="store_true", help="Delete the recorded workspace and its contained Sentinel/data configuration; never purge")
    parser.add_argument("--acknowledge-data-loss", action="store_true", help="I archived needed evidence or intentionally accept its loss; this is not archival verification")
    args = parser.parse_args()
    if args.execute and (not args.subscription or not args.confirm_lab_id):
        parser.error("--execute requires --subscription and --confirm-lab-id")
    m, state, private = load_inputs(args.manifest)
    data = load_json(args.manifest)
    export_path = private / "activity-export-state.json"
    if export_path.resolve() != export_path:
        raise SafetyError("Activity export receipt must be a regular same-checkout private path")
    export_state = load_json(export_path) if export_path.exists() else None
    if args.subscription and guid(args.subscription, "selected subscription") != m.subscription_id:
        raise SafetyError("Selected subscription differs from the manifest")
    if args.confirm_lab_id and guid(args.confirm_lab_id, "lab confirmation") != m.lab_id:
        raise SafetyError("Lab confirmation differs from the manifest")
    targets, plan = build_plan(m, state, include_storage=args.include_storage, include_workspace=args.include_workspace,
                               confirm_storage_name=args.confirm_storage_name, acknowledge_data_loss=args.acknowledge_data_loss,
                               export_state=export_state)
    if args.execute:
        assert_idle(data, check_settling=False)
        report_path = private / "cleanup-state.json"
        cleanup = Cleanup(m, targets, HTTP(), AzureCLI(m, args.subscription), persist=lambda value: write_report(report_path, value),
                          manifest_data=data, export_state=export_state,
                          export_persist=lambda value: write_report(export_path, value))
        cleanup.execute(plan, subscription=args.subscription, confirm_lab_id=args.confirm_lab_id)
    print(json.dumps(plan, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SafetyError, OSError, ValueError, KeyError, TypeError) as exc:
        message = str(exc) if isinstance(exc, SafetyError) else "Cannot load or validate local/live cleanup state; reconcile the private manifest"
        print("Cleanup stopped: " + message, file=sys.stderr)
        raise SystemExit(1)
