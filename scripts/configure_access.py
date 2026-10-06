"""Prepare one owned lab's direct/group writer comparison; no credentials created.

Plan by default. Execute explicitly, then verify the actor's actual baseline.
Only recorded RG-scoped writer assignments are removed; Reader is preserved.
Do not run while a fixed-token experiment is in progress.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from stormlab.core import ARM, GRAPH, AzureCLI, Guard, HTTP, Manifest, SafetyError, guid, load_json, utc_now
from stormlab.__main__ import private_root
from trial_state import begin_trial, finish_trial, record_access_settling


READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
STORAGE_WRITER = "17d1049b-9a84-46fb-8f53-869881c3d3ab"
DATA_READER = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"


def save_manifest(path: Path, data: dict) -> None:
    private_root(path)
    # Ensure newly recorded state still obeys the shared manifest contract.
    Manifest.from_dict(data)
    temporary = path.with_suffix(path.suffix + ".access.tmp")
    if temporary.exists():
        raise SafetyError("An earlier access update is incomplete; reconcile the temporary manifest")
    with temporary.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, allow_nan=False)
        handle.write("\n")
    temporary.replace(path)


def role_definition_id(m: Manifest, role_id: str) -> str:
    return f"/subscriptions/{m.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_id}"


def verify_definition(guard: Guard, role_id: str, name: str) -> None:
    rid = role_definition_id(guard.m, role_id)
    current = guard.checked(guard.read("arm", rid + "?api-version=2022-04-01"))
    if str(current.get("id", "")).lower() != rid.lower() or current.get("properties", {}).get("roleName") != name:
        raise SafetyError("Built-in role definition identity does not match")


def verify_assignment(guard: Guard, row: dict, *, allow_absent: bool = False) -> bool:
    current = guard.read("arm", row["id"] + "?api-version=2022-04-01")
    if current.status == 404 and not current.transport_error and allow_absent:
        return False
    obj = guard.checked(current)
    props = obj.get("properties", {})
    expected = {"principalId": row["principal_id"], "scope": row["scope"], "roleDefinitionId": row["role_definition_id"]}
    if str(obj.get("id", "")).lower() != row["id"].lower() or any(str(props.get(k, "")).lower() != v.lower() for k, v in expected.items()):
        raise SafetyError("Recorded role assignment has different live metadata; refusing adoption")
    return True


def inventory(guard: Guard) -> dict:
    """Check effective candidate paths at the exact storage canary scope.

    atScope() returns assignments at/above that scope. We also consider the
    recorded group before adding membership, to avoid activating an unknown grant.
    Unsupported/paginated responses fail closed rather than undercounting paths.
    """
    m = guard.m
    actor = m.actor["service_principal_object_id"]
    membership = guard.checked(guard.read("graph", f"/v1.0/servicePrincipals/{actor}/transitiveMemberOf?$select=id"))
    assignments = guard.checked(guard.read("arm", m.storage_id + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()"))
    if membership.get("@odata.nextLink") or assignments.get("nextLink"):
        raise SafetyError("Effective-permission inventory is paginated; reconcile before preparation")
    if not isinstance(membership.get("value"), list) or not isinstance(assignments.get("value"), list):
        raise SafetyError("Cannot establish effective-permission inventory")
    principals = {actor}
    for member in membership["value"]:
        principals.add(guid(member.get("id"), "transitive membership ID"))
    if m.group:
        principals.add(m.group["object_id"])
    recorded = {r["id"].lower(): r for r in m.role_assignments}
    unexpected = []
    relevant = []
    for entry in assignments["value"]:
        p = entry.get("properties", {})
        principal = str(p.get("principalId", "")).lower()
        if principal not in principals:
            continue
        rid = str(entry.get("id", ""))
        definition = str(p.get("roleDefinitionId", ""))
        relevant.append({"id": rid, "principal_id": principal, "scope": p.get("scope"), "role_definition_id": definition})
        if definition.rsplit("/", 1)[-1].lower() == READER:
            continue
        recorded_row = recorded.get(rid.lower())
        exact_data_control = (recorded_row is not None and principal == actor
                              and definition.lower() == role_definition_id(m, DATA_READER).lower()
                              and recorded_row["role_definition_id"].lower() == definition.lower()
                              and str(p.get("scope", "")).lower() == m.storage_id.lower()
                              and recorded_row["scope"].lower() == m.storage_id.lower()
                              and recorded_row["principal_id"] == actor)
        if exact_data_control:
            continue
        expected_writer = (recorded_row is not None
                           and recorded_row["role_definition_id"].lower() == role_definition_id(m, STORAGE_WRITER).lower()
                           and recorded_row["scope"].lower() == m.rg_id.lower()
                           and principal in {actor, m.group["object_id"] if m.group else ""}
                           and str(p.get("scope", "")).lower() == recorded_row["scope"].lower()
                           and definition.lower() == recorded_row["role_definition_id"].lower())
        if not expected_writer:
            unexpected.append(rid)
    return {"relevant_assignments": relevant, "unexpected_potential_writer_paths": unexpected,
            "transitive_membership_count": len(membership["value"]), "complete": True}


def ensure_owned_before_mutation(guard: Guard, *, group: bool = False) -> None:
    guard.ownership()
    guard.actor()
    if group:
        guard.group()


def write_exact(guard: Guard, service: str, method: str, path: str, payload: dict | None, *, group: bool = False) -> None:
    """Only this module's fixed-purpose constructors call this helper."""
    m = guard.m
    a = m.actor
    allowed = {
        ("graph", "PATCH", f"/v1.0/servicePrincipals/{a['service_principal_object_id']}"),
    }
    if m.group:
        allowed.add(("graph", "POST", f"/v1.0/groups/{m.group['object_id']}/members/$ref"))
    if service == "arm" and method in {"PUT", "DELETE"}:
        prefix = m.rg_id + "/providers/Microsoft.Authorization/roleAssignments/"
        expected_suffix = "?api-version=2022-04-01"
        if not path.startswith(prefix) or not path.endswith(expected_suffix):
            raise SafetyError("Access write is outside the owned RG")
        guid(path[len(prefix):-len(expected_suffix)], "role assignment ID")
    elif (service, method, path) not in allowed:
        raise SafetyError("Access write is not an allowed operation")
    ensure_owned_before_mutation(guard, group=group)
    response = guard.http.request(method, (ARM if service == "arm" else GRAPH) + path,
                                  {"Authorization": "Bearer " + guard.operator.token(service)}, payload)
    if response.transport_error or not 200 <= response.status < 300:
        raise SafetyError("Access change was not accepted; reconcile recorded state before retrying")


def configure(data: dict, guard: Guard, mode: str, *, execute: bool, enable_actor: bool,
              persist, new_uuid=lambda: str(uuid.uuid4())) -> dict:
    m = guard.m
    if mode not in {"direct", "group"} or not m.actor:
        raise SafetyError("An owned actor and direct/group mode are required")
    if mode == "group" and not m.group:
        raise SafetyError("Group mode requires an explicitly recorded owned group")
    if type(data.get("budget_target_usd")) not in {int, float} or not 0 < data["budget_target_usd"] <= 10:
        raise SafetyError("A positive budget_target_usd at most 10 is required")
    ensure_owned_before_mutation(guard, group=bool(m.group))
    verify_definition(guard, READER, "Reader")
    verify_definition(guard, STORAGE_WRITER, "Storage Account Contributor")
    state = inventory(guard)
    if state["unexpected_potential_writer_paths"]:
        raise SafetyError("Unexpected potential writer paths exist; review independent inherited/group grants")
    actor = m.actor["service_principal_object_id"]
    group_id = m.group["object_id"] if m.group else None
    target = actor if mode == "direct" else group_id
    opposite = group_id if mode == "direct" else actor
    def find(principal: str, definition: str) -> dict | None:
        matches = [r for r in data["role_assignments"] if r["principal_id"] == principal
                   and r["scope"].lower() == m.rg_id.lower()
                   and r["role_definition_id"].lower() == role_definition_id(m, definition).lower()]
        if len(matches) > 1:
            raise SafetyError("Multiple recorded assignments for the same role path; reconcile first")
        return matches[0] if matches else None
    reader = find(actor, READER)
    writer = find(target, STORAGE_WRITER)
    opposite_writer = find(opposite, STORAGE_WRITER) if opposite else None
    for row in [r for r in (reader, writer, opposite_writer) if r]:
        verify_assignment(guard, row, allow_absent=True)
    plan = {"schema_version": 1, "mode": mode, "executed": execute, "status": "planned",
            "preserve_reader": True, "reenable_actor_requested": enable_actor,
            "inventory_relevant_assignments": len(state["relevant_assignments"]),
            "unexpected_writer_paths": 0, "credential_issuance": "not_tested",
            "baseline_authorization": "not_tested", "timestamp": utc_now()}
    if not execute:
        return plan

    def ensure_role(row: dict | None, principal: str, role: str) -> dict:
        if row is None:
            row = {"id": m.rg_id + "/providers/Microsoft.Authorization/roleAssignments/" + guid(new_uuid(), "new assignment ID"),
                   "principal_id": principal, "scope": m.rg_id,
                   "role_definition_id": role_definition_id(m, role)}
            # Record before PUT. A crash preserves the exact ID for reconciliation.
            data["role_assignments"].append(row)
            persist(data)
        if verify_assignment(guard, row, allow_absent=True):
            return row
        write_exact(guard, "arm", "PUT", row["id"] + "?api-version=2022-04-01",
                    {"properties": {"roleDefinitionId": row["role_definition_id"], "principalId": principal,
                                    "principalType": "ServicePrincipal" if principal == actor else "Group"}},
                    group=principal == group_id)
        verify_assignment(guard, row)
        return row

    reader = ensure_role(reader, actor, READER)
    if opposite_writer:
        if verify_assignment(guard, opposite_writer, allow_absent=True):
            # Hard-coded writer check prevents Reader or unrelated role removal.
            if opposite_writer["role_definition_id"].rsplit("/", 1)[-1].lower() != STORAGE_WRITER:
                raise SafetyError("Only the recorded Storage Account Contributor writer may be removed")
            write_exact(guard, "arm", "DELETE", opposite_writer["id"] + "?api-version=2022-04-01", None,
                        group=opposite == group_id)
            absent = guard.read("arm", opposite_writer["id"] + "?api-version=2022-04-01")
            if absent.transport_error or absent.status != 404:
                raise SafetyError("Writer removal could not be verified; leave manifest for reconciliation")
        data["role_assignments"].remove(opposite_writer)
        persist(data)
    if mode == "group":
        member_path = f"/v1.0/groups/{group_id}/members/{actor}"
        member = guard.read("graph", member_path)
        if member.status == 404 and not member.transport_error:
            write_exact(guard, "graph", "POST", f"/v1.0/groups/{group_id}/members/$ref",
                        {"@odata.id": GRAPH + "/v1.0/directoryObjects/" + actor}, group=True)
        elif member.status != 200 or member.transport_error:
            raise SafetyError("Cannot verify exact actor group membership")
        observed = guard.checked(guard.read("graph", member_path))
        if str(observed.get("id", "")).lower() != actor:
            raise SafetyError("Exact group membership not verified")
    writer = ensure_role(writer, target, STORAGE_WRITER)
    if enable_actor:
        sp_path = f"/v1.0/servicePrincipals/{actor}"
        observed = guard.checked(guard.read("graph", sp_path + "?$select=id,appId,accountEnabled"))
        if str(observed.get("id", "")).lower() != actor or str(observed.get("appId", "")).lower() != m.actor["client_id"]:
            raise SafetyError("Cannot verify actor before re-enablement")
        if observed.get("accountEnabled") is not True:
            write_exact(guard, "graph", "PATCH", sp_path, {"accountEnabled": True})
            enabled = guard.checked(guard.read("graph", sp_path + "?$select=id,appId,accountEnabled"))
            if enabled.get("accountEnabled") is not True:
                raise SafetyError("Actor re-enablement has not been verified")
    stages = data.setdefault("stages", [])
    stage = "access-" + mode + "-configured"
    if stage not in stages:
        stages.append(stage)
    persist(data)
    return {**plan, "status": "configuration_verified_baseline_required",
            "reader_assignment_id": reader["id"], "writer_assignment_id": writer["id"]}


def configure_data_reader(data: dict, guard: Guard, operation: str, *, execute: bool, persist,
                          new_uuid=lambda: str(uuid.uuid4())) -> dict:
    """Only the exact actor's recorded account-scoped Blob Data Reader control."""
    m = guard.m
    if operation not in {"add", "remove"} or not m.actor:
        raise SafetyError("Select add/remove for a recorded actor")
    ensure_owned_before_mutation(guard)
    account = guard.checked(guard.read("arm", m.storage_id + "?api-version=2023-05-01"))
    if account.get("tags", {}).get("storm3168LabId") != m.lab_id:
        raise SafetyError("Storage ownership tag mismatch")
    verify_definition(guard, DATA_READER, "Storage Blob Data Reader")
    matches = [r for r in data["role_assignments"] if r["role_definition_id"].rsplit("/", 1)[-1].lower() == DATA_READER]
    if len(matches) > 1 or any(r["scope"].lower() != m.storage_id.lower() or r["principal_id"] != m.actor["service_principal_object_id"] for r in matches):
        raise SafetyError("Data-reader control must be one exact actor/account assignment")
    row = matches[0] if matches else None
    if row:
        verify_assignment(guard, row, allow_absent=True)
    if operation == "add" and inventory(guard)["unexpected_potential_writer_paths"]:
        raise SafetyError("Unexpected inherited/group permission path; reconcile before adding data control")
    if not execute:
        return {"status": "planned", "operation": operation, "scope": "exact storage account", "cloud_mutations": False}
    if operation == "remove" and row is None:
        raise SafetyError("No exact recorded data-reader assignment; refusing discovery")
    if row is None:
        row = {"id": m.storage_id + "/providers/Microsoft.Authorization/roleAssignments/" + guid(new_uuid(), "assignment UUID"),
               "principal_id": m.actor["service_principal_object_id"], "scope": m.storage_id,
               "role_definition_id": role_definition_id(m, DATA_READER)}
        data["role_assignments"].append(row)
        persist(data)
    exists = verify_assignment(guard, row, allow_absent=True)
    if (operation == "add") == exists:
        return {"status": "already_present" if exists else "already_absent", "cloud_mutations": False}
    ensure_owned_before_mutation(guard)
    if verify_assignment(guard, row, allow_absent=True) != exists:
        raise SafetyError("Data-reader assignment changed before mutation")
    body = {"properties": {"principalId": row["principal_id"], "roleDefinitionId": row["role_definition_id"], "principalType": "ServicePrincipal"}} if operation == "add" else None
    response = guard.http.request("PUT" if operation == "add" else "DELETE", ARM + row["id"] + "?api-version=2022-04-01",
                                  {"Authorization": "Bearer " + guard.operator.token("arm")}, body)
    if response.transport_error or response.status not in {200, 201, 204}:
        raise SafetyError("Data-reader change unconfirmed; exact recorded assignment retained")
    if verify_assignment(guard, row, allow_absent=True) != (operation == "add"):
        raise SafetyError("Data-reader postcondition is unconfirmed")
    if operation == "remove":
        data["role_assignments"].remove(row)
        persist(data)
    return {"status": "configuration_verified_baseline_required", "operation": operation, "cloud_mutations": True}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", default="private/manifest.json")
    p.add_argument("--subscription", required=True)
    p.add_argument("--confirm-lab-id", required=True)
    selection = p.add_mutually_exclusive_group(required=True)
    selection.add_argument("--mode", choices=("direct", "group"))
    selection.add_argument("--data-reader-control", choices=("add", "remove"), help="Exact account-scoped actor Blob Data Reader; independent opt-in")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--enable-actor", action="store_true", help="Explicitly enable only the recorded tenant SP; never reactivate the global app")
    args = p.parse_args(argv)
    try:
        path = Path(args.manifest).resolve(strict=True)
        private_root(path)
        data = load_json(path)
        m = Manifest.from_dict(data)
        if guid(args.confirm_lab_id, "confirmation") != m.lab_id:
            raise SafetyError("Lab confirmation mismatch")
        operator = AzureCLI(m, args.subscription)
        guard = Guard(m, HTTP(), operator)
        lease_id = "access-" + str(uuid.uuid4())
        if args.execute:
            begin_trial(data, lease_id, check_settling=False)
        complete = False
        try:
            if args.execute:
                record_access_settling(data, complete=False)
            if args.data_reader_control:
                if args.enable_actor:
                    raise SafetyError("Data-reader control does not enable the actor")
                result = configure_data_reader(data, guard, args.data_reader_control, execute=args.execute,
                                               persist=lambda value: save_manifest(path, value))
            else:
                result = configure(data, guard, args.mode, execute=args.execute, enable_actor=args.enable_actor,
                                   persist=lambda value: save_manifest(path, value))
            if args.execute:
                settling = record_access_settling(data, complete=True)
                result.update(ready_after_epoch=settling["ready_after_epoch"], minimum_settling_seconds=600)
            complete = True
        finally:
            if args.execute:
                finish_trial(data, lease_id, cleanup_confirmed=complete,
                             outcome="access_configured_baseline_required" if complete else "access_configuration_incomplete")
        # Exact IDs remain only in the ignored manifest/evidence; stdout is concise.
        print(json.dumps({k: v for k, v in result.items() if not k.endswith("assignment_id")}, sort_keys=True))
        return 0
    except (SafetyError, OSError, ValueError, KeyError, TypeError):
        print("Access preparation stopped; reconcile manifest, live ownership and effective permissions before retrying.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
