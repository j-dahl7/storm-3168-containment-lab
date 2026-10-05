"""Deploy, explicitly grant, or exercise the owned response workflow via ARM.

No callback URLs are acquired. This helper never changes a Sentinel automation
rule or enables a dispatcher. Cleanup verifies terminal execution and Disabled;
uncertain cleanup is recorded for explicit reconciliation, never called stopped.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import re
import sys
import time
import uuid
from lab_support import ROOT, assert_owned, az, guid, load_owned, private_path, rg_id, save

sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import ARM, AzureCLI, Guard, HTTP, Manifest, SafetyError

TERMINAL = {"Succeeded", "Failed", "Cancelled", "Aborted", "TimedOut"}
CONFIRMATION = "REMOVE_CONFIGURED_LAB_ROLE"
ROLE_ACTIONS = {"microsoft.resources/subscriptions/resourcegroups/read",
                "microsoft.authorization/roleassignments/read",
                "microsoft.authorization/roleassignments/delete"}


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def workflow_path(m: dict) -> str:
    return rg_id(m) + "/providers/Microsoft.Logic/workflows/storm3168-responder-" + m["lab_id"].replace("-", "")[:8]


def call(http: HTTP, operator: AzureCLI, method: str, path: str, body: dict | None = None):
    if not path.startswith("/subscriptions/") or any(part in path for part in ["..", "#", "%"]):
        raise RuntimeError("Invalid ARM target")
    return http.request(method, ARM + path, {"Authorization": "Bearer " + operator.token("arm")}, body)


def check_workflow(m: dict, state: dict, http: HTTP, operator: AzureCLI, *,
                   dry_run: bool | None = None, expected_state: str | None = None) -> dict:
    response = call(http, operator, "GET", state["workflow_id"] + "?api-version=2019-05-01")
    if response.status != 200 or response.transport_error:
        raise RuntimeError("Owned workflow cannot be read")
    item = response.data()
    if item.get("id", "").lower() != workflow_path(m).lower() or item.get("tags", {}).get("storm3168LabId") != m["lab_id"]:
        raise RuntimeError("Workflow identity or ownership drift")
    identity = item.get("identity", {})
    if (identity.get("type") != "SystemAssigned" or
            str(identity.get("principalId", "")).lower() != guid(state["responder_object_id"]) or
            identity.get("userAssignedIdentities") or
            str(identity.get("tenantId", "")).lower() != m["tenant_id"]):
        raise RuntimeError("Responder managed identity drift")
    p = item.get("properties", {}).get("parameters", {})
    for key, expected in {"expectedSubscriptionId": m["subscription_id"], "labId": m["lab_id"],
                          "actorObjectId": m["actor"]["service_principal_object_id"],
                          "resourceGroupId": rg_id(m),
                          "targetRoleAssignmentId": state["assignment"]["id"],
                          "targetRoleScope": state["assignment"]["scope"],
                          "targetRoleDefinitionId": state["assignment"]["role_definition_id"]}.items():
        if str(p.get(key, {}).get("value", "")).lower() != expected.lower():
            raise RuntimeError("Workflow configured target drift")
    controls = item.get("properties", {}).get("accessControl", {}).get("triggers", {})
    if controls.get("sasAuthenticationPolicy", {}).get("state") != "Disabled" or controls.get("allowedCallerIpAddresses") != []:
        raise RuntimeError("Workflow trigger restrictions are not verified")
    if dry_run is not None:
        if p.get("dryRun", {}).get("value") is not dry_run or p.get("executionConfirmation", {}).get("value") != ("" if dry_run else CONFIRMATION):
            raise RuntimeError("Workflow execution mode or confirmation drift")
    if expected_state is not None and item.get("properties", {}).get("state") != expected_state:
        raise RuntimeError("Workflow state is not verified")
    return item


def grant_ids(m: dict, state: dict) -> tuple[str, str]:
    role = f"/subscriptions/{m['subscription_id']}/providers/Microsoft.Authorization/roleDefinitions/{guid(state['role_definition_guid'])}"
    assignment = rg_id(m) + "/providers/Microsoft.Authorization/roleAssignments/" + guid(state["role_assignment_guid"])
    for field, expected in (("role_definition_id", role), ("role_assignment_id", assignment)):
        if field in state and state[field].lower() != expected.lower():
            raise RuntimeError("Recorded responder grant identity drift")
    return role, assignment


def expected_condition(m: dict, state: dict) -> str:
    role = guid(state["assignment"]["role_definition_id"].split("/")[-1])
    actor = guid(m["actor"]["service_principal_object_id"])
    return ("((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR "
            "((@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {" + role + "}) AND "
            "(@Resource[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {" + actor + "}) AND "
            "(@Resource[Microsoft.Authorization/roleAssignments:PrincipalType] StringEqualsIgnoreCase 'ServicePrincipal')))" )


def verify_grants(m: dict, state: dict, http: HTTP, operator: AzureCLI) -> None:
    """Verify this exact grant, not a claim that no other grants exist."""
    role_id, assignment_id = grant_ids(m, state)
    role = call(http, operator, "GET", role_id + "?api-version=2022-04-01")
    grant = call(http, operator, "GET", assignment_id + "?api-version=2022-04-01")
    if any(row.status != 200 or row.transport_error for row in (role, grant)):
        raise RuntimeError("Responder role and grant readback failed")
    role, grant = role.data(), grant.data()
    p = role.get("properties", {})
    permissions = p.get("permissions", [])
    if (str(role.get("id", "")).lower() != role_id.lower() or p.get("type") != "CustomRole" or
            p.get("roleName") != "Storm3168 bounded role removal " + m["lab_id"] or
            [str(scope).lower() for scope in p.get("assignableScopes", [])] != [rg_id(m).lower()] or
            not isinstance(permissions, list) or len(permissions) != 1):
        raise RuntimeError("Responder role definition scope or identity drift")
    rules = permissions[0]
    if not isinstance(rules, dict):
        raise RuntimeError("Responder role permissions are malformed")
    actions = rules.get("actions", [])
    if (not isinstance(actions, list) or len(actions) != len(ROLE_ACTIONS) or
            {str(action).lower() for action in actions} != ROLE_ACTIONS or
            any(rules.get(key) != [] for key in ("notActions", "dataActions", "notDataActions"))):
        raise RuntimeError("Responder role permissions drift")
    p = grant.get("properties", {})
    if (str(grant.get("id", "")).lower() != assignment_id.lower() or
            str(p.get("scope", "")).lower() != rg_id(m).lower() or
            str(p.get("principalId", "")).lower() != guid(state["responder_object_id"]) or
            p.get("principalType") != "ServicePrincipal" or
            str(p.get("roleDefinitionId", "")).lower() != role_id.lower() or
            p.get("conditionVersion") != "2.0" or p.get("condition") != expected_condition(m, state)):
        raise RuntimeError("Responder conditional grant drift")


def read_runs(state: dict, http: HTTP, operator: AzureCLI) -> dict[str, str]:
    response = call(http, operator, "GET", state["workflow_id"] + "/runs?api-version=2016-06-01&$top=100")
    if response.status != 200 or response.transport_error:
        raise RuntimeError("Workflow run inventory unavailable")
    data = response.data()
    if data.get("nextLink") or not isinstance(data.get("value"), list):
        raise RuntimeError("Workflow run inventory incomplete; reconcile manually")
    runs = {}
    for row in data["value"]:
        if not isinstance(row, dict):
            raise RuntimeError("Workflow run identity is unverified")
        name = row.get("name", "")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", name) or name in runs or
                str(row.get("id", "")).lower() != (state["workflow_id"] + "/runs/" + name).lower()):
            raise RuntimeError("Workflow run identity is unverified")
        status = row.get("properties", {}).get("status")
        if not isinstance(status, str):
            raise RuntimeError("Workflow run status is unavailable")
        runs[name] = status
    return runs


def remember_run(state: dict, state_path, name: str, status: str) -> None:
    state["last_run"].update(name=name, status=status, observed_at=stamp())
    save(state_path, state)  # Persist identity immediately, before any further I/O.


def discover_run(state: dict, state_path, before: set[str], http: HTTP, operator: AzureCLI) -> str | None:
    runs = read_runs(state, http, operator)
    candidates = set(runs) - before
    known = state["last_run"].get("name")
    if len(candidates) > 1 or (known and candidates != {known}):
        state["execution_state_unknown"] = True
        save(state_path, state)
        raise RuntimeError("Concurrent or missing run ambiguity; no run may be adopted")
    if candidates:
        name = next(iter(candidates))
        remember_run(state, state_path, name, runs[name])
        return name
    return None


def controlled_invoke(m: dict, state: dict, state_path, http: HTTP, operator: AzureCLI,
                      mode: str, *, run_timeout: float = 180, cleanup_timeout: float = 60) -> None:
    """One invocation. A disabled Consumption app may still have running instances."""
    if mode not in {"dry-run", "invoke"}:
        raise RuntimeError("Invalid workflow execution mode")
    if state.get("execution_state_unknown"):
        raise RuntimeError("Previous execution is unresolved; reconcile before another invocation")
    check_workflow(m, state, http, operator, expected_state="Disabled")
    verify_grants(m, state, http, operator)
    try:
        previous = read_runs(state, http, operator)
    except (RuntimeError, SafetyError, ValueError, KeyError):
        state["execution_state_unknown"] = True
        save(state_path, state)
        raise
    if any(status not in TERMINAL for status in previous.values()):
        raise RuntimeError("Existing nonterminal runs must be reconciled; none were cancelled")
    before = set(previous)
    state.update(disable_acknowledged=False, disabled_verified=False, safe_configuration_restored=False,
                 execution_state_unknown=False)
    state["last_run"] = {"name": None, "status": "not_started", "mode": mode,
                         "observed_at": stamp(), "capability_containment": "not_proven"}
    save(state_path, state)
    trigger_attempted = False
    cleanup_errors = []
    base = state["workflow_id"]
    try:
        deploy(m, state, dry_run=mode == "dry-run")
        check_workflow(m, state, http, operator, dry_run=mode == "dry-run", expected_state="Disabled")
        verify_grants(m, state, http, operator)
        # Deployment does not cancel older instances. Recheck before enabling.
        if read_runs(state, http, operator) != previous:
            state["execution_state_unknown"] = True
            raise RuntimeError("Run inventory changed before enable")
        assert_owned(m, m["subscription_id"])
        enabled = call(http, operator, "POST", base + "/enable?api-version=2016-06-01")
        if enabled.status not in {200, 202, 204} or enabled.transport_error:
            raise RuntimeError("Workflow enable is unconfirmed")
        check_workflow(m, state, http, operator, dry_run=mode == "dry-run", expected_state="Enabled")
        assert_owned(m, m["subscription_id"])
        trigger_attempted = True
        state["last_run"]["trigger_attempted_at"] = stamp()
        save(state_path, state)
        started = call(http, operator, "POST", base + "/triggers/manual/run?api-version=2016-06-01")
        state["last_run"]["trigger_acknowledged"] = started.status in {200, 202} and not started.transport_error
        save(state_path, state)
        if not state["last_run"]["trigger_acknowledged"]:
            raise RuntimeError("Workflow trigger acceptance is unknown")
        deadline = time.monotonic() + run_timeout
        while time.monotonic() < deadline:
            discover_run(state, state_path, before, http, operator)
            if state["last_run"]["status"] in TERMINAL:
                break
            time.sleep(3)
        if state["last_run"]["status"] != "Succeeded":
            raise RuntimeError("Workflow did not reach a successful terminal status")
    finally:
        # Disable first to stop new instances; this does NOT cancel active runs.
        try:
            assert_owned(m, m["subscription_id"])
            disabled = call(http, operator, "POST", base + "/disable?api-version=2016-06-01")
            state["disable_acknowledged"] = disabled.status in {200, 202, 204} and not disabled.transport_error
            deadline = time.monotonic() + cleanup_timeout
            while time.monotonic() < deadline:
                try:
                    check_workflow(m, state, http, operator, expected_state="Disabled")
                    state["disabled_verified"] = True
                    break
                except (RuntimeError, SafetyError):
                    time.sleep(3)
            if not state["disabled_verified"]:
                cleanup_errors.append("workflow_disabled_unverified")
        except (RuntimeError, SafetyError, ValueError, KeyError):
            cleanup_errors.append("workflow_disabled_unverified")
        try:
            if trigger_attempted and not state["last_run"]["name"] and not state["execution_state_unknown"]:
                deadline = time.monotonic() + cleanup_timeout
                while time.monotonic() < deadline:
                    if discover_run(state, state_path, before, http, operator):
                        break
                    time.sleep(3)
            known = state["last_run"]["name"]
            if trigger_attempted and not known:
                raise RuntimeError("Accepted execution cannot be attributed")
            if known and state["last_run"]["status"] not in TERMINAL:
                assert_owned(m, m["subscription_id"])
                check_workflow(m, state, http, operator)
                cancelled = call(http, operator, "POST", base + "/runs/" + known + "/cancel?api-version=2016-06-01")
                state["last_run"]["cancel_acknowledged"] = cancelled.status == 200 and not cancelled.transport_error
                save(state_path, state)
                deadline = time.monotonic() + cleanup_timeout
                while time.monotonic() < deadline:
                    discover_run(state, state_path, before, http, operator)
                    if state["last_run"]["status"] in TERMINAL:
                        break
                    time.sleep(3)
            runs = read_runs(state, http, operator)
            if (state["execution_state_unknown"] or any(value not in TERMINAL for value in runs.values()) or
                    set(runs) - before != ({known} if known else set()) or
                    (known and state["last_run"]["status"] not in TERMINAL)):
                raise RuntimeError("Terminal execution is not verified")
        except (RuntimeError, SafetyError, ValueError, KeyError):
            state["execution_state_unknown"] = True
            cleanup_errors.append("run_terminal_state_unverified")
        # Restore only after the known run is terminal (or no trigger was sent),
        # complete inventory has no extra runs, and disable is GET-verified.
        if state["disabled_verified"] and not state["execution_state_unknown"]:
            try:
                deploy(m, state, dry_run=True)
                check_workflow(m, state, http, operator, dry_run=True, expected_state="Disabled")
                state["safe_configuration_restored"] = True
            except (RuntimeError, SafetyError, ValueError, KeyError):
                cleanup_errors.append("safe_configuration_unverified")
        state["cleanup_problems"] = cleanup_errors
        save(state_path, state)
        if cleanup_errors:
            raise RuntimeError("Responder cleanup is incomplete; reconcile recorded private state before continuing")


def deploy(m: dict, state: dict, *, dry_run: bool) -> dict:
    assert_owned(m, m["subscription_id"])
    a = state["assignment"]
    result = az("deployment", "group", "create", "--subscription", m["subscription_id"],
                "--resource-group", m["resource_group"], "--name", "storm3168-responder",
                "--template-file", str(ROOT / "playbooks" / "main.bicep"), "--parameters",
                "expectedSubscriptionId=" + m["subscription_id"], "labId=" + m["lab_id"],
                "location=" + m["location"], "workflowName=" + state["workflow_id"].split("/")[-1],
                "actorObjectId=" + m["actor"]["service_principal_object_id"],
                "targetRoleAssignmentId=" + a["id"], "targetRoleDefinitionId=" + a["role_definition_id"],
                "targetRoleScope=" + a["scope"], "dryRun=" + str(dry_run).lower(),
                "executionConfirmation=" + ("" if dry_run else CONFIRMATION))
    return result.get("properties", {}).get("outputs", {})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="private/manifest.json")
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--confirm-lab-id", required=True, type=guid)
    parser.add_argument("--operation", choices=["deploy", "grant", "dry-run", "invoke", "status"], required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    _, m = load_owned(args.manifest, args.subscription, args.confirm_lab_id)
    model = Manifest.from_dict(m)
    operator, http = AzureCLI(model, args.subscription), HTTP()
    guard = Guard(model, http, operator)
    guard.ownership()
    guard.actor()
    state_path = private_path(str(ROOT / "private" / "responder-state.json"))
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("lab_id") != m["lab_id"] or state.get("workflow_id") != workflow_path(m):
            raise RuntimeError("Recorded responder state does not belong to this lab")
        if state.get("assignment") not in m["role_assignments"]:
            raise RuntimeError("Recorded target is no longer allowlisted")
    else:
        writers = [r for r in m["role_assignments"] if r["principal_id"] == m["actor"]["service_principal_object_id"]
                   and r["role_definition_id"].endswith("/17d1049b-9a84-46fb-8f53-869881c3d3ab")]
        if len(writers) != 1 or args.operation != "deploy":
            raise RuntimeError("Deploy requires exactly one recorded direct Storage Account Contributor assignment")
        state = {"lab_id": m["lab_id"], "workflow_id": workflow_path(m), "assignment": writers[0],
                 "role_definition_guid": str(uuid.uuid4()), "role_assignment_guid": str(uuid.uuid4()), "stage": "planned"}
    if not args.execute:
        print(json.dumps({"mode": "plan", "operation": args.operation, "target": "exact recorded lab actor assignment", "dry_run_default": True}))
        return 0
    if args.operation == "deploy":
        current = call(http, operator, "GET", state["workflow_id"] + "?api-version=2019-05-01")
        if current.status != 404 or current.transport_error:
            raise RuntimeError("Initial deployment requires verified absence; use the recorded owned workflow for later operations")
        save(state_path, state)
        outputs = deploy(m, state, dry_run=True)
        state["responder_object_id"] = outputs["responderObjectId"]["value"]
        state["stage"] = "deployed_disabled"
        save(state_path, state)
        check_workflow(m, state, http, operator, dry_run=True, expected_state="Disabled")
    elif args.operation == "grant":
        check_workflow(m, state, http, operator, dry_run=True, expected_state="Disabled")
        role_id, grant_id = grant_ids(m, state)
        for target in [role_id, grant_id]:
            existing = call(http, operator, "GET", target + "?api-version=2022-04-01")
            if existing.status != 404 or existing.transport_error:
                raise RuntimeError("Initial responder grant requires absent recorded IDs; reconcile existing role/grant")
        assert_owned(m, args.subscription)
        az("deployment", "group", "create", "--subscription", args.subscription, "--resource-group", m["resource_group"],
           "--name", "storm3168-responder-rbac", "--template-file", str(ROOT / "infra" / "responder-rbac.bicep"),
           "--parameters", "expectedSubscriptionId=" + args.subscription, "labId=" + m["lab_id"],
           "responderObjectId=" + state["responder_object_id"], "actorObjectId=" + m["actor"]["service_principal_object_id"],
           "targetRoleDefinitionId=" + state["assignment"]["role_definition_id"],
           "responderRoleDefinitionGuid=" + state["role_definition_guid"], "responderRoleAssignmentGuid=" + state["role_assignment_guid"],
           "grantResponderPermissions=true")
        state.update(stage="responder_grant_deployed_unverified", role_definition_id=role_id, role_assignment_id=grant_id)
        save(state_path, state)
        verify_grants(m, state, http, operator)
        state["stage"] = "responder_grant_verified"
        save(state_path, state)
    elif args.operation in {"dry-run", "invoke"}:
        controlled_invoke(m, state, state_path, http, operator, args.operation)
    else:
        item = check_workflow(m, state, http, operator)
        print(json.dumps({"state": item["properties"].get("state"), "dryRun": item["properties"]["parameters"]["dryRun"]["value"],
                          "last_run": state.get("last_run"), "capability_containment": "not_proven"}))
        return 0
    print(json.dumps({"operation": args.operation, "stage": state["stage"], "last_run": state.get("last_run"),
                      "capability_containment": "not_proven"}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, KeyError, SafetyError) as exc:
        print(f"Playbook operation stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
