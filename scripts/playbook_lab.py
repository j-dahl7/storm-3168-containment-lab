"""Deploy, explicitly grant, or exercise the owned response workflow via ARM.

No callback URLs are acquired. This helper never changes a Sentinel automation
rule or enables a dispatcher. Cleanup verifies terminal execution and Disabled;
uncertain cleanup is recorded for explicit reconciliation, never called stopped.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
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
SHUTDOWN_PROOF_SECONDS = 900


class ShutdownIdentityUnavailable(RuntimeError):
    pass


class ShutdownIdentityMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class ShutdownProof:
    """In-memory authority to DISABLE one workflow verified before activation.

    Never load this from disk. It grants no enable, cancellation, configuration,
    deployment or RBAC action. A readable identity mismatch revokes this proof;
    unavailable metadata does not prevent bounded idempotent DISABLE retries.
    expires_at blocks activation, never the same-invocation safety stop.
    """
    workflow_id: str
    lab_id: str
    tenant_id: str
    principal_id: str
    expires_at: float


def capture_shutdown_proof(m: dict, state: dict, http: HTTP, operator: AzureCLI) -> ShutdownProof:
    assert_owned(m, m["subscription_id"])
    check_workflow(m, state, http, operator, expected_state="Disabled")
    return ShutdownProof(workflow_path(m), m["lab_id"], m["tenant_id"], guid(state["responder_object_id"]),
                         time.monotonic() + SHUTDOWN_PROOF_SECONDS)


def read_shutdown_identity(proof: ShutdownProof, http: HTTP, operator: AzureCLI) -> dict:
    response = call(http, operator, "GET", proof.workflow_id + "?api-version=2019-05-01")
    if response.status != 200 or response.transport_error:
        raise ShutdownIdentityUnavailable("Emergency shutdown workflow identity unavailable")
    item = response.data()
    identity = item.get("identity", {})
    if (not isinstance(identity, dict) or str(item.get("id", "")).lower() != proof.workflow_id.lower()
            or item.get("tags", {}).get("storm3168LabId") != proof.lab_id
            or identity.get("type") != "SystemAssigned" or identity.get("userAssignedIdentities")
            or str(identity.get("principalId", "")).lower() != proof.principal_id
            or str(identity.get("tenantId", "")).lower() != proof.tenant_id):
        raise ShutdownIdentityMismatch("Emergency shutdown workflow identity or ownership drift")
    return item


def independent_shutdown(proof: ShutdownProof, state: dict, http: HTTP, operator: AzureCLI,
                         *, timeout: float = 60, before_write=None) -> None:
    """Bounded idempotent stop retries for one pinned workflow, never a DELETE.

    The proof's expiry prevents new activation, not shutdown in this invocation.
    Successful identity drift refuses every subsequent write. An unavailable read
    or TimeoutExpired cannot skip the bounded stop attempt or state accounting.
    ``before_write`` is used by explicit cross-invocation reconciliation: it
    requires fresh normal ownership before every write, with no emergency bypass.
    """
    if not math.isfinite(timeout) or not 0 <= timeout <= 120:
        raise RuntimeError("Shutdown timeout must be bounded to 0..120 seconds")
    state.update(disable_acknowledged=False, disabled_verified=False)
    state["shutdown"] = {"attempted_at": stamp(), "authority": "fresh_reconciliation" if before_write else "same_invocation_verified_workflow",
                         "target_identity_verified": False, "outcome": "unknown", "attempts": [],
                         "activation_proof_expired": time.monotonic() >= proof.expires_at}
    deadline = time.monotonic() + timeout
    for number in range(1, 9):
        attempt = {"number": number, "observed_at": stamp()}
        state["shutdown"]["attempts"].append(attempt)
        try:
            read_shutdown_identity(proof, http, operator)
            state["shutdown"]["target_identity_verified"] = True
        except ShutdownIdentityMismatch:
            state["shutdown"]["outcome"] = "ownership_drift_refused"
            raise
        except Exception as exc:
            attempt["metadata_read"] = "unavailable_using_captured_proof"
            attempt["metadata_exception_type"] = type(exc).__name__
            state["shutdown"]["metadata_read"] = "unavailable_using_captured_proof"
        retryable = True
        try:
            if before_write:
                before_write()
            disabled = call(http, operator, "POST", proof.workflow_id + "/disable?api-version=2016-06-01")
            attempt["post_status"] = disabled.status
            acknowledged = disabled.status in {200, 202, 204} and not disabled.transport_error
            state["disable_acknowledged"] = state["disable_acknowledged"] or acknowledged
            retryable = acknowledged or disabled.transport_error or disabled.status in {0, 408, 429, 500, 502, 503, 504}
        except ShutdownIdentityMismatch:
            state["shutdown"]["outcome"] = "ownership_drift_refused"
            raise
        except Exception as exc:
            # Includes subprocess.TimeoutExpired; no exception message, command,
            # token or provider payload is put in the receipt.
            attempt["post_exception_type"] = type(exc).__name__
        try:
            item = read_shutdown_identity(proof, http, operator)
            if item.get("properties", {}).get("state") == "Disabled":
                state["disabled_verified"] = True
                state["shutdown"].update(outcome="disabled_verified", observed_at=stamp())
                return
        except ShutdownIdentityMismatch:
            state["shutdown"]["outcome"] = "ownership_drift_refused"
            raise
        except Exception as exc:
            attempt["readback_exception_type"] = type(exc).__name__
        if not retryable or number == 8 or time.monotonic() >= deadline:
            break
        time.sleep(min(2 ** (number - 1), 15, max(0, deadline - time.monotonic())))
    raise RuntimeError("Independent workflow shutdown is unverified after bounded retries")


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def workflow_path(m: dict) -> str:
    return rg_id(m) + "/providers/Microsoft.Logic/workflows/storm3168-responder-" + m["lab_id"].replace("-", "")[:8]


def call(http: HTTP, operator: AzureCLI, method: str, path: str, body: dict | None = None):
    if not path.startswith("/subscriptions/") or any(part in path for part in ["..", "#", "%"]):
        raise RuntimeError("Invalid ARM target")
    return http.request(method, ARM + path, {"Authorization": "Bearer " + operator.token("arm")}, body)


def check_workflow(m: dict, state: dict, http: HTTP, operator: AzureCLI, *,
                   dry_run: bool | None = None, expected_state: str | None = None,
                   require_trigger_restrictions: bool = True) -> dict:
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
    if require_trigger_restrictions and (controls.get("sasAuthenticationPolicy", {}).get("state") != "Disabled"
            or controls.get("allowedCallerIpAddresses") != [{"addressRange": "0.0.0.0-0.0.0.0"}]):
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
    known = state.setdefault("recorded_run_names", [])
    if name not in known:
        known.append(name)
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


def executor_outcome(state: dict, http: HTTP, operator: AzureCLI) -> str:
    """Read action statuses only; never follow/output run-history SAS links."""
    name = state.get("last_run", {}).get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", name):
        return "outcome_unverified"
    prefix = state["workflow_id"] + "/runs/" + name + "/actions/"
    response = call(http, operator, "GET", prefix[:-1] + "?api-version=2016-06-01")
    if response.status != 200 or response.transport_error:
        return "outcome_unverified"
    data = response.data()
    if data.get("nextLink") or not isinstance(data.get("value"), list):
        return "outcome_unverified"
    outcomes = {"Record_result": "role_assignment_removed_access_unverified", "Record_already_absent": "already_absent_access_unverified",
                "Record_absent_after_unconfirmed_delete": "assignment_absent_delete_unconfirmed",
                "Record_dry_run": "dry_run_no_mutation", "Record_assignment_forbidden": "assignment_read_forbidden",
                "Record_assignment_throttled": "assignment_read_throttled", "Record_assignment_timeout": "assignment_read_timed_out",
                "Record_assignment_unknown": "assignment_read_unknown", "Record_verification_forbidden": "absence_check_forbidden",
                "Record_verification_throttled": "absence_check_throttled", "Record_verification_timeout": "absence_check_timed_out",
                "Record_verification_unknown": "absence_check_unknown"}
    observed = []
    for row in data["value"]:
        action = row.get("name")
        if action in outcomes:
            if str(row.get("id", "")).lower() != (prefix + action).lower():
                return "outcome_unverified"
            if row.get("properties", {}).get("status") == "Succeeded":
                observed.append(outcomes[action])
    return observed[0] if len(observed) == 1 else "outcome_unverified"


def controlled_invoke(m: dict, state: dict, state_path, http: HTTP, operator: AzureCLI,
                      mode: str, *, run_timeout: float = 180, cleanup_timeout: float = 60) -> None:
    """One invocation. A disabled Consumption app may still have running instances."""
    if mode not in {"dry-run", "invoke"}:
        raise RuntimeError("Invalid workflow execution mode")
    if (not math.isfinite(run_timeout) or not math.isfinite(cleanup_timeout)
            or not 0 < run_timeout <= 300 or not 0 <= cleanup_timeout <= 120):
        raise RuntimeError("Invocation and cleanup timeouts exceed the bounded proof window")
    if state.get("execution_state_unknown"):
        raise RuntimeError("Previous execution is unresolved; reconcile before another invocation")
    if state.get("cleanup_problems"):
        raise RuntimeError("Previous shutdown/configuration cleanup is unresolved; reconcile its private receipt before another invocation")
    shutdown_proof = capture_shutdown_proof(m, state, http, operator)
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
        if shutdown_proof.expires_at - time.monotonic() < run_timeout + cleanup_timeout + 30:
            raise RuntimeError("Insufficient shutdown-proof lifetime to enable this workflow")
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
        # Attempt DISABLE before any separate RG lookup, run discovery, local
        # persistence, cancellation or restorative deployment. The in-memory
        # proof was captured while ownership and Disabled were verified, before
        # enable. This exception authorizes only a fresh exact-target DISABLE.
        # Disabling does NOT cancel active runs or prove containment.
        try:
            independent_shutdown(shutdown_proof, state, http, operator, timeout=cleanup_timeout)
        except Exception:
            cleanup_errors.append("workflow_disabled_unverified")
        try:
            save(state_path, state)
        except Exception:
            cleanup_errors.append("shutdown_receipt_persistence_failed")
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
        except Exception:
            state["execution_state_unknown"] = True
            cleanup_errors.append("run_terminal_state_unverified")
        try:
            state["last_run"]["response_outcome"] = executor_outcome(state, http, operator)
        except Exception:
            state["last_run"]["response_outcome"] = "outcome_unverified"
        # Restore only after the known run is terminal (or no trigger was sent),
        # complete inventory has no extra runs, and disable is GET-verified.
        if state["disabled_verified"] and not state["execution_state_unknown"]:
            try:
                assert_owned(m, m["subscription_id"])
                deploy(m, state, dry_run=True)
                check_workflow(m, state, http, operator, dry_run=True, expected_state="Disabled")
                state["safe_configuration_restored"] = True
            except Exception:
                cleanup_errors.append("safe_configuration_unverified")
        state["cleanup_problems"] = cleanup_errors
        try:
            save(state_path, state)
        except Exception:
            cleanup_errors.append("final_cleanup_receipt_persistence_failed")
        if cleanup_errors:
            raise RuntimeError("Responder cleanup is incomplete; reconcile recorded private state before continuing")


def disable_restore(m: dict, state: dict, state_path, http: HTTP, operator: AzureCLI,
                    *, timeout: float = 120) -> None:
    """Explicit fresh-ownership recovery; no prior shutdown receipt grants access.

    Cancel only run names already recorded by this helper, at most 20. An unknown
    queued run remains unresolved instead of being adopted from inventory.
    """
    problems = []
    state.update(disabled_verified=False, safe_configuration_restored=False)
    try:
        assert_owned(m, m["subscription_id"])
        check_workflow(m, state, http, operator, require_trigger_restrictions=False)
        proof = ShutdownProof(workflow_path(m), m["lab_id"], m["tenant_id"], guid(state["responder_object_id"]), time.monotonic())
        def fresh_guard():
            assert_owned(m, m["subscription_id"])
            check_workflow(m, state, http, operator, require_trigger_restrictions=False)
        independent_shutdown(proof, state, http, operator, timeout=timeout, before_write=fresh_guard)
    except Exception:
        problems.append("workflow_disabled_unverified")
    try:
        runs = read_runs(state, http, operator)
        known = set(state.get("recorded_run_names", []))
        if state.get("last_run", {}).get("name"):
            known.add(state["last_run"]["name"])
        if len(known) > 20 or any(not isinstance(n, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", n) for n in known):
            raise RuntimeError("Recorded run set exceeds the bounded reconciliation contract")
        active = {name for name, status in runs.items() if status not in TERMINAL}
        if active - known:
            raise RuntimeError("Unrecorded unfinished runs require exact-ID reconciliation")
        for name in sorted(active):
            assert_owned(m, m["subscription_id"])
            check_workflow(m, state, http, operator, expected_state="Disabled", require_trigger_restrictions=False)
            response = call(http, operator, "POST", state["workflow_id"] + "/runs/" + name + "/cancel?api-version=2016-06-01")
            state.setdefault("reconciled_runs", {})[name] = {"cancel_acknowledged": response.status in {200, 202, 204} and not response.transport_error}
        deadline = time.monotonic() + timeout
        while True:
            runs = read_runs(state, http, operator)
            if all(status in TERMINAL for status in runs.values()):
                state["execution_state_unknown"] = False
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Run cancellation terminal state unverified")
            time.sleep(min(3, max(0, deadline - time.monotonic())))
    except Exception:
        state["execution_state_unknown"] = True
        problems.append("run_terminal_state_unverified")
    if state["disabled_verified"] and not state.get("execution_state_unknown"):
        try:
            deploy(m, state, dry_run=True)
            check_workflow(m, state, http, operator, dry_run=True, expected_state="Disabled")
            state["safe_configuration_restored"] = True
        except Exception:
            problems.append("safe_configuration_unverified")
    state["cleanup_problems"] = problems
    state["reconciliation_observed_at"] = stamp()
    try:
        save(state_path, state)
    except Exception:
        problems.append("final_cleanup_receipt_persistence_failed")
    if problems:
        raise RuntimeError("disable-restore is incomplete; keep the receipt and reconcile exact IDs")


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
    parser.add_argument("--operation", choices=["deploy", "grant", "dry-run", "invoke", "disable-restore", "status"], required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    _, m = load_owned(args.manifest, args.subscription, args.confirm_lab_id)
    model = Manifest.from_dict(m)
    operator, http = AzureCLI(model, args.subscription), HTTP()
    guard = Guard(model, http, operator)
    if args.operation != "disable-restore":
        guard.ownership()
        guard.actor()
    state_path = private_path(str(ROOT / "private" / "responder-state.json"))
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("lab_id") != m["lab_id"] or state.get("workflow_id") != workflow_path(m):
            raise RuntimeError("Recorded responder state does not belong to this lab")
        if args.operation == "disable-restore":
            Manifest.from_dict({**m, "role_assignments": [state["assignment"]]})
        elif state.get("assignment") not in m["role_assignments"]:
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
        state.update(stage="responder_grant_planned", role_definition_id=role_id, role_assignment_id=grant_id)
        save(state_path, state)
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
    elif args.operation == "disable-restore":
        disable_restore(m, state, state_path, http, operator)
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
    except Exception:
        print("Playbook operation stopped; inspect the private receipt and reconcile the exact owned workflow. No raw exception or provider payload is logged.", file=sys.stderr)
        raise SystemExit(1)
