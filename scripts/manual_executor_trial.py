"""CORE09 adapter: one guarded Logic App response, no actor credentials here.

The caller owns the frozen-token baseline/post phases and local trial lease.
This module never calls the harness role-delete operation as a fallback.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from lab_support import ROOT, private_path, save
import playbook_lab as pb
from stormlab.core import AzureCLI, Guard, HTTP, Manifest, SafetyError, load_json, response_target, utc_now

WRITER = "17d1049b-9a84-46fb-8f53-869881c3d3ab"


def load_bound_state(data: dict, assignment_id: str) -> tuple[Path, dict, dict]:
    model = Manifest.from_dict(data)
    target = response_target(model, "role-delete", assignment_id)
    if target["principal_id"] != model.actor["service_principal_object_id"] or target["role_definition_id"].rsplit("/", 1)[-1].lower() != WRITER:
        raise SafetyError("CORE09 requires the exact recorded direct Storage Account Contributor assignment")
    path = private_path(str(ROOT / "private" / "responder-state.json"))
    state = load_json(path)
    row = next(row for row in model.role_assignments if row["id"].lower() == assignment_id.lower())
    if (state.get("lab_id") != model.lab_id or state.get("workflow_id") != pb.workflow_path(data)
            or state.get("assignment") != row or not state.get("responder_object_id")):
        raise SafetyError("Responder receipt does not bind this exact lab assignment")
    if state.get("execution_state_unknown") or state.get("cleanup_problems"):
        raise SafetyError("Responder cleanup is unresolved; reconcile before a trial")
    pb.grant_ids(data, state)
    return path, state, target


def verify_present(model: Manifest, target: dict, http, operator):
    response = pb.call(http, operator, "GET", target["role_assignment_id"] + "?api-version=2022-04-01")
    if response.transport_error or response.status != 200:
        raise SafetyError("CORE09 needs the exact assignment present before invocation")
    item = response.data()
    props = item.get("properties", {})
    expected = {"principalId": target["principal_id"], "scope": target["scope"], "roleDefinitionId": target["role_definition_id"]}
    if (str(item.get("id", "")).lower() != target["role_assignment_id"].lower()
            or props.get("principalType") != "ServicePrincipal"
            or any(str(props.get(k, "")).lower() != v.lower() for k, v in expected.items())):
        raise SafetyError("CORE09 assignment ID, principal, scope or definition changed")


def utc_timestamp(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|\+00:00)", value):
        raise SafetyError("Executor DELETE action lacks an explicit UTC clock")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()


def deletion_action_metadata(state: dict, http, operator) -> dict:
    name = state.get("last_run", {}).get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", name):
        raise SafetyError("Executor run identity is unverified")
    action_id = state["workflow_id"] + "/runs/" + name + "/actions/Delete_configured_assignment"
    response = pb.call(http, operator, "GET", action_id + "?api-version=2016-06-01")
    if response.status != 200 or response.transport_error:
        raise SafetyError("Exact executor DELETE action metadata unavailable")
    item = response.data()
    props = item.get("properties", {})
    if str(item.get("id", "")).lower() != action_id.lower() or props.get("status") != "Succeeded":
        raise SafetyError("Exact executor DELETE action did not report success")
    started, ended = utc_timestamp(props.get("startTime")), utc_timestamp(props.get("endTime"))
    if datetime.fromisoformat(ended) < datetime.fromisoformat(started):
        raise SafetyError("Executor action clocks are out of order")
    # Never fetch outputsLink/inputsLink; they can contain callback-style SAS URLs.
    return {"action_id": action_id, "started_at": started, "ended_at": ended,
            "clock_source": "Logic Apps HTTP action metadata; not direct client request timestamps"}


def invoke(data: dict, subscription: str, assignment_id: str, output: Path, *,
           http=None, operator=None, controller=None) -> dict:
    model = Manifest.from_dict(data)
    state_path, state, target = load_bound_state(data, assignment_id)
    output = private_path(str(output))
    if output.exists():
        raise SafetyError("Refusing to overwrite a trial action receipt")
    http = http or HTTP()
    operator = operator or AzureCLI(model, subscription)
    controller = controller or pb.controlled_invoke
    guard = Guard(model, http, operator)
    guard.ownership()
    guard.actor()
    pb.check_workflow(data, state, http, operator, dry_run=True, expected_state="Disabled")
    pb.verify_grants(data, state, http, operator)
    verify_present(model, target, http, operator)
    receipt = {"schema_version": 1, "kind": "response", "action": "role-delete", "executed": True,
               "target": target, "response_transport": "guarded_logic_app", "status": "indeterminate",
               "timestamp": utc_now(), "request_started_at": None, "acknowledged_at": None,
               "http_status": None, "postcondition_verified": False, "mutation_acknowledged": False,
               "controller_started_at": utc_now(), "controller_completed_at": None,
               "executor": {"workflow_id": state["workflow_id"], "cleanup_verified": False, "run_id": None,
                            "response_outcome": "outcome_unverified"},
               "measurement_limit": "No probes during executor preparation, run and shutdown; retain the resulting observation gap."}

    def persist():
        # The receipt contains only allowlisted metadata, not state/provider bodies.
        output.write_text(json.dumps(receipt, allow_nan=False) + "\n", encoding="utf-8")

    persist()
    error = None
    try:
        controller(data, state, state_path, http, operator, "invoke")
    except BaseException as exc:
        error = exc
    finally:
        receipt["controller_completed_at"] = utc_now()
        last = state.get("last_run", {})
        receipt["executor"].update(run_id=last.get("name"), run_status=last.get("status"),
            response_outcome=last.get("response_outcome", "outcome_unverified"),
            cleanup_verified=state.get("disabled_verified") is True and state.get("safe_configuration_restored") is True
                and not state.get("execution_state_unknown") and not state.get("cleanup_problems"))
        # Any uncertainty is durable even if the controller raised/was interrupted.
        persist()
    if error is not None:
        raise error
    if not receipt["executor"]["cleanup_verified"]:
        raise SafetyError("Executor shutdown/restoration is not verified")
    if receipt["executor"]["response_outcome"] != "role_assignment_removed_access_unverified":
        receipt["status"] = "not_applied" if receipt["executor"]["response_outcome"] in {"already_absent_access_unverified", "dry_run_no_mutation"} else "indeterminate"
        persist()
        raise SafetyError("Executor did not prove a role-removal action for this trial")
    action = deletion_action_metadata(state, http, operator)
    began, completed = datetime.fromisoformat(receipt["controller_started_at"]), datetime.fromisoformat(receipt["controller_completed_at"])
    if not began <= datetime.fromisoformat(action["started_at"]) <= datetime.fromisoformat(action["ended_at"]) <= completed:
        raise SafetyError("Executor action is outside this controller invocation")
    guard.ownership()
    observed = pb.call(http, operator, "GET", target["role_assignment_id"] + "?api-version=2022-04-01")
    receipt.update(request_started_at=action["started_at"], acknowledged_at=action["ended_at"],
                   mutation_acknowledged=True, executor_action=action,
                   postcondition_readback={"http_status": observed.status, "transport_error": observed.transport_error})
    if observed.status == 404 and not observed.transport_error:
        receipt.update(postcondition_verified=True, status="configuration_verified_capability_unproven")
    persist()
    if not receipt["postcondition_verified"]:
        raise SafetyError("Exact role absence is unverified after executor completion")
    return receipt
