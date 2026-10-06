import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import uuid
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import live_trial
from initial_token import acquire_initial_token, CredentialHTTPError, CredentialTransportError
from test_core import token as fake_token
from stormlab.core import utc_now, response_target, Manifest, claims_from_token

SUB = "22222222-2222-4222-8222-222222222222"
LAB = "33333333-3333-4333-8333-333333333333"
CLIENT = "66666666-6666-4666-8666-666666666666"
KEY = "88888888-8888-4888-8888-888888888888"


class LiveTrialProtocolTests(unittest.TestCase):
    def exercise(self, *, action="sp-disable", capability="arm-tag-write", baseline_count=2, lost_creation_reply=False, cleanup_interrupt=False, post_interrupt=False, executor_cleanup=True,
                 initial_errors=(), new_token_error=None):
        (ROOT / "private").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "private") as temp:
            manifest_path = Path(temp) / "manifest.json"
            manifest = json.loads((ROOT / "config" / "manifest.example.json").read_text())
            manifest_path.write_text(json.dumps(manifest))
            state = {"credentials": [], "tokens": [], "responded": False, "token_calls": 0, "issued": []}
            assignment_id = manifest["role_assignments"][0]["id"]
            executor_target = response_target(Manifest.from_dict(manifest), "role-delete", assignment_id)
            created_run_dirs = []
            real_private_path = live_trial.private_path

            def isolated_private_path(value):
                candidate = real_private_path(value)
                runs = ROOT / "private" / "runs"
                if candidate.is_relative_to(runs):
                    candidate = Path(temp) / "runs" / candidate.relative_to(runs)
                    if candidate.parent.name == "runs":
                        candidate.parent.mkdir(parents=True, exist_ok=True)
                        created_run_dirs.append(candidate)
                return candidate

            def request(method, url, token=None, payload=None, form=None, **kwargs):
                if url.endswith("/addPassword"):
                    name = payload["passwordCredential"]["displayName"]
                    state["credentials"] = [{"keyId": KEY, "displayName": name}]
                    state["secret_expiry"] = payload["passwordCredential"]["endDateTime"]
                    if lost_creation_reply:
                        raise RuntimeError("transport failure after remote creation")
                    return {"keyId": KEY, "secretText": "fictional-in-memory-secret"}
                if url.endswith("/removePassword"):
                    self.assertEqual(payload, {"keyId": KEY})
                    if cleanup_interrupt:
                        raise KeyboardInterrupt()
                    state["credentials"] = []
                    return {}
                if "oauth2/v2.0/token" in url:
                    state["token_calls"] += 1
                    if state["responded"] and new_token_error:
                        raise new_token_error
                    if state["token_calls"] <= len(initial_errors):
                        raise initial_errors[state["token_calls"] - 1]
                    issued = fake_token(exp=time.time() + 3600, iat=time.time(), jti=str(state["token_calls"]), aud=form["scope"].removesuffix(".default"))
                    state["issued"].append(issued)
                    return {"access_token": issued}
                if "/servicePrincipals/" in url:
                    return {"appId": CLIENT, "accountEnabled": True}
                return {"id": manifest["actor"]["application_object_id"], "appId": CLIENT,
                        "displayName": "storm3168-" + LAB, "passwordCredentials": list(state["credentials"])}

            def harness(arguments, env):
                if arguments[0] == "probe":
                    state["tokens"].append(env["STORMLAB_PROBE_TOKEN"])
                    output = Path(arguments[arguments.index("--output") + 1])
                    count = baseline_count if output.name == "baseline.jsonl" else 1
                    run = str(uuid.uuid4())
                    identity = {"run_id": run, "credential_label": arguments[arguments.index("--credential-label") + 1],
                                "capability": capability, "auth": "bearer"}
                    claims = claims_from_token(env["STORMLAB_PROBE_TOKEN"])
                    rows = [{"kind": "run_start", "token_metadata": {key: claims.get(key) for key in ("aud", "iat", "exp")}, **identity}]
                    for n in range(count):
                        now = utc_now()
                        rows.append({"kind": "probe", "outcome": "allowed", "http_status": 200,
                                     "timestamp": now, "request_started_at": now, "response_received_at": now, **identity})
                    output.write_text("\n".join(json.dumps(row) for row in rows))
                    if post_interrupt and output.name == "post-action.jsonl":
                        raise KeyboardInterrupt()
                    rows.append({"kind": "run_end", "run_id": run, "status": "completed"})
                    output.write_text("\n".join(json.dumps(row) for row in rows))
                else:
                    state["responded"] = True
                    output = Path(arguments[arguments.index("--output") + 1])
                    self.assertEqual(output.name, "action.jsonl")
                    current = Manifest.from_dict(json.loads(Path(arguments[arguments.index("--manifest") + 1]).read_text()))
                    output.write_text(json.dumps({"kind": "response", "action": action, "executed": True, "target": response_target(current, action),
                                                 "request_started_at": utc_now(), "acknowledged_at": utc_now(), "http_status": 204,
                                                 "status": "configuration_verified_capability_unproven", "postcondition_verified": True}) + "\n")

            def executor(data, subscription, selected_assignment, output):
                state['responded'] = True
                state['manual_executor_calls'] = state.get('manual_executor_calls', 0) + 1
                self.assertEqual(selected_assignment, assignment_id)
                self.assertNotIn('secretText', data)
                self.assertNotIn(state['issued'][0], json.dumps(data))
                result = {"kind": "response", "action": "role-delete", "executed": True, "target": executor_target,
                          "request_started_at": utc_now(), "acknowledged_at": utc_now(), "http_status": None,
                          "status": "configuration_verified_capability_unproven" if executor_cleanup else "indeterminate",
                          "postcondition_verified": executor_cleanup, "measurement_limit": "controller gap",
                          "executor_action": {"clock_source": "service_action_metadata"},
                          "executor": {"cleanup_verified": executor_cleanup, "run_id": "fixture-run", "response_outcome": "role_assignment_removed_access_unverified"}}
                output.write_text(json.dumps(result) + '\n')
                if not executor_cleanup:
                    raise RuntimeError('Executor shutdown unverified')
                return result

            argv = ["live_trial.py", "--manifest", str(manifest_path), "--subscription", SUB,
                    "--confirm-lab-id", LAB, "--action", action, "--capability", capability, "--duration", "20", "--execute", "--check-new-token"]
            if capability == "blob-read":
                argv.extend(["--storage-baseline-state", str(Path(temp) / "storage.json")])
            if action == "manual-executor":
                argv.extend(["--role-assignment-id", assignment_id])
            failure = None
            acquisition_clock = [0.0]
            def bounded_initial(*args, **kwargs):
                return acquire_initial_token(*args, **kwargs, clock=lambda: acquisition_clock[0],
                    sleeper=lambda seconds: acquisition_clock.__setitem__(0, acquisition_clock[0] + seconds))
            with patch.object(sys, "argv", argv), patch.object(live_trial, "load_owned", return_value=(manifest_path, manifest)), \
                 patch.object(live_trial, "private_path", side_effect=isolated_private_path), \
                 patch.object(live_trial, "assert_owned"), patch.object(live_trial, "graph_token", return_value="operator-only"), \
                 patch.object(live_trial, "begin_trial"), patch.object(live_trial, "finish_trial") as finished, \
                 patch.object(live_trial, "assert_storage_window", return_value={"valid": True}) as prepared, \
                 patch.object(live_trial, "request", side_effect=request), patch.object(live_trial, "invoke_harness", side_effect=harness), \
                 patch.object(live_trial, "acquire_initial_token", side_effect=bounded_initial), \
                 patch.object(live_trial.manual_executor_trial, "load_bound_state", return_value=(Path(temp) / "responder.json", {}, executor_target)), \
                 patch.object(live_trial.manual_executor_trial, "invoke", side_effect=executor), \
                 patch.object(live_trial.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="a" * 40)), \
                 contextlib.redirect_stdout(io.StringIO()):
                try:
                    result = live_trial.main()
                    self.assertEqual(result, 0)
                except BaseException as exc:
                    failure = str(exc)
                    state["failure_type"] = type(exc).__name__
                state["finish_cleanup_confirmed"] = finished.call_args.kwargs["cleanup_confirmed"]
                state["storage_checks"] = prepared.call_count
            receipt_path = next((Path(temp) / "runs").rglob("trial.json"))
            receipt_text = receipt_path.read_text()
            self.assertNotIn("fictional-in-memory-secret", receipt_text)
            self.assertNotIn("frozen-probe", receipt_text)
            self.assertNotIn("separate-issuance-control", receipt_text)
            receipt = json.loads(receipt_text)
            if not cleanup_interrupt:
                self.assertTrue(receipt["credential_removed"])
                self.assertEqual(state["credentials"], [])
            return state, receipt, failure

    def test_new_issuance_never_replaces_probe_and_action_receipt_is_local(self):
        state, receipt, failure = self.exercise()
        self.assertIsNone(failure)
        self.assertEqual(state["tokens"], [state["issued"][0], state["issued"][0]])
        self.assertNotEqual(state["issued"][0], state["issued"][1])
        self.assertEqual(receipt["separate_new_token_check"]["status"], "issued")
        self.assertTrue(receipt["action_receipt"]["postcondition_verified"])

    def test_initial_transient_retries_freeze_one_token_and_cleanup_once(self):
        errors = [CredentialTransportError(), CredentialHTTPError(429, "temporarily_unavailable", []), CredentialHTTPError(401, "invalid_client", [7000215])]
        state, receipt, failure = self.exercise(initial_errors=errors)
        self.assertIsNone(failure)
        self.assertEqual(receipt["initial_token_attempts"], 4)
        self.assertEqual(len(receipt["initial_token_acquisition"]), 4)
        self.assertEqual(state["tokens"], [state["issued"][0], state["issued"][0]])
        self.assertEqual(len(state["issued"]), 2)  # One initial token plus the separate new-token control.
        self.assertEqual(sum(r.get("token_frozen") is True for r in receipt["initial_token_acquisition"]), 1)

    def test_initial_nonretryable_auth_failure_never_probes_or_responds(self):
        state, receipt, failure = self.exercise(initial_errors=[CredentialHTTPError(401, "invalid_client", [7000222])])
        self.assertIsNotNone(failure)
        self.assertEqual(state["token_calls"], 1)
        self.assertEqual(state["tokens"], [])
        self.assertFalse(state["responded"])
        self.assertTrue(receipt["credential_removed"])

    def test_initial_retry_exhaustion_preserves_cleanup_without_response(self):
        state, receipt, failure = self.exercise(initial_errors=[CredentialTransportError()] * 100)
        self.assertIsNotNone(failure)
        self.assertFalse(state["responded"])
        self.assertEqual(state["tokens"], [])
        self.assertTrue(receipt["credential_removed"])
        self.assertEqual(receipt["initial_token_acquisition"][-1]["terminal_reason"], "budget_exhausted_before_next_attempt")

    def test_post_action_new_token_check_is_still_one_shot(self):
        state, receipt, failure = self.exercise(new_token_error=CredentialTransportError())
        self.assertIsNone(failure)
        self.assertEqual(state["token_calls"], 2)
        self.assertEqual(receipt["initial_token_attempts"], 1)
        self.assertEqual(receipt["separate_new_token_check"]["attempts"], 1)
        self.assertEqual(receipt["separate_new_token_check"]["status"], "transport_error_or_unknown")

    def test_temporary_secret_expiry_is_outside_maximum_observation(self):
        state, receipt, failure = self.exercise()
        self.assertIsNone(failure)
        self.assertEqual(receipt["temporary_credential_ttl_seconds"], 10800)
        self.assertEqual(receipt["temporary_credential_expires_at"], state["secret_expiry"])
        self.assertNotIn("fictional-in-memory-secret", json.dumps(receipt))

    def test_one_baseline_success_is_insufficient_and_cleanup_still_runs(self):
        state, receipt, failure = self.exercise(baseline_count=1)
        self.assertIn("No successful baseline", failure)
        self.assertFalse(state["responded"])
        self.assertEqual(receipt["status"], "failed_or_incomplete")

    def test_lost_creation_reply_reconciles_only_unique_recorded_credential(self):
        state, receipt, failure = self.exercise(lost_creation_reply=True)
        self.assertIn("transport failure", failure)
        self.assertEqual(receipt["credential_key_id"], KEY)
        self.assertFalse(state["responded"])

    def test_cleanup_keyboard_interrupt_persists_unconfirmed_receipt_then_reraises(self):
        state, receipt, failure = self.exercise(cleanup_interrupt=True)
        self.assertEqual(state["failure_type"], "KeyboardInterrupt")
        self.assertEqual(receipt["status"], "interrupted")
        self.assertFalse(receipt["credential_removed"])
        self.assertIn("cleanup_required", receipt)
        self.assertFalse(state["finish_cleanup_confirmed"])

    def test_partial_post_action_run_id_is_saved_after_interrupt(self):
        state, receipt, failure = self.exercise(post_interrupt=True)
        self.assertEqual(state["failure_type"], "KeyboardInterrupt")
        self.assertIn("post_action", receipt["probe_runs"])
        self.assertEqual(receipt["probe_phase_status"]["post_action"], "incomplete")
        self.assertEqual(receipt["status"], "interrupted")

    def test_core12_uses_storage_audience_and_prepared_window_checks(self):
        state, receipt, failure = self.exercise(capability="blob-read")
        self.assertIsNone(failure)
        self.assertEqual(receipt["frozen_token_metadata"]["aud"], "https://storage.azure.com/")
        self.assertEqual(receipt["separate_new_token_check"]["token_metadata"]["aud"], "https://storage.azure.com/")
        self.assertEqual(state["storage_checks"], 2)

    def test_core09_keeps_one_probe_token_and_records_workflow_transport(self):
        state, receipt, failure = self.exercise(action='manual-executor')
        self.assertIsNone(failure)
        self.assertEqual(state['manual_executor_calls'], 1)
        self.assertEqual(state['tokens'], [state['issued'][0], state['issued'][0]])
        self.assertEqual(receipt['action'], 'role-delete')
        self.assertEqual(receipt['orchestration_action'], 'manual-executor')
        self.assertEqual(receipt['response_transport'], 'guarded_logic_app')
        self.assertIn('controller_observation_gap_seconds', receipt)
        self.assertTrue(state['finish_cleanup_confirmed'])

    def test_core09_unknown_workflow_cleanup_retains_trial_lease(self):
        state, receipt, failure = self.exercise(action='manual-executor', executor_cleanup=False)
        self.assertIn('shutdown unverified', failure)
        self.assertFalse(state['finish_cleanup_confirmed'])
        self.assertTrue(receipt['credential_removed'])
        self.assertFalse(receipt['executor_receipt']['cleanup_verified'])


if __name__ == "__main__":
    unittest.main()
