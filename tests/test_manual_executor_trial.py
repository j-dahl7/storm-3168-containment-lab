"""CORE09 adapter tests with inert ARM responses and no actor credentials."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import manual_executor_trial as adapter
from stormlab.core import Manifest, Response, SafetyError, response_target, utc_now
from test_core import fixture, Operator


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.data["role_assignments"][0]["role_definition_id"] = "/subscriptions/" + self.data["subscription_id"] + "/providers/Microsoft.Authorization/roleDefinitions/" + adapter.WRITER
        self.model = Manifest.from_dict(self.data)
        self.assignment = self.model.role_assignments[0]
        self.target = response_target(self.model, "role-delete", self.assignment["id"])
        self.state = {"lab_id": self.model.lab_id, "workflow_id": adapter.pb.workflow_path(self.data), "assignment": dict(self.assignment),
                      "responder_object_id": "12345678-1234-4234-8234-123456789012", "role_definition_guid": "22345678-1234-4234-8234-123456789012", "role_assignment_guid": "32345678-1234-4234-8234-123456789012"}
        self.deleted, self.calls, self.times = False, [], {}
        self.outcome = "role_assignment_removed_access_unverified"
        self.cleanup = True
        self.controller_error = False
        self.bad_clock = False
        self.absence_status = 404
        self.read_action_status = "Succeeded"

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        if "/actions/Delete_configured_assignment?" in url:
            rid = url.removeprefix(adapter.pb.ARM).split("?")[0]
            data = {"id": rid, "properties": {"status": self.read_action_status, "startTime": "2000-01-01T00:00:00Z" if self.bad_clock else self.times["start"], "endTime": self.times["end"], "outputsLink": {"uri": "https://never-follow.invalid/?sig=DO_NOT_SERIALIZE"}}}
            return Response(200, json.dumps(data).encode())
        if "/roleAssignments/" in url:
            if self.deleted:
                return Response(self.absence_status)
            data = {"id": self.assignment["id"], "properties": {"principalId": self.assignment["principal_id"], "principalType": "ServicePrincipal", "scope": self.assignment["scope"], "roleDefinitionId": self.assignment["role_definition_id"]}}
            return Response(200, json.dumps(data).encode())
        raise AssertionError("Unexpected HTTP request")

    def controller(self, data, state, path, http, operator, mode):
        self.assertEqual(mode, "invoke")
        self.assertNotIn("secretText", data)
        self.times = {"start": utc_now(), "end": utc_now()}
        self.deleted = True
        state.update(disabled_verified=self.cleanup, safe_configuration_restored=self.cleanup, execution_state_unknown=False, cleanup_problems=[])
        state["last_run"] = {"name": "recorded-run", "status": "Succeeded", "response_outcome": self.outcome}
        if self.controller_error:
            raise RuntimeError("Simulated controller failure")

    def exercise(self, expect_error=False):
        (ROOT / "private").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "private") as directory:
            output = Path(directory) / "action.jsonl"
            with patch.object(adapter, "load_bound_state", return_value=(Path(directory) / "responder.json", self.state, self.target)), \
                 patch.object(adapter, "Guard"), patch.object(adapter.pb, "check_workflow"), patch.object(adapter.pb, "verify_grants"):
                if expect_error:
                    with self.assertRaises((RuntimeError, SafetyError)):
                        adapter.invoke(self.data, self.model.subscription_id, self.assignment["id"], output, http=self, operator=Operator(), controller=self.controller)
                else:
                    adapter.invoke(self.data, self.model.subscription_id, self.assignment["id"], output, http=self, operator=Operator(), controller=self.controller)
            raw = output.read_text()
            self.assertNotIn("DO_NOT_SERIALIZE", raw)
            return json.loads(raw)

    def test_verified_workflow_removal_uses_action_clocks_and_independent_404(self):
        result = self.exercise()
        self.assertEqual(result["action"], "role-delete")
        self.assertEqual(result["response_transport"], "guarded_logic_app")
        self.assertTrue(result["postcondition_verified"])
        self.assertTrue(result["executor"]["cleanup_verified"])
        self.assertEqual(result["request_started_at"], adapter.utc_timestamp(self.times["start"]))
        self.assertIsNone(result["http_status"], "Do not invent the hidden HTTP DELETE response code")
        self.assertTrue(all(method == "GET" for method, _ in self.calls), "The adapter must not fall back to direct role deletion")

    def test_already_absent_is_not_a_successful_core09_action(self):
        self.outcome = "already_absent_access_unverified"
        result = self.exercise(True)
        self.assertEqual(result["status"], "not_applied")
        self.assertFalse(result["postcondition_verified"])

    def test_controller_failure_and_unknown_shutdown_are_durable(self):
        self.cleanup = False
        self.controller_error = True
        result = self.exercise(True)
        self.assertEqual(result["status"], "indeterminate")
        self.assertFalse(result["executor"]["cleanup_verified"])

    def test_forbidden_postcondition_does_not_become_absence(self):
        self.absence_status = 403
        result = self.exercise(True)
        self.assertFalse(result["postcondition_verified"])
        self.assertEqual(result["postcondition_readback"]["http_status"], 403)

    def test_wrong_action_clock_or_failed_action_refuses_measurement(self):
        self.bad_clock = True
        result = self.exercise(True)
        self.assertEqual(result["status"], "indeterminate")
        self.bad_clock = False
        self.read_action_status = "Failed"
        self.deleted = False
        result = self.exercise(True)
        self.assertEqual(result["status"], "indeterminate")

    def test_local_receipt_cannot_redirect_executor_or_assignment(self):
        for mutate in (lambda s: s.update(workflow_id=s["workflow_id"] + "-other"),
                       lambda s: s["assignment"].update(id=s["assignment"]["id"] + "-other"),
                       lambda s: s.update(cleanup_problems=["unresolved"])):
            state = copy.deepcopy(self.state)
            mutate(state)
            with patch.object(adapter, "load_json", return_value=state):
                with self.assertRaises(SafetyError):
                    adapter.load_bound_state(self.data, self.assignment["id"])


if __name__ == "__main__":
    unittest.main()
