"""Offline response-workflow orchestration tests; no Azure access."""
import copy
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import playbook_lab as pb
from stormlab.core import Response
from test_core import fixture, Operator


def reply(status=200, data=None, **kwargs):
    return Response(status, json.dumps(data or {}).encode(), **kwargs)


def setup():
    m = fixture()
    state = {"lab_id": m["lab_id"], "workflow_id": pb.workflow_path(m),
             "assignment": copy.deepcopy(m["role_assignments"][0]),
             "responder_object_id": "12345678-1234-4234-8234-123456789012",
             "role_definition_guid": "22345678-1234-4234-8234-123456789012",
             "role_assignment_guid": "32345678-1234-4234-8234-123456789012"}
    role, grant = pb.grant_ids(m, state)
    state.update(role_definition_id=role, role_assignment_id=grant)
    return m, state


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeCloud:
    def __init__(self, m, state, scenario="success"):
        self.m, self.state, self.scenario = m, state, scenario
        self.calls, self.deployments, self.receipts = [], [], []
        self.started = False
        self.cancelled = False
        self.workflow = {"id": state["workflow_id"], "tags": {"storm3168LabId": m["lab_id"]},
                         "identity": {"type": "SystemAssigned", "principalId": state["responder_object_id"], "tenantId": m["tenant_id"]},
                         "properties": {"state": "Disabled", "parameters": {},
                                        "accessControl": {"triggers": {"sasAuthenticationPolicy": {"state": "Disabled"}, "allowedCallerIpAddresses": [{"addressRange": "0.0.0.0-0.0.0.0"}]}}}}
        values = {"expectedSubscriptionId": m["subscription_id"], "labId": m["lab_id"], "resourceGroupId": pb.rg_id(m),
                  "actorObjectId": m["actor"]["service_principal_object_id"], "targetRoleAssignmentId": state["assignment"]["id"],
                  "targetRoleScope": state["assignment"]["scope"], "targetRoleDefinitionId": state["assignment"]["role_definition_id"],
                  "dryRun": True, "executionConfirmation": ""}
        self.workflow["properties"]["parameters"] = {key: {"value": value} for key, value in values.items()}
        role, grant = pb.grant_ids(m, state)
        self.role = {"id": role, "properties": {"type": "CustomRole", "roleName": "Storm3168 bounded role removal " + m["lab_id"],
                     "assignableScopes": [pb.rg_id(m)], "permissions": [{"actions": sorted(pb.ROLE_ACTIONS), "notActions": [], "dataActions": [], "notDataActions": []}]}}
        self.grant = {"id": grant, "properties": {"scope": pb.rg_id(m), "principalId": state["responder_object_id"],
                      "principalType": "ServicePrincipal", "roleDefinitionId": role, "conditionVersion": "2.0",
                      "condition": pb.expected_condition(m, state)}}

    def deploy(self, m, state, *, dry_run):
        self.deployments.append(dry_run)
        self.workflow["properties"]["state"] = "Disabled"
        values = self.workflow["properties"]["parameters"]
        values["dryRun"]["value"] = not dry_run if self.scenario == "mode_drift" else dry_run
        values["executionConfirmation"]["value"] = "" if dry_run else pb.CONFIRMATION
        return {}

    def record(self, path, state):
        self.receipts.append(copy.deepcopy(state))

    def row(self, name, status):
        return {"name": name, "id": self.state["workflow_id"] + "/runs/" + name, "properties": {"status": status}}

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        target = url.split("?", 1)[0]
        base = pb.ARM + self.state["workflow_id"]
        if target == pb.ARM + self.state["role_definition_id"]:
            return reply(data=self.role)
        if target == pb.ARM + self.state["role_assignment_id"]:
            return reply(data=self.grant)
        if target == base:
            return reply(data=self.workflow)
        if target == base + "/enable":
            self.workflow["properties"]["state"] = "Enabled"
            return reply()
        if target == base + "/disable":
            if self.scenario != "disable_unverified":
                self.workflow["properties"]["state"] = "Disabled"
            return reply(202)
        if target == base + "/triggers/manual/run":
            self.started = True
            return reply(0, transport_error=True) if self.scenario in {"uncertain", "unknown"} else reply(202)
        if target.endswith("/cancel"):
            self.cancelled = self.scenario != "cancel_unverified"
            return reply()
        if target.endswith("/runs/new/actions"):
            name = "Record_already_absent" if self.scenario == "already_absent" else "Record_dry_run" if self.workflow["properties"]["parameters"]["dryRun"]["value"] else "Record_result"
            return reply(data={"value": [{"id": self.state["workflow_id"] + "/runs/new/actions/" + name, "name": name, "properties": {"status": "Succeeded"}}]})
        if target == base + "/runs":
            if self.scenario == "pagination":
                return reply(data={"value": [], "nextLink": "https://never-follow.example"})
            rows = [self.row("old", "Succeeded")]
            if self.scenario == "old_active":
                rows[0]["properties"]["status"] = "Running"
            if self.started and self.scenario != "unknown":
                status = "Cancelled" if self.cancelled else "Succeeded" if self.scenario in {"success", "disable_unverified", "already_absent"} else "Running"
                rows.append(self.row("new", status))
                if self.scenario == "concurrent":
                    rows.append(self.row("other-new", "Running"))
            return reply(data={"value": rows})
        raise AssertionError((method, url))


class PlaybookOperatorTests(unittest.TestCase):
    def exercise(self, scenario, *, raises=False, mode="invoke"):
        m, state = setup()
        cloud, clock = FakeCloud(m, state, scenario), Clock()
        with patch.object(pb, "assert_owned"), patch.object(pb, "deploy", side_effect=cloud.deploy), \
                patch.object(pb, "save", side_effect=cloud.record), patch.object(pb.time, "monotonic", clock.monotonic), \
                patch.object(pb.time, "sleep", clock.sleep):
            if raises:
                with self.assertRaises(RuntimeError):
                    pb.controlled_invoke(m, state, Path("never-written.json"), cloud, Operator(), mode, run_timeout=6, cleanup_timeout=6)
            else:
                pb.controlled_invoke(m, state, Path("never-written.json"), cloud, Operator(), mode, run_timeout=6, cleanup_timeout=6)
        return state, cloud

    def test_success_verifies_disable_and_restores_safe_configuration(self):
        state, cloud = self.exercise("success")
        self.assertTrue(state["disabled_verified"])
        self.assertTrue(state["safe_configuration_restored"])
        self.assertFalse(state["execution_state_unknown"])
        self.assertEqual(cloud.deployments, [False, True])
        self.assertTrue(any(row["last_run"]["name"] == "new" for row in cloud.receipts))
        self.assertFalse(any(url.endswith("/cancel?api-version=2016-06-01") for _, url in cloud.calls))
        self.assertEqual(state["last_run"]["response_outcome"], "role_assignment_removed_access_unverified")

    def test_already_absent_executor_is_distinct_from_role_removal(self):
        state, _ = self.exercise("already_absent")
        self.assertEqual(state["last_run"]["response_outcome"], "already_absent_access_unverified")

    def test_disable_restore_cancels_only_recorded_run_and_restores_dryrun(self):
        m, state = setup()
        cloud = FakeCloud(m, state, "timeout")
        cloud.started = True
        cloud.workflow["properties"]["state"] = "Enabled"
        state['last_run'] = {'name': 'new', 'status': 'Running'}
        state['cleanup_problems'] = ['workflow_disabled_unverified']
        with patch.object(pb, 'assert_owned'), patch.object(pb, 'deploy', side_effect=cloud.deploy), patch.object(pb, 'save', side_effect=cloud.record):
            pb.disable_restore(m, state, Path('never-written.json'), cloud, Operator(), timeout=0)
        self.assertTrue(state['disabled_verified'])
        self.assertTrue(state['safe_configuration_restored'])
        self.assertEqual(state['cleanup_problems'], [])
        self.assertEqual(sum('/runs/new/cancel?' in url for _, url in cloud.calls), 1)

    def test_disable_restore_does_not_adopt_unrecorded_queued_run(self):
        m, state = setup()
        cloud = FakeCloud(m, state, 'timeout')
        cloud.started = True
        with patch.object(pb, 'assert_owned'), patch.object(pb, 'save', side_effect=cloud.record):
            with self.assertRaises(RuntimeError):
                pb.disable_restore(m, state, Path('never-written.json'), cloud, Operator(), timeout=0)
        self.assertFalse(any('/cancel?' in url for _, url in cloud.calls))
        self.assertTrue(state['execution_state_unknown'])

    def test_timeout_cancels_only_new_run_before_safe_restore(self):
        state, cloud = self.exercise("timeout", raises=True)
        cancels = [url for method, url in cloud.calls if "/cancel?" in url]
        self.assertEqual(len(cancels), 1)
        self.assertIn("/runs/new/cancel?", cancels[0])
        self.assertEqual(state["last_run"]["status"], "Cancelled")
        self.assertTrue(state["safe_configuration_restored"])

    def test_uncertain_trigger_discovers_and_cancels_exact_new_run(self):
        state, cloud = self.exercise("uncertain", raises=True)
        self.assertFalse(state["last_run"]["trigger_acknowledged"])
        self.assertEqual(state["last_run"]["status"], "Cancelled")
        self.assertTrue(state["safe_configuration_restored"])

    def test_unknown_trigger_never_claims_terminal_or_restores(self):
        state, cloud = self.exercise("unknown", raises=True)
        self.assertTrue(state["execution_state_unknown"])
        self.assertFalse(state["safe_configuration_restored"])
        self.assertEqual(cloud.deployments, [False])
        self.assertFalse(any("/cancel?" in url for _, url in cloud.calls))

    def test_active_old_run_refused_without_any_mutation(self):
        state, cloud = self.exercise("old_active", raises=True)
        self.assertEqual(cloud.deployments, [])
        self.assertTrue(all(method == "GET" for method, _ in cloud.calls))

    def test_incomplete_inventory_fails_closed_and_records_unknown(self):
        state, cloud = self.exercise("pagination", raises=True)
        self.assertTrue(state["execution_state_unknown"])
        self.assertEqual(cloud.deployments, [])
        self.assertTrue(all(method == "GET" for method, _ in cloud.calls))

    def test_ambiguous_new_runs_are_never_cancelled(self):
        state, cloud = self.exercise("concurrent", raises=True)
        self.assertTrue(state["execution_state_unknown"])
        self.assertFalse(state["safe_configuration_restored"])
        self.assertFalse(any("/cancel?" in url for _, url in cloud.calls))

    def test_disable_ack_is_not_disabled_verification(self):
        state, cloud = self.exercise("disable_unverified", raises=True)
        self.assertTrue(state["disable_acknowledged"])
        self.assertFalse(state["disabled_verified"])
        self.assertFalse(state["safe_configuration_restored"])

    def test_cancel_ack_is_not_terminal_verification(self):
        state, cloud = self.exercise("cancel_unverified", raises=True)
        self.assertTrue(state["last_run"]["cancel_acknowledged"])
        self.assertTrue(state["execution_state_unknown"])
        self.assertFalse(state["safe_configuration_restored"])

    def test_execution_mode_drift_prevents_enable_and_trigger(self):
        state, cloud = self.exercise("mode_drift", raises=True)
        self.assertFalse(any("/enable?" in url or "/triggers/" in url for _, url in cloud.calls))

    def test_exact_grant_rejects_broader_actions_scopes_or_condition(self):
        m, state = setup()
        mutations = [lambda c: c.role["properties"]["permissions"][0]["actions"].append("*"),
                     lambda c: c.role["properties"].update(assignableScopes=["/subscriptions/" + m["subscription_id"]]),
                     lambda c: c.grant["properties"].update(condition=None),
                     lambda c: c.grant["properties"].update(conditionVersion="1.0"),
                     lambda c: c.grant["properties"].update(principalId=m["actor"]["service_principal_object_id"])]
        for mutate in mutations:
            cloud = FakeCloud(m, state)
            mutate(cloud)
            with self.assertRaises(RuntimeError):
                pb.verify_grants(m, state, cloud, Operator())

    def test_identity_and_confirmation_drift_rejected(self):
        m, state = setup()
        cloud = FakeCloud(m, state)
        cloud.workflow["identity"]["principalId"] = m["actor"]["service_principal_object_id"]
        with self.assertRaises(RuntimeError):
            pb.check_workflow(m, state, cloud, Operator())
        cloud = FakeCloud(m, state)
        cloud.workflow["properties"]["parameters"]["executionConfirmation"]["value"] = pb.CONFIRMATION
        with self.assertRaises(RuntimeError):
            pb.check_workflow(m, state, cloud, Operator(), dry_run=True)

    def test_rg_lookup_failure_after_trigger_does_not_prevent_independent_disable(self):
        m, state = setup()
        cloud, clock = FakeCloud(m, state), Clock()
        def ownership(*args):
            if cloud.started:
                raise RuntimeError("Simulated transient resource-group lookup failure")
        with patch.object(pb, "assert_owned", side_effect=ownership), patch.object(pb, "deploy", side_effect=cloud.deploy), \
                patch.object(pb, "save", side_effect=cloud.record), patch.object(pb.time, "monotonic", clock.monotonic), \
                patch.object(pb.time, "sleep", clock.sleep):
            with self.assertRaisesRegex(RuntimeError, "cleanup is incomplete"):
                pb.controlled_invoke(m, state, Path("never-written.json"), cloud, Operator(), "invoke", run_timeout=6, cleanup_timeout=6)
        self.assertEqual(cloud.workflow["properties"]["state"], "Disabled")
        self.assertTrue(state["disabled_verified"])
        self.assertFalse(state["safe_configuration_restored"])
        self.assertIn("safe_configuration_unverified", state["cleanup_problems"])
        self.assertEqual(state["shutdown"]["outcome"], "disabled_verified")
        self.assertTrue(any("/disable?" in url for _, url in cloud.calls))
        self.assertEqual(cloud.deployments, [False])

    def test_no_shutdown_authority_without_prior_live_rg_ownership(self):
        m, state = setup()
        cloud = FakeCloud(m, state)
        with patch.object(pb, "assert_owned", side_effect=RuntimeError("not owned")):
            with self.assertRaises(RuntimeError):
                pb.capture_shutdown_proof(m, state, cloud, Operator())
        self.assertEqual(cloud.calls, [])

    def test_independent_stop_refuses_changed_tag_or_managed_identity(self):
        for field in ("tag", "identity"):
            m, state = setup()
            cloud = FakeCloud(m, state)
            with patch.object(pb, "assert_owned"):
                proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
            if field == "tag":
                cloud.workflow["tags"] = {}
            else:
                cloud.workflow["identity"]["principalId"] = m["actor"]["service_principal_object_id"]
            with self.assertRaisesRegex(RuntimeError, "ownership drift"):
                pb.independent_shutdown(proof, state, cloud, Operator(), timeout=0)
            self.assertFalse(any(method == "POST" for method, _ in cloud.calls))
            self.assertFalse(state["disabled_verified"])
            self.assertEqual(state["shutdown"]["outcome"], "ownership_drift_refused")

    def test_stop_target_comes_from_immutable_proof_not_changed_state(self):
        m, state = setup()
        cloud = FakeCloud(m, state)
        with patch.object(pb, "assert_owned"):
            proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
        untrusted_state = {**state, "workflow_id": state["workflow_id"] + "-other"}
        cloud.workflow["properties"]["parameters"]["dryRun"]["value"] = False
        pb.independent_shutdown(proof, untrusted_state, cloud, Operator(), timeout=0)
        self.assertTrue(untrusted_state["disabled_verified"])
        self.assertFalse(any("-other" in url for _, url in cloud.calls))

    def test_lost_disable_response_keeps_ack_and_observation_separate(self):
        m, state = setup()
        cloud = FakeCloud(m, state)
        with patch.object(pb, "assert_owned"):
            proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
        original = cloud.request
        def request(method, url, *args):
            result = original(method, url, *args)
            return reply(0, transport_error=True) if "/disable?" in url else result
        with patch.object(cloud, "request", side_effect=request):
            pb.independent_shutdown(proof, state, cloud, Operator(), timeout=0)
        self.assertFalse(state["disable_acknowledged"])
        self.assertTrue(state["disabled_verified"])

    def test_leaf_get_timeout_still_attempts_captured_exact_disable(self):
        m, state = setup()
        cloud = FakeCloud(m, state)
        with patch.object(pb, "assert_owned"):
            proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
        cloud.workflow["properties"]["state"] = "Enabled"
        original = cloud.request
        unavailable_once = True
        def request(method, url, *args):
            nonlocal unavailable_once
            if method == "GET" and url == pb.ARM + proof.workflow_id + "?api-version=2019-05-01" and unavailable_once:
                unavailable_once = False
                return reply(0, transport_error=True)
            return original(method, url, *args)
        with patch.object(cloud, "request", side_effect=request):
            pb.independent_shutdown(proof, state, cloud, Operator(), timeout=0)
        self.assertEqual(state["shutdown"]["metadata_read"], "unavailable_using_captured_proof")
        self.assertTrue(state["disabled_verified"])
        self.assertEqual(sum("/disable?" in url for _, url in cloud.calls), 1)

    def test_leaf_unavailable_after_stop_never_claims_disabled(self):
        m, state = setup()
        cloud = FakeCloud(m, state)
        with patch.object(pb, "assert_owned"):
            proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
        original = cloud.request
        def request(method, url, *args):
            if method == "GET" and url == pb.ARM + proof.workflow_id + "?api-version=2019-05-01":
                return reply(0, transport_error=True)
            return original(method, url, *args)
        with patch.object(cloud, "request", side_effect=request):
            with self.assertRaisesRegex(RuntimeError, "shutdown is unverified"):
                pb.independent_shutdown(proof, state, cloud, Operator(), timeout=0)
        self.assertTrue(state["disable_acknowledged"])
        self.assertFalse(state["disabled_verified"])
        self.assertEqual(state["shutdown"]["outcome"], "unknown")

    def test_expired_activation_proof_still_stops_same_invocation(self):
        m, state = setup()
        cloud, clock = FakeCloud(m, state), Clock()
        with patch.object(pb, "assert_owned"), patch.object(pb.time, "monotonic", clock.monotonic):
            proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
            clock.now = pb.SHUTDOWN_PROOF_SECONDS
            cloud.workflow["properties"]["state"] = "Enabled"
            pb.independent_shutdown(proof, state, cloud, Operator(), timeout=0)
        self.assertTrue(state["shutdown"]["activation_proof_expired"])
        self.assertTrue(state["disabled_verified"])
        self.assertEqual(sum("/disable?" in url for _, url in cloud.calls), 1)

    def test_transient_disable_and_timeout_are_retried_then_verified(self):
        for failure in (reply(503), reply(429), subprocess.TimeoutExpired("not-recorded", 1)):
            m, state = setup()
            cloud, clock = FakeCloud(m, state), Clock()
            with patch.object(pb, "assert_owned"), patch.object(pb.time, "monotonic", clock.monotonic):
                proof = pb.capture_shutdown_proof(m, state, cloud, Operator())
            cloud.workflow["properties"]["state"] = "Enabled"
            original = cloud.request
            attempts = []
            def request(method, url, *args):
                if "/disable?" in url:
                    attempts.append(url)
                    if len(attempts) == 1:
                        if isinstance(failure, Exception):
                            raise failure
                        return failure
                return original(method, url, *args)
            with patch.object(cloud, "request", side_effect=request), patch.object(pb.time, "monotonic", clock.monotonic), patch.object(pb.time, "sleep", clock.sleep):
                pb.independent_shutdown(proof, state, cloud, Operator(), timeout=10)
            self.assertEqual(len(attempts), 2)
            self.assertEqual(len(set(attempts)), 1)
            self.assertTrue(state["disabled_verified"])
            self.assertNotIn("not-recorded", json.dumps(state))

    def test_unresolved_shutdown_receipt_blocks_another_invocation(self):
        m, state = setup()
        state["cleanup_problems"] = ["workflow_disabled_unverified"]
        cloud = FakeCloud(m, state)
        with self.assertRaisesRegex(RuntimeError, "cleanup is unresolved"):
            pb.controlled_invoke(m, state, Path("never-written.json"), cloud, Operator(), "invoke")
        self.assertEqual(cloud.calls, [])


if __name__ == "__main__":
    unittest.main()
