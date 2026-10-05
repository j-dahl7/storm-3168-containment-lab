"""Cleanup guardrails against fictional metadata; no Azure or Graph calls."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import cleanup_lab as cleanup
from stormlab.core import ARM, GRAPH, Manifest, Response, SafetyError

SUB = "22222222-2222-4222-8222-222222222222"
LAB = "33333333-3333-4333-8333-333333333333"
APP = "44444444-4444-4444-8444-444444444444"
SP = "55555555-5555-4555-8555-555555555555"
CLIENT = "66666666-6666-4666-8666-666666666666"
GROUP = "77777777-7777-4777-8777-777777777777"
MI = "99999999-9999-4999-8999-999999999999"
ROLE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
GRANT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def fixture():
    return Manifest.from_dict(json.loads((ROOT / "config" / "manifest.example.json").read_text(encoding="utf-8")))


def responder(m):
    return {"lab_id": m.lab_id,
            "workflow_id": m.rg_id + "/providers/Microsoft.Logic/workflows/storm3168-responder-" + m.lab_id.replace("-", "")[:8],
            "responder_object_id": MI, "role_definition_guid": ROLE, "role_assignment_guid": GRANT,
            "role_definition_id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{ROLE}",
            "role_assignment_id": m.rg_id + "/providers/Microsoft.Authorization/roleAssignments/" + GRANT,
            "assignment": dict(m.role_assignments[0]), "stage": "deployed_disabled"}


def response(status=200, data=None, **kwargs):
    return Response(status, json.dumps(data or {}).encode(), **kwargs)


class Operator:
    def token(self, service):
        return "FICTIONAL-OPERATOR-CREDENTIAL"


class Cloud:
    def __init__(self, m, targets):
        self.m, self.calls = m, []
        self.rg = {"id": m.rg_id, "tags": {"storm3168LabId": m.lab_id}}
        self.lock = None
        self.runs = {"value": []}
        self.locks = {"value": []}
        self.objects = {}
        self.reject_delete = None
        self.keep_deleted = False
        self.after_mutation = None
        for t in targets:
            value = {"id": t.id}
            if t.kind in {"assignment", "responder_assignment"}:
                value["properties"] = {"principalId": t.metadata["principal_id"], "scope": t.metadata["scope"],
                                       "roleDefinitionId": t.metadata["role_definition_id"], "principalType": "ServicePrincipal"}
            elif t.kind == "role_definition":
                value["properties"] = {"roleName": "Storm3168 bounded role removal " + m.lab_id, "type": "CustomRole",
                                       "description": f"Lab {m.lab_id}: read ownership/assignments and conditionally remove the configured actor role. No effective-access guarantee.",
                                       "assignableScopes": [m.rg_id], "permissions": [{"actions": list(cleanup.ROLE_ACTIONS)}]}
            elif t.kind in {"workflow", "storage", "workspace"}:
                types = {"workflow": "Microsoft.Logic/workflows", "storage": "Microsoft.Storage/storageAccounts", "workspace": "Microsoft.OperationalInsights/workspaces"}
                value.update(tags={"storm3168LabId": m.lab_id}, name=t.id.rsplit("/", 1)[-1], type=types[t.kind])
                if t.kind == "workflow":
                    a = t.metadata["assignment"]
                    parameters = {"expectedSubscriptionId": m.subscription_id, "labId": m.lab_id, "resourceGroupId": m.rg_id,
                                  "actorObjectId": m.actor["service_principal_object_id"], "targetRoleAssignmentId": a["id"],
                                  "targetRoleScope": a["scope"], "targetRoleDefinitionId": a["role_definition_id"]}
                    value.update(identity={"type": "SystemAssigned", "principalId": MI},
                                 properties={"state": "Enabled", "parameters": {k: {"value": v} for k, v in parameters.items()}})
            elif t.kind in {"application", "service_principal"}:
                value.update(displayName=m.name_prefix, appId=m.actor["client_id"])
                if t.kind == "application":
                    value["tags"] = ["storm3168LabId=" + m.lab_id]
                else:
                    value.update(servicePrincipalType="Application", appOwnerOrganizationId=m.tenant_id)
            elif t.kind == "group":
                value.update(displayName=m.name_prefix + "-access", description="storm3168LabId=" + m.lab_id, securityEnabled=True, mailEnabled=False)
            self.objects[(ARM if t.service == "arm" else GRAPH) + t.path] = value

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        if url == ARM + self.m.rg_id + "?api-version=2021-04-01":
            return response(data=self.rg)
        if url == ARM + self.m.lock_id + "?api-version=2016-09-01":
            return response(404) if self.lock is None else response(data=self.lock)
        if "/runs?" in url:
            return response(data=self.runs)
        if "/Microsoft.Authorization/locks?" in url:
            return response(data=self.locks)
        if "/resources?" in url or "/Microsoft.Authorization/roleAssignments?" in url:
            return response(data={"value": []})
        if method == "GET":
            item = self.objects.get(url)
            return response(404) if item is None else response(data=item)
        if method == "POST" and "/disable?" in url:
            key = url.split("/disable?")[0] + "?api-version=2019-05-01"
            self.objects[key]["properties"]["state"] = "Disabled"
        elif method == "DELETE":
            if self.reject_delete:
                return self.reject_delete
            if not self.keep_deleted:
                self.objects.pop(url, None)
        else:
            raise AssertionError("Unexpected cloud mutation")
        if self.after_mutation:
            self.after_mutation(self)
        return response(204)

    @property
    def writes(self):
        return [call for call in self.calls if call[0] != "GET"]


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.m = fixture()
        self.state = responder(self.m)
        self.targets, self.plan = cleanup.build_plan(self.m, self.state)
        self.cloud = Cloud(self.m, self.targets)
        self.worker = cleanup.Cleanup(self.m, self.targets, self.cloud, Operator(), sleeper=lambda _: None)

    def target(self, kind):
        return next(t for t in self.targets if t.kind == kind)

    def obj(self, kind):
        t = self.target(kind)
        return self.cloud.objects[(ARM if t.service == "arm" else GRAPH) + t.path]

    def execute(self):
        return self.worker.execute(self.plan, subscription=SUB, confirm_lab_id=LAB)

    def assert_stops_before_write(self, regex):
        with self.assertRaisesRegex(SafetyError, regex):
            self.execute()
        self.assertEqual(self.cloud.writes, [])

    def test_default_plan_retains_data_and_never_targets_resource_group(self):
        self.assertNotIn("storage", [t.kind for t in self.targets])
        self.assertNotIn("workspace", [t.kind for t in self.targets])
        self.assertNotIn(self.m.rg_id, [t.id for t in self.targets])
        self.assertEqual(len(self.plan["retained"]), 3)
        self.assertEqual(self.plan["live_validation"], "not_performed")

    def test_missing_state_does_not_derive_workflow_role_or_managed_identity(self):
        targets, plan = cleanup.build_plan(self.m)
        self.assertEqual({t.kind for t in targets}, {"assignment", "application", "service_principal", "group"})
        self.assertEqual(len(plan["skipped"]), 3)

    def test_guids_without_deployed_ids_are_not_adopted(self):
        state = {"lab_id": LAB, "role_definition_guid": ROLE, "role_assignment_guid": GRANT}
        targets, _ = cleanup.build_plan(self.m, state)
        self.assertNotIn("role_definition", [t.kind for t in targets])
        self.assertNotIn("responder_assignment", [t.kind for t in targets])

    def test_missing_responder_object_id_retains_workflow(self):
        state = {"lab_id": LAB, "workflow_id": self.state["workflow_id"]}
        targets, plan = cleanup.build_plan(self.m, state)
        self.assertNotIn("workflow", [t.kind for t in targets])
        self.assertTrue(any("missing recorded responder_object_id" in s for s in plan["skipped"]))

    def test_state_other_lab_or_subscription_or_workflow_rejected(self):
        for key, value in [("lab_id", SUB), ("role_definition_id", self.state["role_definition_id"].replace(SUB, LAB)),
                           ("role_assignment_id", self.state["role_assignment_id"].replace(self.m.resource_group, "production")),
                           ("workflow_id", self.state["workflow_id"] + "-other")]:
            state = {**self.state, key: value}
            with self.subTest(key=key), self.assertRaises(SafetyError):
                cleanup.build_plan(self.m, state)

    def test_id_guid_inconsistency_rejected(self):
        with self.assertRaisesRegex(SafetyError, "GUID differ"):
            cleanup.build_plan(self.m, {**self.state, "role_assignment_guid": ROLE})

    def test_role_id_url_injection_rejected(self):
        for extra in ["/../foreign", "?scope=foreign", "#fragment", "%2fwrong"]:
            with self.subTest(extra=extra), self.assertRaises(SafetyError):
                cleanup.build_plan(self.m, {**self.state, "role_definition_id": self.state["role_definition_id"] + extra})

    def test_data_delete_requires_explicit_ack_and_exact_account_name(self):
        for kwargs in [{"include_workspace": True}, {"include_storage": True, "confirm_storage_name": self.m.storage_account},
                       {"include_storage": True, "acknowledge_data_loss": True, "confirm_storage_name": "otheraccount"}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(SafetyError):
                cleanup.build_plan(self.m, self.state, **kwargs)
        targets, plan = cleanup.build_plan(self.m, self.state, include_workspace=True, include_storage=True,
                                           acknowledge_data_loss=True, confirm_storage_name=self.m.storage_account)
        self.assertEqual([t.kind for t in targets][-2:], ["storage", "workspace"])
        self.assertEqual([r["id"] for r in plan["retained"]], [self.m.rg_id])

    def test_subscription_and_confirmation_required_before_reads(self):
        with self.assertRaisesRegex(SafetyError, "confirmation mismatch"):
            self.worker.execute(self.plan, subscription=SUB, confirm_lab_id=SUB)
        self.assertEqual(self.cloud.calls, [])

    def test_rg_ownership_drift_stops_before_write(self):
        self.cloud.rg["tags"] = {}
        self.assert_stops_before_write("ownership tag")

    def test_lock_is_never_removed_and_blocks_cleanup(self):
        self.cloud.lock = {"id": self.m.lock_id, "properties": {"notes": "storm3168LabId=" + LAB}}
        self.assert_stops_before_write("lock-remove")

    def test_unrecorded_rg_lock_blocks_before_any_write(self):
        self.cloud.locks = {"value": [{"id": self.m.rg_id + "/providers/Microsoft.Authorization/locks/foreign", "properties": {"level": "CanNotDelete"}}]}
        self.assert_stops_before_write("locks are present")

    def test_leftovers_are_reported_but_never_added_as_targets(self):
        extra = self.m.rg_id + "/providers/Microsoft.Storage/storageAccounts/unrecorded"
        original = self.cloud.request
        def request(method, url, *args):
            if "/resources?" in url:
                return response(data={"value": [{"id": extra, "type": "Microsoft.Storage/storageAccounts"}]})
            return original(method, url, *args)
        with patch.object(self.cloud, "request", side_effect=request):
            result = self.execute()
        self.assertEqual(result["leftovers"]["unrecorded_resources"][0]["id"], extra)
        self.assertFalse(any(extra in url for _, url in self.cloud.writes))

    def test_recorded_export_is_integrated_before_resource_deletion(self):
        import activity_export as ae
        export_uuid = "12345678-1234-4234-8234-123456789012"
        state = {"lab_id": LAB, "subscription_id": SUB, "export_uuid": export_uuid,
                 "workspace_id": ae.workspace_id(self.m), "setting_id": ae.setting_id(self.m, export_uuid)}
        targets, plan = cleanup.build_plan(self.m, self.state, export_state=state)
        self.assertEqual(plan["operations"][0]["id"], state["setting_id"])
        data = json.loads((ROOT / "config/manifest.example.json").read_text())
        worker = cleanup.Cleanup(self.m, targets, self.cloud, Operator(), sleeper=lambda _: None,
                                 manifest_data=data, export_state=state)
        with patch.object(cleanup.ActivityExport, "read_setting", return_value={}), patch.object(cleanup, "remove_recorded_export", return_value={"status": "absent_verified"}) as remove:
            result = worker.execute(plan, subscription=SUB, confirm_lab_id=LAB)
        remove.assert_called_once()
        self.assertEqual(remove.call_args.args[1]["setting_id"], state["setting_id"])
        self.assertEqual(result["results"][0]["action"], "remove_recorded_activity_export")

    def test_exact_actor_name_required_not_prefix(self):
        self.obj("application")["displayName"] += "-production"
        self.assert_stops_before_write("exact display name")

    def test_actor_client_mismatch_stops_before_write(self):
        self.obj("service_principal")["appId"] = APP
        self.assert_stops_before_write("application ID")

    def test_app_tag_and_group_marker_required(self):
        self.obj("application")["tags"] = []
        self.assert_stops_before_write("Application ownership tag")
        self.obj("application")["tags"] = ["storm3168LabId=" + LAB]
        self.obj("group")["description"] = "unrelated"
        self.assert_stops_before_write("Group exact display name")

    def test_foreign_tenant_sp_rejected(self):
        self.obj("service_principal")["appOwnerOrganizationId"] = SUB
        self.assert_stops_before_write("owner tenant")

    def test_changed_assignment_scope_stops_before_write(self):
        self.obj("assignment")["properties"]["scope"] = "/subscriptions/" + SUB
        self.assert_stops_before_write("assignment principal, scope")

    def test_role_definition_must_be_owned_and_narrow(self):
        self.obj("role_definition")["properties"]["permissions"][0]["actions"].append("*")
        self.assert_stops_before_write("permissions changed")

    def test_changed_managed_identity_or_workflow_tag_rejected(self):
        self.obj("workflow")["identity"]["principalId"] = SP
        self.assert_stops_before_write("managed identity")
        self.obj("workflow")["identity"]["principalId"] = MI
        self.obj("workflow")["tags"] = {}
        self.assert_stops_before_write("resource ownership tag")

    def test_disable_precedes_every_delete_and_roles_precede_identities(self):
        result = self.execute()
        self.assertEqual(result["status"], "completed_with_retained_resources")
        self.assertEqual(self.cloud.writes[0][0], "POST")
        self.assertIn("/disable?", self.cloud.writes[0][1])
        paths = [url for verb, url in self.cloud.writes if verb == "DELETE"]
        self.assertLess(paths.index(ARM + self.target("responder_assignment").path), paths.index(ARM + self.target("workflow").path))
        self.assertLess(paths.index(ARM + self.target("assignment").path), paths.index(GRAPH + self.target("service_principal").path))
        self.assertEqual({r["status"] for r in result["results"]}, {"disabled_no_active_runs", "absence_verified"})
        self.assertFalse(any("/servicePrincipals/" + MI in url for _, url in self.cloud.calls))

    def test_active_run_blocks_deletes_after_disabling(self):
        self.cloud.runs = {"value": [{"properties": {"status": "Running"}}]}
        with self.assertRaisesRegex(SafetyError, "active/unknown run"):
            self.execute()
        self.assertEqual([v for v, _ in self.cloud.writes], ["POST"])

    def test_paginated_runs_fail_closed(self):
        self.cloud.runs = {"value": [], "nextLink": "https://untrusted.example/"}
        with self.assertRaisesRegex(SafetyError, "Cannot prove responder"):
            self.execute()
        self.assertEqual([v for v, _ in self.cloud.writes], ["POST"])

    def test_tag_drift_after_disable_prevents_deletion(self):
        self.cloud.after_mutation = lambda cloud: cloud.rg.update(tags={})
        with self.assertRaisesRegex(SafetyError, "ownership tag"):
            self.execute()
        self.assertEqual([v for v, _ in self.cloud.writes], ["POST"])

    def test_404_is_idempotent_without_writes(self):
        self.cloud.objects.clear()
        result = self.execute()
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual({r["status"] for r in result["results"]}, {"already_absent"})

    def test_transport_error_is_not_absence_or_success(self):
        original = self.cloud.request
        def failed(method, url, *args):
            if url == ARM + self.target("assignment").path:
                return response(0, transport_error=True)
            return original(method, url, *args)
        with patch.object(self.cloud, "request", side_effect=failed):
            self.assert_stops_before_write("Cannot verify cleanup metadata")

    def test_unconfirmed_delete_stops_without_retries_or_following_deletes(self):
        self.cloud.keep_deleted = True
        with self.assertRaisesRegex(SafetyError, "postcondition not confirmed"):
            self.execute()
        self.assertEqual([v for v, _ in self.cloud.writes], ["POST", "DELETE"])
        self.assertEqual(self.plan["status"], "stopped_reconciliation_required")
        self.assertIn("pending", self.plan)

    def test_delete_permission_failure_is_not_absence(self):
        self.cloud.reject_delete = response(403)
        with self.assertRaisesRegex(SafetyError, "not acknowledged"):
            self.execute()
        self.assertEqual([v for v, _ in self.cloud.writes], ["POST", "DELETE"])

    def test_identity_delete_cannot_bypass_recorded_role_removal(self):
        with self.assertRaisesRegex(SafetyError, "role assignment still exists"):
            self.worker.write(self.target("service_principal"), "DELETE")
        self.assertEqual(self.cloud.writes, [])

    def test_write_cannot_use_unrecorded_target(self):
        with self.assertRaisesRegex(SafetyError, "outside the exact cleanup"):
            self.worker.write(cleanup.Target("storage", self.m.storage_id), "DELETE")
        self.assertEqual(self.cloud.calls, [])

    def test_default_cli_plan_has_no_network_or_report_write(self):
        # Exercise the CLI's extra manifest/export reads against an isolated
        # fictional fixture, never an operator's ignored private directory.
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory).resolve() / "private"
            private.mkdir()
            manifest = private / "manifest.json"
            manifest.write_text((ROOT / "config" / "manifest.example.json").read_text(encoding="utf-8"), encoding="utf-8")
            with patch.object(sys, "argv", ["cleanup_lab.py", "--manifest", str(manifest)]), \
                 patch.object(cleanup, "load_inputs", return_value=(self.m, self.state, private)), \
                 patch.object(cleanup, "AzureCLI") as cli, patch.object(cleanup, "HTTP") as http, patch.object(cleanup, "write_report") as save, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cleanup.main(), 0)
            self.assertEqual(sorted(p.name for p in private.iterdir()), ["manifest.json"])
        cli.assert_not_called()
        http.assert_not_called()
        save.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["mode"], "plan")

    def test_cli_execute_missing_confirmations_rejected_before_loading(self):
        with patch.object(sys, "argv", ["cleanup_lab.py", "--execute"]), patch.object(cleanup, "load_inputs") as load, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cleanup.main()
        load.assert_not_called()

    def test_manifest_outside_same_clone_private_rejected(self):
        with self.assertRaisesRegex(SafetyError, "this checkout's private"):
            cleanup.load_inputs(ROOT / "config" / "manifest.example.json")


if __name__ == "__main__":
    unittest.main()
