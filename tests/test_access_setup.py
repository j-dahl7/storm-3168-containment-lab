"""Offline access-path preparation checks. No CLI or Azure network calls."""
import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

from stormlab.core import ARM, GRAPH, Guard, Manifest, SafetyError
from test_core import (APP, ASSIGNMENT, CLIENT, GROUP, LAB, SP, FakeHTTP,
                       Operator, fixture, response)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("configure_access", ROOT / "scripts" / "configure_access.py")
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)


class AccessHTTP(FakeHTTP):
    def __init__(self, m):
        super().__init__(m)
        self.assignments = {r["id"]: {"id": r["id"], "properties": {
            "principalId": r["principal_id"], "scope": r["scope"], "roleDefinitionId": r["role_definition_id"]}}
                            for r in m.role_assignments}
        self.member = False
        self.enabled = False
        self.unexpected = None
        self.group_pagination = False
        self.bad_assignment = False

    def request(self, method, url, headers=None, body=None):
        m = self.m
        if url.startswith(ARM + m.storage_id + "?") and method == "GET":
            self.calls.append((method, url, headers or {}, body))
            return response(data={"id": m.storage_id, "name": m.storage_account, "tags": {"storm3168LabId": LAB}})
        if "/roleDefinitions/" in url:
            self.calls.append((method, url, headers or {}, body))
            rid = url.removeprefix(ARM).split("?", 1)[0]
            name = "Reader" if rid.endswith(access.READER) else "Storage Blob Data Reader" if rid.endswith(access.DATA_READER) else "Storage Account Contributor"
            return response(data={"id": rid, "properties": {"roleName": name}})
        if "/transitiveMemberOf?" in url:
            self.calls.append((method, url, headers or {}, body))
            result = {"value": [{"id": GROUP}] if self.member else []}
            if self.group_pagination:
                result["@odata.nextLink"] = "https://graph.microsoft.com/unexpected"
            return response(data=result)
        if "/roleAssignments?" in url:
            self.calls.append((method, url, headers or {}, body))
            vals = list(self.assignments.values())
            if self.unexpected:
                vals.append(self.unexpected)
            return response(data={"value": copy.deepcopy(vals)})
        if "/roleAssignments/" in url:
            self.calls.append((method, url, headers or {}, body))
            rid = url.removeprefix(ARM).split("?", 1)[0]
            if method == "PUT":
                self.assignments[rid] = {"id": rid, "properties": dict(body["properties"], scope=rid.rsplit("/providers/Microsoft.Authorization/roleAssignments/", 1)[0])}
                return response(201, self.assignments[rid])
            if method == "DELETE":
                self.assignments.pop(rid, None)
                return response(204)
            if rid not in self.assignments:
                return response(404)
            obj = copy.deepcopy(self.assignments[rid])
            if self.bad_assignment:
                obj["properties"]["principalId"] = APP
            return response(data=obj)
        if "/members/$ref" in url and method == "POST":
            self.calls.append((method, url, headers or {}, body))
            if body != {"@odata.id": GRAPH + "/v1.0/directoryObjects/" + SP}:
                raise AssertionError("Wrong member target")
            self.member = True
            return response(204)
        if "/members/" in url:
            self.calls.append((method, url, headers or {}, body))
            return response(data={"id": SP}) if self.member else response(404)
        if f"/servicePrincipals/{SP}" in url and (method == "PATCH" or "accountEnabled" in url):
            self.calls.append((method, url, headers or {}, body))
            if method == "PATCH":
                self.enabled = body["accountEnabled"]
                return response(204)
            return response(data={"id": SP, "appId": CLIENT, "accountEnabled": self.enabled})
        return super().request(method, url, headers, body)


class AccessSetupTests(unittest.TestCase):
    def setup_case(self, *, group=True):
        data = fixture()
        data["budget_target_usd"] = 10
        data["role_assignments"][0]["role_definition_id"] = data["role_assignments"][0]["role_definition_id"].rsplit("/", 1)[0] + "/" + access.STORAGE_WRITER
        if not group:
            data.pop("group")
        m = Manifest.from_dict(data)
        http = AccessHTTP(m)
        guard = Guard(m, http, Operator())
        persisted = []
        return data, m, http, guard, lambda row: persisted.append(copy.deepcopy(row)), persisted

    def test_plan_never_writes(self):
        data, m, http, guard, persist, saved = self.setup_case()
        result = access.configure(data, guard, "group", execute=False, enable_actor=True, persist=persist)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(http.mutations, [])
        self.assertEqual(saved, [])

    def test_direct_works_without_group_and_preserves_reader(self):
        data, m, http, guard, persist, saved = self.setup_case(group=False)
        result = access.configure(data, guard, "direct", execute=True, enable_actor=False, persist=persist)
        self.assertEqual(result["status"], "configuration_verified_baseline_required")
        self.assertEqual(len(data["role_assignments"]), 2)
        self.assertTrue(any(r["role_definition_id"].endswith(access.READER) for r in data["role_assignments"]))
        self.assertFalse(any(c[0] == "DELETE" for c in http.calls))
        self.assertFalse(any(c[0] == "PATCH" for c in http.calls))

    def test_group_requires_recorded_group(self):
        data, m, http, guard, persist, saved = self.setup_case(group=False)
        with self.assertRaises(SafetyError):
            access.configure(data, guard, "group", execute=True, enable_actor=False, persist=persist)
        self.assertEqual(http.calls, [])

    def test_group_switch_removes_only_writer_and_records_before_creation(self):
        data, m, http, guard, persist, saved = self.setup_case()
        existing = m.role_assignments[0]["id"]
        result = access.configure(data, guard, "group", execute=True, enable_actor=True, persist=persist)
        deletes = [c for c in http.calls if c[0] == "DELETE"]
        self.assertEqual(len(deletes), 1)
        self.assertTrue(deletes[0][1].startswith(ARM + existing + "?"))
        self.assertTrue(http.member)
        self.assertTrue(http.enabled)
        self.assertEqual(len(data["role_assignments"]), 2)
        reader = next(r for r in data["role_assignments"] if r["role_definition_id"].endswith(access.READER))
        writer = next(r for r in data["role_assignments"] if r["role_definition_id"].endswith(access.STORAGE_WRITER))
        self.assertEqual(reader["principal_id"], SP)
        self.assertEqual(writer["principal_id"], GROUP)
        self.assertTrue(any(reader in snapshot["role_assignments"] for snapshot in saved))
        self.assertTrue(any(writer in snapshot["role_assignments"] for snapshot in saved))
        self.assertEqual(result["baseline_authorization"], "not_tested")
        self.assertFalse(any("/applications/" in c[1] and c[0] != "GET" for c in http.calls))

    def test_unexpected_inherited_writer_path_stops_before_mutation(self):
        data, m, http, guard, persist, saved = self.setup_case()
        http.unexpected = {"id": "/subscriptions/other/roleAssignments/not-recorded", "properties": {
            "principalId": SP, "scope": "/subscriptions/" + m.subscription_id,
            "roleDefinitionId": access.role_definition_id(m, "b24988ac-6180-42a0-ab88-20f7382dd24c")}}
        with self.assertRaises(SafetyError):
            access.configure(data, guard, "direct", execute=True, enable_actor=False, persist=persist)
        self.assertFalse(http.mutations)
        self.assertFalse(saved)

    def test_recorded_assignment_cannot_be_adopted_with_changed_principal(self):
        data, m, http, guard, persist, saved = self.setup_case()
        http.bad_assignment = True
        with self.assertRaises(SafetyError):
            access.configure(data, guard, "direct", execute=True, enable_actor=False, persist=persist)
        self.assertFalse(http.mutations)

    def test_incomplete_group_inventory_fails_closed(self):
        data, m, http, guard, persist, saved = self.setup_case()
        http.group_pagination = True
        with self.assertRaises(SafetyError):
            access.configure(data, guard, "direct", execute=True, enable_actor=False, persist=persist)
        self.assertFalse(http.mutations)

    def test_tag_rechecked_before_role_creation(self):
        data, m, http, guard, persist, saved = self.setup_case()
        http.break_tag_after = 1
        with self.assertRaises(SafetyError):
            access.configure(data, guard, "direct", execute=True, enable_actor=False, persist=persist)
        self.assertFalse(http.mutations)
        self.assertTrue(saved)  # Intended ID retained for reconciliation.

    def test_data_reader_is_recorded_before_exact_account_scoped_creation(self):
        data, m, http, guard, persist, saved = self.setup_case()
        result = access.configure_data_reader(data, guard, "add", execute=True, persist=persist)
        row = next(r for r in data["role_assignments"] if r["role_definition_id"].endswith(access.DATA_READER))
        self.assertEqual(row["scope"], m.storage_id)
        self.assertEqual(row["principal_id"], SP)
        self.assertIn(row, saved[0]["role_assignments"])
        self.assertEqual(len(http.mutations), 1)
        self.assertEqual(http.mutations[0][0], "PUT")

    def test_exact_recorded_data_reader_is_not_an_unexpected_writer(self):
        data, m, http, guard, persist, saved = self.setup_case()
        access.configure_data_reader(data, guard, "add", execute=True, persist=persist)
        m = Manifest.from_dict(data)
        guard = Guard(m, http, Operator())
        self.assertEqual(access.inventory(guard)["unexpected_potential_writer_paths"], [])

    def test_data_reader_at_rg_or_for_group_is_rejected(self):
        for scope_kind, principal in [("rg", SP), ("account", GROUP)]:
            data, m, http, guard, persist, saved = self.setup_case()
            scope = m.rg_id if scope_kind == "rg" else m.storage_id
            data["role_assignments"].append({"id": scope + "/providers/Microsoft.Authorization/roleAssignments/11111111-2222-4333-8444-555555555555", "principal_id": principal,
                "scope": scope, "role_definition_id": access.role_definition_id(m, access.DATA_READER)})
            with self.assertRaises(SafetyError):
                access.configure_data_reader(data, guard, "add", execute=True, persist=persist)
            self.assertFalse(http.mutations)

    def test_unrecorded_data_reader_is_not_adopted(self):
        data, m, http, guard, persist, saved = self.setup_case()
        http.unexpected = {"id": m.storage_id + "/providers/Microsoft.Authorization/roleAssignments/unrecorded", "properties": {
            "principalId": SP, "scope": m.storage_id, "roleDefinitionId": access.role_definition_id(m, access.DATA_READER)}}
        self.assertTrue(access.inventory(guard)["unexpected_potential_writer_paths"])
        with self.assertRaises(SafetyError):
            access.configure_data_reader(data, guard, "add", execute=True, persist=persist)
        self.assertFalse(http.mutations)


if __name__ == "__main__":
    unittest.main()
