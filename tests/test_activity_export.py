"""Offline export scope/ownership tests; no Azure calls."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import activity_export as ae
from stormlab.core import Manifest, Response, SafetyError
from test_core import fixture, Operator


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.data["budget_target_usd"] = 10
        self.m = Manifest.from_dict(self.data)
        export_uuid = "12345678-1234-4234-8234-123456789012"
        self.state = {"lab_id": self.m.lab_id, "subscription_id": self.m.subscription_id, "export_uuid": export_uuid,
                      "workspace_id": ae.workspace_id(self.m), "setting_id": ae.setting_id(self.m, export_uuid)}
        self.setting = None
        self.tag = self.m.lab_id
        self.calls, self.receipts = [], []
        self.worker = ae.ActivityExport(self.data, self, Operator())

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, body))
        if "Microsoft.OperationalInsights/workspaces/" in url:
            return Response(200, json.dumps({"id": ae.workspace_id(self.m), "tags": {"storm3168LabId": self.tag}}).encode())
        if method == "GET":
            return Response(404) if self.setting is None else Response(200, json.dumps(self.setting).encode())
        if method == "PUT":
            self.setting = {"id": self.state["setting_id"], **body}
            return Response(200)
        if method == "DELETE":
            self.setting = None
            return Response(204)
        raise AssertionError(method)

    def perform(self, operation="create", ack=True):
        with patch.object(ae, "assert_owned"):
            return self.worker.perform(operation, self.state, confirm_lab_id=self.m.lab_id,
                                       acknowledge_subscription_wide=ack, persist=lambda s: self.receipts.append(copy.deepcopy(s)))

    def test_only_administrative_exact_owned_workspace(self):
        result = self.perform()
        self.assertEqual(result["status"], "present_verified")
        writes = [row for row in self.calls if row[0] != "GET"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][2], ae.payload(self.m))
        self.assertEqual(self.receipts[0]["stage"], "create_planned")
        self.assertFalse(any("mcp-lab-law" in row[1] or "graph.microsoft.com" in row[1] for row in self.calls))

    def test_existing_setting_never_overwritten(self):
        self.setting = {"id": self.state["setting_id"], **ae.payload(self.m)}
        with self.assertRaisesRegex(SafetyError, "refusing overwrite"):
            self.perform()
        self.assertTrue(all(row[0] == "GET" for row in self.calls))

    def test_changed_destination_not_adopted_even_for_remove(self):
        self.setting = {"id": self.state["setting_id"], "properties": {"workspaceId": "/foreign", "logs": [{"category": "Administrative", "enabled": True}]}}
        with self.assertRaisesRegex(SafetyError, "destination or categories changed"):
            self.perform("remove")
        self.assertTrue(all(row[0] == "GET" for row in self.calls))

    def test_workspace_tag_changed_blocks_write(self):
        self.tag = "other"
        with self.assertRaisesRegex(SafetyError, "identity/tag changed"):
            self.perform()
        self.assertTrue(all(row[0] == "GET" for row in self.calls))

    def test_subscription_wide_ack_required(self):
        with self.assertRaisesRegex(SafetyError, "subscription-wide"):
            self.perform(ack=False)
        self.assertTrue(all(row[0] == "GET" for row in self.calls))

    def test_recorded_state_cannot_select_an_existing_named_export(self):
        self.state["setting_id"] = f"/subscriptions/{self.m.subscription_id}/providers/Microsoft.Insights/diagnosticSettings/mcp-lab-law"
        with self.assertRaisesRegex(SafetyError, "exact recorded"):
            self.perform()
        self.assertEqual(self.calls, [])

    def test_uncertain_put_preserves_exact_state_unknown(self):
        original = self.request
        def failed(method, *args):
            return Response(0, transport_error=True) if method == "PUT" else original(method, *args)
        with patch.object(self, "request", side_effect=failed):
            with self.assertRaisesRegex(SafetyError, "unconfirmed"):
                self.perform()
        self.assertEqual(self.receipts[-1]["stage"], "outcome_unknown")
        self.assertEqual(self.receipts[-1]["setting_id"], self.state["setting_id"])

    def test_exact_export_remove_and_idempotent_absence(self):
        self.perform()
        result = self.perform("remove")
        self.assertEqual(result["status"], "absent_verified")
        self.assertEqual(sum(row[0] == "DELETE" for row in self.calls), 1)
        self.perform("remove")
        self.assertEqual(sum(row[0] == "DELETE" for row in self.calls), 1)


if __name__ == "__main__":
    unittest.main()
