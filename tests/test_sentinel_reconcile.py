"""Offline exact-ID post-trial reconciliation; no Azure calls."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sentinel_reconcile as sr
from stormlab.core import Manifest, Response, SafetyError
from test_core import fixture, Operator

INCIDENT = "12345678-1234-4234-8234-123456789012"
RULE = "22345678-1234-4234-8234-123456789012"
EVENT = "32345678-1234-4234-8234-123456789012"
MI = "42345678-1234-4234-8234-123456789012"


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.data, self.calls = fixture(), []
        self.m = Manifest.from_dict(self.data)
        self.workflow_id = self.m.rg_id + "/providers/Microsoft.Logic/workflows/test-executor"
        self.incident_id = sr.workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/incidents/" + INCIDENT
        self.receipt = {"schema_version": 1, "lab_id": self.m.lab_id, "subscription_id": self.m.subscription_id,
                        "workspace_id": sr.workspace_id(self.m), "analytic_rule_id": RULE,
                        "not_before_utc": "2026-10-05T10:00:00Z", "not_after_utc": "2026-10-05T12:00:00Z",
                        "incident_ids": [INCIDENT], "workflows": [{"resource_id": self.workflow_id, "kind": "executor", "principal_id": MI, "run_names": ["queued-one"]}]}
        values = {"expectedSubscriptionId": self.m.subscription_id, "resourceGroupId": self.m.rg_id, "labId": self.m.lab_id, "actorObjectId": self.m.actor["service_principal_object_id"]}
        self.workflow = {"id": self.workflow_id, "tags": {"storm3168LabId": self.m.lab_id},
                         "identity": {"type": "SystemAssigned", "principalId": MI, "tenantId": self.m.tenant_id},
                         "properties": {"state": "Enabled", "parameters": {k: {"value": v} for k, v in values.items()}}}
        self.runs = {"queued-one": "Waiting"}
        self.cancel_finishes = True
        self.incident = {"id": self.incident_id, "etag": '"fixture-etag"', "properties": {"title": "Lab incident", "severity": "Medium", "status": "New", "createdTimeUtc": "2026-10-05T11:01:00Z",
                         "relatedAnalyticRuleIds": [sr.workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/alertRules/" + RULE]}}
        self.details = {"LabId": [self.m.lab_id], "ActorObjectId": [self.m.actor["service_principal_object_id"]], "ResourceId": [self.m.storage_id], "ProviderEventId": [EVENT], "ProviderEventTime": ["2026-10-05T11:00:00Z"]}
        self.alerts = {"value": [{"kind": "SecurityAlert", "properties": {"alertType": RULE, "additionalData": {"Custom Details": self.details}}}]}
        self.worker = sr.Reconciler(self.data, self.receipt, self, Operator(), sleeper=lambda _: None)

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        path = url.removeprefix(sr.ARM).split("?", 1)[0]
        value = None
        if path == sr.workspace_id(self.m):
            value = {"id": path, "tags": {"storm3168LabId": self.m.lab_id}}
        elif path == self.workflow_id:
            value = self.workflow
        elif path == self.workflow_id + "/disable":
            self.workflow["properties"]["state"] = "Disabled"
        elif path == self.workflow_id + "/runs":
            value = {"value": [{"id": self.workflow_id + "/runs/" + n, "name": n, "properties": {"status": s}} for n, s in self.runs.items()]}
        elif path.startswith(self.workflow_id + "/runs/"):
            name = path[len(self.workflow_id + "/runs/"):].split("/")[0]
            if path.endswith("/cancel"):
                if self.cancel_finishes:
                    self.runs[name] = "Cancelled"
            else:
                value = {"id": self.workflow_id + "/runs/" + name, "name": name, "properties": {"status": self.runs[name]}}
        elif path == self.incident_id + "/alerts":
            self.assertEqual(method, "POST")
            value = self.alerts
        elif path == self.incident_id:
            if method == "PUT":
                self.assertEqual(headers["If-Match"], self.incident["etag"])
                self.incident["properties"]["status"] = "Closed"
            value = self.incident
        else:
            raise AssertionError((method, path))
        return Response(200, json.dumps(value or {}).encode())

    def run_cleanup(self):
        with patch.object(sr, "assert_owned"):
            return self.worker.execute(confirm_lab_id=self.m.lab_id, persist=lambda _: None, timeout=0)

    def test_disable_cancel_known_queue_then_conditional_exact_incident_close(self):
        result = self.run_cleanup()
        self.assertEqual(result["status"], "reconciled")
        writes = [(method, url) for method, url, _, _ in self.calls if method in {"POST", "PUT"} and "/alerts?" not in url]
        self.assertTrue(writes[0][1].endswith("/disable?api-version=2016-06-01"))
        self.assertTrue(writes[1][1].endswith("/runs/queued-one/cancel?api-version=2016-06-01"))
        self.assertEqual(writes[2], ("PUT", sr.ARM + self.incident_id + "?api-version=2025-09-01"))
        self.assertFalse(any(url.endswith("/incidents?api-version=2025-09-01") for _, url, _, _ in self.calls))

    def test_unrecorded_queued_run_is_never_adopted_or_incident_closed(self):
        self.runs["unrecorded"] = "Waiting"
        result = self.run_cleanup()
        self.assertEqual(result["status"], "partial_reconciliation_required")
        self.assertFalse(any("/cancel?" in url or method == "PUT" for method, url, _, _ in self.calls))

    def test_unconfirmed_cancellation_does_not_close_incident(self):
        self.cancel_finishes = False
        result = self.run_cleanup()
        self.assertEqual(result["status"], "partial_reconciliation_required")
        self.assertFalse(any(method == "PUT" for method, _, _, _ in self.calls))

    def test_fresh_incident_for_old_provider_event_not_closed(self):
        self.details["ProviderEventTime"] = ["2026-10-05T09:59:59Z"]
        result = self.run_cleanup()
        self.assertEqual(result["incidents"][0]["status"], "unresolved")
        self.assertFalse(any(method == "PUT" for method, _, _, _ in self.calls))

    def test_changed_actor_or_rule_never_closed(self):
        self.details["ActorObjectId"] = [self.m.actor["client_id"]]
        result = self.run_cleanup()
        self.assertEqual(result["incidents"][0]["status"], "unresolved")
        self.assertFalse(any(method == "PUT" for method, _, _, _ in self.calls))

    def test_receipt_bounds_and_cross_group_targets_rejected_without_io(self):
        for mutation in [lambda r: r["workflows"][0].update(resource_id=self.workflow_id.replace(self.m.resource_group, "foreign")),
                         lambda r: r.update(not_after_utc="2026-10-06T12:00:00Z"),
                         lambda r: r["workflows"][0].update(run_names=["../other"]),
                         lambda r: r.update(incident_ids=[INCIDENT] * 11)]:
            receipt = copy.deepcopy(self.receipt)
            mutation(receipt)
            with self.assertRaises(SafetyError):
                sr.validate_receipt(self.m, receipt)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
