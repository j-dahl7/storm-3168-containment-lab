import contextlib
from datetime import datetime, timedelta, timezone
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
import telemetry
import recovery_check
from stormlab.core import Manifest

SUB = "22222222-2222-4222-8222-222222222222"
TENANT = "11111111-1111-4111-8111-111111111111"
LAB = "33333333-3333-4333-8333-333333333333"
ACTOR = "55555555-5555-4555-8555-555555555555"
CUSTOMER = "77777777-7777-4777-8777-777777777777"
DATA = {
    "schema_version": 1, "subscription_id": SUB, "tenant_id": TENANT, "lab_id": LAB,
    "resource_group": "nls-storm3168-12345678", "location": "eastus2",
    "storage_account": "nlsstorm3168test", "workspace_name": "law-storm3168-test",
    "role_assignments": [], "actor": {
        "application_object_id": "44444444-4444-4444-8444-444444444444",
        "service_principal_object_id": ACTOR, "client_id": "66666666-6666-4666-8666-666666666666"},
}
M = Manifest.from_dict(DATA)
START, END = "2026-10-01T10:00:00Z", "2026-10-01T10:10:00Z"


def workspace(customer=CUSTOMER):
    return {"id": telemetry.workspace_id(M), "customerId": customer,
            "tags": {"storm3168LabId": LAB}}


def activity_row():
    return {"TimeGenerated": "2026-10-01T10:01:00Z",
            "ResourceId": M.storage_id, "ActorObjectId": ACTOR,
            "OperationNameValue": "Microsoft.Storage/storageAccounts/write",
            "ActivityStatusValue": "Succeeded",
            "Claims_d": {"secret": "MUST_NOT_BE_WRITTEN"},
            "HTTPRequest": "Authorization: Bearer MUST_NOT_BE_WRITTEN"}


class TelemetryTests(unittest.TestCase):
    def test_time_requires_utc_and_bound(self):
        now = datetime(2026, 10, 5, tzinfo=timezone.utc)
        for start, end in [
            ("2026-10-01T10:00:00", END),
            (START, "2026-10-01T10:10:00-05:00"),
            (END, START),
            (START, "2026-10-03T10:00:00Z"),
            (START, "2026-10-06T10:00:00Z"),
        ]:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                telemetry.time_window(start, end, now)
        self.assertEqual(telemetry.time_window(START, END, now)[0], "2026-10-01T10:00:00+00:00")

    def test_ownership_failure_precedes_workspace_lookup(self):
        with patch.object(telemetry, "assert_context"), patch.object(telemetry, "assert_owned", side_effect=RuntimeError("ownership")), patch.object(telemetry, "az") as command:
            with self.assertRaises(RuntimeError):
                telemetry.resolve_workspace(DATA, M, telemetry.workspace_id(M), owned=True)
        command.assert_not_called()

    def test_workspace_id_must_be_exact_no_query_or_host(self):
        with patch.object(telemetry, "az") as command:
            for suffix in ("?x=1", "/providers/extra", "%2fother", "\n"):
                with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                    telemetry.resolve_workspace(DATA, M, telemetry.workspace_id(M) + suffix, owned=True)
            with self.assertRaises(ValueError):
                telemetry.resolve_workspace(DATA, M, telemetry.workspace_id(M).replace("test", "foreign"), owned=True)
        command.assert_not_called()

    def test_live_resource_id_and_tag_checked(self):
        for bad in [
            {**workspace(), "id": telemetry.workspace_id(M) + "-other"},
            {**workspace(), "tags": {}},
            {**workspace(), "customerId": "not-a-guid"},
        ]:
            with self.subTest(bad=bad), patch.object(telemetry, "assert_context"), patch.object(telemetry, "assert_owned"), patch.object(telemetry, "az", return_value=bad):
                with self.assertRaises((RuntimeError, ValueError)):
                    telemetry.resolve_workspace(DATA, M, telemetry.workspace_id(M), owned=True)

    def test_query_uses_fresh_customer_id_never_resource_id(self):
        calls = []
        def command(*args):
            calls.append(args)
            if args[:4] == ("monitor", "log-analytics", "workspace", "show"):
                return workspace()
            if args[:3] == ("monitor", "log-analytics", "query"):
                return [activity_row()]
            raise AssertionError(args)
        with patch.object(telemetry, "assert_context"), patch.object(telemetry, "assert_owned"), patch.object(telemetry, "az", side_effect=command):
            selected = telemetry.resolve_workspace(DATA, M, telemetry.workspace_id(M), owned=True)
            result = telemetry.query_source(DATA, M, selected, "AzureActivity", START, END, 100)
        q = [c for c in calls if c[:3] == ("monitor", "log-analytics", "query")][0]
        self.assertEqual(q[q.index("--workspace") + 1], CUSTOMER)
        self.assertEqual(q[q.index("--subscription") + 1], SUB)
        self.assertIn("take 101", q[q.index("--analytics-query") + 1])
        self.assertIn('strcat(Scope, \'/\')', q[q.index("--analytics-query") + 1])
        serialized = json.dumps(result)
        self.assertNotIn("MUST_NOT_BE_WRITTEN", serialized)
        self.assertNotIn("Claims_d", serialized)

    def test_changed_customer_id_prevents_query(self):
        selected = {"resource_id": telemetry.workspace_id(M), "customer_id": CUSTOMER, "ownership_required": True}
        alternate = "88888888-8888-4888-8888-888888888888"
        with patch.object(telemetry, "assert_context"), patch.object(telemetry, "assert_owned"), patch.object(telemetry, "az", return_value=workspace(alternate)) as command:
            with self.assertRaisesRegex(RuntimeError, "customer ID changed"):
                telemetry.query_source(DATA, M, selected, "AzureActivity", START, END, 100)
        self.assertFalse(any(c.args[:3] == ("monitor", "log-analytics", "query") for c in command.call_args_list))

    def test_optional_workspace_is_explicit_read_only_and_same_tenant(self):
        foreign = telemetry.workspace_id(M).replace("12345678", "87654321")
        with patch.object(telemetry, "assert_context") as context, patch.object(telemetry, "assert_owned"), patch.object(telemetry, "az", return_value={**workspace(), "id": foreign, "tags": {}}):
            chosen = telemetry.resolve_workspace(DATA, M, foreign, owned=False)
        context.assert_called_with(SUB, TENANT)
        self.assertFalse(chosen["diagnostic_settings_changed"])
        self.assertEqual(chosen["selection"], "explicit_existing_identity_workspace")

    def test_no_signin_query_unless_explicitly_selected(self):
        with patch.object(telemetry, "resolve_workspace", return_value={"selection": "owned"}), patch.object(telemetry, "query_source", return_value={"status": "query_completed_no_rows", "rows": []}) as query:
            out = telemetry.collect(DATA, M, START, END)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(query.call_args.args[3], "AzureActivity")
        self.assertEqual(out["status"], "collection_completed")

    def test_missing_table_is_failure_not_no_rows(self):
        with patch.object(telemetry, "resolve_workspace", return_value={"selection": "owned"}), patch.object(telemetry, "query_source", side_effect=RuntimeError("SECRET STDERR")):
            out = telemetry.collect(DATA, M, START, END)
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["sources"][0]["status"], "query_failed")
        self.assertNotIn("SECRET", json.dumps(out))

    def test_sibling_resource_row_is_rejected(self):
        bad = {**activity_row(), "ResourceId": M.rg_id + "-foreign/providers/Microsoft.Storage/storageAccounts/other"}
        selection = {"resource_id": telemetry.workspace_id(M), "customer_id": CUSTOMER, "ownership_required": True}
        with patch.object(telemetry, "assert_owned"), patch.object(telemetry, "resolve_workspace", return_value={**selection, "subscription_id": SUB}), patch.object(telemetry, "az", return_value=[bad]):
            with self.assertRaises(RuntimeError):
                telemetry.query_source(DATA, M, selection, "AzureActivity", START, END, 100)

    def test_result_envelope_malformed_and_partial_fail_closed(self):
        self.assertEqual(telemetry.result_rows({"tables": [{"name": "PrimaryResult", "columns": [{"name": "x"}], "rows": [[1]]}]}), [{"x": 1}])
        for value in ({}, {"error": {"message": "hidden"}, "tables": []}, {"tables": [{"name": "PrimaryResult", "columns": [{"name": "x"}], "rows": [[1, 2]]}]}, [42]):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                telemetry.result_rows(value)

    def test_sanitizer_drops_payload_and_masks_unsafe_scalar(self):
        out = telemetry.sanitize_row({**activity_row(), "ActivityStatusValue": "https://evil/?sig=secret", "ResultDescription": "token=secret"})
        self.assertIsNone(out["ActivityStatusValue"])
        self.assertIn("ActivityStatusValue", out["RedactedFields"])
        self.assertNotIn("ResultDescription", out)

    def test_private_output_refuses_escape_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "evidence.json"
            with self.assertRaises(ValueError):
                telemetry.write_private(str(outside), {})
            with patch.object(telemetry, "private_path", side_effect=lambda p: Path(p)):
                telemetry.write_private(str(outside), {"status": "synthetic_test"})
                with self.assertRaises(FileExistsError):
                    telemetry.write_private(str(outside), {"status": "overwrite"})
            self.assertEqual(json.loads(outside.read_text())["status"], "synthetic_test")

    def test_max_rows_is_bounded_before_queries(self):
        with patch.object(telemetry, "resolve_workspace") as resolver:
            for limit in (0, 5001, True):
                with self.assertRaises(ValueError):
                    telemetry.collect(DATA, M, START, END, max_rows=limit)
        resolver.assert_not_called()


class RecoveryCheckTests(unittest.TestCase):
    def test_absent_account_does_not_claim_recoverability(self):
        now = datetime(2026, 10, 5, tzinfo=timezone.utc)
        with patch.object(recovery_check, "assert_owned"), patch.object(recovery_check, "az", return_value=[]) as command:
            out = recovery_check.check(DATA, M, "2026-10-04T00:00:00Z", now)
        self.assertEqual(out["restore_eligibility"], "not_established")
        self.assertTrue(out["within_14_days_if_timestamp_correct"])
        self.assertEqual(out["same_name_not_reused"], "not_verified")
        self.assertFalse(out["restore_attempted"])
        self.assertEqual(command.call_args.args[:2], ("resource", "list"))

    def test_existing_account_reads_only_config_not_keys(self):
        calls = []
        def command(*args):
            calls.append(args)
            if args[:2] == ("resource", "list"):
                return [{"id": M.storage_id}]
            return {"id": M.storage_id, "tags": {"storm3168LabId": LAB},
                    "kind": "StorageV2", "sku": {"name": "Standard_LRS"},
                    "encryption": {"keySource": "Microsoft.Storage", "keyvaultproperties": {"keyvaulturi": "SECRET"}},
                    "allowSharedKeyAccess": {"unexpected": "SECRET"},
                    "keys": [{"value": "SECRET"}], "privateEndpointConnections": []}
        with patch.object(recovery_check, "assert_owned"), patch.object(recovery_check, "az", side_effect=command):
            out = recovery_check.check(DATA, M)
        self.assertEqual(out["account_state"], "present_and_owned")
        self.assertNotIn("SECRET", json.dumps(out))
        self.assertEqual(calls[-1][:3], ("storage", "account", "show"))
        self.assertTrue(all("delete" not in c and "restore" not in c and "keys" not in c for c in calls))

    def test_wrong_live_tag_stops_report(self):
        with patch.object(recovery_check, "assert_owned"), patch.object(recovery_check, "az", side_effect=[[{"id": M.storage_id}], {"id": M.storage_id, "tags": {}}]):
            with self.assertRaisesRegex(RuntimeError, "ownership tag"):
                recovery_check.check(DATA, M)

    def test_future_deletion_date_fails_before_azure(self):
        with patch.object(recovery_check, "az") as command:
            with self.assertRaises(ValueError):
                recovery_check.check(DATA, M, "2030-01-01T00:00:00Z", datetime(2026, 10, 5, tzinfo=timezone.utc))
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
