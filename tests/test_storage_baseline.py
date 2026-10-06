import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import storage_baseline as baseline
from stormlab.core import Manifest, Response, SafetyError

DATA = {
    "schema_version": 1, "tenant_id": "11111111-1111-4111-8111-111111111111",
    "subscription_id": "22222222-2222-4222-8222-222222222222",
    "lab_id": "33333333-3333-4333-8333-333333333333",
    "resource_group": "nls-storm3168-12345678", "storage_account": "nlsstorm3168test",
    "workspace_name": "law-storm3168-test", "location": "eastus2",
    "role_assignments": [], "blob": {"container": "canary", "name": "synthetic.txt"}
}
M = Manifest.from_dict(DATA)
NONCE = "44444444-4444-4444-8444-444444444444"


def closed():
    return {"allowSharedKeyAccess": False, "publicNetworkAccess": "Enabled",
            "networkAcls": {"bypass": "None", "defaultAction": "Deny", "ipRules": [],
                            "virtualNetworkRules": [], "resourceAccessRules": []}}


def state():
    before = closed()
    return {"state_kind": "storm3168_storage_baseline", "lab_id": M.lab_id,
            "subscription_id": M.subscription_id, "storage_id": M.storage_id,
            "original_settings": before, "client_ip": "8.8.8.8", "enable_shared_key": True,
            "prepared_settings": baseline.desired_settings(before, "8.8.8.8", True)}


class BaselineSafetyTests(unittest.TestCase):
    def test_only_explicit_public_single_ipv4(self):
        for ip in ("0.0.0.0", "0.0.0.0/0", "8.8.8.8/32", "10.0.0.1", "127.0.0.1", "::1", "8.8.8.8\n"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                baseline.client_ip(ip)
        self.assertEqual(baseline.client_ip("8.8.8.8"), "8.8.8.8")

    def test_original_settings_cannot_be_broad_or_shared_key_on(self):
        for original in [
            {**closed(), "allowSharedKeyAccess": True},
            {**closed(), "networkAcls": {**closed()["networkAcls"], "defaultAction": "Allow"}},
            {**closed(), "networkAcls": {**closed()["networkAcls"], "ipRules": [{"value": "0.0.0.0/0"}]}},
        ]:
            with self.assertRaises(SafetyError):
                baseline.initial_settings({"properties": original})

    def test_plan_does_not_mutate_or_acquire_keys(self):
        guard = Mock(m=M)
        with patch.object(baseline, "account", return_value={"properties": closed()}), patch.object(baseline, "container_preflight", return_value=("exact", True)), patch.object(baseline, "patch_settings") as mutate, patch.object(baseline, "seed_credential") as credentials:
            result = baseline.prepare(DATA, guard, "8.8.8.8", "bearer", False, 60, Path("unused"), False)
        self.assertFalse(result["cloud_mutations"])
        mutate.assert_not_called()
        credentials.assert_not_called()

    def test_shared_key_requires_explicit_optin_before_reads(self):
        with patch.object(baseline, "account") as read:
            with self.assertRaises(SafetyError):
                baseline.prepare(DATA, Mock(m=M), "8.8.8.8", "shared-key", False, 60, Path("unused"), False)
        read.assert_not_called()

    def test_bounded_hold_required(self):
        for seconds in (0, 59, 7801, True, 600.0):
            with self.assertRaises(SafetyError):
                baseline.prepare(DATA, Mock(m=M), "8.8.8.8", "bearer", False, seconds, Path("unused"), False)

    def test_long_explicit_hold_plan_remains_bounded_and_read_only(self):
        with patch.object(baseline, "account", return_value={"properties": closed()}), patch.object(baseline, "container_preflight", return_value=("exact", True)), patch.object(baseline, "patch_settings") as mutate:
            for seconds in (60, 1801, 5400, 7800):
                with self.subTest(seconds=seconds):
                    result = baseline.prepare(DATA, Mock(m=M), "8.8.8.8", "bearer", False, seconds, Path("unused"), False)
                    self.assertEqual(result["hold_seconds"], seconds)
                    self.assertFalse(result["cloud_mutations"])
        mutate.assert_not_called()

    def test_foreign_container_is_not_adopted(self):
        guard = Mock(m=M)
        guard.read.return_value = Response(200)
        guard.checked.return_value = {"id": M.storage_id + "/blobServices/default/containers/canary", "properties": {"metadata": {}}}
        with self.assertRaises(SafetyError):
            baseline.container_preflight(guard)

    def test_restore_checks_receipt_identity_before_network(self):
        receipt = state()
        receipt["storage_id"] += "-foreign"
        with patch.object(baseline, "account") as read:
            with self.assertRaises(SafetyError):
                baseline.restore(Mock(m=M), receipt, True)
        read.assert_not_called()

    def test_restore_refuses_network_drift(self):
        current = baseline.desired_settings(closed(), "8.8.4.4", True)
        with patch.object(baseline, "account", return_value={"properties": current}), patch.object(baseline, "patch_settings") as update:
            with self.assertRaises(SafetyError):
                baseline.restore(Mock(m=M), state(), True)
        update.assert_not_called()

    def test_restore_accepts_deliberate_shared_key_disable(self):
        current = baseline.desired_settings(closed(), "8.8.8.8", False)
        with patch.object(baseline, "account", return_value={"properties": current}), patch.object(baseline, "patch_settings") as update:
            result = baseline.restore(Mock(m=M), state(), True)
        update.assert_called_once()
        self.assertEqual(update.call_args.args[1], closed())
        self.assertTrue(result["settings_restored"])

    def test_restore_plan_is_read_only(self):
        with patch.object(baseline, "account", return_value={"properties": state()["prepared_settings"]}), patch.object(baseline, "patch_settings") as update:
            result = baseline.restore(Mock(m=M), state(), False)
        update.assert_not_called()
        self.assertEqual(result["status"], "restore_planned")

    def test_signed_seed_headers_have_conditional_write_no_secret(self):
        key = base64.b64encode(b"x" * 64).decode()
        headers = baseline.blob_headers("PUT", "/canary/baseline-" + NONCE + ".txt", b"test", "shared-key", key, M, NONCE)
        self.assertEqual(headers["If-None-Match"], "*")
        self.assertEqual(headers["Content-Length"], "4")
        self.assertTrue(headers["Authorization"].startswith("SharedKey " + M.storage_account + ":"))
        self.assertNotIn(key, json.dumps(headers))

    def test_blob_name_cannot_select_another_target(self):
        with self.assertRaises(SafetyError):
            baseline.blob_request(Mock(m=M), "PUT", "../production", NONCE, "bearer", "token", b"x")

    def test_container_creation_conflict_is_not_adopted(self):
        guard = Mock(m=M)
        with patch.object(baseline, "account"), patch.object(baseline, "container_preflight", return_value=("exact", True)), patch.object(baseline, "storage_request", return_value=Response(409)) as request:
            with self.assertRaises(SafetyError):
                baseline.create_container(guard, "exact", "bearer", "operator-token")
        self.assertEqual(request.call_args.args[2], "/canary?restype=container")
        headers = request.call_args.args[3]
        self.assertNotIn("x-ms-blob-public-access", headers)
        self.assertNotIn("x-ms-blob-type", headers)

    def test_container_shared_key_signature_includes_query(self):
        key = base64.b64encode(b"x" * 64).decode()
        date = "Mon, 05 Oct 2026 12:00:00 GMT"
        with patch.object(baseline, "formatdate", return_value=date):
            headers = baseline.blob_headers("PUT", "/canary", None, "shared-key", key, M, "", container=True)
        canonical = ("PUT\n" + "\n" * 11 + "x-ms-date:" + date + "\n"
                     + "x-ms-meta-storm3168labid:" + M.lab_id + "\n"
                     + "x-ms-version:2023-11-03\n/" + M.storage_account + "/canary\nrestype:container")
        expected = base64.b64encode(hmac.new(b"x" * 64, canonical.encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(headers["Authorization"], "SharedKey " + M.storage_account + ":" + expected)
        self.assertEqual(headers["Content-Length"], "0")

    def _execute(self, directory, *, fail_upload=False, interrupt=False, hold_seconds=60):
        guard = Mock(m=M)
        payload = ("storm3168 synthetic canary\nnonce=" + NONCE + "\n").encode()
        replies = [Response(403)] if fail_upload else [
            Response(201), Response(200, payload, {"x-ms-meta-storm3168nonce": NONCE, "x-ms-meta-storm3168labid": M.lab_id})]
        def local_save(path, obj):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(json.dumps(obj))
        with patch.object(baseline, "ROOT", Path(directory)), patch.object(baseline, "private_path", side_effect=Path), patch.object(baseline, "save", side_effect=local_save), patch.object(baseline, "account", return_value={"properties": closed()}), patch.object(baseline, "container_preflight", return_value=("exact", True)), patch.object(baseline, "patch_settings"), patch.object(baseline, "create_container"), patch.object(baseline, "wait_for_firewall", return_value={"readiness": "authorized_not_found"}), patch.object(baseline, "seed_credential", return_value="secret-not-for-state"), patch.object(baseline, "blob_request", side_effect=replies), patch.object(baseline.uuid, "uuid4", return_value=NONCE), patch.object(baseline, "restore", return_value={"status": "verified", "settings_restored": True}) as restore:
            sleeper = Mock(side_effect=KeyboardInterrupt()) if interrupt else Mock()
            path = Path(directory) / "state.json"
            error = None
            try:
                baseline.prepare(DATA, guard, "8.8.8.8", "shared-key", True, hold_seconds, path, True, sleeper=sleeper, announce=lambda _: None)
            except (SafetyError, KeyboardInterrupt) as exc:
                error = exc
            result = json.loads(path.read_text())
            restore.assert_called_once()
            self.assertNotIn("secret-not-for-state", path.read_text())
            if not fail_upload and not interrupt:
                self.assertEqual(sleeper.call_count, hold_seconds)
                self.assertTrue(all(call.args == (1,) for call in sleeper.call_args_list))
            return error, result

    def test_success_restores_and_records_checksum_but_not_actor_success(self):
        with tempfile.TemporaryDirectory() as d:
            error, result = self._execute(d)
        self.assertIsNone(error)
        self.assertTrue(result["settings_restored"])
        self.assertEqual(result["preparation_status"], "operator_seed_verified_actor_unverified")

    def test_failed_seed_still_restores(self):
        with tempfile.TemporaryDirectory() as d:
            error, result = self._execute(d, fail_upload=True)
        self.assertIsInstance(error, SafetyError)
        self.assertTrue(result["settings_restored"])
        self.assertEqual(result["preparation_status"], "not_completed")

    def test_interrupt_still_restores(self):
        with tempfile.TemporaryDirectory() as d:
            error, result = self._execute(d, interrupt=True)
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertTrue(result["settings_restored"])

    def test_maximum_hold_records_fixed_restoration_deadline_and_restores(self):
        start = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d, patch.object(baseline, "datetime") as wall_clock:
            wall_clock.now.return_value = start
            error, result = self._execute(d, hold_seconds=7800)
        self.assertIsNone(error)
        self.assertEqual(result["hold_seconds"], 7800)
        self.assertEqual(result["hold_started_at"], start.isoformat())
        self.assertEqual(result["restoration_due_at"], (start + timedelta(seconds=7800)).isoformat())
        self.assertTrue(result["settings_restored"])

    def test_interrupt_retains_original_deadline_without_extension(self):
        start = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d, patch.object(baseline, "datetime") as wall_clock:
            wall_clock.now.return_value = start
            error, result = self._execute(d, interrupt=True, hold_seconds=5400)
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertEqual(result["restoration_due_at"], (start + timedelta(seconds=5400)).isoformat())
        self.assertTrue(result["settings_restored"])

    def test_restore_retries_transient_failure_then_verifies(self):
        receipt = state()
        sleep = Mock()
        with patch.object(baseline, "restore", side_effect=[SafetyError("HTTP 429"), SafetyError("HTTP 503"), {"status": "original_settings_verified", "settings_restored": True}]) as attempt:
            result = baseline.restore_with_retry(Mock(m=M), receipt, sleeper=sleep)
        self.assertTrue(result["settings_restored"])
        self.assertEqual(attempt.call_count, 3)
        self.assertEqual([x.args[0] for x in sleep.call_args_list], [2, 4])

    def test_firewall_readiness_waits_only_with_gets(self):
        responses = [Response(403, headers={"x-ms-error-code": "AuthorizationFailure"}),
                     Response(404, headers={"x-ms-error-code": "ContainerNotFound"})]
        with patch.object(baseline, "blob_request", side_effect=responses) as read:
            result = baseline.wait_for_firewall(Mock(m=M), "baseline-" + NONCE + ".txt", NONCE, "shared-key", "synthetic", sleeper=Mock())
        self.assertEqual(result["attempts"], 2)
        self.assertTrue(all(call.args[1] == "GET" for call in read.call_args_list))

    def test_firewall_readiness_does_not_retry_bad_permission(self):
        with patch.object(baseline, "blob_request", return_value=Response(403, headers={"x-ms-error-code": "AuthorizationPermissionMismatch"})) as read:
            with self.assertRaises(SafetyError):
                baseline.wait_for_firewall(Mock(m=M), "baseline-" + NONCE + ".txt", NONCE, "bearer", "synthetic", sleeper=Mock())
        self.assertEqual(read.call_count, 1)

    def test_firewall_readiness_is_bounded(self):
        with patch.object(baseline, "blob_request", return_value=Response(503)) as read:
            with self.assertRaises(SafetyError):
                baseline.wait_for_firewall(Mock(m=M), "baseline-" + NONCE + ".txt", NONCE, "bearer", "synthetic", sleeper=Mock())
        self.assertEqual(read.call_count, 19)

    def test_restore_retry_budget_is_bounded_and_never_claims_success(self):
        receipt = state()
        sleep = Mock()
        with patch.object(baseline, "restore", side_effect=SafetyError("Unavailable")) as attempt:
            with self.assertRaises(SafetyError):
                baseline.restore_with_retry(Mock(m=M), receipt, sleeper=sleep)
        self.assertEqual(attempt.call_count, 8)
        self.assertEqual(sum(x.args[0] for x in sleep.call_args_list), 120)
        self.assertEqual(receipt["restoration_status"], "manual_restore_required")

    def test_restore_runs_despite_receipt_disk_failure(self):
        receipt = state()
        with patch.object(baseline, "restore", side_effect=[SafetyError("HTTP 503"), {"status": "verified", "settings_restored": True}]) as attempt:
            result = baseline.restore_with_retry(Mock(m=M), receipt, sleeper=Mock(), persist=Mock(side_effect=OSError("disk full")))
        self.assertTrue(result["settings_restored"])
        self.assertEqual(attempt.call_count, 2)
        self.assertTrue(receipt["receipt_persistence_unconfirmed"])

    def test_slow_restore_attempt_consumes_retry_budget(self):
        receipt = state()
        clock = Mock(side_effect=[0, 121])
        with patch.object(baseline, "restore", side_effect=SafetyError("slow timeout")) as attempt:
            with self.assertRaises(SafetyError):
                baseline.restore_with_retry(Mock(m=M), receipt, sleeper=Mock(), clock=clock)
        self.assertEqual(attempt.call_count, 1)

    def test_storage_window_requires_exact_active_blob_and_sufficient_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = json.loads(json.dumps(DATA))
            prepared["blob"]["name"] = "baseline-" + NONCE + ".txt"
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps(prepared))
            receipt = {**state(), "nonce": NONCE, "prepared_manifest": str(manifest_path),
                       "preparation_status": "operator_seed_verified_actor_unverified",
                       "settings_restored": False, "status": "ready_for_separate_actor_baseline",
                       "restoration_due_at": datetime.fromtimestamp(3000, timezone.utc).isoformat(), "sha256": "synthetic"}
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(receipt))
            with patch.object(baseline, "private_path", side_effect=Path), patch.object(baseline.time, "time", return_value=1000):
                self.assertEqual(baseline.assert_storage_window(prepared, path, 2500)["nonce"], NONCE)
                with self.assertRaises(SafetyError):
                    baseline.assert_storage_window(prepared, path, 3001)
                with self.assertRaises(SafetyError):
                    baseline.assert_storage_window(DATA, path, 2500)
                receipt["settings_restored"] = True
                path.write_text(json.dumps(receipt))
                with self.assertRaises(SafetyError):
                    baseline.assert_storage_window(prepared, path, 2500)


if __name__ == "__main__":
    unittest.main()
