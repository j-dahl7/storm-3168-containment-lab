"""Synthetic credentials and mocked cloud only. No Azure calls."""
import base64
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "scripts"))
import storage_trial as trial
from stormlab.core import Manifest, SafetyError, response_target, validate_sas

DATA = json.loads((ROOT / "config/manifest.example.json").read_text())
DATA["budget_target_usd"] = 10
M = Manifest.from_dict(DATA)
KEY = base64.b64encode(b"x" * 64).decode()
KEYID = "99999999-9999-4999-8999-999999999999"
COHORT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
NONCE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def delegation(start, end):
    return {"SignedOid": M.actor["service_principal_object_id"], "SignedTid": M.tenant_id,
            "SignedStart": start, "SignedExpiry": end, "SignedService": "b", "SignedVersion": trial.VERSION, "Value": KEY}


class StorageTrialTests(unittest.TestCase):
    def test_plan_has_no_cloud_or_state_writes(self):
        with tempfile.TemporaryDirectory() as d, patch.object(trial, "ROOT", Path(d)), patch.object(trial, "private_path", side_effect=Path), patch.object(trial, "load_json", return_value=DATA), patch.object(trial, "source_hashes", return_value={}), patch.object(trial, "Guard") as guard, patch.object(trial, "save") as save, redirect_stdout(io.StringIO()):
            result = trial.main(["--manifest", "synthetic", "--subscription", M.subscription_id, "--action", "rotate-key1", "--series-id", COHORT, "--client-ip", "8.8.8.8"])
        self.assertEqual(result, 0)
        guard.assert_not_called()
        save.assert_not_called()

    def test_wrong_confirmation_is_rejected_before_provider_access(self):
        with tempfile.TemporaryDirectory() as d, patch.object(trial, "ROOT", Path(d)), patch.object(trial, "private_path", side_effect=Path), patch.object(trial, "load_json", return_value=DATA), patch.object(trial, "source_hashes", return_value={}), patch.object(trial, "Guard") as guard:
            with self.assertRaises(SafetyError):
                trial.main(["--manifest", "synthetic", "--subscription", M.subscription_id, "--confirm-lab-id", COHORT, "--action", "rotate-key1", "--series-id", COHORT, "--client-ip", "8.8.8.8", "--execute"])
        guard.assert_not_called()

    def test_parallel_phase_starts_all_six_channels_and_keeps_separate_evidence(self):
        barrier = threading.Barrier(6)
        channels = {name: {"auth": "shared-key", "credential": "synthetic", "label": COHORT} for name in trial.CHANNELS}
        def probe(m, http, guard, capability, credential, **kwargs):
            barrier.wait(timeout=3)
            kwargs["emit"]({"kind": "probe", "outcome": "allowed"})
        with tempfile.TemporaryDirectory() as d, patch.object(trial, "private_path", side_effect=Path), patch.object(trial, "append_jsonl") as append, patch.object(trial, "run_probe", side_effect=probe):
            result = trial.parallel_phase(M, channels, Path(d), "baseline", 20, 10, http_factory=Mock, operator_factory=Mock)
        self.assertEqual(set(result), set(trial.CHANNELS))
        self.assertEqual(len({str(c.args[0]) for c in append.call_args_list}), 6)

    def test_sas_signatures_match_independent_reference_vectors(self):
        # Service/account independently generated with Azure SDK 12.28.0b1.
        # UD: SDK hook canonical string normalized by removing the two blank
        # 2025 delegation fields, as required by Learn's 2020-12-06 contract.
        start, end = "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"
        expected = {"service": "8Vki4h156uQRpElE7bHNZNplM3mDuUAMJXszUE9+JQU=",
                    "account": "5v0z/eHOUAljcIRp3H4PvaX6HJ+HolJy9S0Kya843/4=",
                    "user-delegation": "Ml9Egc8uc8YcDTwXwuBOXl3J5/FsFTDzNHkb4mNIidc="}
        for kind in expected:
            query = trial.make_sas(M, kind, KEY, start, end, "8.8.8.8", delegation(start, end))
            parsed = parse_qs(query)
            self.assertEqual(parsed["sig"], [expected[kind]])
            self.assertEqual(parsed["sp"], ["r"])
            self.assertEqual(parsed["spr"], ["https"])
            self.assertEqual(parsed["sip"], ["8.8.8.8"])
            validate_sas(query, M, datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc).timestamp())

    def test_missing_exact_data_reader_fails_before_any_cloud_read(self):
        guard = Mock(m=M)
        with self.assertRaises(SafetyError):
            trial.verify_data_control(DATA, guard)
        guard.ownership.assert_not_called()

    def exercise(self, *, baseline_ok=True, checksum_ok=True, control_ok=True, action_ack=True,
                 action_name="rotate-key1", verified=False, failed_control="entra-blob"):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            folder = root / COHORT
            prepared = json.loads(json.dumps(DATA))
            prepared["blob"]["name"] = "baseline-" + NONCE + ".txt"
            model = Manifest.from_dict(prepared)
            state = {"prepared_manifest": "synthetic-private-manifest", "nonce": NONCE, "sha256": "synthetic-checksum", "settings_restored": False}
            secret_removed = []
            created = [False]
            token_payload = {"tid": M.tenant_id, "oid": M.actor["service_principal_object_id"], "appid": M.actor["client_id"],
                             "aud": "https://storage.azure.com/", "iat": int(time.time()), "exp": int(time.time()) + 3600}
            token = "synthetic." + base64.urlsafe_b64encode(json.dumps(token_payload).encode()).decode().rstrip("=") + ".synthetic"
            def save(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            def append(path, row):
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a") as f: f.write(json.dumps(row) + "\n")
            def request(method, url, *args, **kwargs):
                if url.endswith("/addPassword"):
                    created[0] = True
                    return {"keyId": KEYID, "secretText": "SYNTHETIC_CLIENT_SECRET"}
                if url.endswith("/token"):
                    return {"access_token": token}
                if url.endswith("/removePassword"):
                    created[0] = False; secret_removed.append(True); return {}
                return {"id": M.actor["application_object_id"], "appId": M.actor["client_id"], "displayName": M.name_prefix,
                        "passwordCredentials": [{"keyId": KEYID, "displayName": "storm3168-storage-" + COHORT}] if created[0] else []}
            def prepare(data, guard, ip, mode, shared, hold, state_path, execute, **kwargs):
                save(state_path, state)
                try: return kwargs["during_hold"](prepared, state)
                finally:
                    state["settings_restored"] = True
                    save(state_path, state)
            anchor = time.time()
            def parallel(m, channels, folder, phase, duration, interval):
                results = {}
                for name, ch in channels.items():
                    identity = {"run_id": name + phase, "capability": "blob-read", "auth": ch["auth"], "credential_label": ch["label"], "transport_address_family": trial.configured_address_family()}
                    rows = [{"kind": "run_start", **identity, "token_metadata": {k: token_payload[k] for k in ("aud", "iat", "exp")} if ch["auth"] == "bearer" else {}}]
                    offsets = [-60, -40, -20] if phase == "baseline" else [0, 30, 60]
                    for offset in offsets:
                        outcome = "allowed"
                        if phase == "baseline" and not baseline_ok and name == "key1": outcome = "credential_rejected"
                        affected = {"key1", "service-sas-key1"} if action_name == "rotate-key1" else {"key2", "account-sas-key2"} if action_name == "rotate-key2" else {"key1", "key2", "service-sas-key1", "account-sas-key2"}
                        if phase != "baseline" and name in affected: outcome = "credential_rejected"
                        if phase != "baseline" and not control_ok and name == failed_control: outcome = "network_denied"
                        stamp = datetime.fromtimestamp(anchor + offset, timezone.utc).isoformat()
                        rows.append({"kind": "probe", **identity, "outcome": outcome, "timestamp": stamp, "request_started_at": stamp, "response_received_at": stamp})
                    rows.append({"kind": "run_end", "run_id": identity["run_id"], "status": "completed"})
                    for row in rows: append(folder / name / (phase + ".jsonl"), row)
                    results[name] = rows
                return results
            action = {"kind": "response", "action": action_name, "executed": True, "target": response_target(model, action_name),
                      "status": "accepted_unverified" if action_ack else "indeterminate", "http_status": 200 if action_ack else 0,
                      "postcondition_verified": verified, "mutation_acknowledged": action_ack,
                      "request_started_at": datetime.fromtimestamp(anchor - 1, timezone.utc).isoformat(), "acknowledged_at": datetime.fromtimestamp(anchor, timezone.utc).isoformat()}
            mocks = {"private_path": lambda p: Path(p), "save": save, "append_jsonl": append, "prepare": prepare,
                     "source_hashes": lambda: {"source": "synthetic-hash"}, "begin_trial": Mock(), "finish_trial": Mock(), "verify_data_control": Mock(),
                     "account": Mock(), "initial_settings": Mock(), "assert_storage_window": Mock(), "assert_owned": Mock(),
                     "request": request, "graph_token": Mock(return_value="SYNTHETIC_OPERATOR"), "get_keys": lambda _: {"key1": KEY, "key2": KEY},
                     "get_delegation": lambda guard, token, start, end: delegation(start, end), "parallel_phase": parallel,
                     "full_read": lambda *args: {"verified": checksum_ok}, "respond": Mock(return_value=action)}
            for name, value in mocks.items(): stack.enter_context(patch.object(trial, name, value))
            stack.enter_context(patch.object(trial.Guard, "ownership")); stack.enter_context(patch.object(trial.Guard, "actor"))
            failure = None
            try: result = trial.run_cohort(DATA, Mock(m=M), folder, action_name, "8.8.8.8", 300, 20)
            except SafetyError as exc: failure = type(exc).__name__
            receipt = json.loads((folder / "cohort.json").read_text())
            public = "".join(p.read_text() for p in folder.rglob("*.json*"))
            for secret in (KEY, token, "SYNTHETIC_CLIENT_SECRET"):
                self.assertNotIn(secret, public)
            return receipt, failure, mocks["respond"].call_count, bool(secret_removed), mocks["finish_trial"].call_args.kwargs

    def test_six_channels_share_exactly_one_action_and_no_credentials_are_saved(self):
        receipt, failure, actions, cleaned, lease = self.exercise()
        self.assertIsNone(failure)
        self.assertEqual(actions, 1)
        self.assertTrue(receipt["valid_trial"])
        self.assertTrue(cleaned)
        self.assertTrue(lease["cleanup_confirmed"])

    def test_baseline_failure_prevents_response_and_cleans_up(self):
        receipt, failure, actions, cleaned, lease = self.exercise(baseline_ok=False)
        self.assertEqual(actions, 0)
        self.assertTrue(cleaned)
        self.assertFalse(receipt["valid_trial"])

    def test_nonce_checksum_failure_prevents_response(self):
        receipt, failure, actions, cleaned, lease = self.exercise(checksum_ok=False)
        self.assertEqual(actions, 0)
        self.assertTrue(cleaned)

    def test_lost_action_reply_is_not_replayed_and_retains_lease(self):
        receipt, failure, actions, cleaned, lease = self.exercise(action_ack=False)
        self.assertEqual(actions, 1)
        self.assertFalse(receipt["valid_trial"])
        self.assertFalse(lease["cleanup_confirmed"])
        self.assertTrue(cleaned)

    def test_unhealthy_control_prevents_valid_trial_count(self):
        receipt, failure, actions, cleaned, lease = self.exercise(control_ok=False)
        self.assertEqual(actions, 1)
        self.assertFalse(receipt["valid_trial"])
        self.assertEqual(receipt["status"], "observation_control_inconclusive")

    def test_shared_key_disable_requires_verified_readback_before_post_window(self):
        receipt, failure, actions, cleaned, lease = self.exercise(action_name="disable-shared-key", verified=False)
        self.assertEqual(actions, 1)
        self.assertEqual(failure, "SafetyError")
        self.assertFalse(receipt["valid_trial"])
        self.assertFalse(receipt["action_unambiguous"])
        self.assertNotIn("control_post_checksums", receipt)
        self.assertFalse(lease["cleanup_confirmed"])
        self.assertTrue(cleaned)

    def test_verified_shared_key_disable_can_be_a_valid_trial(self):
        receipt, failure, actions, cleaned, lease = self.exercise(action_name="disable-shared-key", verified=True)
        self.assertIsNone(failure)
        self.assertTrue(receipt["valid_trial"])
        self.assertEqual(actions, 1)

    def test_each_rotation_requires_unaffected_key_sas_control(self):
        for action, control in (("rotate-key1", "account-sas-key2"), ("rotate-key2", "service-sas-key1")):
            with self.subTest(action=action):
                receipt, failure, actions, cleaned, lease = self.exercise(action_name=action, control_ok=False, failed_control=control)
                self.assertFalse(receipt["valid_trial"])
                self.assertFalse(receipt["controls_healthy"])
                self.assertIn(control, receipt["control_post_checksums"])
                self.assertEqual(actions, 1)


if __name__ == "__main__":
    unittest.main()
