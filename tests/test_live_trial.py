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
from test_core import token as fake_token
from stormlab.core import utc_now, response_target, Manifest, claims_from_token

SUB = "22222222-2222-4222-8222-222222222222"
LAB = "33333333-3333-4333-8333-333333333333"
CLIENT = "66666666-6666-4666-8666-666666666666"
KEY = "88888888-8888-4888-8888-888888888888"


class LiveTrialProtocolTests(unittest.TestCase):
    def exercise(self, *, action="sp-disable", baseline_count=2, lost_creation_reply=False):
        (ROOT / "private").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "private") as temp:
            manifest_path = Path(temp) / "manifest.json"
            manifest = json.loads((ROOT / "config" / "manifest.example.json").read_text())
            manifest_path.write_text(json.dumps(manifest))
            state = {"credentials": [], "tokens": [], "responded": False, "token_calls": 0, "issued": []}
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

            def request(method, url, token=None, payload=None, form=None):
                if url.endswith("/addPassword"):
                    name = payload["passwordCredential"]["displayName"]
                    state["credentials"] = [{"keyId": KEY, "displayName": name}]
                    if lost_creation_reply:
                        raise RuntimeError("transport failure after remote creation")
                    return {"keyId": KEY, "secretText": "fictional-in-memory-secret"}
                if url.endswith("/removePassword"):
                    self.assertEqual(payload, {"keyId": KEY})
                    state["credentials"] = []
                    return {}
                if "oauth2/v2.0/token" in url:
                    state["token_calls"] += 1
                    issued = fake_token(exp=time.time() + 3600, iat=time.time(), jti=str(state["token_calls"]))
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
                                "capability": "arm-tag-write", "auth": "bearer"}
                    claims = claims_from_token(env["STORMLAB_PROBE_TOKEN"])
                    rows = [{"kind": "run_start", "token_metadata": {key: claims.get(key) for key in ("aud", "iat", "exp")}, **identity}]
                    for n in range(count):
                        now = utc_now()
                        rows.append({"kind": "probe", "outcome": "allowed", "http_status": 200,
                                     "timestamp": now, "request_started_at": now, "response_received_at": now, **identity})
                    output.write_text("\n".join(json.dumps(row) for row in rows))
                else:
                    state["responded"] = True
                    output = Path(arguments[arguments.index("--output") + 1])
                    self.assertEqual(output.name, "action.jsonl")
                    current = Manifest.from_dict(json.loads(Path(arguments[arguments.index("--manifest") + 1]).read_text()))
                    output.write_text(json.dumps({"kind": "response", "action": action, "executed": True, "target": response_target(current, action),
                                                 "request_started_at": utc_now(), "acknowledged_at": utc_now(), "http_status": 204,
                                                 "status": "configuration_verified_capability_unproven", "postcondition_verified": True}) + "\n")

            argv = ["live_trial.py", "--manifest", str(manifest_path), "--subscription", SUB,
                    "--confirm-lab-id", LAB, "--action", action, "--duration", "20", "--execute", "--check-new-token"]
            failure = None
            with patch.object(sys, "argv", argv), patch.object(live_trial, "load_owned", return_value=(manifest_path, manifest)), \
                 patch.object(live_trial, "private_path", side_effect=isolated_private_path), \
                 patch.object(live_trial, "assert_owned"), patch.object(live_trial, "graph_token", return_value="operator-only"), \
                 patch.object(live_trial, "request", side_effect=request), patch.object(live_trial, "invoke_harness", side_effect=harness), \
                 patch.object(live_trial.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="a" * 40)), \
                 contextlib.redirect_stdout(io.StringIO()):
                try:
                    result = live_trial.main()
                    self.assertEqual(result, 0)
                except RuntimeError as exc:
                    failure = str(exc)
            receipt_path = next((Path(temp) / "runs").rglob("trial.json"))
            receipt_text = receipt_path.read_text()
            self.assertNotIn("fictional-in-memory-secret", receipt_text)
            self.assertNotIn("frozen-probe", receipt_text)
            self.assertNotIn("separate-issuance-control", receipt_text)
            receipt = json.loads(receipt_text)
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


if __name__ == "__main__":
    unittest.main()
