"""Regression reproductions for review findings; entirely offline."""
from datetime import datetime, timedelta, timezone
import http.client
import json
from pathlib import Path
import sys
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from live_trial import observation_window, invoke_harness
from stormlab.core import (HTTP, Manifest, SafetyError, classify, summarize, summarize_trial,
                          validate_sas, response_target, run_probe)
from test_core import fixture, response, token, FakeHTTP, Operator, Guard

LABEL = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def trial_fixture(outcomes):
    anchor = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stamp = lambda seconds: (anchor + timedelta(seconds=seconds)).isoformat()
    target = response_target(Manifest.from_dict(fixture()), "sp-disable")
    action = {"kind": "response", "action": "sp-disable", "executed": True, "target": target, "status": "configuration_verified_capability_unproven",
              "http_status": 204, "postcondition_verified": True, "request_started_at": stamp(-1), "acknowledged_at": stamp(0)}
    receipt = {"run_id": "safe-random-trial", "action": "sp-disable", "capability": "arm-tag-write", "auth": "bearer",
               "credential_label": LABEL, "token_refresh": False, "probe_runs": {"baseline": "before", "post_action": "after"},
               "action_requested_at": stamp(-1), "action_target": target, "action_receipt": action, "access_path": target["access_path"],
               "frozen_token_metadata": {"aud": "https://management.azure.com/", "iat": 1767225500, "exp": 1767232800}}
    def phase(run, observations):
        identity = {"run_id": run, "capability": "arm-tag-write", "auth": "bearer", "credential_label": LABEL}
        return [{"kind": "run_start", "token_metadata": dict(receipt["frozen_token_metadata"]), **identity}] + [{"kind": "probe", "outcome": outcome, "elapsed_seconds": elapsed,
                "timestamp": stamp(elapsed), "request_started_at": stamp(elapsed), "response_received_at": stamp(elapsed), **identity} for elapsed, outcome in observations]
    return receipt, phase("before", [(-60, "allowed"), (-30, "allowed")]), [action], phase("after", outcomes)


class EvidenceRegressionTests(unittest.TestCase):
    def test_first_post_action_denial_uses_verified_baseline(self):
        result = summarize_trial(*trial_fixture([(0, "authorization_denied"), (30, "authorization_denied"), (60, "authorization_denied")]))
        self.assertTrue(result["sustained_denial_observed"])
        self.assertEqual(result["first_sustained_denial_elapsed_seconds"], 0)
        self.assertEqual(result["denial_intervals"][0]["last_allowed_seconds"], -30)
        self.assertEqual(result["action_causality"], "unproven")

    def test_expiry_preserves_previously_observed_interval(self):
        result = summarize_trial(*trial_fixture([(0, "authorization_denied"), (30, "authorization_denied"), (60, "authorization_denied"), (90, "expired")]))
        self.assertTrue(result["sustained_denial_observed"])
        self.assertFalse(result["sustained_denial_at_end"])
        self.assertEqual(result["denial_intervals"][0]["end_reason"], "credential_expired")
        self.assertEqual(result["observation_end_reason"], "credential_expired")

    def test_rotation_authentication_rejection_is_observed_not_causal(self):
        self.assertEqual(classify(response(403, {"error": {"code": "AuthenticationFailed"}}), auth="shared-key"), "credential_rejected")
        result = summarize_trial(*trial_fixture([(0, "credential_rejected"), (30, "credential_rejected"), (60, "credential_rejected")]))
        self.assertTrue(result["sustained_denial_observed"])
        self.assertEqual(result["action_causality"], "unproven")
        self.assertEqual(classify(response(401), auth="bearer"), "authentication_or_unknown_denial")

    def test_firewall_denials_do_not_count_as_identity_containment(self):
        for code, expected in [("AuthorizationFailure", "authorization_unattributed"), ("AuthorizationSourceIPMismatch", "network_policy_denied"), ("Forbidden", "authorization_unattributed")]:
            outcome = classify(response(403, {"error": {"code": code}}), auth="sas")
            self.assertEqual(outcome, expected)
            result = summarize_trial(*trial_fixture([(0, outcome), (30, outcome), (60, outcome)]))
            self.assertFalse(result["sustained_denial_observed"])

    def test_expiry_or_window_end_without_denial_is_censored(self):
        for observations, reason in [([(0, "allowed"), (30, "expired")], "credential_expired"), ([(0, "allowed"), (30, "allowed")], "observation_window_ended")]:
            result = summarize_trial(*trial_fixture(observations))
            self.assertFalse(result["sustained_denial_observed"])
            self.assertTrue(result["denial_onset_right_censored"])
            self.assertEqual(result["observation_end_reason"], reason)

    def test_mismatched_label_capability_run_target_or_phase_refused(self):
        for change in [lambda r, b, a, p: p[1].update(credential_label="other"),
                       lambda r, b, a, p: p[1].update(capability="blob-read"),
                       lambda r, b, a, p: p[0].update(run_id="wrong"),
                       lambda r, b, a, p: p[0]["token_metadata"].update(exp=1),
                       lambda r, b, a, p: r.update(action_target={"wrong": "target"}),
                       lambda r, b, a, p: p[1].update(request_started_at=b[1]["timestamp"], response_received_at=b[1]["timestamp"])]:
            args = trial_fixture([(0, "authorization_denied")])
            change(*args)
            with self.assertRaises(SafetyError):
                summarize_trial(*args)

    def test_unstitched_runs_never_borrow_other_credential_baseline(self):
        rows = [{"kind": "probe", "run_id": "same", "capability": "blob-read", "auth": "sas", "credential_label": label,
                 "elapsed_seconds": second, "outcome": outcome} for label, second, outcome in [("a", 0, "allowed"), ("b", 1, "authorization_denied"), ("b", 31, "authorization_denied"), ("b", 61, "authorization_denied")]]
        result = summarize(rows)
        self.assertEqual(len(result["runs"]), 2)
        self.assertFalse(any(row["sustained_denial_observed"] for row in result["runs"]))

    def test_malformed_sas_traceback_never_contains_signature(self):
        sensitive = "DO_NOT_LOG_THIS_SIGNATURE"
        try:
            validate_sas("sv=2023-11-03&" + sensitive, Manifest.from_dict(fixture()), 0)
        except SafetyError:
            formatted = traceback.format_exc()
        self.assertNotIn(sensitive, formatted)
        self.assertNotIn("bad query field", formatted)

    def test_http_url_failure_never_escapes_with_sas_query(self):
        client = HTTP()
        with patch.object(client.opener, "open", side_effect=http.client.InvalidURL("secret-sig-in-url")):
            result = client.request("GET", "https://fakestormlab.blob.core.windows.net/canary/file?sig=secret")
        self.assertTrue(result.transport_error)
        self.assertEqual(result.status, 0)

    def test_expired_at_phase_start_records_expiry_without_network(self):
        m = Manifest.from_dict(fixture())
        fake = FakeHTTP(m)
        rows = []
        run_probe(m, fake, Guard(m, fake, Operator()), "arm-read", token(exp=999), emit=rows.append, clock=lambda: 1000)
        self.assertEqual(fake.calls, [])
        self.assertEqual(rows[1]["outcome"], "expired")

    def test_window_defaults_expiry_margin_and_cap(self):
        self.assertEqual(observation_window("role-delete", None, False)["duration_seconds"], 900)
        self.assertEqual(observation_window("group-member-remove", None, False)["duration_seconds"], 900)
        self.assertEqual(observation_window("sp-disable", None, True, 4600, now=1000)["duration_seconds"], 3660)
        capped = observation_window("sp-disable", None, True, 12000, now=1000)
        self.assertEqual(capped["duration_seconds"], 7200)
        self.assertTrue(capped["expiry_window_capped"])
        for duration in (19, 7201):
            with self.assertRaises(ValueError):
                observation_window("none", duration, False)
        with self.assertRaises(ValueError):
            observation_window("none", 30, True)

    def test_expiry_window_subprocess_timeout_does_not_truncate_two_hours(self):
        with patch("live_trial.subprocess.run", return_value=SimpleNamespace(returncode=0)) as runner:
            invoke_harness(["probe", "--duration", "7200"], {"STORMLAB_PROBE_TOKEN": "in-memory-only"})
        self.assertEqual(runner.call_args.kwargs["timeout"], 7800)

    def test_action_target_records_direct_and_group_paths(self):
        value = fixture()
        row = value["role_assignments"][0]
        self.assertEqual(response_target(Manifest.from_dict(value), "role-delete", row["id"])["access_path"], "direct_role_assignment")
        row["principal_id"] = value["group"]["object_id"]
        target = response_target(Manifest.from_dict(value), "role-delete", row["id"])
        self.assertEqual(target["access_path"], "group_role_assignment")
        self.assertEqual(target["scope"], row["scope"])
        self.assertEqual(target["principal_id"], row["principal_id"])
        self.assertEqual(response_target(Manifest.from_dict(value), "group-member-remove")["access_path"], "group_membership")


if __name__ == "__main__":
    unittest.main()
