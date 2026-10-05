"""Review-round-two failure reproductions, with no cloud access."""
import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.parse
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import live_trial
from stormlab.__main__ import main
from stormlab.core import (ARM, Guard, HTTP, Manifest, Response, SafetyError, TransientReadError,
                          classify, observation_summary, probe_once, respond, response_target,
                          run_probe, validate_sas)
from test_core import fixture, FakeHTTP, Operator, token, response, LAB


class RoundTwoHarnessTests(unittest.TestCase):
    def setUp(self):
        self.m = Manifest.from_dict(fixture())

    def test_token_actions_default_to_expiry_and_explicit_short_window_is_labeled(self):
        for action in ("sp-disable", "app-deactivate", "secret-remove"):
            result = live_trial.observation_window(action, None, False, 5000, now=1000)
            self.assertEqual(result["duration_seconds"], 4060)
            self.assertEqual(result["mode"], "until_token_expiry")
            self.assertEqual(live_trial.observation_window(action, 30, False)["mode"], "explicit_fixed_window")

    def test_writer_removal_rejects_read_measurement_before_manifest_or_network(self):
        for action in ("role-delete", "group-member-remove"):
            argv = ["live_trial.py", "--subscription", self.m.subscription_id, "--confirm-lab-id", LAB,
                    "--action", action, "--capability", "arm-read"]
            with patch.object(sys, "argv", argv), patch.object(live_trial, "load_owned") as load, self.assertRaises(SafetyError):
                live_trial.main()
            load.assert_not_called()

    def test_reader_assignment_cannot_be_deleted_even_directly(self):
        value = fixture()
        value["role_assignments"][0]["role_definition_id"] = f"/subscriptions/{self.m.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
        manifest = Manifest.from_dict(value)
        fake = FakeHTTP(manifest)
        with self.assertRaises(SafetyError):
            respond(Guard(manifest, fake, Operator()), "role-delete", execute=True, confirm_lab_id=LAB, assignment_id=manifest.role_assignments[0]["id"])
        self.assertEqual(fake.calls, [])

    def test_gap_is_visible_and_neither_advances_nor_resets_denial_series(self):
        rows = [{"elapsed_seconds": t, "outcome": outcome} for t, outcome in [(0, "allowed"), (10, "credential_rejected"), (30, "transport_error"), (40, "credential_rejected"), (70, "credential_rejected"), (90, "throttled")]]
        result = observation_summary(rows)
        self.assertTrue(result["sustained_credential_rejection_observed"])
        self.assertEqual(len(result["denial_intervals"]), 1)
        self.assertEqual(result["denial_intervals"][0]["last_observed_seconds"], 70)
        self.assertEqual(result["denial_intervals"][0]["inconclusive_samples"], 2)
        self.assertFalse(result["continuous_observation"])
        self.assertEqual(len(result["observation_gaps"]), 2)
        self.assertFalse(result["sustained_denial_at_end"])

    def test_known_bearer_rejection_counts_but_bare_401_does_not(self):
        known = classify(response(401, {"error": {"code": "InvalidAuthenticationToken"}}), auth="bearer")
        self.assertEqual(known, "credential_rejected")
        self.assertEqual(classify(response(401), auth="bearer"), "authentication_or_unknown_denial")
        result = observation_summary([{"elapsed_seconds": t, "outcome": known} for t in (0, 30, 60)])
        self.assertFalse(result["denial_onset_right_censored"])
        self.assertTrue(result["denial_observed_without_successful_baseline"])
        self.assertEqual(result["first_denial_elapsed_seconds"], 0)
        self.assertFalse(result["sustained_denial_observed"])

    def test_later_success_cannot_relabel_an_earlier_unbaselined_denial(self):
        result = observation_summary([{"elapsed_seconds": t, "outcome": outcome} for t, outcome in [(0, "credential_rejected"), (10, "allowed"), (20, "credential_rejected")]])
        self.assertTrue(result["denial_observed_without_successful_baseline"])
        self.assertEqual(result["onset_classification"], "already_denied_without_baseline")
        self.assertEqual(result["first_denial_elapsed_seconds"], 0)
        self.assertEqual(result["first_post_baseline_denial_elapsed_seconds"], 20)

    def test_rejected_write_prerequisite_is_reported_without_claiming_denied_patch(self):
        for code, expected in [("InvalidAuthenticationToken", True), ("", False)]:
            fake = FakeHTTP(self.m)
            fake.actor_storage_response = response(401, {"error": {"code": code}})
            row = probe_once(self.m, fake, Guard(self.m, fake, Operator()), "arm-tag-write", token(), allow_mutation=True, now=1000)
            row["elapsed_seconds"] = 0
            result = observation_summary([row], baseline_allowed=True, last_allowed=-30)
            self.assertEqual(row["outcome"], "precondition_failed")
            self.assertFalse(row["mutation_attempted"])
            self.assertEqual(fake.mutations, [])
            self.assertEqual(result["prerequisite_credential_rejection_observed"], expected)
            self.assertFalse(result["sustained_denial_observed"])

    def test_transient_write_guard_never_sends_mutation(self):
        fake = FakeHTTP(self.m)
        guard = Guard(self.m, fake, Operator())
        with patch.object(guard, "ownership", side_effect=TransientReadError(429)):
            result = probe_once(self.m, fake, guard, "arm-tag-write", token(), allow_mutation=True, now=1000)
        self.assertEqual(result["outcome"], "guard_read_inconclusive")
        self.assertFalse(result["mutation_attempted"])
        self.assertEqual(fake.calls, [])

    def test_transient_initial_guard_is_sampled_and_later_probes_resume(self):
        fake, rows, clock = FakeHTTP(self.m), [], [1000.0]
        guard = Guard(self.m, fake, Operator())
        with patch.object(guard, "ownership", side_effect=[TransientReadError(503), None]), patch.object(guard, "actor"):
            run_probe(self.m, fake, guard, "arm-read", token(), emit=rows.append, duration=10, interval=5,
                      clock=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds))
        probes = [row for row in rows if row["kind"] == "probe"]
        self.assertEqual([row["outcome"] for row in probes], ["guard_read_inconclusive", "allowed", "allowed"])
        self.assertEqual(rows[-1]["status"], "completed")

    def test_real_ownership_mismatch_is_fatal_but_partial_receipt_is_emitted(self):
        fake, rows = FakeHTTP(self.m), []
        fake.bad_tag = True
        with self.assertRaises(SafetyError):
            run_probe(self.m, fake, Guard(self.m, fake, Operator()), "arm-read", token(), emit=rows.append, clock=lambda: 1000)
        self.assertEqual([row["kind"] for row in rows], ["run_start", "run_end"])
        self.assertEqual(rows[-1]["status"], "failed_or_incomplete")

    def test_monotonic_targets_resist_latency_and_backward_wall_clock(self):
        monotonic, wall, rows, starts = [0.0], [1000.0], [], []
        def sleep(seconds):
            monotonic[0] += seconds
            wall[0] += seconds
        def probe(*args, **kwargs):
            starts.append(monotonic[0])
            monotonic[0] += 7
            wall[0] -= 100
            return {"kind": "probe", "outcome": "allowed"}
        guard = Guard(self.m, FakeHTTP(self.m), Operator())
        with patch.object(guard, "ownership"), patch.object(guard, "actor"), patch("stormlab.core.probe_once", side_effect=probe):
            run_probe(self.m, guard.http, guard, "arm-read", token(), emit=rows.append, duration=30, interval=10,
                      clock=lambda: wall[0], monotonic=lambda: monotonic[0], sleep=sleep)
        self.assertEqual(starts, [0, 10, 20, 30])

    def test_mutation_lost_reply_checks_postcondition_without_retry(self):
        fake = FakeHTTP(self.m)
        original = fake.request
        def request(method, url, headers=None, body=None):
            if method == "PATCH":
                fake.calls.append((method, url, headers or {}, body))
                return Response(0, transport_error=True)
            if "?$select=id,accountEnabled" in url:
                fake.calls.append((method, url, headers or {}, body))
                return response(data={"accountEnabled": False})
            return original(method, url, headers, body)
        fake.request = request
        result = respond(Guard(self.m, fake, Operator()), "sp-disable", execute=True, confirm_lab_id=LAB)
        self.assertFalse(result["mutation_acknowledged"])
        self.assertTrue(result["postcondition_verified"])
        self.assertEqual(len(fake.mutations), 1)

    def test_readback_failure_does_not_erase_accepted_mutation_receipt(self):
        fake = FakeHTTP(self.m)
        guard = Guard(self.m, fake, Operator())
        original = guard.read
        with patch.object(guard, "read", side_effect=lambda service, path: (_ for _ in ()).throw(TransientReadError(0)) if "?$select=id,accountEnabled" in path else original(service, path)):
            result = respond(guard, "sp-disable", execute=True, confirm_lab_id=LAB)
        self.assertEqual(result["status"], "accepted_unverified")
        self.assertFalse(result["postcondition_verified"])
        self.assertEqual(result["postcondition_readback"], "unavailable")

    def test_sas_character_boundaries_date_formats_and_policy_restrictions(self):
        base = {"sv": "2023-11-03", "sp": "r", "spr": "https", "sr": "b", "se": "1970-01-02", "sig": base64.b64encode(b"a" * 32).decode()}
        self.assertEqual(validate_sas(urllib.parse.urlencode(base), self.m, 1)["exp"], 86400)
        base["se"] = "1970-01-02T00:00Z"
        self.assertEqual(validate_sas(urllib.parse.urlencode(base), self.m, 1)["exp"], 86400)
        for bad in ("raw space", "\x7f", "é"):
            with self.assertRaises(SafetyError):
                validate_sas(urllib.parse.urlencode(base | {"rscc": bad}), self.m, 1)
        account = {k: v for k, v in base.items() if k != "sr"} | {"ss": "b", "srt": "o", "si": "policy"}
        with self.assertRaises(SafetyError):
            validate_sas(urllib.parse.urlencode(account), self.m, 1)
        for field in ("sduoid", "skdutid", "srh", "srq"):
            with self.assertRaisesRegex(SafetyError, "unsupported"):
                validate_sas(urllib.parse.urlencode(base | {field: "x"}), self.m, 1)

    def test_sensitive_response_repr_and_final_cli_exception_boundary(self):
        self.assertNotIn("secret", repr(Response(200, b"secret-body", {"secret": "secret-header"})))
        with patch("stormlab.__main__.read_jsonl", side_effect=Exception("sig=secret")), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(main(["summarize", "--input", "fake.jsonl"]), 2)
        self.assertNotIn("secret", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
