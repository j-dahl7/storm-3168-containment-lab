"""Pre-freeze retry and credential-error boundary; no network calls or real waits."""
import http.client
import io
import json
from pathlib import Path
import ssl
import sys
import unittest
import urllib.error
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "scripts"))
from initial_token import acquire_initial_token, CredentialHTTPError, CredentialTransportError, InitialTokenError
import live_trial


class InitialTokenTests(unittest.TestCase):
    def run_acquisition(self, results, *, budget=300, validator=None):
        now, rows, timeouts, sleeps = [0.0], [], [], []
        iterator = iter(results)
        def issue(timeout):
            timeouts.append(timeout)
            value = next(iterator)
            if isinstance(value, BaseException): raise value
            return value
        def sleep(seconds):
            sleeps.append(seconds); now[0] += seconds
        validate = validator or Mock(return_value={"exp": 99999})
        token = acquire_initial_token(issue, validate=validate, record=rows.append, budget_seconds=budget,
                                      clock=lambda: now[0], sleeper=sleep)
        return token, rows, timeouts, sleeps, validate

    def test_known_propagation_transport_429_and_5xx_then_one_frozen_token(self):
        errors = [CredentialHTTPError(401, "invalid_client", [7000215]), CredentialTransportError(),
                  CredentialHTTPError(429, "temporarily_unavailable", []), CredentialHTTPError(503, "server_error", [])]
        result, rows, timeouts, delays, validate = self.run_acquisition([*errors, {"access_token": "SYNTHETIC_FROZEN_TOKEN"}])
        self.assertEqual(result[0], "SYNTHETIC_FROZEN_TOKEN")
        self.assertEqual(len(timeouts), 5)
        validate.assert_called_once_with("SYNTHETIC_FROZEN_TOKEN")
        self.assertEqual(sum(r.get("token_frozen") is True for r in rows), 1)
        self.assertTrue(all(0 < t <= 30 for t in timeouts))
        self.assertNotIn("SYNTHETIC_FROZEN_TOKEN", json.dumps(rows))

    def test_unknown_401_and_forbidden_and_bad_request_never_retry(self):
        for error in (CredentialHTTPError(401, "invalid_client", [7000222]), CredentialHTTPError(403, "access_denied", []), CredentialHTTPError(400, "invalid_scope", [])):
            issue, record, sleep = Mock(side_effect=error), Mock(), Mock()
            with self.assertRaises(InitialTokenError):
                acquire_initial_token(issue, validate=Mock(), record=record, sleeper=sleep)
            issue.assert_called_once()
            sleep.assert_not_called()

    def test_budget_caps_request_timeout_and_stops_without_freezing(self):
        now, rows, timeouts = [0.0], [], []
        def issue(timeout):
            timeouts.append(timeout)
            now[0] += 2
            raise CredentialTransportError()
        with self.assertRaises(InitialTokenError):
            acquire_initial_token(issue, validate=Mock(), record=rows.append, budget_seconds=12,
                                  clock=lambda: now[0], sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual(timeouts, [12, 5])
        self.assertLessEqual(now[0], 12)
        self.assertFalse(any(r.get("token_frozen") for r in rows))

    def test_response_after_deadline_is_not_frozen(self):
        now, rows = [0.0], []
        result = {"access_token": "SYNTHETIC_LATE_TOKEN"}
        def issue(timeout):
            now[0] = 301
            return result
        validate = Mock()
        with self.assertRaises(InitialTokenError):
            acquire_initial_token(issue, validate=validate, record=rows.append, clock=lambda: now[0])
        validate.assert_not_called()
        self.assertEqual(result, {})
        self.assertNotIn("SYNTHETIC_LATE_TOKEN", json.dumps(rows))

    def test_invalid_response_is_not_retried_or_exposed(self):
        error = RuntimeError("SYNTHETIC_SECRET_SHOULD_NOT_ESCAPE")
        issue, rows = Mock(side_effect=error), []
        with self.assertRaises(InitialTokenError) as caught:
            acquire_initial_token(issue, validate=Mock(), record=rows.append)
        issue.assert_called_once()
        self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception) + json.dumps(rows))

    def test_interrupt_is_recorded_and_reraised_without_retry(self):
        issue, rows = Mock(side_effect=KeyboardInterrupt()), []
        with self.assertRaises(KeyboardInterrupt):
            acquire_initial_token(issue, validate=Mock(), record=rows.append)
        issue.assert_called_once()
        self.assertEqual(rows[-1]["outcome"], "interrupted_or_invalid_response")


class CredentialRequestTests(unittest.TestCase):
    URL = "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/token"

    def test_transport_exception_is_typed_and_sanitized(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.URLError("SYNTHETIC_SECRET")
        with patch.object(live_trial.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(CredentialTransportError) as caught:
                live_trial.request("POST", self.URL, form={"client_secret": "SYNTHETIC_SECRET"}, request_timeout=7)
        self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 7)
        self.assertEqual(opener.open.call_count, 1)

    def test_http_error_retains_codes_not_provider_description(self):
        payload = {"error": "invalid_client", "error_codes": [7000215], "error_description": "SYNTHETIC_SECRET"}
        error = urllib.error.HTTPError(self.URL, 401, "SYNTHETIC_SECRET", {}, io.BytesIO(json.dumps(payload).encode()))
        opener = Mock(); opener.open.side_effect = error
        with patch.object(live_trial.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(CredentialHTTPError) as caught:
                live_trial.request("POST", self.URL, form={"client_secret": "SYNTHETIC_SECRET"})
        self.assertEqual(caught.exception.code, "invalid_client")
        self.assertEqual(caught.exception.numeric_codes, [7000215])
        self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))

    def test_certificate_failure_is_not_a_retryable_transport_error(self):
        opener = Mock(); opener.open.side_effect = urllib.error.URLError(ssl.SSLCertVerificationError("synthetic"))
        with patch.object(live_trial.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(RuntimeError) as caught:
                live_trial.request("POST", self.URL)
        self.assertNotIsInstance(caught.exception, CredentialTransportError)

    def test_response_body_reset_is_retryable_and_sanitized(self):
        reply = Mock()
        reply.__enter__ = Mock(return_value=reply); reply.__exit__ = Mock(return_value=False)
        reply.read.side_effect = http.client.IncompleteRead(b"SYNTHETIC_SECRET", 30)
        opener = Mock(); opener.open.return_value = reply
        with patch.object(live_trial.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(CredentialTransportError) as caught:
                live_trial.request("POST", self.URL)
        self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
