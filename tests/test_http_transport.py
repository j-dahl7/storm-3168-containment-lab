"""Offline transport invariants. No socket is opened by these tests."""
from email.message import Message
import http.client
from pathlib import Path
import ssl
import sys
import unittest
import urllib.request
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "scripts"))
from stormlab.core import ARM, HTTP, MAX_RESPONSE, DirectHTTPSOpener, SafetyError, classify
import storage_baseline


class Reply:
    def __init__(self, status=200, payload=b"{}", headers=None, error=None):
        self.status, self.payload, self.error = status, payload, error
        self.headers = Message()
        for key, value in (headers or {}).items(): self.headers[key] = value
        self.closed = False
        self.read_sizes = []

    def read(self, count):
        self.read_sizes.append(count)
        if self.error: raise self.error
        data, self.payload = self.payload[:count], self.payload[count:]
        return data

    def close(self): self.closed = True


class Connection:
    def __init__(self, reply=None, error=None):
        self.reply = reply or Reply()
        self.error = error
        self.calls = []
        self.closed = False

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error: raise self.error

    def getresponse(self): return self.reply
    def close(self): self.closed = True


class DirectTransportTests(unittest.TestCase):
    def test_default_uses_direct_tls_with_system_trust_and_hostname_check(self):
        connection = Connection(Reply(payload=b'{"ok":true}', headers={"X-MS-Request-Id": "synthetic"}))
        with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection) as factory:
            result = HTTP().request("GET", ARM + "/synthetic?api-version=2023-05-01", {"Authorization": "Bearer SYNTHETIC"})
        self.assertEqual(result.status, 200)
        self.assertEqual(factory.call_args.args, ("management.azure.com",))
        context = factory.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(connection.calls[0][0], ("GET", "/synthetic?api-version=2023-05-01"))
        self.assertEqual(len(connection.calls), 1)
        self.assertTrue(connection.closed and connection.reply.closed)

    def test_redirect_is_returned_without_following_or_forwarding_auth(self):
        connection = Connection(Reply(302, headers={"Location": "https://untrusted.example/"}))
        with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection) as factory:
            result = HTTP().request("GET", ARM + "/", {"Authorization": "Bearer SYNTHETIC"})
        self.assertEqual(classify(result), "redirect_blocked")
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(len(connection.calls), 1)

    def test_auth_failure_is_not_retried(self):
        connection = Connection(Reply(401))
        with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection):
            result = HTTP().request("GET", ARM + "/")
        self.assertEqual(result.status, 401)
        self.assertEqual(len(connection.calls), 1)

    def test_proxy_environment_is_not_consulted(self):
        connection = Connection()
        with patch.dict("os.environ", {"HTTPS_PROXY": "https://untrusted.example", "ALL_PROXY": "https://untrusted.example"}), patch("urllib.request.getproxies", side_effect=AssertionError("must not read proxy")), patch("stormlab.core.http.client.HTTPSConnection", return_value=connection) as factory:
            HTTP().request("GET", "https://graph.microsoft.com/v1.0/synthetic")
        self.assertEqual(factory.call_args.args[0], "graph.microsoft.com")

    def test_allowlist_is_enforced_on_direct_opener_too(self):
        for url in ("http://management.azure.com/", "https://management.azure.com:444/", "https://user:pass@management.azure.com/", "https://management.azure.com.evil.example/", "https://other.example/", ARM + "/#fragment", ARM + "/bad path"):
            with self.subTest(url=url), patch("stormlab.core.http.client.HTTPSConnection") as factory:
                with self.assertRaises(SafetyError):
                    DirectHTTPSOpener().open(urllib.request.Request(url))
                factory.assert_not_called()

    def test_mismatched_host_and_proxy_auth_headers_are_rejected(self):
        for headers in ({"Host": "other.example"}, {"Proxy-Authorization": "SYNTHETIC"}):
            with patch("stormlab.core.http.client.HTTPSConnection") as factory:
                with self.assertRaises(SafetyError):
                    DirectHTTPSOpener().open(urllib.request.Request(ARM + "/", headers=headers))
                factory.assert_not_called()

    def test_certificate_failure_is_sanitized_and_connection_closed(self):
        connection = Connection(error=ssl.SSLCertVerificationError("synthetic-sig-must-not-escape"))
        with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection):
            result = HTTP().request("GET", ARM + "/")
        self.assertTrue(result.transport_error)
        self.assertTrue(connection.closed)
        self.assertNotIn("synthetic-sig", repr(result))

    def test_unverified_tls_context_is_refused(self):
        context = ssl._create_unverified_context()
        with patch("stormlab.core.ssl.create_default_context", return_value=context), patch("stormlab.core.http.client.HTTPSConnection") as factory:
            with self.assertRaises(SafetyError):
                HTTP().request("GET", ARM + "/")
        factory.assert_not_called()

    def test_reset_read_failure_is_sanitized_and_closes_both(self):
        for error in (ConnectionResetError("synthetic-sig"), http.client.IncompleteRead(b"synthetic-sig", 100)):
            connection = Connection(Reply(error=error))
            with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection):
                result = HTTP().request("GET", ARM + "/")
            self.assertTrue(result.transport_error)
            self.assertTrue(connection.closed and connection.reply.closed)

    def test_response_size_remains_bounded(self):
        connection = Connection(Reply(payload=b"x" * (MAX_RESPONSE + 50)))
        with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection):
            result = HTTP().request("GET", ARM + "/")
        self.assertTrue(result.transport_error)
        self.assertEqual(connection.reply.read_sizes, [MAX_RESPONSE + 1])
        self.assertTrue(connection.closed)

    def test_raw_storage_request_uses_same_backend_and_handles_read_failure(self):
        connection = Connection(Reply(error=ConnectionResetError("synthetic-sig")))
        guard = Mock()
        guard.m.storage_account = "syntheticaccount"
        guard.http = HTTP()
        with patch("stormlab.core.http.client.HTTPSConnection", return_value=connection) as factory:
            result = storage_baseline.storage_request(guard, "GET", "/canary/synthetic.txt?sig=synthetic", {})
        self.assertTrue(result.transport_error)
        self.assertEqual(factory.call_args.args[0], "syntheticaccount.blob.core.windows.net")
        self.assertTrue(connection.closed)

    def test_opener_remains_injectable(self):
        client = HTTP()
        with patch.object(client.opener, "open", side_effect=http.client.InvalidURL("synthetic-sig")):
            result = client.request("GET", ARM + "/")
        self.assertTrue(result.transport_error)


if __name__ == "__main__":
    unittest.main()
