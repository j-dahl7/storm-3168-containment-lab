"""Direct JSON transport contracts with fabricated operator tokens; no network."""
import io
import json
from pathlib import Path
import sys
import time
import unittest
import urllib.error
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import loganalytics_query as query_client
from stormlab.core import Manifest, SafetyError
from test_core import fixture, token, APP, SP, SUB

CUSTOMER = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


class FakeResult(io.BytesIO):
    def __init__(self, body, code=200):
        super().__init__(json.dumps(body).encode())
        self.code = code


class LogAnalyticsQueryTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.m = Manifest.from_dict(self.data)
        self.workspace = {"resource_id": query_client.workspace_id(self.m), "customer_id": CUSTOMER,
                          "subscription_id": self.m.subscription_id, "ownership_required": True}

    def run_query(self, query, *, body=None, claims=None, error=None):
        opener = Mock()
        opener.open.return_value = FakeResult(body if body is not None else {"tables": []})
        if error:
            opener.open.side_effect = error
        values = {"aud": query_client.RESOURCE, "oid": APP, "exp": time.time() + 3600}
        values.update(claims or {})
        credential = token(**values)
        with patch.object(query_client, "resolve_workspace", return_value=self.workspace), \
                patch.object(query_client, "assert_context", return_value={"state": "Enabled"}), \
                patch.object(query_client, "az", return_value={"accessToken": credential}) as cli:
            result = query_client.query_owned_workspace(self.data, self.m, query, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", opener=opener)
        return result, opener, cli

    def test_large_query_is_exact_json_body_never_cli_argument(self):
        text = '// synthetic\n' + 'print Value="' + ('a&b\n' * 12000) + '"'
        (body, receipt), opener, cli = self.run_query(text)
        request = opener.open.call_args.args[0]
        self.assertGreater(len(request.data), 32768)
        self.assertEqual(json.loads(request.data)["query"], text)
        self.assertEqual(request.full_url, query_client.ENDPOINT + CUSTOMER + "/query")
        self.assertEqual(request.method, "POST")
        self.assertNotIn(text, str(cli.call_args))
        self.assertEqual(cli.call_args.args[:2], ("account", "get-access-token"))
        self.assertEqual(receipt["transport"], "direct_json_post")
        self.assertEqual(receipt["request_attempts"], 1)

    def test_wrong_workspace_refused_before_token_or_request(self):
        self.workspace["resource_id"] += "-foreign"
        with patch.object(query_client, "resolve_workspace", return_value=self.workspace), patch.object(query_client, "az") as cli, self.assertRaises(SafetyError):
            query_client.query_owned_workspace(self.data, self.m, "print x=1", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", opener=Mock())
        cli.assert_not_called()

    def test_probe_actor_cannot_be_used_as_query_operator(self):
        opener = Mock()
        with patch.object(query_client, "resolve_workspace", return_value=self.workspace), \
                patch.object(query_client, "assert_context", return_value={"state": "Enabled"}), \
                patch.object(query_client, "az", return_value={"accessToken": token(aud=query_client.RESOURCE, oid=SP, exp=time.time()+100)}), self.assertRaises(SafetyError):
            query_client.query_owned_workspace(self.data, self.m, "print x=1", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", opener=opener)
        opener.open.assert_not_called()

    def test_wrong_audience_tenant_expiry_or_missing_identity_refused(self):
        for claims in ({"aud": "https://management.azure.com/"}, {"tid": SUB}, {"exp": 1}, {"oid": None}):
            with self.assertRaises(SafetyError):
                self.run_query("print x=1", claims=claims)

    def test_service_error_extracts_codes_without_messages(self):
        raw = {"error": {"code": "BadArgumentError", "message": "sig=DO_NOT_PRINT", "innererror": {"code": "SemanticError", "innererror": {"code": "SEM0255", "message": "query with secret"}}}}
        error = urllib.error.HTTPError("https://fixed", 400, "sensitive-provider-message", {}, io.BytesIO(json.dumps(raw).encode()))
        with self.assertRaises(query_client.QueryError) as caught:
            self.run_query("print x=1", error=error)
        self.assertEqual(caught.exception.codes, ("BadArgumentError", "SemanticError", "SEM0255"))
        self.assertNotIn("DO_NOT_PRINT", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))

    def test_partial_results_are_not_success(self):
        with self.assertRaisesRegex(query_client.QueryError, "partial_or_invalid_result"):
            self.run_query("print x=1", body={"tables": [], "error": {"code": "PartialError"}})

    def test_transport_error_is_sanitized_and_not_retried(self):
        with self.assertRaises(query_client.QueryError) as caught:
            self.run_query("print x=1", error=urllib.error.URLError("TOKEN_SHOULD_NOT_APPEAR"))
        self.assertEqual(caught.exception.kind, "transport_error")
        self.assertNotIn("TOKEN", str(caught.exception))

    def test_command_or_oversized_query_rejected_before_workspace_lookup(self):
        with patch.object(query_client, "resolve_workspace") as resolve:
            for text in (".drop table x", "x" * (query_client.MAX_QUERY_BYTES + 1)):
                with self.assertRaises(SafetyError):
                    query_client.query_owned_workspace(self.data, self.m, text, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", opener=Mock())
        resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
