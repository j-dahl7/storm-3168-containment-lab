"""Negative-path tests with fictional identities and no Azure/network access."""
import base64
import copy
import json
import unittest
import urllib.parse
from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from stormlab.core import (ARM, GRAPH, AzureCLI, Guard, HTTP, Manifest, NoRedirect, azure_cli_prefix,
                          Response, SafetyError, classify, probe_once, respond,
                          run_probe, signed_blob_headers, summarize, validate_actor_token, validate_sas)
from stormlab.__main__ import live_output, main, private_root

TENANT = "11111111-1111-4111-8111-111111111111"
SUB = "22222222-2222-4222-8222-222222222222"
LAB = "33333333-3333-4333-8333-333333333333"
APP = "44444444-4444-4444-8444-444444444444"
SP = "55555555-5555-4555-8555-555555555555"
CLIENT = "66666666-6666-4666-8666-666666666666"
GROUP = "77777777-7777-4777-8777-777777777777"
SECRET = "88888888-8888-4888-8888-888888888888"
ROLE = "99999999-9999-4999-8999-999999999999"
ASSIGNMENT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def fixture():
    rg = f"/subscriptions/{SUB}/resourceGroups/test-lab"
    return {"schema_version": 1, "tenant_id": TENANT, "subscription_id": SUB,
            "resource_group": "test-lab", "lab_id": LAB, "location": "eastus",
            "storage_account": "fakestormlab", "workspace_name": "fake-workspace",
            "actor": {"application_object_id": APP, "service_principal_object_id": SP, "client_id": CLIENT},
            "group": {"object_id": GROUP}, "owned_secret_key_id": SECRET,
            "blob": {"container": "canary", "name": "safe-test.txt"},
            "role_assignments": [{"id": rg + "/providers/Microsoft.Authorization/roleAssignments/" + ASSIGNMENT,
                                  "principal_id": SP, "scope": rg,
                                  "role_definition_id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{ROLE}"}]}


def token(**updates):
    # Fabricated, unsigned diagnostic token; never used with any real service.
    claims = {"aud": ARM + "/", "tid": TENANT, "oid": SP, "appid": CLIENT, "exp": 4000, "iat": 1000}
    claims.update(updates)
    encode = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return encode({"alg": "none"}) + "." + encode(claims) + ".not-a-signature"


def response(code=200, data=None, **kw):
    return Response(code, json.dumps(data or {}).encode(), **kw)


class Operator:
    def token(self, service):
        return "FAKE-OPERATOR-CREDENTIAL"


class FakeHTTP:
    def __init__(self, m):
        self.m = m
        self.calls = []
        self.bad_tag = False
        self.bad_actor = False
        self.bad_role = False
        self.bad_definition = False
        self.bad_scope = False
        self.secret_absent = False
        self.existing_lock = None
        self.probe_response = response(200)
        self.storage_tags = {"purpose": "existing-purpose", "keep": "original-value"}
        self.actor_storage_response = None
        self.rg_reads = 0
        self.break_tag_after = None

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        m = self.m
        if "/listKeys?" in url or "/regenerateKey?" in url:
            return self.probe_response
        if method == "PATCH" and url.startswith(ARM + m.storage_id + "?") and body and "tags" in body:
            self.storage_tags = copy.deepcopy(body["tags"])
            return response(200)
        if method != "GET":
            return response(200)
        if url.startswith(ARM + m.rg_id + "?"):
            self.rg_reads += 1
            bad = self.bad_tag or (self.break_tag_after is not None and self.rg_reads > self.break_tag_after)
            return response(data={"id": m.rg_id, "tags": {"storm3168LabId": "wrong" if bad else LAB}})
        if url.startswith(ARM + m.storage_id + "?") and (headers or {}).get("Authorization") == "Bearer FAKE-OPERATOR-CREDENTIAL":
            return response(data={"id": m.storage_id, "name": m.storage_account})
        if url.startswith(ARM + m.storage_id + "?"):
            if self.actor_storage_response is not None:
                return self.actor_storage_response
            return response(data={"id": m.storage_id, "name": m.storage_account, "tags": self.storage_tags})
        if "/applications/" in url:
            return response(data={"id": APP, "appId": CLIENT, "displayName": "foreign" if self.bad_actor else m.name_prefix,
                                  "passwordCredentials": [] if self.secret_absent else [{"keyId": SECRET}]})
        if "/servicePrincipals/" in url:
            return response(data={"id": SP, "appId": CLIENT, "displayName": m.name_prefix})
        if "/groups/" in url:
            if "/members/" in url:
                return response(data={"id": SP})
            return response(data={"id": GROUP, "displayName": m.name_prefix + "-access"})
        if "/roleAssignments/" in url:
            r = m.role_assignments[0]
            return response(data={"id": r["id"], "properties": {"principalId": APP if self.bad_role else r["principal_id"],
                                      "scope": "/subscriptions/" + SUB if self.bad_scope else r["scope"],
                                      "roleDefinitionId": "wrong" if self.bad_definition else r["role_definition_id"]}})
        if "/locks/" in url:
            return response(404) if self.existing_lock is None else response(data=self.existing_lock)
        return self.probe_response

    @property
    def mutations(self):
        return [c for c in self.calls if c[0] != "GET"]


class ManifestTests(unittest.TestCase):
    def test_valid(self):
        m = Manifest.from_dict(fixture())
        self.assertEqual(m.subscription_id, SUB)

    def test_reject_cross_subscription_or_ancestor_assignment(self):
        for change in (lambda r: r.update(scope="/subscriptions/" + SUB),
                       lambda r: r.update(id=r["id"].replace(SUB, TENANT)),
                       lambda r: r.update(principal_id=APP),
                       lambda r: r.update(role_definition_id=r["role_definition_id"].replace(SUB, TENANT))):
            d = fixture()
            change(d["role_assignments"][0])
            with self.assertRaises(SafetyError):
                Manifest.from_dict(d)

    def test_reject_unknown_and_path_injection(self):
        for field, value in (("storage_account", "evil.example"), ("resource_group", "lab/../production"), ("schema_version", True), ("lab_id", "bad"), ("unknown", 1)):
            d = fixture()
            d[field] = value
            with self.assertRaises(SafetyError):
                Manifest.from_dict(d)
        for name in ("../secret", "x?sig=secret", "https://evil", "a\\b", "foo//bar"):
            d = fixture()
            d["blob"]["name"] = name
            with self.assertRaises(SafetyError):
                Manifest.from_dict(d)

    def test_private_paths(self):
        with TemporaryDirectory() as t:
            private = Path(t) / "private"
            private.mkdir()
            (Path(t) / ".gitignore").write_text("private/\n")
            manifest = private / "manifest.json"
            manifest.write_text("{}")
            with patch("stormlab.__main__.REPO_ROOT", Path(t)):
                self.assertEqual(private_root(manifest), private.resolve())
            with self.assertRaises(SafetyError):
                live_output(str(Path(t) / "public.jsonl"), private, "ignored")

    def test_other_private_directory_rejected(self):
        with TemporaryDirectory() as actual, TemporaryDirectory() as other:
            (Path(actual) / ".gitignore").write_text("private/\n")
            foreign = Path(other) / "private"
            foreign.mkdir()
            manifest = foreign / "manifest.json"
            manifest.write_text("{}")
            with patch("stormlab.__main__.REPO_ROOT", Path(actual)), self.assertRaises(SafetyError):
                private_root(manifest)

    def test_unignored_private_directory_rejected(self):
        with TemporaryDirectory() as t:
            private = Path(t) / "private"
            private.mkdir()
            (Path(t) / ".gitignore").write_text("something-else/\n")
            manifest = private / "manifest.json"
            manifest.write_text("{}")
            with patch("stormlab.__main__.REPO_ROOT", Path(t)), self.assertRaises(SafetyError):
                private_root(manifest)


class AzureCLILauncherTests(unittest.TestCase):
    def test_native_executable_is_unchanged(self):
        with patch("stormlab.core.shutil.which", return_value="/usr/bin/az"):
            self.assertEqual(azure_cli_prefix(), ["/usr/bin/az"])

    def test_missing_cli_fails_closed(self):
        with patch("stormlab.core.shutil.which", return_value=None), self.assertRaises(SafetyError):
            azure_cli_prefix()

    def test_batch_launcher_uses_python_and_preserves_opaque_arguments(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "wbin").mkdir()
            launcher = root / "wbin" / "az.cmd"
            launcher.write_text('@IF EXIST "%~dp0\\..\\python.exe" (\n  "%~dp0\\..\\python.exe" -IBm azure.cli %*\n)\n')
            (root / "python.exe").write_bytes(b"fake executable, never run")
            calls = []
            def runner(args, **kwargs):
                calls.append((args, kwargs))
                return SimpleNamespace(returncode=0, stdout="{}")
            query = 'Table\n| where Value == "a&b"; $(never)'
            with patch("stormlab.core.shutil.which", return_value=str(launcher)):
                AzureCLI(Manifest.from_dict(fixture()), SUB, runner=runner)._json(["query", "--analytics-query", query])
            self.assertEqual(calls[0][0][:3], [str(root / "python.exe"), "-IBm", "azure.cli"])
            self.assertEqual(calls[0][0][3:6], ["query", "--analytics-query", query])
            self.assertIs(calls[0][1]["shell"], False)

    def test_unrecognized_batch_and_missing_python_fail_closed(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "wbin").mkdir()
            launcher = root / "wbin" / "az.BAT"
            with patch("stormlab.core.shutil.which", return_value=str(launcher)):
                launcher.write_text("python -m some_other_module %*\n")
                (root / "python.exe").write_bytes(b"fake executable, never run")
                with self.assertRaises(SafetyError):
                    azure_cli_prefix()
                launcher.write_text('"%~dp0\\..\\python.exe" -IBm azure.cli %*\n')
                (root / "python.exe").unlink()
                with self.assertRaises(SafetyError):
                    azure_cli_prefix()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.m = Manifest.from_dict(fixture())
        self.http = FakeHTTP(self.m)
        self.guard = Guard(self.m, self.http, Operator())

    def test_respond_default_is_offline_plan(self):
        result = respond(self.guard, "sp-disable")
        self.assertEqual(result["status"], "planned")
        self.assertEqual(self.http.calls, [])

    def test_missing_confirmation_fails_before_network(self):
        with self.assertRaises(SafetyError):
            respond(self.guard, "sp-disable", execute=True)
        self.assertFalse(self.http.calls)

    def test_wrong_subscription_before_auth(self):
        with self.assertRaises(SafetyError):
            AzureCLI(self.m, TENANT)

    def test_bad_live_tag_cannot_mutate(self):
        self.http.bad_tag = True
        with self.assertRaises(SafetyError):
            respond(self.guard, "rotate-key1", execute=True, confirm_lab_id=LAB)
        self.assertFalse(self.http.mutations)

    def test_mutation_target_allowlist_cannot_be_bypassed(self):
        with self.assertRaises(SafetyError):
            self.guard.mutation("arm", "DELETE", "/subscriptions/" + SUB + "?api-version=2021-04-01", None)
        self.assertFalse(self.http.calls)

    def test_actor_mismatch_cannot_disable(self):
        self.http.bad_actor = True
        with self.assertRaises(SafetyError):
            respond(self.guard, "app-deactivate", execute=True, confirm_lab_id=LAB)
        self.assertFalse(self.http.mutations)

    def test_role_exact_contract(self):
        for attr in ("bad_role", "bad_definition", "bad_scope"):
            setattr(self.http, attr, True)
            with self.assertRaises(SafetyError):
                respond(self.guard, "role-delete", execute=True, confirm_lab_id=LAB, assignment_id=self.m.role_assignments[0]["id"])
            setattr(self.http, attr, False)
        self.assertFalse(self.http.mutations)

    def test_role_not_allowlisted(self):
        with self.assertRaises(SafetyError):
            respond(self.guard, "role-delete", execute=True, confirm_lab_id=LAB, assignment_id="/subscriptions/evil")
        self.assertFalse(self.http.calls)

    def test_secret_absent_cannot_remove(self):
        self.http.secret_absent = True
        with self.assertRaises(SafetyError):
            respond(self.guard, "secret-remove", execute=True, confirm_lab_id=LAB)
        self.assertFalse(self.http.mutations)

    def test_group_removal_uses_ref_never_object_delete(self):
        respond(self.guard, "group-member-remove", execute=True, confirm_lab_id=LAB)
        deletion = self.http.mutations[0]
        self.assertEqual(deletion[0], "DELETE")
        self.assertTrue(deletion[1].endswith(f"/groups/{GROUP}/members/{SP}/$ref"))

    def test_lock_collision_not_adopted(self):
        self.http.existing_lock = {"id": self.m.lock_id, "properties": {"notes": "someone else's lock"}}
        with self.assertRaises(SafetyError):
            respond(self.guard, "lock-readonly", execute=True, confirm_lab_id=LAB)
        self.assertFalse(self.http.mutations)

    def test_absent_lock_not_removed(self):
        with self.assertRaises(SafetyError):
            respond(self.guard, "lock-remove", execute=True, confirm_lab_id=LAB)
        self.assertFalse(self.http.mutations)

    def test_rotation_no_keys_in_evidence(self):
        self.http.probe_response = response(data={"keys": [{"value": "ROTATION-SECRET-MUST-NOT-LEAK"}]})
        result = respond(self.guard, "rotate-key2", execute=True, confirm_lab_id=LAB)
        self.assertEqual(self.http.mutations[-1][3], {"keyName": "key2"})
        self.assertFalse(result["postcondition_verified"])
        self.assertEqual(result["status"], "accepted_unverified")
        self.assertNotIn("FAKE-OPERATOR", json.dumps(result))
        self.assertNotIn("ROTATION-SECRET", json.dumps(result))

    def test_metadata_get_retries_at_most_twice_on_transport_only(self):
        class Responses:
            def __init__(self, values):
                self.values, self.calls = iter(values), []
            def request(self, *args):
                self.calls.append(args)
                return next(self.values)
        sleeps = []
        http = Responses([Response(0, transport_error=True), Response(0), response(200, {"ok": True})])
        guard = Guard(self.m, http, Operator(), sleeper=sleeps.append)
        result = guard.read("arm", self.m.rg_id + "?api-version=2021-04-01")
        self.assertEqual(result.status, 200)
        self.assertEqual(len(http.calls), 3)
        self.assertEqual(sleeps, [0.5, 1.0])
        self.assertEqual(guard.read_transport_retries, 2)
        self.assertTrue(all(call[0] == "GET" for call in http.calls))
        for status in (403, 404, 429, 500, 503):
            http = Responses([response(status)])
            guard = Guard(self.m, http, Operator(), sleeper=lambda _: self.fail("Must not retry HTTP status"))
            self.assertEqual(guard.read("arm", "/test").status, status)
            self.assertEqual(len(http.calls), 1)
        http = Responses([Response(0), Response(0), Response(0)])
        guard = Guard(self.m, http, Operator(), sleeper=lambda _: None)
        self.assertEqual(guard.read("arm", "/test").status, 0)
        self.assertEqual(len(http.calls), 3)

    def test_mutation_transport_error_is_never_retried(self):
        self.http.probe_response = Response(0, transport_error=True)
        result = respond(self.guard, "rotate-key1", execute=True, confirm_lab_id=LAB)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["outcome"], "transport_error")
        self.assertEqual(len(self.http.mutations), 1)
        self.assertEqual(self.guard.read_transport_retries, 0)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.m = Manifest.from_dict(fixture())
        self.http = FakeHTTP(self.m)
        self.guard = Guard(self.m, self.http, Operator())

    def test_token_actor_audience_tenant_expiry_and_delegation(self):
        for fields in ({"oid": APP}, {"tid": SUB}, {"aud": GRAPH}, {"exp": 900}, {"scp": "user.read"}, {"appid": APP}, {"nbf": 1100}):
            with self.assertRaises(SafetyError):
                validate_actor_token(token(**fields), self.m, "arm", 1000)

    def test_fixed_credential_across_polls_no_metadata_leak(self):
        now = [1000.0]
        frozen = token()
        rows = []
        run_probe(self.m, self.http, self.guard, "arm-read", frozen, duration=15, interval=5, emit=rows.append,
                  clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        probes = [c for c in self.http.calls if c[2].get("Authorization") == "Bearer " + frozen]
        self.assertEqual(len(probes), 4)
        serialized = json.dumps(rows)
        self.assertNotIn(frozen, serialized)
        self.assertNotIn(SP, serialized)
        self.assertNotIn(SUB, serialized)

    def test_expiry_stops_requests_and_is_not_denial(self):
        now = [1000.0]
        rows = []
        frozen = token(exp=1006)
        run_probe(self.m, self.http, self.guard, "arm-read", frozen, duration=30, interval=5, emit=rows.append,
                  clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        probes = [r for r in rows if r["kind"] == "probe"]
        self.assertEqual([r["outcome"] for r in probes], ["allowed", "allowed", "expired"])
        self.assertFalse(summarize(rows)["runs"][0]["sustained_denial_observed"])

    def test_live_tag_rechecked_for_each_write(self):
        self.http.break_tag_after = 1
        probe_once(self.m, self.http, self.guard, "arm-tag-write", token(), allow_mutation=True, now=1000)
        with self.assertRaises(SafetyError):
            probe_once(self.m, self.http, self.guard, "arm-tag-write", token(), allow_mutation=True, now=1010)
        self.assertEqual(len(self.http.mutations), 1)

    def test_write_without_flag_no_request(self):
        with self.assertRaises(SafetyError):
            probe_once(self.m, self.http, self.guard, "arm-tag-write", token(), now=1000)
        self.assertFalse(self.http.calls)

    def test_storage_patch_preserves_existing_tags(self):
        previous = copy.deepcopy(self.http.storage_tags)
        result = probe_once(self.m, self.http, self.guard, "arm-tag-write", token(), allow_mutation=True, now=1000)
        self.assertEqual(result["outcome"], "allowed")
        mutation = self.http.mutations[-1]
        self.assertEqual(mutation[1], ARM + self.m.storage_id + "?api-version=2023-05-01")
        self.assertNotIn("Microsoft.Resources/tags", mutation[1])
        self.assertEqual(set(mutation[3]), {"tags"})
        for key, value in previous.items():
            self.assertEqual(mutation[3]["tags"][key], value)
        self.assertIn("storm3168Probe", mutation[3]["tags"])

    def test_actor_preread_failure_never_writes_or_claims_containment(self):
        variants = [response(403, {"error": {"code": "AuthorizationFailed"}}),
                    response(200, {"id": self.m.rg_id, "tags": {}}),
                    response(200, {"id": self.m.storage_id, "tags": ["wrong"]}),
                    Response(200, b"not-json")]
        for variant in variants:
            self.http.actor_storage_response = variant
            result = probe_once(self.m, self.http, self.guard, "arm-tag-write", token(), allow_mutation=True, now=1000)
            self.assertEqual(result["outcome"], "precondition_failed")
            self.assertFalse(result["mutation_attempted"])
        self.assertFalse(self.http.mutations)

    def test_listkeys_never_records_response(self):
        self.http.probe_response = response(data={"keys": [{"value": "SECRET-MUST-NOT-LEAK"}]})
        result = probe_once(self.m, self.http, self.guard, "listkeys", token(), now=1000)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("keys", result)

    def test_bounds(self):
        for interval, duration in ((1, 10), (5, 7201), (5, -1), (float("nan"), 10)):
            with self.assertRaises(SafetyError):
                run_probe(self.m, self.http, self.guard, "arm-read", token(), interval=interval, duration=duration, emit=lambda x: None)
        self.assertFalse(self.http.calls)

    def test_probe_transport_failure_is_recorded_once_with_request_timestamps(self):
        self.http.actor_storage_response = Response(0, transport_error=True)
        with patch("stormlab.core.utc_now", side_effect=["request-start", "response-return"]):
            result = probe_once(self.m, self.http, self.guard, "arm-read", token(), now=1000)
        self.assertEqual(result["outcome"], "transport_error")
        self.assertEqual(result["http_status"], 0)
        self.assertEqual(result["request_started_at"], "request-start")
        self.assertEqual(result["timestamp"], "request-start")
        self.assertEqual(result["response_received_at"], "response-return")
        self.assertEqual(len(self.http.calls), 1)
        self.assertEqual(self.guard.read_transport_retries, 0)

    def test_shared_key_only_targets_exact_blob(self):
        key = base64.b64encode(b"x" * 64).decode()
        probe_once(self.m, self.http, self.guard, "blob-read", key, auth="shared-key", now=1000)
        method, url, headers, _ = self.http.calls[-1]
        self.assertEqual(url, "https://fakestormlab.blob.core.windows.net/canary/safe-test.txt")
        self.assertEqual(headers["Range"], "bytes=0-0")
        self.assertTrue(headers["Authorization"].startswith("SharedKey fakestormlab:"))
        self.assertNotIn(key, headers["Authorization"])


class EvidenceTests(unittest.TestCase):
    def test_error_outcomes_are_not_containment(self):
        cases = [(Response(0, transport_error=True), "transport_error"), (response(429), "throttled"),
                 (response(302), "redirect_blocked"), (response(500), "service_error"),
                 (response(404), "unknown"), (response(403), "authentication_or_unknown_denial"),
                 (response(401, {"error": {"code": "ExpiredAuthenticationToken"}}), "expired")]
        for r, expected in cases:
            self.assertEqual(classify(r), expected)

    def test_sustained_requires_baseline_and_duration(self):
        def p(t, result):
            return {"kind": "probe", "run_id": "x", "capability": "arm-read", "elapsed_seconds": t, "outcome": result}
        denial = [p(10, "authorization_denied"), p(40, "authorization_denied"), p(70, "authorization_denied")]
        self.assertFalse(summarize(denial)["runs"][0]["sustained_denial_observed"])
        rows = [p(0, "allowed")] + denial
        self.assertTrue(summarize(rows)["runs"][0]["sustained_denial_observed"])
        returned = summarize(rows + [p(80, "allowed")])["runs"][0]
        self.assertTrue(returned["sustained_denial_observed"])
        self.assertFalse(returned["sustained_denial_at_end"])
        self.assertEqual(returned["denial_intervals"][0]["end_reason"], "access_returned")

    def test_empty_is_not_tested(self):
        self.assertEqual(summarize([])["status"], "not_tested")

    def test_no_redirect_or_unknown_host(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example"))
        with self.assertRaises(SafetyError):
            HTTP().request("GET", "https://evil.example/")

    def test_offline_cli_demo_and_summary(self):
        with TemporaryDirectory() as t:
            path, summary = Path(t) / "demo.jsonl", Path(t) / "summary.json"
            with patch("stormlab.core.HTTP.request", side_effect=AssertionError("Network not allowed")):
                self.assertEqual(main(["demo", "--output", str(path)]), 0)
                self.assertEqual(main(["summarize", "--input", str(path), "--output", str(summary)]), 0)
            self.assertEqual(json.loads(summary.read_text())["evidence_type"], "offline_demo")


class SASTests(unittest.TestCase):
    def setUp(self):
        self.m = Manifest.from_dict(fixture())
        self.http = FakeHTTP(self.m)
        self.guard = Guard(self.m, self.http, Operator())

    def sas(self, **updates):
        fields = {"sv": "2023-11-03", "spr": "https", "sp": "r", "sr": "b",
                  "se": "1970-01-01T02:00:00Z", "sig": base64.b64encode(b"s" * 32).decode()}
        fields.update(updates)
        return urllib.parse.urlencode(fields)

    def test_fixed_url_without_authorization_and_no_credential_output(self):
        query = self.sas()
        row = probe_once(self.m, self.http, self.guard, "blob-read", query, auth="sas", now=1000)
        method, url, headers, _ = self.http.calls[-1]
        self.assertEqual(url, "https://fakestormlab.blob.core.windows.net/canary/safe-test.txt?" + query)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn(query, json.dumps(row))
        self.assertNotIn("sig", row)
        self.assertEqual(row["outcome"], "allowed")

    def test_reject_url_injection_duplicate_unknown_and_privileged_permissions(self):
        attacks = ["https://evil.example/evil?" + self.sas(), self.sas() + "&sig=duplicate",
                   self.sas() + "&url=https%3A%2F%2Fevil.example", self.sas() + "#fragment",
                   self.sas(sp="rw"), self.sas(spr="https,http"), self.sas(se="1970-01-01T02:00:00"),
                   self.sas(sig="notbase64"), self.sas() + "&se=1970-01-02T02%3A00%3A00Z",
                   self.sas() + "&versionid=other-blob-version", self.sas() + "&sip=%zz"]
        for query in attacks:
            with self.subTest(query_kind=attacks.index(query)), self.assertRaises(SafetyError):
                probe_once(self.m, self.http, self.guard, "blob-read", query, auth="sas", now=1000)
        self.assertFalse(self.http.calls)

    def test_expired_is_not_denial_and_makes_no_request(self):
        row = probe_once(self.m, self.http, self.guard, "blob-read", self.sas(se="1970-01-01T00:15:00Z"), auth="sas", now=1000)
        self.assertEqual(row["outcome"], "expired")
        self.assertEqual(self.http.calls, [])

    def test_delegation_identity_and_earliest_expiry(self):
        delegation = {"skoid": SP, "sktid": TENANT, "skt": "1970-01-01T00:00:00Z",
                      "ske": "1970-01-01T00:20:00Z", "sks": "b", "skv": "2023-11-03"}
        self.assertEqual(validate_sas(self.sas(**delegation), self.m, 1000)["exp"], 1200)
        row = probe_once(self.m, self.http, self.guard, "blob-read", self.sas(**delegation), auth="sas", now=1201)
        self.assertEqual(row["outcome"], "expired")
        self.assertFalse(self.http.calls)
        for mismatch in ({"skoid": APP}, {"sktid": SUB}, {"saoid": APP}):
            with self.assertRaises(SafetyError):
                validate_sas(self.sas(**(delegation | mismatch)), self.m, 1000)

    def test_account_sas_and_fixed_poll_metadata(self):
        fields = dict(urllib.parse.parse_qsl(self.sas()))
        fields.pop("sr")
        fields.update(ss="b", srt="o")
        query = urllib.parse.urlencode(fields)
        self.assertEqual(validate_sas(query, self.m, 1000)["sas_type"], "account")
        rows, now = [], [1000.0]
        run_probe(self.m, self.http, self.guard, "blob-read", query, auth="sas", interval=5, duration=10,
                  emit=rows.append, clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertNotIn(query, json.dumps(rows))
        sas_requests = [c for c in self.http.calls if ".blob.core.windows.net/" in c[1]]
        self.assertEqual(len(sas_requests), 3)
        self.assertEqual(len({c[1] for c in sas_requests}), 1)
        self.assertTrue(all("Authorization" not in c[2] for c in sas_requests))


if __name__ == "__main__":
    unittest.main()
