"""Small, fail-closed operational core. Only explicit calls perform network I/O."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from typing import Any, Callable


ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com"
ARM_AUDIENCES = {ARM, ARM + "/", "https://management.core.windows.net/", "https://management.core.windows.net"}
GRAPH_AUDIENCES = {GRAPH, GRAPH + "/", "00000003-0000-0000-c000-000000000000"}
MAX_RESPONSE = 2_000_000
MAX_DURATION = 7_200
MIN_INTERVAL = 5


class SafetyError(Exception):
    """A missing proof or an unsafe request; messages contain no credentials."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def guid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SafetyError(f"{field} must be a UUID string")
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise SafetyError(f"{field} must be a UUID") from exc
    if value.lower() != parsed:
        raise SafetyError(f"{field} must use canonical UUID formatting")
    return parsed


def strict_keys(data: Any, required: set[str], optional: set[str], field: str) -> dict:
    if not isinstance(data, dict):
        raise SafetyError(f"{field} must be an object")
    missing = required - data.keys()
    unknown = data.keys() - required - optional
    if missing or unknown:
        raise SafetyError(f"{field}: missing {sorted(missing)}; unknown {sorted(unknown)}")
    return data


def load_json(path: Path) -> dict:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise SafetyError("Duplicate JSON property")
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=reject_duplicates)
    except (OSError, ValueError) as exc:
        raise SafetyError("Cannot read valid JSON input") from exc


@dataclass(frozen=True)
class Manifest:
    tenant_id: str
    subscription_id: str
    resource_group: str
    lab_id: str
    location: str
    storage_account: str
    workspace_name: str
    actor: dict[str, str] | None
    role_assignments: tuple[dict[str, str], ...]
    group: dict[str, str] | None = None
    owned_secret_key_id: str | None = None
    blob: dict[str, str] | None = None

    @property
    def rg_id(self) -> str:
        return f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"

    @property
    def storage_id(self) -> str:
        return self.rg_id + f"/providers/Microsoft.Storage/storageAccounts/{self.storage_account}"

    @property
    def name_prefix(self) -> str:
        return "storm3168-" + self.lab_id

    @property
    def lock_id(self) -> str:
        return self.storage_id + "/providers/Microsoft.Authorization/locks/" + self.name_prefix

    @classmethod
    def from_dict(cls, value: dict) -> "Manifest":
        required = {"schema_version", "tenant_id", "subscription_id", "resource_group", "lab_id", "location", "storage_account", "workspace_name", "role_assignments"}
        d = strict_keys(value, required, {"actor", "group", "owned_secret_key_id", "blob", "stages", "budget_target_usd", "evidence_status", "sentinel_enabled"}, "manifest")
        if type(d["schema_version"]) is not int or d["schema_version"] != 1:
            raise SafetyError("Only schema_version 1 is supported")
        if "budget_target_usd" in d and (type(d["budget_target_usd"]) not in {int, float} or not 0 < d["budget_target_usd"] <= 10):
            raise SafetyError("This lab requires a positive usage target no greater than $10")
        if "sentinel_enabled" in d and type(d["sentinel_enabled"]) is not bool:
            raise SafetyError("sentinel_enabled must be boolean")
        tenant = guid(d["tenant_id"], "tenant_id")
        subscription = guid(d["subscription_id"], "subscription_id")
        lab = guid(d["lab_id"], "lab_id")
        patterns = {"resource_group": r"[A-Za-z0-9_-]{1,90}", "storage_account": r"[a-z0-9]{3,24}", "workspace_name": r"[A-Za-z0-9-]{3,63}", "location": r"[a-z0-9]{2,40}"}
        for field, pattern in patterns.items():
            if not isinstance(d[field], str) or not re.fullmatch(pattern, d[field]):
                raise SafetyError(f"Invalid {field}")
        actor = d.get("actor")
        if actor is not None:
            actor = strict_keys(actor, {"application_object_id", "service_principal_object_id", "client_id"}, set(), "actor")
            actor = {k: guid(v, "actor." + k) for k, v in actor.items()}
        group = d.get("group")
        if group is not None:
            group = strict_keys(group, {"object_id"}, set(), "group")
            group = {"object_id": guid(group["object_id"], "group.object_id")}
        if not isinstance(d["role_assignments"], list):
            raise SafetyError("role_assignments must be a list")
        rg = f"/subscriptions/{subscription}/resourceGroups/{d['resource_group']}"
        assignments = []
        seen = set()
        allowed_principals = set()
        if actor:
            allowed_principals.add(actor["service_principal_object_id"])
        if group:
            allowed_principals.add(group["object_id"])
        for row in d["role_assignments"]:
            row = dict(strict_keys(row, {"id", "principal_id", "scope", "role_definition_id"}, set(), "role assignment"))
            row["principal_id"] = guid(row["principal_id"], "principal_id")
            if row["principal_id"] not in allowed_principals:
                raise SafetyError("Assignment principal is not the recorded actor or group")
            scope = row["scope"]
            if not isinstance(scope, str) or not (scope.lower() == rg.lower() or scope.lower().startswith(rg.lower() + "/")):
                raise SafetyError("Role scope must be the owned resource group or a descendant")
            if any(x in scope for x in ["..", "%", "?", "#", "\\"]) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", scope):
                raise SafetyError("Unsafe role scope")
            suffix = "/providers/Microsoft.Authorization/roleAssignments/"
            if not isinstance(row["id"], str) or not row["id"].lower().startswith((scope + suffix).lower()):
                raise SafetyError("Assignment ID does not match its scope")
            guid(row["id"][len(scope + suffix):], "role assignment ID")
            definition = row["role_definition_id"]
            definition_prefix = f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleDefinitions/"
            if not isinstance(definition, str) or not definition.lower().startswith(definition_prefix.lower()):
                raise SafetyError("Role definition must be an exact ID in the selected subscription")
            guid(definition[len(definition_prefix):], "role definition ID")
            if row["id"].lower() in seen:
                raise SafetyError("Duplicate role assignment")
            seen.add(row["id"].lower())
            assignments.append(row)
        secret = d.get("owned_secret_key_id")
        if secret is not None:
            secret = guid(secret, "owned_secret_key_id")
            if not actor:
                raise SafetyError("Owned secret requires an actor")
        blob = d.get("blob")
        if blob is not None:
            blob = dict(strict_keys(blob, {"container", "name"}, set(), "blob"))
            if not isinstance(blob["container"], str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61})[a-z0-9]", blob["container"]) or "--" in blob["container"]:
                raise SafetyError("Invalid blob container")
            name = blob["name"]
            if not isinstance(name, str) or not 1 <= len(name) <= 256 or not re.fullmatch(r"[A-Za-z0-9_./-]+", name) or any(p in {"", ".", ".."} for p in name.split("/")):
                raise SafetyError("Invalid canary blob name")
        return cls(tenant, subscription, d["resource_group"], lab, d["location"], d["storage_account"], d["workspace_name"], actor, tuple(assignments), group, secret, blob)


def claims_from_token(token: str) -> dict:
    """Read diagnostic claims only; the resource service verifies signatures."""
    if not isinstance(token, str) or len(token) > 32768 or any(c.isspace() for c in token):
        raise SafetyError("Invalid credential format")
    parts = token.split(".")
    if len(parts) != 3:
        raise SafetyError("This experimental harness requires a JWT bearer token")
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, UnicodeError) as exc:
        raise SafetyError("Cannot read credential metadata") from exc
    if not isinstance(data, dict) or type(data.get("exp")) not in {int, float} or not math.isfinite(data["exp"]):
        raise SafetyError("Credential has no numeric expiry")
    return data


def validate_actor_token(token: str, manifest: Manifest, audience: str, now: float | None = None, *, allow_expired: bool = False) -> dict:
    c = claims_from_token(token)
    if not manifest.actor:
        raise SafetyError("A recorded actor is required for bearer probes")
    accepted = ARM_AUDIENCES if audience == "arm" else {"https://storage.azure.com", "https://storage.azure.com/"}
    if not isinstance(c.get("aud"), str) or c.get("aud") not in accepted or str(c.get("tid", "")).lower() != manifest.tenant_id:
        raise SafetyError("Credential audience or tenant does not match the manifest")
    if str(c.get("oid", "")).lower() != manifest.actor["service_principal_object_id"]:
        raise SafetyError("Credential is not for the recorded service principal")
    client_id = c.get("appid", c.get("azp"))
    if not isinstance(client_id, str) or client_id.lower() != manifest.actor["client_id"] or c.get("scp"):
        raise SafetyError("Credential must be an app-only token for the recorded client")
    now = time.time() if now is None else now
    if c["exp"] <= now and not allow_expired:
        raise SafetyError("Credential is already expired")
    if type(c.get("nbf", 0)) not in {int, float} or c.get("nbf", 0) > now:
        raise SafetyError("Credential is not yet valid")
    return c


SAS_KEYS = {"sv", "ss", "srt", "sp", "se", "st", "spr", "sip", "sig", "sr", "si",
            "rscc", "rscd", "rsce", "rscl", "rsct", "skoid", "sktid", "skt", "ske", "sks", "skv",
            "saoid", "suoid", "scid", "sdd", "ses"}


def validate_sas(query: str, manifest: Manifest, now: float, *, allow_expired: bool = False) -> dict:
    """Validate an externally supplied frozen read-only SAS without re-signing it."""
    if not isinstance(query, str) or not 1 <= len(query) <= 4096 or any(c in query for c in "?#\r\n") or "://" in query or re.search(r"%(?![A-Fa-f0-9]{2})", query):
        raise SafetyError("SAS must be a bounded query string only, without URL or fragment")
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=32, errors="strict")
    except (ValueError, UnicodeError):
        # parse_qsl includes the offending field (possibly sig) in its error.
        raise SafetyError("Malformed SAS query") from None
    fields: dict[str, str] = {}
    for key, value in pairs:
        if key not in SAS_KEYS or key in fields or not value or any(ord(c) < 32 for c in value):
            raise SafetyError("Unknown, duplicate, empty, or unsafe SAS field")
        fields[key] = value
    if fields.get("sp") != "r" or fields.get("spr") != "https" or not {"sig", "se", "sv"} <= fields.keys():
        raise SafetyError("SAS requires explicit expiry, read-only permission, HTTPS and signature")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fields["sv"]):
        raise SafetyError("Invalid SAS service version")
    try:
        if len(base64.b64decode(fields["sig"], validate=True)) != 32:
            raise ValueError("signature length")
    except ValueError:
        raise SafetyError("Invalid SAS signature encoding") from None
    def utc_time(key: str) -> float:
        value = fields[key]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)", value):
            raise SafetyError("SAS timestamps must explicitly use UTC")
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise SafetyError("Invalid SAS UTC timestamp") from None
    expiry = utc_time("se")
    start = utc_time("st") if "st" in fields else 0
    delegated = bool({"skoid", "sktid", "skt", "ske", "sks", "skv"} & fields.keys())
    if delegated:
        if not {"skoid", "sktid", "skt", "ske", "sks", "skv"} <= fields.keys() or not manifest.actor:
            raise SafetyError("User-delegation SAS requires its complete key metadata and a recorded actor")
        if guid(fields["skoid"], "SAS object ID") != manifest.actor["service_principal_object_id"] or guid(fields["sktid"], "SAS tenant") != manifest.tenant_id or fields["sks"] != "b":
            raise SafetyError("User-delegation SAS is not for the recorded actor and tenant")
        for optional_actor in ("saoid", "suoid"):
            if optional_actor in fields and guid(fields[optional_actor], "SAS authorized actor") != manifest.actor["service_principal_object_id"]:
                raise SafetyError("SAS authorized actor mismatches")
        expiry = min(expiry, utc_time("ske"))
        start = max(start, utc_time("skt"))
    elif {"saoid", "suoid", "scid"} & fields.keys():
        raise SafetyError("Delegation fields require a user-delegation SAS")
    if "ss" in fields or "srt" in fields:
        if delegated or "sr" in fields or fields.get("ss") != "b" or "o" not in fields.get("srt", "") or any(c not in "sco" for c in fields["srt"]) or len(set(fields["srt"])) != len(fields["srt"]):
            raise SafetyError("Account SAS must allow blob objects only in the fixed target path")
    elif fields.get("sr") not in {"b", "c", "d"}:
        raise SafetyError("Service SAS must name a supported blob resource type")
    if expiry <= start:
        raise SafetyError("SAS validity window is empty")
    if start > now:
        raise SafetyError("SAS is not yet valid")
    if expiry <= now and not allow_expired:
        raise SafetyError("SAS is already expired")
    return {"aud": "sas:fixed-manifest-blob", "exp": expiry, "nbf": start, "sas_type": "user-delegation" if delegated else "account" if "ss" in fields else "service"}


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: dict[str, str] | None = None
    transport_error: bool = False

    def data(self) -> dict:
        try:
            result = json.loads(self.body) if self.body else {}
        except (ValueError, UnicodeError) as exc:
            raise SafetyError("Service did not return valid JSON") from exc
        if not isinstance(result, dict):
            raise SafetyError("Service returned an unexpected response")
        return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTP:
    """No redirects, implicit auth, proxy auth, or retries. Bounded response size."""
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method: str, url: str, headers: dict | None = None, body: dict | None = None) -> Response:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in {None, 443}:
            raise SafetyError("Only HTTPS service endpoints are allowed")
        host = parsed.hostname or ""
        if host not in {"management.azure.com", "graph.microsoft.com"} and not re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", host):
            raise SafetyError("Host is not an allowed Azure service")
        payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        req_headers = dict(headers or {})
        if payload is not None:
            req_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=payload, headers=req_headers, method=method)
        try:
            result = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            result = exc
        except (urllib.error.URLError, OSError, TimeoutError, ValueError, UnicodeError, http.client.HTTPException):
            return Response(0, transport_error=True)
        try:
            with result:
                data = result.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    return Response(result.code, transport_error=True)
                return Response(result.code, data, {k.lower(): v for k, v in result.headers.items()})
        except (OSError, TimeoutError, ValueError, UnicodeError, http.client.HTTPException):
            return Response(0, transport_error=True)


def azure_cli_prefix() -> list[str]:
    """Resolve the Windows MSI launcher without ever invoking a batch parser."""
    executable = shutil.which("az")
    if not executable:
        raise SafetyError("Azure CLI is required for operator authentication")
    launcher = Path(executable)
    if launcher.suffix.lower() not in {".cmd", ".bat"}:
        return [executable]
    try:
        launcher = launcher.resolve(strict=True)
        if launcher.stat().st_size > 65536:
            raise SafetyError("Unrecognized Azure CLI Windows launcher")
        content = launcher.read_text(encoding="utf-8-sig")
        # Only recognize the MSI layout verified by its exact Python/module line.
        # The launcher itself is never run, and none of its content becomes argv.
        invocation = r'^\s*"%~dp0[\\/]?\.\.[\\/]python\.exe"\s+-IBm\s+azure\.cli\s+%\*\s*$'
        if not re.search(invocation, content, re.IGNORECASE | re.MULTILINE):
            raise SafetyError("Unrecognized Azure CLI Windows launcher")
        python = launcher.parent.parent / "python.exe"
        if not python.is_file():
            raise SafetyError("Azure CLI Windows Python executable is missing")
        return [str(python), "-IBm", "azure.cli"]
    except (OSError, UnicodeError) as exc:
        raise SafetyError("Cannot resolve a safe Azure CLI executable") from exc


class AzureCLI:
    """Operator credentials only. The frozen probe path never calls this provider."""
    def __init__(self, manifest: Manifest, subscription: str, runner: Callable = subprocess.run):
        if guid(subscription, "selected subscription") != manifest.subscription_id:
            raise SafetyError("Explicit subscription does not match manifest")
        self.manifest, self.runner = manifest, runner
        self.cache: dict[str, tuple[str, float]] = {}

    def _json(self, args: list[str]) -> dict:
        # No shell interpolation. Azure CLI output stays in process memory.
        prefix = azure_cli_prefix()
        try:
            result = self.runner([*prefix, *args, "--only-show-errors", "--output", "json"], capture_output=True, text=True, timeout=45, check=False, shell=False)
            if result.returncode:
                raise SafetyError("Azure CLI operator authentication failed")
            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                raise SafetyError("Unexpected Azure CLI response")
            return data
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise SafetyError("Cannot read Azure CLI operator credentials") from exc

    def token(self, service: str) -> str:
        m = self.manifest
        if service in self.cache and self.cache[service][1] > time.time():
            return self.cache[service][0]
        account = self._json(["account", "show", "--subscription", m.subscription_id])
        if str(account.get("id", "")).lower() != m.subscription_id or str(account.get("tenantId", "")).lower() != m.tenant_id or account.get("state") != "Enabled":
            raise SafetyError("Operator subscription/tenant is not the enabled manifest subscription")
        resource = ARM + "/" if service == "arm" else GRAPH + "/"
        result = self._json(["account", "get-access-token", "--subscription", m.subscription_id, "--resource", resource])
        token = result.get("accessToken", "")
        c = claims_from_token(token)
        allowed = ARM_AUDIENCES if service == "arm" else GRAPH_AUDIENCES
        if c.get("aud") not in allowed or str(c.get("tid", "")).lower() != m.tenant_id or c["exp"] <= time.time():
            raise SafetyError("Operator token audience, tenant, or expiry is invalid")
        if m.actor and str(c.get("oid", "")).lower() == m.actor["service_principal_object_id"]:
            raise SafetyError("Operator identity must be separate from the probe actor")
        self.cache[service] = (token, min(time.time() + 240, c["exp"] - 60))
        return token


def service_code(response: Response) -> str:
    headers = response.headers or {}
    candidate = headers.get("x-ms-error-code", "")
    if not candidate and response.body:
        try:
            error = json.loads(response.body).get("error", {})
            candidate = error.get("code", "") if isinstance(error, dict) else ""
        except (ValueError, AttributeError):
            pass
    return candidate if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", candidate) else ""


def classify(response: Response, expired: bool = False, *, auth: str | None = None) -> str:
    if expired:
        return "expired"
    if response.transport_error or response.status == 0:
        return "transport_error"
    if response.status == 429:
        return "throttled"
    if 300 <= response.status < 400:
        return "redirect_blocked"
    code = service_code(response)
    if code in {"ExpiredAuthenticationToken", "AuthenticationTokenExpired", "TokenExpired", "InvalidAuthenticationTokenLifetime"}:
        return "expired"
    if 200 <= response.status < 300:
        return "allowed"
    if response.status in {403, 409} and code in {"ScopeLocked", "ResourceLocked", "LockViolation"}:
        return "lock_denied"
    if response.status in {401, 403} and code in {"AuthorizationSourceIPMismatch", "AuthorizationProtocolMismatch", "IpAddressNotAllowed", "NetworkAccessDenied", "PublicNetworkAccessDisabled", "RequestDisallowedByNetworkSecurityPerimeter"}:
        return "network_policy_denied"
    # Storage firewall denials can use AuthorizationFailure. A generic provider
    # denial is not enough to identify an identity/credential containment event.
    if response.status == 403 and code in {"AuthorizationFailure", "AccessDenied", "Forbidden", "RequestDisallowedByPolicy"}:
        return "authorization_unattributed"
    if response.status in {401, 403} and code == "AuthenticationFailed" and auth in {"shared-key", "sas"}:
        return "credential_rejected"
    if response.status == 403 and code in {"AuthorizationFailed", "AuthorizationPermissionMismatch", "KeyBasedAuthenticationNotPermitted"}:
        return "authorization_denied"
    if response.status in {401, 403}:
        return "authentication_or_unknown_denial"
    if response.status >= 500:
        return "service_error"
    return "unknown"


class Guard:
    def __init__(self, manifest: Manifest, http: HTTP, operator: AzureCLI, *, sleeper: Callable[[float], None] | None = None):
        self.m, self.http, self.operator = manifest, http, operator
        self.last_mutation_started: str | None = None
        self.last_mutation_acknowledged: str | None = None
        self.read_transport_retries = 0
        self.sleeper = sleeper or time.sleep

    def read(self, service: str, path: str) -> Response:
        base = ARM if service == "arm" else GRAPH
        headers = {"Authorization": "Bearer " + self.operator.token(service)}
        # Ownership/metadata GETs alone may retry transient transport failures.
        # Probe requests and cloud mutations never enter this retry loop.
        for attempt in range(3):
            response = self.http.request("GET", base + path, headers)
            if not (response.transport_error or response.status == 0) or attempt == 2:
                return response
            self.read_transport_retries += 1
            self.sleeper(0.5 * (attempt + 1))
        raise AssertionError("Unreachable bounded read retry")

    @staticmethod
    def checked(response: Response) -> dict:
        if response.transport_error or response.status != 200:
            raise SafetyError(f"Ownership verification failed (HTTP {response.status})")
        return response.data()

    def ownership(self) -> None:
        m = self.m
        rg = self.checked(self.read("arm", m.rg_id + "?api-version=2021-04-01"))
        if str(rg.get("id", "")).lower() != m.rg_id.lower() or rg.get("tags", {}).get("storm3168LabId") != m.lab_id:
            raise SafetyError("Live resource-group ID or ownership tag does not match")
        storage = self.checked(self.read("arm", m.storage_id + "?api-version=2023-05-01"))
        if str(storage.get("id", "")).lower() != m.storage_id.lower() or storage.get("name") != m.storage_account:
            raise SafetyError("Live storage account is not the manifest resource")

    def actor(self) -> tuple[dict, dict]:
        if not self.m.actor:
            raise SafetyError("Recorded actor required for this action")
        a = self.m.actor
        app = self.checked(self.read("graph", f"/v1.0/applications/{a['application_object_id']}?$select=id,appId,displayName,passwordCredentials"))
        sp = self.checked(self.read("graph", f"/v1.0/servicePrincipals/{a['service_principal_object_id']}?$select=id,appId,displayName"))
        for obj, expected in [(app, a["application_object_id"]), (sp, a["service_principal_object_id"])]:
            if str(obj.get("id", "")).lower() != expected or str(obj.get("appId", "")).lower() != a["client_id"] or not str(obj.get("displayName", "")).startswith(self.m.name_prefix):
                raise SafetyError("Live actor ID, client ID, or lab display name mismatches")
        return app, sp

    def group(self) -> dict:
        if not self.m.group:
            raise SafetyError("No owned group recorded")
        result = self.checked(self.read("graph", f"/v1.0/groups/{self.m.group['object_id']}?$select=id,displayName"))
        if str(result.get("id", "")).lower() != self.m.group["object_id"] or not str(result.get("displayName", "")).startswith(self.m.name_prefix):
            raise SafetyError("Live group does not match owned group")
        return result

    def mutation(self, service: str, method: str, path: str, body: dict | None, validate: Callable | None = None) -> Response:
        # Every mutation gets fresh live guard reads. There is no fallback or retry.
        m = self.m
        allowed = {
            ("arm", "PATCH", m.storage_id + "?api-version=2023-05-01"),
            ("arm", "POST", m.storage_id + "/regenerateKey?api-version=2023-05-01"),
            ("arm", "PUT", m.lock_id + "?api-version=2016-09-01"),
            ("arm", "DELETE", m.lock_id + "?api-version=2016-09-01"),
        }
        allowed.update(("arm", "DELETE", r["id"] + "?api-version=2022-04-01") for r in m.role_assignments)
        if m.actor:
            a = m.actor
            allowed.update({
                ("graph", "PATCH", f"/v1.0/servicePrincipals/{a['service_principal_object_id']}"),
                ("graph", "PATCH", f"/v1.0/applications/{a['application_object_id']}"),
                ("graph", "POST", f"/v1.0/applications/{a['application_object_id']}/removePassword"),
            })
            if m.group:
                allowed.add(("graph", "DELETE", f"/v1.0/groups/{m.group['object_id']}/members/{a['service_principal_object_id']}/$ref"))
        if (service, method, path) not in allowed:
            raise SafetyError("Mutation is not an exact manifest-allowlisted operation")
        self.ownership()
        if validate:
            validate()
        token = self.operator.token(service)
        self.last_mutation_started = utc_now()
        response = self.http.request(method, (ARM if service == "arm" else GRAPH) + path, {"Authorization": "Bearer " + token}, body)
        self.last_mutation_acknowledged = utc_now()
        return response


ACTIONS = ("role-delete", "sp-disable", "app-deactivate", "secret-remove", "group-member-remove", "lock-readonly", "lock-cannotdelete", "lock-remove", "rotate-key1", "rotate-key2", "disable-shared-key")


def response_target(m: Manifest, action: str, assignment_id: str | None = None) -> dict:
    if action == "role-delete":
        rows = [row for row in m.role_assignments if assignment_id and row["id"].lower() == assignment_id.lower()]
        if len(rows) != 1:
            raise SafetyError("Select one exact recorded role assignment")
        row = rows[0]
        return {"role_assignment_id": row["id"], "principal_id": row["principal_id"], "scope": row["scope"],
                "role_definition_id": row["role_definition_id"],
                "access_path": "direct_role_assignment" if m.actor and row["principal_id"] == m.actor["service_principal_object_id"] else "group_role_assignment"}
    if action == "group-member-remove":
        if not m.group or not m.actor:
            raise SafetyError("Group membership action needs recorded group and actor")
        return {"group_object_id": m.group["object_id"], "member_object_id": m.actor["service_principal_object_id"], "access_path": "group_membership"}
    if action in {"sp-disable", "app-deactivate", "secret-remove"}:
        if not m.actor:
            raise SafetyError("Identity action requires a recorded actor")
        result = {"application_object_id": m.actor["application_object_id"], "service_principal_object_id": m.actor["service_principal_object_id"], "access_path": "tenant_service_principal" if action == "sp-disable" else "application"}
        if action == "secret-remove":
            result["credential_key_id"] = m.owned_secret_key_id
        return result
    if action == "none":
        return {"access_path": "no_action_control"}
    return {"storage_resource_id": m.storage_id, "access_path": "storage_account", **({"key_name": action.removeprefix("rotate-")} if action.startswith("rotate-key") else {})}


def respond(guard: Guard, action: str, *, execute: bool = False, confirm_lab_id: str | None = None, assignment_id: str | None = None) -> dict:
    m = guard.m
    retry_start = guard.read_transport_retries
    if action not in ACTIONS:
        raise SafetyError("Unknown response action")
    if execute and confirm_lab_id != m.lab_id:
        raise SafetyError("--confirm-lab-id must exactly match for mutation")
    a = m.actor or {}
    body = None
    method, service = "PATCH", "graph"
    validator: Callable | None = guard.actor
    if action == "role-delete":
        rows = [r for r in m.role_assignments if assignment_id and r["id"].lower() == assignment_id.lower()]
        if len(rows) != 1:
            raise SafetyError("Select one exact role-assignment ID from the manifest")
        row = rows[0]
        path = row["id"] + "?api-version=2022-04-01"
        method, service = "DELETE", "arm"
        def validate_assignment():
            guard.actor()
            if m.group and row["principal_id"] == m.group["object_id"]:
                guard.group()
            current = guard.checked(guard.read("arm", path))
            p = current.get("properties", {})
            expected = {"principalId": row["principal_id"], "scope": row["scope"], "roleDefinitionId": row["role_definition_id"]}
            if str(current.get("id", "")).lower() != row["id"].lower() or any(str(p.get(k, "")).lower() != v.lower() for k, v in expected.items()):
                raise SafetyError("Live assignment principal, scope, definition, or ID mismatches")
        validator = validate_assignment
    elif action in {"sp-disable", "app-deactivate", "secret-remove", "group-member-remove"}:
        if not a:
            raise SafetyError("This action requires a recorded actor")
        if action == "sp-disable":
            path, body = f"/v1.0/servicePrincipals/{a['service_principal_object_id']}", {"accountEnabled": False}
        elif action == "app-deactivate":
            path, body = f"/v1.0/applications/{a['application_object_id']}", {"isDisabled": True}
        elif action == "secret-remove":
            if not m.owned_secret_key_id:
                raise SafetyError("No exact owned secret key ID recorded")
            path, method, body = f"/v1.0/applications/{a['application_object_id']}/removePassword", "POST", {"keyId": m.owned_secret_key_id}
            def validate_secret():
                app, _ = guard.actor()
                if not any(str(c.get("keyId", "")).lower() == m.owned_secret_key_id for c in app.get("passwordCredentials", [])):
                    raise SafetyError("Owned secret key ID is absent from the owned application")
            validator = validate_secret
        else:
            if not m.group:
                raise SafetyError("No exact owned group recorded")
            path, method = f"/v1.0/groups/{m.group['object_id']}/members/{a['service_principal_object_id']}/$ref", "DELETE"
            def validate_group_member():
                guard.actor()
                guard.group()
                member = guard.checked(guard.read("graph", f"/v1.0/groups/{m.group['object_id']}/members/{a['service_principal_object_id']}"))
                if str(member.get("id", "")).lower() != a["service_principal_object_id"]:
                    raise SafetyError("Exact actor membership not present")
            validator = validate_group_member
    elif action.startswith("lock-"):
        service, method = "arm", "PUT"
        path = m.lock_id + "?api-version=2016-09-01"
        if action == "lock-remove":
            method = "DELETE"
        else:
            body = {"properties": {"level": "ReadOnly" if action == "lock-readonly" else "CanNotDelete", "notes": "storm3168LabId=" + m.lab_id}}
        def validate_lock():
            guard.actor()
            existing = guard.read("arm", path)
            if existing.status == 404 and not existing.transport_error and action != "lock-remove":
                return
            current = guard.checked(existing)
            if str(current.get("id", "")).lower() != m.lock_id.lower() or current.get("properties", {}).get("notes") != "storm3168LabId=" + m.lab_id:
                raise SafetyError("Refusing to adopt or change an unowned lock")
        validator = validate_lock
    elif action.startswith("rotate-key"):
        service, method = "arm", "POST"
        path = m.storage_id + "/regenerateKey?api-version=2023-05-01"
        body = {"keyName": action.removeprefix("rotate-")}
    else:
        service, path = "arm", m.storage_id + "?api-version=2023-05-01"
        body = {"properties": {"allowSharedKeyAccess": False}}
    result = {"schema_version": 1, "kind": "response", "action": action, "target": response_target(m, action, assignment_id), "timestamp": utc_now(), "executed": execute, "status": "planned"}
    if not execute:
        return result
    response = guard.mutation(service, method, path, body, validator)
    result.update(http_status=response.status, service_code=service_code(response), status="accepted_unverified" if not response.transport_error and 200 <= response.status < 300 else "failed", outcome=classify(response))
    result.update(request_started_at=guard.last_mutation_started, acknowledged_at=guard.last_mutation_acknowledged)
    if not response.transport_error and 200 <= response.status < 300 and not action.startswith("rotate-key"):
        verification_path = path
        if action == "sp-disable":
            verification_path += "?$select=id,accountEnabled"
        elif action == "app-deactivate":
            verification_path += "?$select=id,isDisabled"
        elif action == "secret-remove":
            verification_path = f"/v1.0/applications/{a['application_object_id']}?$select=id,passwordCredentials"
        elif action == "group-member-remove":
            verification_path = path.removesuffix("/$ref")
        verified = guard.read(service, verification_path)
        confirmed = False
        if method == "DELETE":
            confirmed = verified.status == 404 and not verified.transport_error
        elif verified.status == 200 and not verified.transport_error:
            try:
                current = verified.data()
                if action == "sp-disable":
                    confirmed = current.get("accountEnabled") is False
                elif action == "app-deactivate":
                    confirmed = current.get("isDisabled") is True
                elif action == "secret-remove":
                    confirmed = "passwordCredentials" in current and not any(str(item.get("keyId", "")).lower() == m.owned_secret_key_id for item in current["passwordCredentials"])
                elif action.startswith("lock-"):
                    confirmed = current.get("properties", {}).get("level") == body["properties"]["level"] and current.get("properties", {}).get("notes") == body["properties"]["notes"]
                elif action == "disable-shared-key":
                    confirmed = current.get("properties", {}).get("allowSharedKeyAccess") is False
            except (SafetyError, TypeError, AttributeError):
                pass
        result["postcondition_verified"] = confirmed
        if confirmed:
            result["status"] = "configuration_verified_capability_unproven"
    else:
        result["postcondition_verified"] = False
    result["guard_read_transport_retries"] = guard.read_transport_retries - retry_start
    # Do not serialize response bodies: regenerateKey/listKeys return secrets.
    return result


def signed_blob_headers(account: str, path: str, key: str, now: float) -> dict[str, str]:
    try:
        decoded = base64.b64decode(key, validate=True)
    except ValueError as exc:
        raise SafetyError("Shared Key credential is not valid base64") from exc
    if len(decoded) != 64:
        raise SafetyError("Shared Key credential has an unexpected length")
    date = formatdate(now, usegmt=True)
    standard = ["GET", "", "", "", "", "", "", "", "", "", "", "bytes=0-0"]
    canonical = "\n".join(standard) + f"\nx-ms-date:{date}\nx-ms-version:2023-11-03\n/{account}{path}"
    signature = base64.b64encode(hmac.new(decoded, canonical.encode(), hashlib.sha256).digest()).decode()
    return {"x-ms-date": date, "x-ms-version": "2023-11-03", "Authorization": f"SharedKey {account}:{signature}", "Range": "bytes=0-0"}


CAPABILITIES = ("arm-read", "arm-tag-write", "listkeys", "blob-read")


def probe_once(m: Manifest, http: HTTP, guard: Guard, capability: str, credential: str, *, auth: str = "bearer", credential_claims: dict | None = None, allow_mutation: bool = False, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    retry_start = guard.read_transport_retries
    result = {"schema_version": 1, "kind": "probe", "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(), "capability": capability, "auth": auth}
    if capability not in CAPABILITIES or auth not in {"bearer", "shared-key", "sas"}:
        raise SafetyError("Unsupported probe")
    if auth != "bearer" and capability != "blob-read":
        raise SafetyError("Shared Key and SAS are supported only for the blob-read canary")
    if auth == "bearer":
        credential_claims = validate_actor_token(credential, m, "storage" if capability == "blob-read" else "arm", now, allow_expired=True)
    elif auth == "sas":
        credential_claims = validate_sas(credential, m, now, allow_expired=True)
    if credential_claims and credential_claims["exp"] <= now:
        return {**result, "http_status": 0, "service_code": "", "outcome": "expired"}
    method, body = "GET", None
    headers = {"Authorization": "Bearer " + credential}
    if capability == "blob-read":
        if not m.blob:
            raise SafetyError("No exact canary blob recorded")
        raw_path = "/" + m.blob["container"] + "/" + m.blob["name"]
        url = f"https://{m.storage_account}.blob.core.windows.net" + urllib.parse.quote(raw_path, safe="/")
        headers.update({"x-ms-date": formatdate(now, usegmt=True), "x-ms-version": "2023-11-03", "Range": "bytes=0-0"})
        if auth == "shared-key":
            headers = signed_blob_headers(m.storage_account, raw_path, credential, now)
        elif auth == "sas":
            url += "?" + credential
            headers.pop("Authorization", None)
    else:
        url = ARM + m.storage_id
        if capability == "listkeys":
            url += "/listKeys"
            method = "POST"
        elif capability == "arm-tag-write":
            if not allow_mutation:
                raise SafetyError("Tag-write probe requires --allow-mutation")
            guard.ownership()
            guard.actor()
            # Storage Account Contributor permits storageAccounts/write, not the
            # generic Microsoft.Resources/tags API. This read/merge/write is not
            # atomic: serialize canary writers on the dedicated lab account.
            pre_read_started = utc_now()
            pre_read = http.request("GET", url + "?api-version=2023-05-01", headers)
            pre_read_received = utc_now()
            try:
                current = pre_read.data()
                tags = current.get("tags", {})
                if (pre_read.status != 200 or pre_read.transport_error
                        or str(current.get("id", "")).lower() != m.storage_id.lower()
                        or not isinstance(tags, dict)
                        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in tags.items())):
                    raise SafetyError("Canary pre-read failed")
            except SafetyError:
                return {**result, "http_status": pre_read.status, "service_code": service_code(pre_read),
                        "outcome": "precondition_failed", "probe_stage": "actor_pre_read",
                        "pre_read_outcome": classify(pre_read, auth=auth), "mutation_attempted": False,
                        "pre_read_started_at": pre_read_started, "pre_read_response_received_at": pre_read_received,
                        "guard_read_transport_retries": guard.read_transport_retries - retry_start}
            method = "PATCH"
            body = {"tags": {**tags, "storm3168Probe": str(uuid.uuid4())}}
        url += "?api-version=2023-05-01"
    result["scheduled_at"] = result["timestamp"]
    result["request_started_at"] = utc_now()
    result["timestamp"] = result["request_started_at"]
    result["mutation_attempted"] = capability == "arm-tag-write"
    response = http.request(method, url, headers, body)
    result["response_received_at"] = utc_now()
    result.update(http_status=response.status, service_code=service_code(response), outcome=classify(response, auth=auth), request_id=(response.headers or {}).get("x-ms-request-id", ""))
    if capability == "arm-tag-write" and result["outcome"] == "allowed":
        verification = http.request("GET", ARM + m.storage_id + "?api-version=2023-05-01", {"Authorization": "Bearer " + credential})
        try:
            state = verification.data()
            verified = (verification.status == 200 and not verification.transport_error
                        and str(state.get("id", "")).lower() == m.storage_id.lower()
                        and state.get("tags", {}).get("storm3168Probe") == body["tags"]["storm3168Probe"])
        except SafetyError:
            verified = False
        if not verified:
            result["outcome"] = "write_accepted_unverified"
    result["guard_read_transport_retries"] = guard.read_transport_retries - retry_start
    return result


def run_probe(m: Manifest, http: HTTP, guard: Guard, capability: str, credential: str, *, interval: float = 20, duration: float = 180, auth: str = "bearer", allow_mutation: bool = False, credential_label: str | None = None, emit: Callable[[dict], None], clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep) -> None:
    if not MIN_INTERVAL <= interval <= 300 or not 0 <= duration <= MAX_DURATION:
        raise SafetyError("Probe interval must be 5–300 seconds; duration must be 0–7200 seconds")
    if capability == "arm-tag-write" and not allow_mutation:
        raise SafetyError("Tag-write requires --allow-mutation")
    start = clock()
    if capability not in CAPABILITIES or auth not in {"bearer", "shared-key", "sas"}:
        raise SafetyError("Unsupported probe")
    c = validate_actor_token(credential, m, "storage" if capability == "blob-read" else "arm", start, allow_expired=True) if auth == "bearer" else None
    if auth == "shared-key":
        if capability != "blob-read":
            raise SafetyError("Shared Key can only probe blob-read")
        signed_blob_headers(m.storage_account, "/", credential, start)
    elif auth == "sas":
        if capability != "blob-read":
            raise SafetyError("SAS can only probe the exact blob-read canary")
        c = validate_sas(credential, m, start, allow_expired=True)
    if not c or c["exp"] > start:
        guard.ownership()
        # Identity receipt is checked once before read probes, and per mutation.
        guard.actor()
    label, run_id = guid(credential_label, "credential_label") if credential_label is not None else str(uuid.uuid4()), str(uuid.uuid4())
    emit({"schema_version": 1, "kind": "run_start", "timestamp": utc_now(), "run_id": run_id, "credential_label": label, "capability": capability, "auth": auth, "duration_seconds": duration, "interval_seconds": interval, "token_metadata": {k: c.get(k) for k in ("aud", "iat", "exp")} if c else {}})
    limit = int(duration // interval) + 1
    for n in range(limit):
        now = clock()
        if n and now > start + duration:
            break
        row = probe_once(m, http, guard, capability, credential, auth=auth, credential_claims=c, allow_mutation=allow_mutation, now=now)
        row.update(run_id=run_id, credential_label=label, elapsed_seconds=round(now - start, 3), sequence=n)
        emit(row)
        if row["outcome"] == "expired" or n + 1 == limit:
            break
        sleep(min(interval, max(0, start + duration - clock())))
    emit({"schema_version": 1, "kind": "run_end", "timestamp": utc_now(), "run_id": run_id, "status": "completed", "claim": "Observed capability only; no blanket containment claim"})


DENIAL_OUTCOMES = {"authorization_denied", "lock_denied", "credential_rejected"}


def observation_summary(probes: list[dict], *, baseline_allowed: bool = False,
                        last_allowed: float | None = None) -> dict:
    """Keep observed intervals even when later expiry/gaps censor observation."""
    counts: dict[str, int] = {}
    intervals: list[dict] = []
    segment: dict | None = None
    previous_time: float | None = None
    baseline = baseline_allowed

    def close(reason: str) -> None:
        nonlocal segment
        if segment is not None:
            segment["end_reason"] = reason
            segment["duration_right_censored"] = reason != "access_returned"
            segment["sustained"] = segment["sample_count"] >= 3 and segment["last_observed_seconds"] - segment["first_observed_seconds"] >= 60
            intervals.append(segment)
            segment = None

    for probe in probes:
        value = probe.get("elapsed_seconds")
        if type(value) not in {int, float} or not math.isfinite(value) or (previous_time is not None and value < previous_time):
            raise SafetyError("Probe times must be finite and chronological")
        previous_time = value
        outcome = str(probe.get("outcome", "unknown"))
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome in DENIAL_OUTCOMES and baseline:
            if segment is not None and segment["outcome"] != outcome:
                close("denial_type_changed")
            if segment is None:
                segment = {"outcome": outcome, "first_observed_seconds": value, "last_observed_seconds": value,
                           "last_allowed_seconds": last_allowed, "sample_count": 0}
            segment["last_observed_seconds"] = value
            segment["sample_count"] += 1
        else:
            close("access_returned" if outcome == "allowed" else "credential_expired" if outcome == "expired" else "observation_gap")
        if outcome == "allowed":
            baseline, last_allowed = True, value
    close("observation_window_ended")
    sustained = [item for item in intervals if item["sustained"]]
    final = str(probes[-1].get("outcome", "unknown")) if probes else "not_tested"
    end_reason = "credential_expired" if final == "expired" else "observation_window_ended" if final == "allowed" or final in DENIAL_OUTCOMES else "observation_gap" if probes else "not_tested"
    return {"outcomes": counts, "baseline_allowed_observed": baseline, "denial_intervals": intervals,
            "sustained_denial_observed": bool(sustained),
            "first_sustained_denial_elapsed_seconds": sustained[0]["first_observed_seconds"] if sustained else None,
            "sustained_denial_at_end": bool(sustained and intervals[-1]["sustained"] and intervals[-1]["end_reason"] == "observation_window_ended"),
            "last_observed_outcome": final, "observation_end_reason": end_reason,
            "denial_onset_right_censored": not bool(intervals) and baseline,
            "sustained_denial_confirmation_censored": bool(intervals) and not bool(sustained),
            "action_causality": "unproven",
            "interpretation": "Observed capability only. Expiry, network policy and gaps do not prove containment; an independent healthy control and action attribution still need review."}


def summarize(rows: list[dict]) -> dict:
    runs: dict[tuple, list[dict]] = {}
    for row in rows:
        if row.get("kind") == "probe":
            identity = (str(row.get("run_id", "unlabeled")), row.get("capability"), row.get("auth"), row.get("credential_label"))
            runs.setdefault(identity, []).append(row)
    output = [{"run_id": identity[0], "capability": identity[1], "auth": identity[2], "credential_label": identity[3], **observation_summary(probes)}
              for identity, probes in runs.items()]
    return {"schema_version": 1, "evidence_type": "offline_demo" if rows and all(r.get("simulated") for r in rows) else "recorded_observations", "status": "observed" if output else "not_tested", "runs": output}


def evidence_time(value: Any) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError()
        return parsed.timestamp()
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise SafetyError("Evidence timestamp must explicitly use UTC") from None


def summarize_trial(receipt: dict, baseline_rows: list[dict], action_rows: list[dict], post_rows: list[dict]) -> dict:
    """Stitch only the exact recorded credential/capability across two phases."""
    capability, auth = receipt.get("capability"), receipt.get("auth")
    label = guid(receipt.get("credential_label"), "trial credential_label")
    if capability not in CAPABILITIES or auth not in {"bearer", "shared-key", "sas"} or receipt.get("token_refresh") is not False:
        raise SafetyError("Trial identity or frozen credential contract is missing")
    action = receipt.get("action")
    if action not in (*ACTIONS, "none"):
        raise SafetyError("Unsupported recorded action")
    if action == "none":
        if action_rows:
            raise SafetyError("No-action trial unexpectedly contains an action")
        anchor = evidence_time(receipt.get("action_returned_at"))
        configuration_verified = False
    else:
        if len(action_rows) != 1 or action_rows[0].get("kind") != "response" or action_rows[0].get("action") != action or action_rows[0].get("executed") is not True:
            raise SafetyError("Trial requires its exact executed action receipt")
        actual = action_rows[0]
        if not receipt.get("action_target") or actual.get("target") != receipt["action_target"]:
            raise SafetyError("Trial action target mismatch")
        if receipt.get("access_path") != receipt["action_target"].get("access_path"):
            raise SafetyError("Trial access path mismatch")
        for key in ("action", "status", "http_status", "postcondition_verified", "request_started_at", "acknowledged_at", "target"):
            if receipt.get("action_receipt", {}).get(key) != actual.get(key):
                raise SafetyError("Trial action receipt mismatch")
        anchor = evidence_time(actual.get("acknowledged_at"))
        configuration_verified = actual.get("postcondition_verified") is True
    requested = evidence_time(receipt.get("action_requested_at"))
    if anchor < requested:
        raise SafetyError("Action timestamps are out of order")

    def phase(rows: list[dict], phase_name: str) -> list[dict]:
        starts = [row for row in rows if row.get("kind") == "run_start"]
        if len(starts) != 1:
            raise SafetyError("Trial phase requires exactly one run receipt")
        expected_run = receipt.get("probe_runs", {}).get(phase_name)
        if not expected_run or starts[0].get("run_id") != expected_run:
            raise SafetyError("Trial run receipt mismatch")
        if auth == "bearer" and (not receipt.get("frozen_token_metadata") or starts[0].get("token_metadata") != receipt["frozen_token_metadata"]):
            raise SafetyError("Trial token metadata differs between recorded phases")
        probes = []
        previous = None
        for row in rows:
            if row.get("kind") not in {"probe", "run_start"}:
                continue
            if (row.get("run_id") != expected_run or row.get("capability") != capability or
                    row.get("auth") != auth or row.get("credential_label") != label):
                raise SafetyError("Trial phase credential or capability mismatch")
            if row.get("kind") == "probe":
                timestamp = evidence_time(row.get("request_started_at", row.get("timestamp")))
                received = evidence_time(row.get("response_received_at", row.get("timestamp")))
                if received < timestamp or (previous is not None and timestamp < previous):
                    raise SafetyError("Trial phase timing is not chronological")
                if (phase_name == "baseline" and received > requested) or (phase_name == "post_action" and timestamp < anchor):
                    raise SafetyError("Probe does not belong to its recorded action phase")
                previous = timestamp
                probes.append({**row, "elapsed_seconds": timestamp - anchor})
        return probes

    baseline, post = phase(baseline_rows, "baseline"), phase(post_rows, "post_action")
    allowed = [row for row in baseline if row.get("outcome") == "allowed"]
    if len(allowed) < 2:
        raise SafetyError("Trial requires two successful baseline probes")
    result = observation_summary(post, baseline_allowed=True, last_allowed=allowed[-1]["elapsed_seconds"])
    return {"schema_version": 1, "evidence_type": "trial_observations", "status": "observed" if post else "not_tested",
            "trial_id": receipt.get("run_id"), "capability": capability, "auth": auth, "credential_label": label,
            "action": action, "access_path": receipt.get("access_path"), "action_target_recorded": bool(receipt.get("action_target")),
            "observation_window": {key: receipt.get("observation_window", {}).get(key) for key in ("mode", "duration_seconds", "maximum_seconds", "expiry_margin_seconds", "expiry_window_capped")},
            "action_configuration_verified": configuration_verified, "time_origin": "action_acknowledged_at" if action != "none" else "no_action_marker",
            **result}


def demo_rows() -> list[dict]:
    run = "simulated-rbac-example"
    return [{"schema_version": 1, "kind": "probe", "simulated": True, "run_id": run, "capability": "arm-tag-write", "elapsed_seconds": elapsed, "outcome": outcome, "http_status": 200 if outcome == "allowed" else 403} for elapsed, outcome in [(0, "allowed"), (20, "allowed"), (40, "authorization_denied"), (60, "authorization_denied"), (80, "authorization_denied"), (100, "authorization_denied")]]
