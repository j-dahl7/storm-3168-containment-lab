"""Bounded operator-only Log Analytics JSON POST; query text never enters argv."""
from __future__ import annotations
import hashlib
import http.client
import json
import re
import time
import urllib.error
import urllib.request

from lab_support import assert_context, az, guid
from telemetry import resolve_workspace, workspace_id, time_window
from stormlab.core import Manifest, NoRedirect, SafetyError, claims_from_token

ENDPOINT = "https://api.loganalytics.azure.com/v1/workspaces/"
RESOURCE = "https://api.loganalytics.io"
MAX_QUERY_BYTES = 1_000_000
MAX_RESULT_BYTES = 5_000_000


class QueryError(RuntimeError):
    def __init__(self, kind: str, status: int = 0, codes: tuple[str, ...] = ()):
        self.kind, self.status, self.codes = kind, status, codes
        super().__init__(f"Log Analytics query {kind}; HTTP {status}; codes={','.join(codes)}")


def error_codes(raw: bytes) -> tuple[str, ...]:
    """Never return provider messages, query fragments, tokens or response rows."""
    try:
        current = json.loads(raw).get("error", {})
    except (ValueError, AttributeError, UnicodeError):
        return ()
    codes = []
    for _ in range(5):
        if not isinstance(current, dict):
            break
        code = current.get("code")
        if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", code):
            codes.append(code)
        current = current.get("innererror", current.get("innerError", {}))
    return tuple(codes)


def query_owned_workspace(data: dict, model: Manifest, query: str, start: str, end: str,
                          *, opener=None) -> tuple[dict, dict]:
    """Resolve the exact owned workspace, then submit one read-only query."""
    if not isinstance(query, str) or not 1 <= len(query.encode("utf-8")) <= MAX_QUERY_BYTES or query.lstrip().startswith("."):
        raise SafetyError("Query must be bounded KQL, not a management command")
    left, right = time_window(start, end)
    selected = resolve_workspace(data, model, workspace_id(model), owned=True)
    customer = guid(selected["customer_id"])
    if (selected["resource_id"].lower() != workspace_id(model).lower() or
            selected["subscription_id"] != model.subscription_id or selected.get("ownership_required") is not True):
        raise SafetyError("Query workspace does not match the owned manifest")
    context = assert_context(model.subscription_id, model.tenant_id)
    if context.get("state") != "Enabled":
        raise SafetyError("Operator subscription is not enabled")
    acquired = az("account", "get-access-token", "--subscription", model.subscription_id, "--resource", RESOURCE)
    token = acquired.get("accessToken", "")
    claims = claims_from_token(token)
    if (str(claims.get("tid", "")).lower() != model.tenant_id or
            claims.get("aud") not in {RESOURCE, RESOURCE + "/"} or claims["exp"] <= time.time() or
            not claims.get("oid") or
            (model.actor and str(claims.get("oid", "")).lower() == model.actor["service_principal_object_id"])):
        raise SafetyError("Operator query token tenant, audience, expiry or identity is invalid")
    payload = json.dumps({"query": query, "timespan": left + "/" + right}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    metadata = {"transport": "direct_json_post", "submitted_query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "submitted_query_utf8_bytes": len(query.encode("utf-8")), "request_body_sha256": hashlib.sha256(payload).hexdigest(),
                "request_attempts": 1, "workspace_verified": True}
    request = urllib.request.Request(ENDPOINT + customer + "/query", data=payload, method="POST",
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"})
    transport = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        try:
            result = transport.open(request, timeout=90)
        except urllib.error.HTTPError as exc:
            result = exc
        with result:
            status = result.code
            raw = result.read(MAX_RESULT_BYTES + 1)
        if len(raw) > MAX_RESULT_BYTES:
            raise QueryError("response_too_large", status)
        if status != 200:
            raise QueryError("rejected", status, error_codes(raw))
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise QueryError("invalid_json", status) from None
        if not isinstance(body, dict) or "error" in body or not isinstance(body.get("tables"), list):
            raise QueryError("partial_or_invalid_result", status, error_codes(raw))
        return body, {**metadata, "http_status": status}
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException, UnicodeError):
        raise QueryError("transport_error") from None
