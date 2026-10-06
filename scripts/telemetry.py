"""Read-only, bounded provider telemetry export. No diagnostic settings are changed."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

from lab_support import ROOT, assert_context, assert_owned, az, guid, private_path
sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import Manifest, SafetyError, load_json

MAX_WINDOW = timedelta(hours=24)
MAX_ROWS = 5000
WORKSPACE_RE = re.compile(
    r"/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([A-Za-z0-9_-]{1,90})"
    r"/providers/Microsoft\.OperationalInsights/workspaces/([A-Za-z0-9-]{3,63})",
    re.IGNORECASE,
)
TIME_FIELDS = {"TimeGenerated", "EventSubmissionTimestamp", "WorkspaceIngestionTime", "CreatedDateTime"}
UUID_FIELDS = {"ActorObjectId", "EventDataId", "OperationId", "CorrelationId", "ServicePrincipalId", "AppId", "AADTenantId", "Id"}
STATUS_FIELDS = {"ActivityStatusValue", "ActivitySubstatusValue", "ResultType", "ResultSignature", "ConditionalAccessStatus", "ClientCredentialType"}
ALLOWED_COLUMNS = TIME_FIELDS | UUID_FIELDS | STATUS_FIELDS | {"ResourceId", "OperationNameValue", "CallerIpAddress", "IPAddress", "ResourceDisplayName"}


def utc(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)", value
    ):
        raise ValueError("Timestamp must explicitly use UTC in ISO 8601 format")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid UTC timestamp") from None
    return parsed


def time_window(start: str, end: str, now: datetime | None = None) -> tuple[str, str]:
    left, right = utc(start), utc(end)
    if not left < right or right - left > MAX_WINDOW:
        raise ValueError("Query window must be positive and at most 24 hours")
    if right > (now or datetime.now(timezone.utc)) + timedelta(minutes=5):
        raise ValueError("Query end cannot be in the future")
    return left.isoformat(), right.isoformat()


def load_manifest(path: str, subscription: str) -> tuple[dict, Manifest]:
    selected = private_path(path)
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    if not any(line.strip() in {"private/", "/private/"} for line in ignore.splitlines()):
        raise ValueError("private/ must be ignored")
    data = load_json(selected)
    manifest = Manifest.from_dict(data)
    if guid(subscription) != manifest.subscription_id:
        raise ValueError("Explicit subscription must match manifest")
    assert_owned(data, subscription)
    return data, manifest


def workspace_id(manifest: Manifest) -> str:
    return manifest.rg_id + "/providers/Microsoft.OperationalInsights/workspaces/" + manifest.workspace_name


def resolve_workspace(data: dict, manifest: Manifest, selected_id: str, *, owned: bool) -> dict:
    match = WORKSPACE_RE.fullmatch(selected_id) if isinstance(selected_id, str) else None
    if not match:
        raise ValueError("An exact canonical workspace resource ID is required")
    selected_sub = guid(match.group(1))
    if owned and selected_id.lower() != workspace_id(manifest).lower():
        raise ValueError("Workspace is not the manifest workspace")
    # Existing identity workspace may be in another subscription, but never another tenant.
    assert_context(selected_sub, manifest.tenant_id)
    assert_owned(data, manifest.subscription_id)
    live = az("monitor", "log-analytics", "workspace", "show",
              "--ids", selected_id, "--subscription", selected_sub)
    if not isinstance(live, dict) or str(live.get("id", "")).lower() != selected_id.lower():
        raise RuntimeError("Live workspace resource identity mismatch")
    if owned and (not isinstance(live.get("tags"), dict)
                  or live["tags"].get("storm3168LabId") != manifest.lab_id):
        raise RuntimeError("Owned workspace tag mismatch")
    customer = guid(live.get("customerId", ""))
    return {"resource_id": selected_id, "customer_id": customer, "subscription_id": selected_sub,
            "selection": "owned_manifest_workspace" if owned else "explicit_existing_identity_workspace",
            "ownership_required": owned, "diagnostic_settings_changed": False}


def activity_query(manifest: Manifest, start: str, end: str, max_rows: int) -> str:
    return (
        f'let Scope=tolower("{manifest.rg_id}");\n'
        "AzureActivity\n"
        '| extend ResourceId = coalesce(tostring(column_ifexists("_ResourceId", "")), tostring(column_ifexists("ResourceId", "")))\n'
        f"| where TimeGenerated between (datetime({start}) .. datetime({end}))\n"
        "| where tolower(ResourceId) == Scope or tolower(ResourceId) startswith strcat(Scope, '/')\n"
        '| extend ActorObjectId=tolower(coalesce(tostring(Claims_d["http://schemas.microsoft.com/identity/claims/objectidentifier"]), tostring(Claims_d.oid), Caller)), WorkspaceIngestionTime=ingestion_time()\n'
        "| project TimeGenerated, EventSubmissionTimestamp, WorkspaceIngestionTime, ActorObjectId,\n"
        "    CallerIpAddress, ResourceId, OperationNameValue, ActivityStatusValue,\n"
        "    ActivitySubstatusValue, EventDataId, OperationId, CorrelationId\n"
        "| order by TimeGenerated asc\n"
        f"| take {max_rows + 1}"
    )


def canonical_resource_id(row: dict) -> str:
    """Standard _ResourceId wins; only an absent/null/empty value falls back.

    Never OR both scope predicates: a foreign standard ID must not be rescued by
    a conflicting legacy canary ID. Non-string identifiers are invalid metadata.
    """
    for name in ("_ResourceId", "ResourceId"):
        value = row.get(name)
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            raise RuntimeError("Provider resource identifier is not a string")
        return value
    return ""


def signin_query(manifest: Manifest, start: str, end: str, max_rows: int) -> str:
    if not manifest.actor:
        raise ValueError("A recorded actor is required for sign-in queries")
    return (
        "AADServicePrincipalSignInLogs\n"
        f"| where TimeGenerated between (datetime({start}) .. datetime({end}))\n"
        f'| where ServicePrincipalId =~ "{manifest.actor["service_principal_object_id"]}" and AADTenantId =~ "{manifest.tenant_id}"\n'
        "| extend WorkspaceIngestionTime=ingestion_time()\n"
        "| project TimeGenerated, CreatedDateTime, WorkspaceIngestionTime, ServicePrincipalId,\n"
        "    AADTenantId, AppId, IPAddress, ResourceDisplayName, ClientCredentialType,\n"
        "    ResultType, ResultSignature, ConditionalAccessStatus, CorrelationId, Id\n"
        "| order by TimeGenerated asc\n"
        f"| take {max_rows + 1}"
    )


def result_rows(result: object) -> list[dict]:
    if isinstance(result, list) and all(isinstance(row, dict) for row in result):
        return result
    # Also accept the documented Log Analytics REST-style result envelope.
    if isinstance(result, dict) and "error" not in result and isinstance(result.get("tables"), list):
        primary = [t for t in result["tables"] if isinstance(t, dict) and t.get("name") == "PrimaryResult"]
        if len(primary) != 1:
            raise RuntimeError("Query result has no unique PrimaryResult")
        table = primary[0]
        columns, values = table.get("columns"), table.get("rows")
        if not isinstance(columns, list) or not isinstance(values, list):
            raise RuntimeError("Malformed query result")
        if not all(isinstance(c, dict) and isinstance(c.get("name"), str) for c in columns):
            raise RuntimeError("Malformed query columns")
        names = [c["name"] for c in columns]
        if len(set(names)) != len(names) or not all(isinstance(r, list) and len(r) == len(names) for r in values):
            raise RuntimeError("Malformed query rows")
        return [dict(zip(names, row)) for row in values]
    raise RuntimeError("Unsupported or incomplete query response")


def sanitize_row(row: dict) -> dict:
    """Allow known scalar metadata only; drop free-form payloads and unsafe field values."""
    clean, redacted = {}, []
    for key in sorted(ALLOWED_COLUMNS & row.keys()):
        value = row[key]
        if value is None or value == "":
            clean[key] = value
            continue
        try:
            if key in TIME_FIELDS:
                clean[key] = utc(value).isoformat()
            elif key in UUID_FIELDS:
                clean[key] = guid(value)
            elif key in {"CallerIpAddress", "IPAddress"}:
                clean[key] = str(ipaddress.ip_address(value))
            elif key == "ResourceId":
                if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]{1,1024}", value) or ".." in value:
                    raise ValueError()
                clean[key] = value
            elif key == "OperationNameValue":
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,256}", value):
                    raise ValueError()
                clean[key] = value
            else:
                # No URLs, query strings, emails, JSON or raw remote error bodies.
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_ .():/-]{1,128}", value):
                    raise ValueError()
                clean[key] = value
        except (ValueError, TypeError, AttributeError):
            clean[key] = None
            redacted.append(key)
    if redacted:
        clean["RedactedFields"] = redacted
    return clean


def query_source(data: dict, manifest: Manifest, selection: dict, source: str,
                 start: str, end: str, max_rows: int) -> dict:
    if source not in {"AzureActivity", "AADServicePrincipalSignInLogs"}:
        raise ValueError("Unsupported provider source")
    assert_owned(data, manifest.subscription_id)
    # Resolve AGAIN immediately before the query; a caller-supplied customer ID is never used.
    checked = resolve_workspace(data, manifest, selection["resource_id"], owned=selection["ownership_required"])
    if checked["customer_id"] != selection["customer_id"]:
        raise RuntimeError("Workspace customer ID changed")
    query = activity_query(manifest, start, end, max_rows) if source == "AzureActivity" else signin_query(manifest, start, end, max_rows)
    raw = az("monitor", "log-analytics", "query", "--workspace", checked["customer_id"],
             "--analytics-query", query, "--timespan", start + "/" + end,
             "--subscription", checked["subscription_id"])
    rows = result_rows(raw)
    if len(rows) > max_rows + 1:
        raise RuntimeError("Query response exceeds the declared row bound")
    for row in rows:
        if source == "AzureActivity":
            resource = canonical_resource_id(row)
            scope = manifest.rg_id.lower()
            if not isinstance(resource, str) or not (resource.lower() == scope or resource.lower().startswith(scope + "/")):
                raise RuntimeError("Query returned an out-of-scope resource")
            # The query projects this alias; also enforce it if a provider/mock
            # returns additional raw fields. The public evidence schema stays
            # ResourceId, and sanitize_row drops the raw _ResourceId column.
            row["ResourceId"] = resource
        else:
            principal, tenant = row.get("ServicePrincipalId"), row.get("AADTenantId")
            if (not isinstance(principal, str) or not isinstance(tenant, str)
                    or principal.lower() != manifest.actor["service_principal_object_id"]
                    or tenant.lower() != manifest.tenant_id):
                raise RuntimeError("Query returned an out-of-scope identity")
    return {"source": source, "status": "query_completed" if rows else "query_completed_no_rows",
            "selection": checked, "row_limit": max_rows, "truncated": len(rows) > max_rows,
            "rows": [sanitize_row(r) for r in rows[:max_rows]],
            "observed_at": datetime.now(timezone.utc).isoformat()}


def collect(data: dict, manifest: Manifest, start: str, end: str, *, max_rows: int = 1000,
            include_signins: bool = False, identity_workspace_id: str | None = None) -> dict:
    start, end = time_window(start, end)
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
        raise ValueError("Row limit must be 1..5000")
    if (include_signins or identity_workspace_id) and not manifest.actor:
        raise ValueError("Sign-in collection requires a recorded actor")
    owned = resolve_workspace(data, manifest, workspace_id(manifest), owned=True)
    sources = [("AzureActivity", owned)]
    if include_signins or identity_workspace_id:
        identity = resolve_workspace(data, manifest, identity_workspace_id, owned=False) if identity_workspace_id else owned
        sources.append(("AADServicePrincipalSignInLogs", identity))
    result = {"schema_version": 1, "kind": "provider_telemetry", "mode": "live_read_only",
              "cloud_mutations": False, "start_utc": start, "end_utc": end, "sources": [],
              "limitations": ["AzureActivity generally omits reads.",
                             "Sign-in records do not represent every resource request.",
                             "Empty results do not prove failed access or complete collection.",
                             "No tenant diagnostic settings are configured by this script."]}
    for source, selection in sources:
        try:
            result["sources"].append(query_source(data, manifest, selection, source, start, end, max_rows))
        except RuntimeError:
            result["sources"].append({"source": source, "selection": selection, "status": "query_failed",
                                      "rows": [], "error": "Read-only query failed; check table availability, extension, access and source export."})
    result["status"] = "partial" if any(s["status"] == "query_failed" for s in result["sources"]) else "collection_completed"
    return result


def write_private(path: str, value: dict) -> Path:
    destination = private_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination = private_path(str(destination))
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")
    return destination


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--start", required=True, help="Explicit UTC ISO timestamp")
    parser.add_argument("--end", required=True, help="Explicit UTC ISO timestamp, <=24h after start")
    parser.add_argument("--max-rows", type=int, default=1000)
    parser.add_argument("--include-signins", action="store_true")
    parser.add_argument("--identity-workspace-resource-id", help="Explicit existing same-tenant workspace, read only")
    parser.add_argument("--output", required=True, help="New JSON file inside ignored private/")
    args = parser.parse_args(argv)
    try:
        destination = private_path(args.output)
        if destination.exists():
            raise ValueError("Refusing to overwrite evidence")
        time_window(args.start, args.end)
        # Disable dynamic extension installation for this process only.
        os.environ["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
        data, manifest = load_manifest(args.manifest, args.subscription)
        az("extension", "show", "--name", "log-analytics")
        result = collect(data, manifest, args.start, args.end, max_rows=args.max_rows,
                         include_signins=args.include_signins,
                         identity_workspace_id=args.identity_workspace_resource_id)
        write_private(args.output, result)
        print(json.dumps({"status": result["status"], "rows": sum(len(s["rows"]) for s in result["sources"]),
                          "cloud_mutations": False, "private_evidence_written": True}))
        return 2 if result["status"] == "partial" else 0
    except (SafetyError, RuntimeError, ValueError, OSError, KeyError, TypeError):
        print("Telemetry stopped: verify private paths, explicit scope, ownership, UTC window, CLI extension and read permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
