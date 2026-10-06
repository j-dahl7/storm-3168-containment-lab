"""Optional bounded storage baseline. Default is plan-only; never grants identity roles."""
from __future__ import annotations
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
import uuid

from lab_support import ROOT, az, guid, private_path, save
from telemetry import load_manifest
from stormlab.core import ARM, AzureCLI, Guard, HTTP, Manifest, Response, SafetyError, claims_from_token, service_code

API = "?api-version=2023-05-01"


def assert_storage_window(manifest: dict, state_path: str | Path, required_until_epoch: float) -> dict:
    """Validate an explicit preparation receipt, never infer actual actor access."""
    m = Manifest.from_dict(manifest)
    state = json.loads(private_path(str(state_path)).read_text(encoding="utf-8"))
    if (state.get("state_kind") != "storm3168_storage_baseline" or state.get("lab_id") != m.lab_id
            or state.get("subscription_id") != m.subscription_id or state.get("storage_id", "").lower() != m.storage_id.lower()
            or state.get("preparation_status") != "operator_seed_verified_actor_unverified"
            or state.get("settings_restored") is not False or state.get("status") != "ready_for_separate_actor_baseline"
            or not m.blob or m.blob["name"] != "baseline-" + guid(state.get("nonce", "")) + ".txt"):
        raise SafetyError("Blob trial needs the exact active nonce preparation receipt")
    prepared_path = private_path(state.get("prepared_manifest", ""))
    prepared = Manifest.from_dict(json.loads(prepared_path.read_text(encoding="utf-8")))
    if prepared.storage_id != m.storage_id or prepared.blob != m.blob:
        raise SafetyError("Prepared manifest blob differs from selected trial blob")
    deadline = datetime.fromisoformat(state["restoration_due_at"]).timestamp()
    if not isinstance(required_until_epoch, (int, float)) or not time.time() < required_until_epoch < deadline:
        raise SafetyError("Storage hold cannot cover the declared baseline/action/probe/cleanup deadline")
    return {"restoration_due_at": state["restoration_due_at"], "sha256": state["sha256"], "nonce": state["nonce"]}


def client_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Supply one explicit public IPv4 address, not a range") from None
    if address.version != 4 or not address.is_global or str(address) != value:
        raise ValueError("Supply one canonical public IPv4 address")
    return value


def account(guard: Guard) -> dict:
    guard.ownership()
    value = guard.checked(guard.read("arm", guard.m.storage_id + API))
    if (str(value.get("id", "")).lower() != guard.m.storage_id.lower()
            or value.get("tags", {}).get("storm3168LabId") != guard.m.lab_id):
        raise SafetyError("Storage account is not the tagged manifest account")
    return value


def settings(value: dict) -> dict:
    p = value.get("properties", {})
    acl = p.get("networkAcls")
    if not isinstance(acl, dict):
        raise SafetyError("Storage network policy is unavailable")
    return {"allowSharedKeyAccess": p.get("allowSharedKeyAccess"),
            "publicNetworkAccess": p.get("publicNetworkAccess"),
            "networkAcls": {k: copy.deepcopy(acl.get(k, [] if k.endswith("Rules") else None))
                            for k in ("bypass", "defaultAction", "ipRules", "virtualNetworkRules", "resourceAccessRules")}}


def initial_settings(value: dict) -> dict:
    original = settings(value)
    acl = original["networkAcls"]
    # This helper only opens the isolated foundation's closed baseline.
    # It never restores an arbitrary broad policy supplied in a state file.
    if (original["allowSharedKeyAccess"] is not False
            or original["publicNetworkAccess"] not in {"Enabled", "Disabled"}
            or acl["defaultAction"] != "Deny" or acl["bypass"] != "None"
            or any(acl[k] != [] for k in ("ipRules", "virtualNetworkRules", "resourceAccessRules"))):
        raise SafetyError("Baseline requires Shared Key off and empty Deny/None network ACLs; reconcile existing state")
    return original


def desired_settings(original: dict, ip: str, enable_shared_key: bool) -> dict:
    client_ip(ip)
    desired = copy.deepcopy(original)
    desired["publicNetworkAccess"] = "Enabled"
    desired["networkAcls"]["ipRules"] = [{"value": ip, "action": "Allow"}]
    desired["allowSharedKeyAccess"] = bool(enable_shared_key)
    return desired


def patch_settings(guard: Guard, target: dict) -> None:
    account(guard)
    response = guard.http.request("PATCH", ARM + guard.m.storage_id + API,
                                  {"Authorization": "Bearer " + guard.operator.token("arm")},
                                  {"properties": target})
    if response.transport_error or response.status not in {200, 201, 202}:
        raise SafetyError("Storage settings request failed; inspect state receipt")
    # One bounded read-back; propagation is not retried as a mutation.
    if settings(account(guard)) != target:
        raise SafetyError("Storage settings postcondition is not confirmed")


def container_preflight(guard: Guard) -> tuple[str, bool]:
    if not guard.m.blob:
        raise SafetyError("A manifest canary container is required")
    path = guard.m.storage_id + "/blobServices/default/containers/" + guard.m.blob["container"] + API
    value = guard.read("arm", path)
    if value.status == 404 and not value.transport_error:
        return path, True
    current = guard.checked(value)
    if (str(current.get("id", "")).lower() != path.split("?")[0].lower()
            or current.get("properties", {}).get("metadata", {}).get("storm3168labid") != guard.m.lab_id
            or current.get("properties", {}).get("publicAccess", "None") != "None"):
        raise SafetyError("Refusing to adopt a pre-existing canary container")
    return path, False


def create_container(guard: Guard, path: str, mode: str, credential: str) -> None:
    account(guard)
    fresh_path, absent = container_preflight(guard)
    if path != fresh_path or not absent:
        raise SafetyError("Canary container changed before creation")
    # Data-plane Create Container is create-only: an existing name fails.
    # Do not rely on an undocumented ARM If-None-Match implementation.
    data_path = "/" + guard.m.blob["container"]
    headers = blob_headers("PUT", data_path, None, mode, credential, guard.m, "", container=True)
    result = storage_request(guard, "PUT", data_path + "?restype=container", headers)
    if result.transport_error or result.status != 201:
        raise SafetyError("Canary container creation not confirmed")
    _, still_absent = container_preflight(guard)
    if still_absent:
        raise SafetyError("Created container could not be verified")


def seed_credential(guard: Guard, mode: str) -> str:
    account(guard)
    if mode == "shared-key":
        response = guard.http.request("POST", ARM + guard.m.storage_id + "/listKeys" + API,
                                      {"Authorization": "Bearer " + guard.operator.token("arm")})
        if response.transport_error or response.status != 200:
            raise SafetyError("Operator could not obtain seed key")
        keys = response.data().get("keys", [])
        selected = [k for k in keys if isinstance(k, dict) and k.get("keyName") == "key1"]
        if len(selected) != 1:
            raise SafetyError("Seed key identity is ambiguous")
        key = selected[0].get("value")
        try:
            if not isinstance(key, str) or len(base64.b64decode(key, validate=True)) != 64:
                raise ValueError()
        except ValueError:
            raise SafetyError("Invalid seed key") from None
        return key
    result = az("account", "get-access-token", "--subscription", guard.m.subscription_id,
                "--resource", "https://storage.azure.com/")
    token = result.get("accessToken", "")
    claims = claims_from_token(token)
    if (claims.get("aud") not in {"https://storage.azure.com", "https://storage.azure.com/"}
            or str(claims.get("tid", "")).lower() != guard.m.tenant_id
            or claims["exp"] <= time.time()
            or (guard.m.actor and str(claims.get("oid", "")).lower() == guard.m.actor["service_principal_object_id"])):
        raise SafetyError("Seed token must belong to an independent operator in the selected tenant")
    return token


def blob_headers(method: str, path: str, body: bytes | None, mode: str, credential: str,
                 m: Manifest, nonce: str, *, container: bool = False) -> dict:
    headers = {"x-ms-date": formatdate(usegmt=True), "x-ms-version": "2023-11-03"}
    if container:
        headers.update({"Content-Length": "0", "x-ms-meta-storm3168labid": m.lab_id})
    elif method == "PUT":
        headers.update({"x-ms-blob-type": "BlockBlob", "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(body)), "If-None-Match": "*",
                        "x-ms-meta-storm3168labid": m.lab_id, "x-ms-meta-storm3168nonce": nonce})
    if mode == "bearer":
        headers["Authorization"] = "Bearer " + credential
    else:
        standard = [method, "", "", str(len(body)) if body else "", "", headers.get("Content-Type", ""),
                    "", "", "", headers.get("If-None-Match", ""), "", ""]
        canonical_headers = "".join(k.lower() + ":" + str(headers[k]).strip() + "\n"
                                    for k in sorted(headers, key=str.lower) if k.lower().startswith("x-ms-"))
        canonical_resource = "/" + m.storage_account + path + ("\nrestype:container" if container else "")
        to_sign = "\n".join(standard) + "\n" + canonical_headers + canonical_resource
        signature = base64.b64encode(hmac.new(base64.b64decode(credential), to_sign.encode(), hashlib.sha256).digest()).decode()
        headers["Authorization"] = "SharedKey " + m.storage_account + ":" + signature
    return headers


def blob_request(guard: Guard, method: str, name: str, nonce: str, mode: str,
                 credential: str, body: bytes | None = None) -> Response:
    # Name is derived solely from the recorded nonce; no arbitrary destination accepted.
    if name != "baseline-" + guid(nonce) + ".txt" or method not in {"PUT", "GET"}:
        raise SafetyError("Unexpected seed request")
    path = "/" + guard.m.blob["container"] + "/" + name
    if method == "PUT":
        account(guard)
    headers = blob_headers(method, path, body, mode, credential, guard.m, nonce)
    return storage_request(guard, method, path, headers, body)


def storage_request(guard: Guard, method: str, path: str, headers: dict,
                    body: bytes | None = None) -> Response:
    # Internal caller supplies a manifest-derived container/blob path only.
    url = "https://" + guard.m.storage_account + ".blob.core.windows.net" + path
    request = urllib.request.Request(url, method=method, data=body, headers=headers)
    try:
        result = guard.http.opener.open(request, timeout=20)
    except urllib.error.HTTPError as exc:
        result = exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError, UnicodeError, http.client.HTTPException):
        return Response(0, transport_error=True)
    try:
        with result:
            payload = result.read(8193)
            if len(payload) > 8192:
                return Response(result.code, transport_error=True)
            return Response(result.code, payload, {k.lower(): v for k, v in result.headers.items()})
    except (OSError, TimeoutError, ValueError, UnicodeError, http.client.HTTPException):
        return Response(0, transport_error=True)


def wait_for_firewall(guard: Guard, name: str, nonce: str, mode: str, credential: str,
                      *, sleeper=time.sleep, clock=time.monotonic) -> dict:
    """Read-only readiness check against the future unique nonce path, max 90s.

    A verified not-found response establishes that the request passed the old
    restrictive firewall. Upload remains create-only and is never retried.
    """
    deadline = clock() + 90
    for attempt in range(19):
        observed = blob_request(guard, "GET", name, nonce, mode, credential)
        code = service_code(observed)
        if observed.status == 404 and code in {"BlobNotFound", "ContainerNotFound", "ResourceNotFound"} and not observed.transport_error:
            return {"readiness": "authorized_not_found", "attempts": attempt + 1}
        retryable = observed.transport_error or observed.status in {0, 429} or observed.status >= 500 or (observed.status == 403 and
                    (code == "AuthorizationFailure" or (mode == "shared-key" and code == "KeyBasedAuthenticationNotPermitted")))
        if not retryable or clock() >= deadline or attempt == 18:
            raise SafetyError("Storage firewall readiness unconfirmed; no canary write attempted")
        sleeper(min(5, max(0, deadline - clock())))
    raise SafetyError("Storage readiness deadline reached")


def restore(guard: Guard, state: dict, execute: bool) -> dict:
    if (state.get("lab_id") != guard.m.lab_id or state.get("subscription_id") != guard.m.subscription_id
            or str(state.get("storage_id", "")).lower() != guard.m.storage_id.lower()
            or state.get("state_kind") != "storm3168_storage_baseline"):
        raise SafetyError("Baseline receipt does not match the manifest")
    # Validate closed original shape, never trust an arbitrary restore payload.
    original = initial_settings({"properties": state.get("original_settings", {})})
    target = desired_settings(original, state.get("client_ip", ""), state.get("enable_shared_key") is True)
    if state.get("prepared_settings") != target:
        raise SafetyError("Baseline receipt settings mismatch")
    current = settings(account(guard))
    if current == original:
        return {"status": "original_settings_already_present", "settings_restored": True}
    # Shared Key may have been turned OFF as the measured response.
    if (current["networkAcls"] != target["networkAcls"]
            or current["publicNetworkAccess"] != target["publicNetworkAccess"]
            or current["allowSharedKeyAccess"] not in {False, target["allowSharedKeyAccess"]}):
        raise SafetyError("Concurrent configuration drift; refusing blind restore")
    if not execute:
        return {"status": "restore_planned", "settings_restored": False}
    patch_settings(guard, original)
    return {"status": "original_settings_verified", "settings_restored": True}


def restore_with_retry(guard: Guard, state: dict, *, sleeper=time.sleep, persist=lambda _: None,
                       clock=time.monotonic) -> dict:
    """Retry restoration only, with ownership/drift checks repeated on every try.

    Two minutes of backoff in total. A previous PATCH may have succeeded even if
    its reply was lost; restore() first rereads and accepts the closed policy.
    No retry relaxes the target, ownership or concurrent-drift validation.
    """
    deadline = clock() + 120
    def try_persist():
        # A broken local disk must not prevent a guarded cloud rollback.
        try:
            persist(state)
        except BaseException:
            state["receipt_persistence_unconfirmed"] = True
    for attempt, delay in enumerate((0, 2, 4, 8, 16, 30, 30, 30), 1):
        if attempt > 1 and clock() >= deadline:
            break
        if delay:
            sleeper(min(delay, max(0, deadline - clock())))
            if clock() >= deadline:
                break
        state["restoration_attempts"] = attempt
        try_persist()
        try:
            return restore(guard, state, True)
        except Exception:
            state["restoration_status"] = "retry_pending" if attempt < 8 else "manual_restore_required"
            try_persist()
    state["restoration_status"] = "manual_restore_required"
    try_persist()
    raise SafetyError("Restoration unconfirmed after bounded retries; reconcile the private receipt")


def prepare(data: dict, guard: Guard, ip: str, mode: str, enable_shared_key: bool,
            hold_seconds: int, state_path: Path, execute: bool, *, sleeper=time.sleep,
            announce=lambda x: print(json.dumps(x), flush=True), during_hold=None) -> dict:
    if type(hold_seconds) is not int or not 60 <= hold_seconds <= 7800:
        raise SafetyError("Baseline hold must be 60..7800 seconds")
    ip = client_ip(ip)
    if mode not in {"bearer", "shared-key"} or (mode == "shared-key" and not enable_shared_key):
        raise SafetyError("Shared-key seeding requires explicit --enable-shared-key")
    original = initial_settings(account(guard))
    container_path, absent = container_preflight(guard)
    if not execute:
        return {"mode": "plan", "cloud_mutations": False, "hold_seconds": hold_seconds,
                "network": "single explicitly supplied IPv4; default Deny; no broad range",
                "enable_shared_key": enable_shared_key, "seed_auth": mode,
                "create_container": absent, "after": "restore original closed settings; retain recorded canary"}
    if state_path.exists():
        raise SafetyError("Receipt already exists; use restore to reconcile")
    nonce = str(uuid.uuid4())
    body = ("storm3168 synthetic canary\nnonce=" + nonce + "\n").encode()
    name = "baseline-" + nonce + ".txt"
    prepared_manifest_path = private_path(str(state_path.with_name(state_path.stem + "-manifest.json")))
    if prepared_manifest_path.exists():
        raise SafetyError("Prepared manifest already exists")
    modified = copy.deepcopy(data)
    modified["blob"] = {"container": guard.m.blob["container"], "name": name}
    state = {"schema_version": 1, "state_kind": "storm3168_storage_baseline",
             "lab_id": guard.m.lab_id, "subscription_id": guard.m.subscription_id,
             "storage_id": guard.m.storage_id, "original_settings": original,
             "prepared_settings": desired_settings(original, ip, enable_shared_key),
             "client_ip": ip, "enable_shared_key": enable_shared_key,
             "hold_seconds": hold_seconds,
             "seed_auth": mode, "nonce": nonce, "blob_name": name,
             "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
             "prepared_manifest": str(prepared_manifest_path.relative_to(ROOT)),
             "status": "planned", "preparation_status": "not_completed", "settings_restored": False,
             "created_at": datetime.now(timezone.utc).isoformat()}
    save(state_path, state)  # Write rollback receipt before the first cloud mutation.
    credential = ""
    try:
        patch_settings(guard, state["prepared_settings"])
        state["status"] = "network_prepared"
        save(state_path, state)
        credential = seed_credential(guard, mode)
        state["firewall_readiness"] = wait_for_firewall(guard, name, nonce, mode, credential, sleeper=sleeper)
        save(state_path, state)
        if absent:
            create_container(guard, container_path, mode, credential)
            state["container_created"] = True
            save(state_path, state)
        uploaded = blob_request(guard, "PUT", name, nonce, mode, credential, body)
        if uploaded.transport_error or uploaded.status != 201:
            raise SafetyError("Canary upload failed; no access baseline established")
        observed = blob_request(guard, "GET", name, nonce, mode, credential)
        if (observed.transport_error or observed.status != 200
                or hashlib.sha256(observed.body).hexdigest() != state["sha256"]
                or (observed.headers or {}).get("x-ms-meta-storm3168nonce") != nonce
                or (observed.headers or {}).get("x-ms-meta-storm3168labid") != guard.m.lab_id):
            raise SafetyError("Canary read/checksum/nonce not verified")
        credential = ""
        save(prepared_manifest_path, modified)
        hold_started_at = datetime.now(timezone.utc)
        state.update(status="ready_for_separate_actor_baseline",
                     preparation_status="operator_seed_verified_actor_unverified",
                     hold_started_at=hold_started_at.isoformat(),
                     restoration_due_at=(hold_started_at + timedelta(seconds=hold_seconds)).isoformat())
        save(state_path, state)
        announce({"status": state["status"], "manifest": state["prepared_manifest"],
                  "hold_seconds": hold_seconds, "actor_access_verified": False,
                  "restoration_due_at": state["restoration_due_at"],
                  "credentials_exported": False, "restore_on_exit": True})
        if during_hold is not None:
            result = during_hold(modified, state)
            if datetime.now(timezone.utc) >= hold_started_at + timedelta(seconds=hold_seconds):
                raise SafetyError("Embedded trial exceeded its declared storage hold; results are incomplete")
            return result
        # Other terminal/process performs the selected frozen-credential trial.
        # This process never refreshes or exports that trial credential.
        for _ in range(hold_seconds):
            sleeper(1)
        return {"status": "hold_completed", "actor_access_verified": False}
    finally:
        credential = ""
        try:
            result = restore_with_retry(guard, state, sleeper=sleeper, persist=lambda value: save(state_path, value))
            state["restoration_status"] = result["status"]
            state["settings_restored"] = result["settings_restored"]
            state["status"] = "restored_after_seed" if state["preparation_status"] == "operator_seed_verified_actor_unverified" else "restored_after_incomplete_preparation"
        except BaseException:
            state.update(status="manual_restore_required", settings_restored=False)
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        save(state_path, state)
        if not state["settings_restored"]:
            raise SafetyError("Original settings restoration is unconfirmed; use the saved receipt and reconcile")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "restore"])
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--state", required=True, help="Private non-secret rollback receipt")
    parser.add_argument("--client-ip", type=client_ip)
    parser.add_argument("--seed-auth", choices=["bearer", "shared-key"], default="bearer")
    parser.add_argument("--enable-shared-key", action="store_true")
    parser.add_argument("--hold-seconds", type=int, default=600,
                        help="Explicit 60..7800-second hold; include actor baseline, action, full probe and cleanup margin (default 600)")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-lab-id", type=guid)
    args = parser.parse_args(argv)
    try:
        path = private_path(args.state)
        data, model = load_manifest(args.manifest, args.subscription)
        if args.execute and args.confirm_lab_id != model.lab_id:
            raise SafetyError("Execution requires exact lab confirmation")
        guard = Guard(model, HTTP(), AzureCLI(model, args.subscription))
        if args.action == "restore":
            state = json.loads(path.read_text(encoding="utf-8"))
            result = restore_with_retry(guard, state, persist=lambda value: save(path, value)) if args.execute else restore(guard, state, False)
            if args.execute:
                state.update(result)
                save(path, state)
        else:
            if not args.client_ip:
                raise SafetyError("Preparation requires explicit --client-ip")
            result = prepare(data, guard, args.client_ip, args.seed_auth,
                             args.enable_shared_key, args.hold_seconds, path, args.execute)
        print(json.dumps(result))
        return 0
    except (SafetyError, RuntimeError, ValueError, OSError, KeyError, TypeError):
        print("Storage baseline stopped; inspect the private receipt and bounded restoration status.", file=sys.stderr)
        # Paths/IDs only; never echo service bodies, credentials or a SAS URL.
        print("Recovery command (after checking receipt): python scripts/storage_baseline.py restore"
              + " --manifest " + json.dumps(args.manifest) + " --subscription " + args.subscription
              + " --state " + json.dumps(args.state) + " --execute --confirm-lab-id LAB_UUID_FROM_RECEIPT", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; inspect the private receipt for restoration status.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
