"""Guarded six-channel storage cohorts. Offline plan by default; no secret files.

One response per fresh cohort; resume starts a NEW cohort after read-only guards.
The runner never replays a possibly accepted rotation or refreshes probe secrets.
"""
from __future__ import annotations
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
import hashlib
import hmac
import json
from pathlib import Path
import sys
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from lab_support import ROOT, private_path, save, assert_owned
sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import (ARM, AzureCLI, Guard, HTTP, Manifest, SafetyError,
                          load_json, respond, run_probe, signed_blob_headers, validate_actor_token, validate_sas)
from stormlab.__main__ import append_jsonl
from configure_access import DATA_READER, role_definition_id, verify_assignment, inventory
from live_trial import request, graph_token, CredentialHTTPError
from phase3_link import link
from storage_baseline import (API, account, client_ip, initial_settings, prepare, settings,
                              storage_request, assert_storage_window)
from trial_state import begin_trial, finish_trial, assert_idle

VERSION = "2023-11-03"
CHANNELS = ("key1", "key2", "service-sas-key1", "account-sas-key2", "user-delegation-sas", "entra-blob")
ACTIONS = ("rotate-key1", "rotate-key2", "disable-shared-key")


def stamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(key: str, parts: list[str]) -> str:
    decoded = base64.b64decode(key, validate=True)
    if len(decoded) != 64:
        raise SafetyError("Unexpected signing key shape")
    return base64.b64encode(hmac.new(decoded, "\n".join(parts).encode(), hashlib.sha256).digest()).decode()


def make_sas(m: Manifest, kind: str, key: str, start: str, end: str, ip: str, delegation: dict | None = None) -> str:
    client_ip(ip)
    if not m.blob:
        raise SafetyError("Exact canary blob is required")
    fields = {"sp": "r", "st": start, "se": end, "sip": ip, "spr": "https", "sv": VERSION}
    resource = "/blob/" + m.storage_account + "/" + m.blob["container"] + "/" + m.blob["name"]
    if kind == "account":
        fields.update(ss="b", srt="o")
        parts = [m.storage_account, "r", "b", "o", start, end, ip, "https", VERSION, "", ""]
    elif kind == "service":
        fields["sr"] = "b"
        parts = ["r", start, end, resource, "", ip, "https", VERSION, "b", "", "", "", "", "", "", ""]
    elif kind == "user-delegation" and delegation:
        mapping = {"skoid": "SignedOid", "sktid": "SignedTid", "skt": "SignedStart", "ske": "SignedExpiry", "sks": "SignedService", "skv": "SignedVersion"}
        fields.update({k: delegation[v] for k, v in mapping.items()})
        fields["sr"] = "b"
        parts = ["r", start, end, resource, *[fields[k] for k in mapping], "", "", "", ip, "https", VERSION, "b", "", "", "", "", "", "", ""]
    else:
        raise SafetyError("Unsupported SAS constructor")
    fields["sig"] = sign(key, parts)
    return urllib.parse.urlencode(fields)


def verify_data_control(data: dict, guard: Guard) -> None:
    m = guard.m
    matches = [r for r in m.role_assignments if r["role_definition_id"].lower() == role_definition_id(m, DATA_READER).lower()]
    if len(matches) != 1 or not m.actor or matches[0]["scope"].lower() != m.storage_id.lower() or matches[0]["principal_id"] != m.actor["service_principal_object_id"]:
        raise SafetyError("Exactly one recorded actor/account Blob Data Reader assignment is required")
    guard.ownership()
    app, _ = guard.actor()
    if app.get("passwordCredentials") != []:
        raise SafetyError("Fresh storage cohorts require no pre-existing application password credentials")
    verify_assignment(guard, matches[0])
    if inventory(guard)["unexpected_potential_writer_paths"]:
        raise SafetyError("Unexpected actor/group permission path; cohort refused")
    sp = guard.checked(guard.read("graph", "/v1.0/servicePrincipals/" + m.actor["service_principal_object_id"] + "?$select=id,appId,accountEnabled"))
    if sp.get("id") != m.actor["service_principal_object_id"] or sp.get("appId") != m.actor["client_id"] or sp.get("accountEnabled") is not True:
        raise SafetyError("Recorded actor must be enabled before storage trials")


def get_keys(guard: Guard) -> dict:
    account(guard)
    response = guard.http.request("POST", ARM + guard.m.storage_id + "/listKeys" + API,
                                  {"Authorization": "Bearer " + guard.operator.token("arm")})
    if response.transport_error or response.status != 200:
        raise SafetyError("Cannot acquire copied canary keys")
    rows = response.data().get("keys", [])
    keys = {}
    for name in ("key1", "key2"):
        matches = [r for r in rows if r.get("keyName") == name]
        if len(matches) != 1 or len(base64.b64decode(matches[0]["value"], validate=True)) != 64:
            raise SafetyError("Ambiguous account key material")
        keys[name] = matches[0]["value"]
    return keys


def get_delegation(guard: Guard, token: str, start: str, end: str) -> dict:
    account(guard)
    claims = validate_actor_token(token, guard.m, "storage")
    body = ("<KeyInfo><Start>" + start + "</Start><Expiry>" + end + "</Expiry></KeyInfo>").encode()
    response = storage_request(guard, "POST", "/?restype=service&comp=userdelegationkey",
        {"Authorization": "Bearer " + token, "x-ms-date": formatdate(usegmt=True), "x-ms-version": VERSION,
         "Content-Type": "application/xml", "Content-Length": str(len(body))}, body)
    if response.transport_error or response.status != 200:
        raise SafetyError("Actor delegation-key request failed")
    root = ET.fromstring(response.body)
    values = {x.tag: x.text for x in root}
    required = {"SignedOid", "SignedTid", "SignedStart", "SignedExpiry", "SignedService", "SignedVersion", "Value"}
    if (root.tag != "UserDelegationKey" or set(values) != required or len(root) != len(required)
            or values["SignedOid"] != guard.m.actor["service_principal_object_id"]
            or values["SignedTid"] != guard.m.tenant_id or values["SignedService"] != "b"
            or values["SignedVersion"] != VERSION):
        raise SafetyError("Delegation key identity/contract differs from the actor")
    return values


def full_read(guard: Guard, auth: str, credential: str, expected: dict) -> dict:
    m = guard.m
    raw_path = "/" + m.blob["container"] + "/" + m.blob["name"]
    headers = {"x-ms-version": VERSION, "x-ms-date": formatdate(usegmt=True)}
    path = raw_path
    if auth == "shared-key":
        # Full-body checksum verification uses the shared full-GET signer.
        from storage_baseline import blob_headers
        headers = blob_headers("GET", raw_path, None, auth, credential, m, expected["nonce"])
    elif auth == "bearer":
        validate_actor_token(credential, m, "storage")
        headers["Authorization"] = "Bearer " + credential
    elif auth == "sas":
        validate_sas(credential, m, time.time())
        path += "?" + credential
    else:
        raise SafetyError("Unexpected checksum authentication")
    response = storage_request(guard, "GET", path, headers)
    valid = (response.status == 200 and not response.transport_error
             and hashlib.sha256(response.body).hexdigest() == expected["sha256"]
             and (response.headers or {}).get("x-ms-meta-storm3168nonce") == expected["nonce"]
             and (response.headers or {}).get("x-ms-meta-storm3168labid") == m.lab_id)
    return {"verified": valid, "http_status": response.status, "sha256_matches": valid}


def parallel_phase(m: Manifest, channels: dict, folder: Path, phase: str, duration: int, interval: int,
                   *, http_factory=HTTP, operator_factory=AzureCLI) -> dict:
    stop = threading.Event()
    output = {}
    def run(name, channel):
        rows = []
        directory = private_path(str(folder / name))
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / (phase + ".jsonl")
        if path.exists():
            raise SafetyError("Refusing to overwrite a channel phase")
        http = http_factory()
        guard = Guard(m, http, operator_factory(m, m.subscription_id))
        def emit(row):
            append_jsonl(path, row)
            rows.append(row)
        def sleep(seconds):
            if stop.wait(seconds):
                raise InterruptedError("Channel cancelled")
        try:
            run_probe(m, http, guard, "blob-read", channel["credential"], auth=channel["auth"],
                      duration=duration, interval=interval, credential_label=channel["label"], emit=emit, sleep=sleep)
            return rows
        finally:
            output[name] = rows
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(run, name, channel) for name, channel in channels.items()]
        try:
            for future in as_completed(futures):
                future.result()
        except BaseException:
            stop.set()
            raise
    return output


def source_hashes() -> dict:
    paths = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def run_cohort(data: dict, guard: Guard, folder: Path, action: str, ip: str, duration: int, interval: int) -> dict:
    m = guard.m
    trial_id = folder.name
    receipt = {"schema_version": 1, "cohort_id": trial_id, "action": action, "status": "starting",
               "lab_id": m.lab_id, "subscription_id": m.subscription_id, "storage_id": m.storage_id,
               "source_hashes": source_hashes(), "started_at": stamp(time.time()), "channels": list(CHANNELS),
               "credential_cleanup_verified": False, "action_invoked": False, "action_unambiguous": True}
    folder.mkdir(parents=True, exist_ok=False)
    persist = lambda: save(folder / "cohort.json", receipt)
    persist()
    begin_trial(data, trial_id)
    state_path = private_path(str(folder / "storage-baseline.json"))
    credential_id = None
    credential_attempted = False
    channels = {}
    app_url = "https://graph.microsoft.com/v1.0/applications/" + m.actor["application_object_id"]
    credential_name = "storm3168-storage-" + trial_id
    try:
        verify_data_control(data, guard)
        initial_settings(account(guard))
        def during(prepared, state):
            nonlocal credential_id, credential_attempted, channels
            current = Manifest.from_dict(prepared)
            current_guard = Guard(current, HTTP(), AzureCLI(current, current.subscription_id))
            assert_storage_window(prepared, state_path, time.time() + duration + 300)
            receipt.update(prepared_manifest=state["prepared_manifest"], nonce=state["nonce"], checksum=state["sha256"], status="credential_preparation")
            receipt["credential_display_name"] = credential_name
            persist()
            current_guard.ownership()
            current_guard.actor()
            credential_attempted = True
            receipt["credential_creation_attempted"] = True
            persist()
            secret = request("POST", app_url + "/addPassword", graph_token(m.subscription_id),
                             {"passwordCredential": {"displayName": credential_name, "endDateTime": stamp(time.time() + 3600)}})
            credential_id = str(uuid.UUID(secret["keyId"]))
            receipt["credential_key_id"] = credential_id
            persist()
            try:
                for attempt in range(4):
                    try:
                        result = request("POST", "https://login.microsoftonline.com/" + m.tenant_id + "/oauth2/v2.0/token",
                                         form={"grant_type": "client_credentials", "client_id": m.actor["client_id"], "client_secret": secret["secretText"], "scope": "https://storage.azure.com/.default"})
                        break
                    except CredentialHTTPError as exc:
                        if exc.status != 401 or 7000215 not in exc.numeric_codes or attempt == 3:
                            raise
                        time.sleep(15)
            finally:
                secret.clear()
            token = result.pop("access_token")
            result.clear()
            claims = validate_actor_token(token, current, "storage")
            expiry = time.time() + duration + 600
            if claims["exp"] <= expiry:
                raise SafetyError("Actor token cannot cover the complete cohort")
            start, end = stamp(time.time() - 60), stamp(expiry)
            receipt["stage"] = "capture_account_keys_and_actor_delegation"
            persist()
            keys = get_keys(current_guard)
            delegation = get_delegation(current_guard, token, start, end)
            channels = {
                "key1": {"auth": "shared-key", "credential": keys["key1"]},
                "key2": {"auth": "shared-key", "credential": keys["key2"]},
                "service-sas-key1": {"auth": "sas", "credential": make_sas(current, "service", keys["key1"], start, end, ip)},
                "account-sas-key2": {"auth": "sas", "credential": make_sas(current, "account", keys["key2"], start, end, ip)},
                "user-delegation-sas": {"auth": "sas", "credential": make_sas(current, "user-delegation", delegation["Value"], start, end, ip, delegation)},
                "entra-blob": {"auth": "bearer", "credential": token}}
            keys.clear()
            delegation.clear()
            for name, channel in channels.items():
                channel["label"] = str(uuid.uuid4())
                if channel["auth"] == "sas":
                    validate_sas(channel["credential"], current, time.time())
            receipt["stage"] = "verify_six_checksum_baselines"
            receipt["channel_metadata"] = {name: {"auth": ch["auth"], "credential_label": ch["label"]} for name, ch in channels.items()}
            receipt["checksum_baselines"] = {name: full_read(current_guard, ch["auth"], ch["credential"], state) for name, ch in channels.items()}
            persist()
            if not all(v["verified"] for v in receipt["checksum_baselines"].values()):
                raise SafetyError("Every channel must verify the nonce checksum before response")
            before = parallel_phase(current, channels, folder, "baseline", 20, 10)
            if set(before) != set(CHANNELS) or any(sum(r.get("kind") == "probe" and r.get("outcome") == "allowed" for r in rows) < 2 for rows in before.values()):
                raise SafetyError("Every fixed credential requires two successful baseline requests")
            assert_storage_window(prepared, state_path, time.time() + duration + 120)
            for channel in channels.values():
                claims = validate_sas(channel["credential"], current, time.time()) if channel["auth"] == "sas" else validate_actor_token(channel["credential"], current, "storage") if channel["auth"] == "bearer" else None
                if claims and claims["exp"] <= time.time() + duration + 60:
                    raise SafetyError("Fixed credential cannot cover observation; no response applied")
            if source_hashes() != receipt["source_hashes"]:
                raise SafetyError("Source changed before response")
            receipt.update(status="action_pending", action_invoked=True, action_unambiguous=False)
            persist()
            action_receipt = respond(current_guard, action, execute=True, confirm_lab_id=m.lab_id)
            append_jsonl(folder / "action.jsonl", action_receipt)
            receipt["action_receipt"] = action_receipt
            receipt["action_unambiguous"] = (action_receipt.get("mutation_acknowledged") is True
                and (action != "disable-shared-key" or action_receipt.get("postcondition_verified") is True))
            persist()
            if not receipt["action_unambiguous"]:
                raise SafetyError("Response acknowledgment or required configuration readback is uncertain; never replay in this cohort")
            assert_storage_window(prepared, state_path, time.time() + duration + 60)
            after = parallel_phase(current, channels, folder, "post-action", duration, interval)
            receipt["all_channels_observed"] = set(after) == set(CHANNELS) and all(
                any(r.get("kind") == "run_end" and r.get("status") == "completed" for r in rows)
                and sum(r.get("kind") == "probe" and r.get("outcome") in {"allowed", "authorization_denied", "credential_rejected"} for r in rows) >= 2
                and not any(r.get("outcome") == "expired" for r in rows) for rows in after.values())
            for name in CHANNELS:
                linked, summary = link(prepared, trial_id, before[name], [action_receipt], after[name])
                save(folder / name / "linked.json", {"receipt": linked, "summary": summary,
                     "source_files": {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in {
                         "baseline": folder/name/"baseline.jsonl", "action": folder/"action.jsonl", "post_action": folder/name/"post-action.jsonl"}.items()}})
            controls = ["user-delegation-sas", "entra-blob"] + (["key2", "account-sas-key2"] if action == "rotate-key1" else ["key1", "service-sas-key1"] if action == "rotate-key2" else [])
            receipt["control_post_checksums"] = {name: full_read(current_guard, channels[name]["auth"], channels[name]["credential"], state) for name in controls}
            receipt["controls_healthy"] = all(v["verified"] for v in receipt["control_post_checksums"].values()) and all(
                rows and all(r.get("outcome") == "allowed" for r in rows if r.get("kind") == "probe") for rows in (after[n] for n in controls))
            receipt["status"] = "observation_completed" if receipt["controls_healthy"] and receipt["all_channels_observed"] else "observation_control_inconclusive"
            persist()
            return {"status": receipt["status"]}
        prepare(data, guard, ip, "shared-key", True, duration + 600, state_path, True,
                announce=lambda _: None, during_hold=during)
    except BaseException:
        receipt["status"] = "failed_or_incomplete"
        raise
    finally:
        channels.clear()
        cleanup_error = None
        if credential_attempted:
            try:
                assert_owned(data, m.subscription_id)
                app = request("GET", app_url, graph_token(m.subscription_id))
                if app.get("id") != m.actor["application_object_id"] or app.get("appId") != m.actor["client_id"] or app.get("displayName") != m.name_prefix:
                    raise SafetyError("Actor application changed during credential cleanup")
                candidates = [x for x in app.get("passwordCredentials", []) if x.get("displayName") == credential_name]
                if credential_id is None:
                    if len(candidates) != 1:
                        raise SafetyError("Temporary credential creation outcome requires reconciliation")
                    credential_id = str(uuid.UUID(candidates[0]["keyId"]))
                    receipt["credential_key_id"] = credential_id
                if any(x.get("keyId") == credential_id for x in app.get("passwordCredentials", [])):
                    request("POST", app_url + "/removePassword", graph_token(m.subscription_id), {"keyId": credential_id})
                checked = request("GET", app_url + "?$select=id,appId,passwordCredentials", graph_token(m.subscription_id))
                if checked.get("appId") != m.actor["client_id"] or "passwordCredentials" not in checked or any(x.get("keyId") == credential_id for x in checked["passwordCredentials"]):
                    raise SafetyError("Temporary credential removal unconfirmed")
                receipt["credential_cleanup_verified"] = True
            except BaseException as exc:
                cleanup_error = exc
        else:
            receipt["credential_cleanup_verified"] = True
        try:
            state = load_json(state_path) if state_path.exists() else {}
            initial_settings(account(guard))
            receipt["storage_restored"] = state.get("settings_restored") is True or not state_path.exists()
        except BaseException as exc:
            receipt["storage_restored"] = False
            cleanup_error = cleanup_error or exc
        receipt["source_unchanged"] = source_hashes() == receipt["source_hashes"]
        receipt["finished_at"] = stamp(time.time())
        receipt["valid_trial"] = receipt["status"] == "observation_completed" and receipt["source_unchanged"] and receipt["credential_cleanup_verified"] and receipt["storage_restored"]
        persist()
        finish_trial(data, trial_id, cleanup_confirmed=receipt["credential_cleanup_verified"] and receipt["storage_restored"] and receipt["action_unambiguous"], outcome=receipt["status"])
        if cleanup_error:
            raise SafetyError("Storage cohort cleanup is unconfirmed; reconcile private receipt") from None
    return receipt


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True)
    p.add_argument("--subscription", required=True)
    p.add_argument("--confirm-lab-id")
    p.add_argument("--action", required=True, choices=ACTIONS)
    p.add_argument("--series-id", required=True, type=uuid.UUID)
    p.add_argument("--client-ip", required=True, type=client_ip)
    p.add_argument("--trials", type=int, default=3, choices=[1, 2, 3])
    p.add_argument("--duration", type=int, default=300)
    p.add_argument("--interval", type=int, default=20)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--execute", action="store_true")
    a = p.parse_args(argv)
    data = load_json(private_path(a.manifest))
    m = Manifest.from_dict(data)
    if str(uuid.UUID(a.subscription)) != m.subscription_id or not 60 <= a.duration <= 900 or not 5 <= a.interval <= 30:
        raise SafetyError("Explicit subscription and bounded duration/interval required")
    if not m.actor or not m.blob or type(data.get("budget_target_usd")) not in {int, float} or not 0 < data["budget_target_usd"] <= 10:
        raise SafetyError("Recorded actor, blob and positive budget target at most 10 required")
    path = private_path(str(ROOT / "private" / ("storage-series-" + str(a.series_id) + ".json")))
    series = load_json(path) if path.exists() else {"schema_version": 1, "series_id": str(a.series_id), "lab_id": m.lab_id, "subscription_id": m.subscription_id,
        "storage_id": m.storage_id, "action": a.action, "source_hashes": source_hashes(), "duration": a.duration, "interval": a.interval, "cohorts": []}
    if not path.exists():
        series["client_ip"] = a.client_ip
    if any(series.get(k) != v for k, v in {"series_id": str(a.series_id), "lab_id": m.lab_id, "subscription_id": m.subscription_id, "storage_id": m.storage_id,
                                          "action": a.action, "source_hashes": source_hashes(), "duration": a.duration, "interval": a.interval, "client_ip": a.client_ip}.items()):
        raise SafetyError("Series identity/configuration/source mismatch")
    if not a.execute:
        print(json.dumps({"mode": "offline_plan", "action": a.action, "target_valid_trials": a.trials, "channels": list(CHANNELS), "duration": a.duration,
                          "mutations_per_cohort": ["temporary single-IP/Shared Key baseline", "temporary owned app secret", a.action, "restore original closed settings", "remove temporary secret"],
                          "data_reader_granted": False, "cloud_calls": False}))
        return 0
    if a.confirm_lab_id != m.lab_id or (path.exists() and not a.resume):
        raise SafetyError("Execution requires exact lab confirmation; existing series requires explicit --resume")
    if any(not c.get("cleanup_verified") for c in series["cohorts"]):
        raise SafetyError("Prior cohort outcome/cleanup must be reconciled before a new trial")
    guard = Guard(m, HTTP(), AzureCLI(m, a.subscription))
    assert_idle(data)
    verify_data_control(data, guard)
    initial_settings(account(guard))
    save(path, series)
    while sum(c.get("valid_trial") is True for c in series["cohorts"]) < a.trials:
        cohort_id = str(uuid.uuid4())
        folder = private_path(str(ROOT / "private" / "storage-runs" / cohort_id))
        entry = {"cohort_id": cohort_id, "status": "planned", "cleanup_verified": False, "valid_trial": False}
        series["cohorts"].append(entry)
        save(path, series)
        try:
            result = run_cohort(data, guard, folder, a.action, a.client_ip, a.duration, a.interval)
        finally:
            receipt_path = folder / "cohort.json"
            if receipt_path.exists():
                result = load_json(receipt_path)
                entry.update(status=result["status"], valid_trial=result.get("valid_trial", False),
                             cleanup_verified=result.get("credential_cleanup_verified") is True and result.get("storage_restored") is True and result.get("action_unambiguous") is True,
                             evidence=str(receipt_path.relative_to(ROOT)))
            save(path, series)
        if not entry["valid_trial"]:
            raise SafetyError("Cohort was inconclusive; preserved for review, no automatic replacement")
        assert_idle(data)
        verify_data_control(data, guard)
        initial_settings(account(guard))
        print(json.dumps({"status": "cohort_completed", "valid_trials": sum(c.get("valid_trial") is True for c in series["cohorts"]), "target": a.trials}), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print("Storage series stopped; inspect private cohort/restoration/credential receipts. No response is automatically retried.", file=sys.stderr)
        raise SystemExit(1)
