"""Run ONE bounded, fixed-token ARM experiment against an already-created lab.

Creates a short-lived credential in memory, acquires one actor token, performs
baseline probes, applies one selected action, and probes the SAME token again.
The credential is removed in finally. The selected response remains applied.
This is live cloud work, not a fixture runner. No full-incident containment claim.
"""
from __future__ import annotations
import argparse
import hashlib
from datetime import datetime, timedelta, timezone
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from lab_support import ROOT, assert_context, assert_owned, az, guid, load_owned, private_path, save


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CredentialHTTPError(RuntimeError):
    def __init__(self, status, code, numeric_codes):
        self.status, self.code, self.numeric_codes = status, code, numeric_codes
        super().__init__(f"Credential operation returned HTTP {status}; code={code}; numeric_codes={numeric_codes}")


def request(method: str, url: str, token: str | None = None, payload: dict | None = None,
            form: dict | None = None) -> dict:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"graph.microsoft.com", "login.microsoftonline.com"}:
        raise ValueError("Disallowed credential-operation endpoint")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
            raw = response.read(1024 * 1024)
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        # Extract only provider error identifiers, never descriptions/request data.
        code, numbers = "", []
        try:
            error_data = json.loads(exc.read(32768))
            candidate = error_data.get("error", "")
            candidate = candidate.get("code", "") if isinstance(candidate, dict) else candidate
            if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", candidate):
                code = candidate
            numbers = [value for value in error_data.get("error_codes", []) if type(value) is int][:5]
        except (ValueError, AttributeError, TypeError):
            pass
        raise CredentialHTTPError(exc.code, code, numbers) from None
    except urllib.error.URLError:
        raise RuntimeError("Credential operation transport failure") from None


def graph_token(subscription: str) -> str:
    account = assert_context(subscription)
    result = az("account", "get-access-token", "--subscription", subscription,
                "--resource", "https://graph.microsoft.com")
    token = result["accessToken"]
    sys.path.insert(0, str(ROOT / "src"))
    from stormlab.core import claims_from_token, GRAPH_AUDIENCES
    claims = claims_from_token(token)
    if claims.get("tid") != account["tenantId"] or claims.get("aud") not in GRAPH_AUDIENCES or claims["exp"] <= time.time():
        raise RuntimeError("Operator Graph credential tenant, audience or expiry mismatch")
    return token


def invoke_harness(arguments: list[str], env: dict[str, str]) -> None:
    result = subprocess.run([sys.executable, "-m", "stormlab", *arguments], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=2400, check=False)
    if result.returncode:
        # Harness errors should already be sanitized, but don't copy arbitrary subprocess output.
        raise RuntimeError(f"Harness {arguments[0]} failed; inspect ignored local evidence and rerun preflight")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="private/manifest.json")
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--confirm-lab-id", required=True, type=guid)
    parser.add_argument("--action", required=True, choices=["none", "role-delete", "sp-disable", "app-deactivate", "secret-remove", "group-member-remove"])
    parser.add_argument("--capability", choices=["arm-read", "arm-tag-write", "listkeys"], default="arm-tag-write")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--baseline-seconds", type=int, default=60)
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--role-assignment-id")
    parser.add_argument("--check-new-token", action="store_true", help="Separate issuance control; never replaces the fixed probe token")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not 20 <= args.duration <= 1200 or not 20 <= args.baseline_seconds <= 120 or not 5 <= args.interval <= 60:
        parser.error("Duration must be 20..1200 seconds; baseline 20..120; interval 5..60")
    path, manifest = load_owned(args.manifest, args.subscription, args.confirm_lab_id)
    actor = manifest["actor"]
    app_id = guid(actor["application_object_id"])
    client_id = guid(actor["client_id"])
    guid(actor["service_principal_object_id"])
    if not args.execute:
        print(json.dumps({"mode": "plan", "action": args.action, "credential_refresh": False,
                          "baseline_seconds": args.baseline_seconds, "observation_seconds": args.duration,
                          "mutations": ["add temporary owned application credential", args.action, "remove temporary credential"]}))
        return 0
    operator_token = graph_token(args.subscription)
    app_url = "https://graph.microsoft.com/v1.0/applications/" + app_id
    application = request("GET", app_url, operator_token)
    if application.get("appId") != client_id or not application.get("displayName", "").startswith("storm3168-" + manifest["lab_id"]):
        raise RuntimeError("Application ownership mismatch")
    service_principal = request("GET", "https://graph.microsoft.com/v1.0/servicePrincipals/" + actor["service_principal_object_id"], operator_token)
    if service_principal.get("appId") != client_id or service_principal.get("accountEnabled") is not True:
        raise RuntimeError("Canary service principal is mismatched or disabled; restore it explicitly before a new run")
    run_id = str(uuid.uuid4())
    run_dir = private_path(str(ROOT / "private" / "runs" / run_id))
    run_dir.mkdir(parents=True, exist_ok=False)
    trial_manifest = dict(manifest)
    trial_path = private_path(str(run_dir / "manifest.json"))
    metadata = {"schema_version": 1, "run_id": run_id, "mode": "live", "action": args.action,
                "capability": args.capability, "status": "started", "started_at": datetime.now(timezone.utc).isoformat(),
                "source_manifest": str(path.relative_to(ROOT)), "token_refresh": False, "credential_removed": False}
    source_paths = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))
    metadata["source_hashes"] = {str(item.relative_to(ROOT)): hashlib.sha256(item.read_bytes()).hexdigest() for item in source_paths}
    revision = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    metadata["source_commit"] = revision.stdout.strip() if revision.returncode == 0 else None
    metadata["source_status"] = "prototype_worktree; review hashes against pinned source before publication"
    save(run_dir / "trial.json", metadata)
    credential_id = None
    credential_attempted = False
    client_secret = ""
    credential_name = "storm3168-trial-" + run_id
    try:
        assert_owned(manifest, args.subscription)
        credential_attempted = True
        metadata["credential_creation_attempted"] = True
        metadata["credential_display_name"] = credential_name
        save(run_dir / "trial.json", metadata)
        credential = request("POST", app_url + "/addPassword", operator_token,
                             {"passwordCredential": {"displayName": credential_name,
                             "endDateTime": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}})
        credential_id = guid(credential["keyId"])
        metadata["credential_key_id"] = credential_id  # Identifier only; never secretText.
        save(run_dir / "trial.json", metadata)
        trial_manifest["owned_secret_key_id"] = credential_id
        save(trial_path, trial_manifest)
        client_secret = credential["secretText"]
        # Bounded initial issuance only. No token has been frozen yet; this is
        # NOT a probe retry or refresh. Retain failures in the private receipt.
        for attempt in range(4):
            metadata["initial_token_attempts"] = attempt + 1
            save(run_dir / "trial.json", metadata)
            try:
                token_response = request("POST", f"https://login.microsoftonline.com/{guid(manifest['tenant_id'])}/oauth2/v2.0/token",
                                         form={"grant_type": "client_credentials", "client_id": client_id,
                                               "client_secret": client_secret, "scope": "https://management.azure.com/.default"})
                break
            except CredentialHTTPError as exc:
                if exc.status != 401 or exc.code != "invalid_client" or 7000215 not in exc.numeric_codes or attempt == 3:
                    raise
                time.sleep(15)
        credential.clear()
        frozen_token = token_response["access_token"]
        token_response.clear()
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["STORMLAB_PROBE_TOKEN"] = frozen_token
        common = ["--manifest", str(trial_path), "--subscription", args.subscription]
        probe_common = ["probe", *common, "--capability", args.capability,
                        "--interval", str(args.interval), "--token-env", "STORMLAB_PROBE_TOKEN"]
        if args.capability == "arm-tag-write":
            probe_common.append("--allow-mutation")
        invoke_harness([*probe_common, "--duration", str(args.baseline_seconds), "--output", str(run_dir / "baseline.jsonl")], env)
        # Require actual successful baseline authorization before applying any response.
        baseline = [json.loads(line) for line in (run_dir / "baseline.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        if sum(item.get("kind") == "probe" and item.get("outcome") == "allowed" for item in baseline) < 2:
            raise RuntimeError("No successful baseline; response was not applied")
        metadata["action_requested_at"] = datetime.now(timezone.utc).isoformat()
        save(run_dir / "trial.json", metadata)
        if args.action != "none":
            action_path = private_path(str(run_dir / "action.jsonl"))
            action_args = ["respond", *common, "--action", args.action, "--execute", "--confirm-lab-id", manifest["lab_id"], "--output", str(action_path)]
            if args.role_assignment_id:
                action_args.extend(["--role-assignment-id", args.role_assignment_id])
            invoke_harness(action_args, env)
            receipts = [json.loads(line) for line in action_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if len(receipts) != 1 or receipts[0].get("action") != args.action:
                raise RuntimeError("Expected one exact action receipt")
            metadata["action_receipt"] = {key: receipts[0].get(key) for key in ["action", "status", "http_status", "postcondition_verified", "request_started_at", "acknowledged_at"]}
        metadata["action_returned_at"] = datetime.now(timezone.utc).isoformat()
        save(run_dir / "trial.json", metadata)
        if args.check_new_token:
            issuance = {"checked_at": datetime.now(timezone.utc).isoformat(), "replaces_probe_token": False}
            try:
                separate = request("POST", f"https://login.microsoftonline.com/{guid(manifest['tenant_id'])}/oauth2/v2.0/token",
                                   form={"grant_type": "client_credentials", "client_id": client_id,
                                         "client_secret": client_secret, "scope": "https://management.azure.com/.default"})
                issuance["status"] = "issued" if "access_token" in separate else "unknown_response"
                separate.clear()
            except CredentialHTTPError as exc:
                issuance.update(status="rejected", http_status=exc.status, error_code=exc.code, numeric_codes=exc.numeric_codes)
            except RuntimeError:
                issuance["status"] = "transport_error_or_unknown"
            metadata["separate_new_token_check"] = issuance
            save(run_dir / "trial.json", metadata)
        invoke_harness([*probe_common, "--duration", str(args.duration), "--output", str(run_dir / "post-action.jsonl")], env)
        env.pop("STORMLAB_PROBE_TOKEN", None)
        frozen_token = ""
        metadata["status"] = "observation_completed"
        return 0
    except (RuntimeError, ValueError, KeyError):
        metadata["status"] = "failed_or_incomplete"
        raise
    finally:
        if credential_attempted:
            try:
                assert_owned(manifest, args.subscription)
                current = request("GET", app_url, graph_token(args.subscription))
                if current.get("appId") != client_id or not current.get("displayName", "").startswith("storm3168-" + manifest["lab_id"]):
                    raise RuntimeError("Application changed during cleanup")
                if not credential_id:
                    candidates = [item for item in current.get("passwordCredentials", []) if item.get("displayName") == credential_name]
                    if len(candidates) != 1:
                        raise RuntimeError("Credential creation outcome is uncertain; reconcile the exact recorded label")
                    credential_id = guid(candidates[0]["keyId"])
                    metadata["credential_key_id"] = credential_id
                remaining = [item for item in current.get("passwordCredentials", []) if item.get("keyId") == credential_id]
                if remaining:
                    request("POST", app_url + "/removePassword", graph_token(args.subscription), {"keyId": credential_id})
                confirmed = request("GET", app_url + "?$select=id,appId,passwordCredentials", graph_token(args.subscription))
                if confirmed.get("appId") != client_id or "passwordCredentials" not in confirmed or any(item.get("keyId") == credential_id for item in confirmed["passwordCredentials"]):
                    raise RuntimeError("Temporary credential absence is unverified")
                metadata["credential_removed"] = True
            except (RuntimeError, ValueError, KeyError):
                metadata["credential_removed"] = False
                metadata["cleanup_required"] = "Reconcile the recorded unique credential label/key ID on the owned application"
        client_secret = ""
        metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            metadata["source_changed_during_trial"] = any(hashlib.sha256(item.read_bytes()).hexdigest() != metadata["source_hashes"][str(item.relative_to(ROOT))] for item in source_paths)
        except OSError:
            metadata["source_changed_during_trial"] = None
            metadata["source_verification"] = "unverifiable"
        save(run_dir / "trial.json", metadata)
        print(json.dumps({"run_id": run_id, "status": metadata["status"], "credential_removed": metadata["credential_removed"],
                          "evidence": str(run_dir.relative_to(ROOT)), "scope": "one action and one capability; not whole-incident containment"}))
        if credential_attempted and not metadata["credential_removed"]:
            raise RuntimeError("Temporary credential cleanup is unconfirmed; reconcile its recorded key ID")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, KeyError) as exc:
        print(f"Trial stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
