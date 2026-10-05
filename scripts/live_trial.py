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
import math
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

sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import Manifest, SafetyError, response_target, summarize_trial, validate_actor_token


def observation_window(action: str, duration: int | None, until_expiry: bool,
                       expiry: float | None = None, now: float | None = None) -> dict:
    if duration is not None and until_expiry:
        raise ValueError("Choose a fixed duration or --until-token-expiry, not both")
    if duration is not None and (type(duration) is not int or not 20 <= duration <= 7200):
        raise ValueError("Explicit duration must be 20..7200 seconds")
    if until_expiry:
        if expiry is None:
            return {"mode": "until_token_expiry", "maximum_seconds": 7200, "expiry_margin_seconds": 60}
        current = time.time() if now is None else now
        requested = max(20, math.ceil(expiry - current + 60))
        return {"mode": "until_token_expiry", "duration_seconds": min(7200, requested),
                "maximum_seconds": 7200, "expiry_margin_seconds": 60, "expiry_window_capped": requested > 7200}
    return {"mode": "explicit_fixed_window" if duration is not None else "action_default",
            "duration_seconds": duration if duration is not None else 900 if action in {"role-delete", "group-member-remove"} else 300,
            "maximum_seconds": 7200, "expiry_window_capped": False}


def read_rows(path: pathlib.Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def record_phase(metadata: dict, rows: list[dict], phase: str) -> None:
    starts = [row for row in rows if row.get("kind") == "run_start"]
    if len(starts) != 1 or any(starts[0].get(key) != metadata[key] for key in ("capability", "auth", "credential_label")):
        raise RuntimeError("Probe phase does not match the frozen credential receipt")
    metadata.setdefault("probe_runs", {})[phase] = starts[0]["run_id"]


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
    duration = float(arguments[arguments.index("--duration") + 1]) if "--duration" in arguments else 0
    timeout = max(300, min(7800, duration + 600))
    result = subprocess.run([sys.executable, "-m", "stormlab", *arguments], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=timeout, check=False)
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
    parser.add_argument("--duration", type=int, help="Explicit post-action observation seconds, 20..7200; overrides the action default")
    parser.add_argument("--until-token-expiry", action="store_true", help="Explicitly observe until the frozen token expires, plus 60s scheduling margin; maximum 2h")
    parser.add_argument("--baseline-seconds", type=int, default=60)
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--role-assignment-id")
    parser.add_argument("--check-new-token", action="store_true", help="Separate issuance control; never replaces the fixed probe token")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not 20 <= args.baseline_seconds <= 120 or not 5 <= args.interval <= 60:
        parser.error("Baseline must be 20..120 seconds; interval 5..60")
    try:
        window = observation_window(args.action, args.duration, args.until_token_expiry)
    except ValueError as exc:
        parser.error(str(exc))
    path, manifest = load_owned(args.manifest, args.subscription, args.confirm_lab_id)
    model = Manifest.from_dict(manifest)
    target = response_target(model, args.action, args.role_assignment_id)
    actor = manifest["actor"]
    app_id = guid(actor["application_object_id"])
    client_id = guid(actor["client_id"])
    guid(actor["service_principal_object_id"])
    if not args.execute:
        print(json.dumps({"mode": "plan", "action": args.action, "credential_refresh": False,
                          "baseline_seconds": args.baseline_seconds, "observation_window": window,
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
                "auth": "bearer", "credential_label": str(uuid.uuid4()), "action_target": target, "access_path": target["access_path"],
                "separate_new_token_check": {"status": "not_requested", "replaces_probe_token": False},
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
        metadata["action_target"] = response_target(Manifest.from_dict(trial_manifest), args.action, args.role_assignment_id)
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
        frozen_claims = validate_actor_token(frozen_token, model, "arm")
        metadata["frozen_token_metadata"] = {key: frozen_claims.get(key) for key in ("aud", "iat", "exp")}
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["STORMLAB_PROBE_TOKEN"] = frozen_token
        common = ["--manifest", str(trial_path), "--subscription", args.subscription]
        probe_common = ["probe", *common, "--capability", args.capability,
                        "--interval", str(args.interval), "--token-env", "STORMLAB_PROBE_TOKEN", "--credential-label", metadata["credential_label"]]
        if args.capability == "arm-tag-write":
            probe_common.append("--allow-mutation")
        invoke_harness([*probe_common, "--duration", str(args.baseline_seconds), "--output", str(run_dir / "baseline.jsonl")], env)
        # Require actual successful baseline authorization before applying any response.
        baseline = read_rows(run_dir / "baseline.jsonl")
        record_phase(metadata, baseline, "baseline")
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
            metadata["action_receipt"] = {key: receipts[0].get(key) for key in ["action", "status", "http_status", "postcondition_verified", "request_started_at", "acknowledged_at", "target"]}
            if metadata["action_receipt"]["target"] != metadata["action_target"]:
                raise RuntimeError("Action receipt target differs from the trial receipt")
        metadata["action_returned_at"] = datetime.now(timezone.utc).isoformat()
        save(run_dir / "trial.json", metadata)
        if args.check_new_token:
            issuance = {"checked_at": datetime.now(timezone.utc).isoformat(), "replaces_probe_token": False,
                        "credential_key_id": credential_id, "action": args.action, "phase": "after_action_before_observation", "attempts": 1}
            try:
                separate = request("POST", f"https://login.microsoftonline.com/{guid(manifest['tenant_id'])}/oauth2/v2.0/token",
                                   form={"grant_type": "client_credentials", "client_id": client_id,
                                         "client_secret": client_secret, "scope": "https://management.azure.com/.default"})
                if "access_token" in separate:
                    issued_claims = validate_actor_token(separate["access_token"], model, "arm")
                    issuance.update(status="issued", token_metadata={key: issued_claims.get(key) for key in ("aud", "iat", "exp")})
                else:
                    issuance["status"] = "unknown_response"
                separate.clear()
            except CredentialHTTPError as exc:
                issuance.update(status="provider_rejected" if exc.status in {400, 401} else "service_error_or_unknown", http_status=exc.status, error_code=exc.code, numeric_codes=exc.numeric_codes)
            except (RuntimeError, SafetyError):
                issuance["status"] = "transport_error_or_unknown"
            issuance["response_received_at"] = datetime.now(timezone.utc).isoformat()
            metadata["separate_new_token_check"] = issuance
            save(run_dir / "trial.json", metadata)
        window = observation_window(args.action, args.duration, args.until_token_expiry, frozen_claims["exp"])
        metadata["observation_window"] = window
        save(run_dir / "trial.json", metadata)
        invoke_harness([*probe_common, "--duration", str(window["duration_seconds"]), "--output", str(run_dir / "post-action.jsonl")], env)
        post = read_rows(run_dir / "post-action.jsonl")
        record_phase(metadata, post, "post_action")
        action_rows = read_rows(run_dir / "action.jsonl") if args.action != "none" else []
        save(private_path(str(run_dir / "summary.json")), summarize_trial(metadata, baseline, action_rows, post))
        env.pop("STORMLAB_PROBE_TOKEN", None)
        frozen_token = ""
        metadata["status"] = "observation_completed"
        return 0
    except (RuntimeError, SafetyError, ValueError, KeyError, subprocess.TimeoutExpired):
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
    except (RuntimeError, SafetyError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"Trial stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
