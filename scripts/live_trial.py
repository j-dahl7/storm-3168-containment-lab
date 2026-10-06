"""Run ONE bounded, fixed-token ARM or prepared Blob experiment.

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
from trial_state import begin_trial, finish_trial
from storage_baseline import assert_storage_window
import manual_executor_trial

TOKEN_ACTIONS = {"sp-disable", "app-deactivate", "secret-remove"}


def observation_window(action: str, duration: int | None, until_expiry: bool,
                       expiry: float | None = None, now: float | None = None) -> dict:
    if duration is not None and until_expiry:
        raise ValueError("Choose a fixed duration or --until-token-expiry, not both")
    if duration is not None and (type(duration) is not int or not 20 <= duration <= 7200):
        raise ValueError("Explicit duration must be 20..7200 seconds")
    until_expiry = until_expiry or (duration is None and action in TOKEN_ACTIONS)
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
    ends = [row for row in rows if row.get("kind") == "run_end" and row.get("run_id") == starts[0]["run_id"]]
    metadata.setdefault("probe_phase_status", {})[phase] = ends[0].get("status", "incomplete") if len(ends) == 1 else "incomplete"


def execute_probe_phase(arguments: list[str], env: dict[str, str], metadata: dict, run_dir: pathlib.Path, phase: str) -> list[dict]:
    """Always retain the emitted run ID, even if the child stops mid-window."""
    path = pathlib.Path(arguments[arguments.index("--output") + 1])
    rows = []
    try:
        invoke_harness(arguments, env)
    finally:
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        metadata.setdefault("partial_evidence", {})[phase] = "truncated_jsonl"
                        break
            try:
                record_phase(metadata, rows, phase)
            except (RuntimeError, KeyError, TypeError):
                metadata.setdefault("partial_evidence", {})[phase] = "phase_receipt_unverified"
        else:
            metadata.setdefault("partial_evidence", {})[phase] = "no_phase_receipt"
        save(run_dir / "trial.json", metadata)
    if metadata.get("probe_phase_status", {}).get(phase) != "completed":
        raise RuntimeError("Probe phase did not complete; partial evidence was retained")
    return rows


def validate_pairing(action: str, capability: str) -> None:
    if action in {"role-delete", "group-member-remove", "manual-executor"} and capability == "arm-read":
        raise SafetyError("Reader remains a healthy control; use arm-tag-write or listkeys to measure writer removal")
    if action == "manual-executor" and capability not in {"arm-tag-write", "listkeys"}:
        raise SafetyError("CORE09 measures arm-tag-write or listkeys against its direct writer assignment")


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
    parser.add_argument("--action", required=True, choices=["none", "role-delete", "sp-disable", "app-deactivate", "secret-remove", "group-member-remove", "manual-executor"])
    parser.add_argument("--capability", choices=["arm-read", "arm-tag-write", "listkeys", "blob-read"], default="arm-tag-write")
    parser.add_argument("--storage-baseline-state", help="Required for blob-read: explicit prepared storage receipt covering the entire trial")
    parser.add_argument("--duration", type=int, help="Explicit post-action observation seconds, 20..7200; overrides the action default")
    parser.add_argument("--until-token-expiry", action="store_true", help="Explicitly observe until the frozen token expires, plus 60s scheduling margin; maximum 2h")
    parser.add_argument("--baseline-seconds", type=int, default=60)
    parser.add_argument("--interval", type=int, help="Post-action interval; default 60s for expiry windows, otherwise 10s")
    parser.add_argument("--role-assignment-id")
    parser.add_argument("--check-new-token", action="store_true", help="Separate issuance control; never replaces the fixed probe token")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    canonical_action = "role-delete" if args.action == "manual-executor" else args.action
    if not 20 <= args.baseline_seconds <= 120 or (args.interval is not None and not 5 <= args.interval <= 60):
        parser.error("Baseline must be 20..120 seconds; interval 5..60")
    try:
        window = observation_window(canonical_action, args.duration, args.until_token_expiry)
    except ValueError as exc:
        parser.error(str(exc))
    interval = args.interval if args.interval is not None else 60 if window["mode"] == "until_token_expiry" else 10
    validate_pairing(args.action, args.capability)
    if args.capability == "blob-read" and not args.storage_baseline_state:
        parser.error("blob-read requires --storage-baseline-state")
    path, manifest = load_owned(args.manifest, args.subscription, args.confirm_lab_id)
    model = Manifest.from_dict(manifest)
    audience = "storage" if args.capability == "blob-read" else "arm"
    token_scope = "https://storage.azure.com/.default" if audience == "storage" else "https://management.azure.com/.default"
    target = response_target(model, canonical_action, args.role_assignment_id)
    if args.action == "manual-executor":
        _, _, executor_target = manual_executor_trial.load_bound_state(manifest, args.role_assignment_id)
        if executor_target != target:
            raise SafetyError("Manual executor target differs from the trial target")
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
    metadata = {"schema_version": 1, "run_id": run_id, "mode": "live", "action": canonical_action,
                "orchestration_action": args.action,
                "response_transport": "guarded_logic_app" if args.action == "manual-executor" else "operator_harness",
                "auth": "bearer", "credential_label": str(uuid.uuid4()), "action_target": target, "access_path": target["access_path"],
                "separate_new_token_check": {"status": "not_requested", "replaces_probe_token": False},
                "capability": args.capability, "status": "started", "started_at": datetime.now(timezone.utc).isoformat(),
                "location": model.location, "probe_interval_seconds": interval,
                "source_manifest": str(path.relative_to(ROOT)), "token_refresh": False, "credential_removed": False}
    source_paths = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "scripts").glob("*.py"))
    if args.action == "manual-executor":
        source_paths += sorted((ROOT / "playbooks").glob("*.bicep")) + sorted((ROOT / "playbooks").glob("*.json"))
    metadata["source_hashes"] = {str(item.relative_to(ROOT)): hashlib.sha256(item.read_bytes()).hexdigest() for item in source_paths}
    revision = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    metadata["source_commit"] = revision.stdout.strip() if revision.returncode == 0 else None
    metadata["source_status"] = "prototype_worktree; review hashes against pinned source before publication"
    save(run_dir / "trial.json", metadata)
    credential_id = None
    credential_attempted = False
    client_secret = ""
    env = {}
    frozen_token = ""
    lease_acquired = False
    credential_name = "storm3168-trial-" + run_id
    try:
        if args.capability == "blob-read":
            budget = window.get("duration_seconds", 7200) + args.baseline_seconds + 300
            metadata["storage_preparation"] = assert_storage_window(manifest, args.storage_baseline_state, time.time() + budget)
        begin_trial(manifest, run_id)
        lease_acquired = True
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
        metadata["action_target"] = response_target(Manifest.from_dict(trial_manifest), canonical_action, args.role_assignment_id)
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
                                               "client_secret": client_secret, "scope": token_scope})
                break
            except CredentialHTTPError as exc:
                if exc.status != 401 or exc.code != "invalid_client" or 7000215 not in exc.numeric_codes or attempt == 3:
                    raise
                time.sleep(15)
        credential.clear()
        frozen_token = token_response["access_token"]
        token_response.clear()
        frozen_claims = validate_actor_token(frozen_token, model, audience)
        metadata["frozen_token_metadata"] = {key: frozen_claims.get(key) for key in ("aud", "iat", "exp")}
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        env["STORMLAB_PROBE_TOKEN"] = frozen_token
        common = ["--manifest", str(trial_path), "--subscription", args.subscription]
        probe_common = ["probe", *common, "--capability", args.capability,
                        "--token-env", "STORMLAB_PROBE_TOKEN", "--credential-label", metadata["credential_label"]]
        if args.capability == "arm-tag-write":
            probe_common.append("--allow-mutation")
        baseline = execute_probe_phase([*probe_common, "--interval", "10", "--duration", str(args.baseline_seconds), "--output", str(run_dir / "baseline.jsonl")], env, metadata, run_dir, "baseline")
        # Require actual successful baseline authorization before applying any response.
        if sum(item.get("kind") == "probe" and item.get("outcome") == "allowed" for item in baseline) < 2:
            raise RuntimeError("No successful baseline; response was not applied")
        if args.capability == "blob-read":
            actual_window = observation_window(canonical_action, args.duration, args.until_token_expiry, frozen_claims["exp"])
            metadata["storage_preparation"] = assert_storage_window(manifest, args.storage_baseline_state, time.time() + actual_window["duration_seconds"] + 300)
        metadata["action_requested_at"] = datetime.now(timezone.utc).isoformat()
        save(run_dir / "trial.json", metadata)
        if args.action != "none":
            action_path = private_path(str(run_dir / "action.jsonl"))
            action_args = ["respond", *common, "--action", canonical_action, "--execute", "--confirm-lab-id", manifest["lab_id"], "--output", str(action_path)]
            if args.role_assignment_id:
                action_args.extend(["--role-assignment-id", args.role_assignment_id])
            metadata["action_invocation_started"] = True
            save(run_dir / "trial.json", metadata)
            try:
                if args.action == "manual-executor":
                    # The executor receives no env/token/secret; only the
                    # operator-authenticated adapter changes the configured role.
                    manual_executor_trial.invoke(trial_manifest, args.subscription, args.role_assignment_id, action_path)
                else:
                    invoke_harness(action_args, env)
            finally:
                if action_path.exists():
                    receipts = read_rows(action_path)
                    if len(receipts) != 1 or receipts[0].get("action") != canonical_action:
                        raise RuntimeError("Expected one exact action receipt")
                    metadata["action_receipt"] = {key: receipts[0].get(key) for key in ["action", "status", "http_status", "postcondition_verified", "request_started_at", "acknowledged_at", "target", "mutation_acknowledged", "postcondition_readback"]}
                    if args.action == "manual-executor":
                        metadata["executor_receipt"] = receipts[0].get("executor", {})
                        metadata["action_clock_source"] = receipts[0].get("executor_action", {}).get("clock_source", "unverified")
                        metadata["observation_gap_note"] = receipts[0].get("measurement_limit")
                save(run_dir / "trial.json", metadata)
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
                                         "client_secret": client_secret, "scope": token_scope})
                if "access_token" in separate:
                    issued_claims = validate_actor_token(separate["access_token"], model, audience)
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
        window = observation_window(canonical_action, args.duration, args.until_token_expiry, frozen_claims["exp"])
        metadata["observation_window"] = window
        save(run_dir / "trial.json", metadata)
        post = execute_probe_phase([*probe_common, "--interval", str(interval), "--duration", str(window["duration_seconds"]), "--output", str(run_dir / "post-action.jsonl")], env, metadata, run_dir, "post_action")
        action_rows = read_rows(run_dir / "action.jsonl") if args.action != "none" else []
        summary = summarize_trial(metadata, baseline, action_rows, post)
        if args.action == "manual-executor":
            earlier = [r for r in baseline if r.get("kind") == "probe"][-1]
            later = [r for r in post if r.get("kind") == "probe"]
            gap = (datetime.fromisoformat(later[0]["request_started_at"]) - datetime.fromisoformat(earlier["response_received_at"])).total_seconds() if later else None
            metadata["controller_observation_gap_seconds"] = gap
            summary.update(orchestration_action="manual-executor", response_transport="guarded_logic_app",
                           controller_observation_gap_seconds=gap, executor_outcome=metadata["executor_receipt"].get("response_outcome"),
                           action_clock_source=metadata["action_clock_source"])
        save(private_path(str(run_dir / "summary.json")), summary)
        env.pop("STORMLAB_PROBE_TOKEN", None)
        frozen_token = ""
        metadata["status"] = "observation_completed"
        return 0
    except BaseException as exc:
        metadata["status"] = "interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed_or_incomplete"
        raise
    finally:
        cleanup_error = None
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
            except BaseException as exc:
                cleanup_error = exc
                metadata["credential_removed"] = False
                metadata["cleanup_required"] = "Reconcile the recorded unique credential label/key ID on the owned application"
                metadata["status"] = "interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed_or_incomplete"
        client_secret = ""
        frozen_token = ""
        env.pop("STORMLAB_PROBE_TOKEN", None)
        metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            metadata["source_changed_during_trial"] = any(hashlib.sha256(item.read_bytes()).hexdigest() != metadata["source_hashes"][str(item.relative_to(ROOT))] for item in source_paths)
        except OSError:
            metadata["source_changed_during_trial"] = None
            metadata["source_verification"] = "unverifiable"
        save(run_dir / "trial.json", metadata)
        if lease_acquired:
            try:
                uncertain_action = metadata.get("action_invocation_started") and metadata.get("action_receipt", {}).get("status") in {None, "indeterminate", "accepted_unverified"}
                if args.action == "manual-executor" and metadata.get("action_invocation_started"):
                    uncertain_action = uncertain_action or metadata.get("executor_receipt", {}).get("cleanup_verified") is not True
                finish_trial(manifest, run_id, cleanup_confirmed=(not credential_attempted or metadata["credential_removed"]) and not uncertain_action, outcome=metadata["status"])
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
                metadata["cleanup_required"] = "Reconcile the recorded trial lease and credential state"
                save(run_dir / "trial.json", metadata)
        print(json.dumps({"run_id": run_id, "status": metadata["status"], "credential_removed": metadata["credential_removed"],
                          "evidence": str(run_dir.relative_to(ROOT)), "scope": "one action and one capability; not whole-incident containment"}))
        if isinstance(cleanup_error, (KeyboardInterrupt, SystemExit)):
            raise cleanup_error from None
        if cleanup_error or (credential_attempted and not metadata["credential_removed"]):
            raise RuntimeError("Temporary credential cleanup is unconfirmed; reconcile its recorded key ID")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Trial interrupted; inspect its private cleanup receipt before continuing.", file=sys.stderr)
        raise SystemExit(130)
    except Exception:
        print("Trial stopped; inspect private evidence and cleanup state before continuing.", file=sys.stderr)
        raise SystemExit(1)
