"""Local concurrency/settling guard; never treats elapsed time as authorization."""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from lab_support import ROOT, save
from stormlab.core import Manifest, SafetyError


def paths():
    private = ROOT / "private"
    return private / "active-trial.json", private / "active-trial.lock", private / "access-state.json"


def read(path: Path) -> dict:
    if path.is_symlink() or path.resolve() != path.absolute():
        raise SafetyError("Trial state must use regular private paths")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise SafetyError("Invalid local trial state")
    return obj


def assert_idle(manifest: dict, *, check_settling: bool = True) -> None:
    m = Manifest.from_dict(manifest)
    marker, lock, access = paths()
    if lock.exists():
        raise SafetyError("A trial/configuration lease remains; reconcile its private receipt before proceeding")
    if marker.exists() and read(marker).get("state") in {"active", "incomplete"}:
        raise SafetyError("A trial is active or incomplete; reconcile before preparation")
    if check_settling and access.exists():
        current = read(access)
        if current.get("lab_id") != m.lab_id or current.get("subscription_id") != m.subscription_id:
            raise SafetyError("Access state belongs to a different lab")
        if current.get("status") != "settling" or not isinstance(current.get("ready_after_epoch"), (int, float)):
            raise SafetyError("Access preparation is incomplete; reconcile before a trial")
        if time.time() < current["ready_after_epoch"]:
            raise SafetyError("Access preparation is still inside its recorded 600-second settling interval")


def begin_trial(manifest: dict, trial_id: str, *, check_settling: bool = True) -> None:
    m = Manifest.from_dict(manifest)
    if not isinstance(trial_id, str) or not trial_id or len(trial_id) > 120:
        raise SafetyError("A bounded local trial ID is required")
    assert_idle(manifest, check_settling=check_settling)
    marker, lock, _ = paths()
    marker.parent.mkdir(parents=True, exist_ok=True)
    state = {"schema_version": 1, "lab_id": m.lab_id, "subscription_id": m.subscription_id,
             "trial_id": trial_id, "state": "active", "started_at": datetime.now(timezone.utc).isoformat()}
    # Exclusive creation prevents two local starts passing a concurrent read.
    with lock.open("x", encoding="utf-8") as handle:
        json.dump(state, handle)
    save(marker, state)


def finish_trial(manifest: dict, trial_id: str, *, cleanup_confirmed: bool, outcome: str) -> None:
    m = Manifest.from_dict(manifest)
    marker, lock, _ = paths()
    state = read(lock)
    if state.get("lab_id") != m.lab_id or state.get("subscription_id") != m.subscription_id or state.get("trial_id") != trial_id:
        raise SafetyError("Only the matching invocation may release its local trial lease")
    state.update(state="finished" if cleanup_confirmed else "incomplete", outcome=outcome,
                 finished_at=datetime.now(timezone.utc).isoformat(), cleanup_confirmed=bool(cleanup_confirmed))
    save(marker, state)
    if cleanup_confirmed:
        lock.unlink()


def record_access_settling(manifest: dict, *, complete: bool) -> dict:
    m = Manifest.from_dict(manifest)
    state = {"schema_version": 1, "lab_id": m.lab_id, "subscription_id": m.subscription_id,
             "status": "settling" if complete else "incomplete", "baseline_required": True,
             "ready_after_epoch": time.time() + 600 if complete else None}
    save(paths()[2], state)
    return state


if __name__ == "__main__":
    import argparse
    import sys
    from lab_support import private_path
    from stormlab.core import load_json
    parser = argparse.ArgumentParser(description="Local manual-trial lease; no cloud calls. Releasing requires stopped probes and verified cleanup.")
    parser.add_argument("operation", choices=["begin", "finish"])
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument("--cleanup-confirmed", action="store_true", help="Explicit assertion that every probe stopped and all recorded cleanup is verified")
    args = parser.parse_args()
    try:
        data = load_json(private_path(args.manifest))
        if args.operation == "begin":
            begin_trial(data, args.trial_id)
        else:
            finish_trial(data, args.trial_id, cleanup_confirmed=args.cleanup_confirmed,
                         outcome="manual_trial_finished" if args.cleanup_confirmed else "manual_cleanup_unconfirmed")
        print("Local trial state recorded; no cloud calls.")
    except (Exception, KeyboardInterrupt):
        print("Local trial state refused; reconcile its private receipt without bypassing an active process.", file=sys.stderr)
        raise SystemExit(1)
