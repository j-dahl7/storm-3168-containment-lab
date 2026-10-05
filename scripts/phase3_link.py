"""Offline linkage of one manually probed credential channel to one action receipt.

No cloud access, credential issuance, response execution or automatic orchestration.
Raw evidence remains unchanged. Run once per channel in the same action cohort.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
from lab_support import ROOT, private_path, save
sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import Manifest, SafetyError, guid, load_json, response_target, summarize_trial


def link(data: dict, trial_id: str, baseline: list[dict], actions: list[dict], post: list[dict]) -> tuple[dict, dict]:
    m = Manifest.from_dict(data)
    guid(trial_id, "cohort trial ID")
    if len(actions) != 1 or actions[0].get("action") not in {"rotate-key1", "rotate-key2", "disable-shared-key"}:
        raise SafetyError("Phase 3 links exactly one selected storage response receipt")
    action = actions[0]
    if action.get("target") != response_target(m, action["action"], None):
        raise SafetyError("Action is not for the exact selected storage account")
    starts = [[r for r in rows if r.get("kind") == "run_start"] for rows in (baseline, post)]
    if any(len(rows) != 1 for rows in starts):
        raise SafetyError("Each channel phase needs exactly one raw run receipt")
    first, second = starts[0][0], starts[1][0]
    for field in ("capability", "auth", "credential_label"):
        if first.get(field) != second.get(field):
            raise SafetyError("Baseline and post-action channel identities differ")
    if first.get("capability") != "blob-read":
        raise SafetyError("Phase 3 links only canary blob reads")
    receipt = {"schema_version": 1, "run_id": trial_id, "capability": "blob-read", "auth": first.get("auth"),
               "credential_label": first.get("credential_label"), "token_refresh": False,
               "action": action["action"], "action_target": action["target"], "access_path": action["target"]["access_path"],
               "action_requested_at": action.get("request_started_at"), "action_returned_at": action.get("acknowledged_at"),
               "action_receipt": {k: action.get(k) for k in ("action", "status", "http_status", "postcondition_verified", "request_started_at", "acknowledged_at", "target")},
               "frozen_token_metadata": first.get("token_metadata"),
               "probe_runs": {"baseline": first.get("run_id"), "post_action": second.get("run_id")},
               "observation_window": {"mode": "manual_fixed_window", "maximum_seconds": 7200},
               "orchestration": "manual; independently verify unchanged credentials and concurrent healthy control",
               "location": m.location}
    return receipt, summarize_trial(receipt, baseline, actions, post)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "baseline", "action-receipt", "post", "output"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--trial-id", required=True)
    a = p.parse_args(argv)
    sources = {name: private_path(getattr(a, name)) for name in ("manifest", "baseline", "action_receipt", "post")}
    output = private_path(a.output)
    if output.exists():
        raise SafetyError("Refusing to overwrite linked evidence")
    rows = lambda path: [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    receipt, summary = link(load_json(sources["manifest"]), a.trial_id, rows(sources["baseline"]), rows(sources["action_receipt"]), rows(sources["post"]))
    hashes = {name: {"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in sources.items()}
    save(output, {"receipt": receipt, "summary": summary, "source_files": hashes, "cloud_calls": False})
    print("Saved private offline channel linkage; no cloud calls or new measurements.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print("Phase 3 linkage stopped; inspect raw private phase/action receipts. No source evidence was changed.", file=sys.stderr)
        raise SystemExit(1)
