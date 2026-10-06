"""Offline, sanitized publication candidates from explicitly selected trial files.

Nothing is accepted without a separately reviewed private allowlist. This tool
never queries Azure, accepts a run automatically, or edits source evidence.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stormlab.core import (ACTIONS, CAPABILITIES, DENIAL_OUTCOMES, Manifest, SafetyError,
                          evidence_time, response_target, summarize_trial)

REVIEWER = "Codex operator evidence review"
FILES = ("trial.json", "manifest.json", "baseline.jsonl", "action.jsonl", "post-action.jsonl")
HEX = re.compile(r"[0-9a-f]{64}")
OUTCOMES = {"allowed", "expired", "authorization_denied", "lock_denied", "credential_rejected",
            "transport_error", "throttled", "service_error", "redirect_blocked", "precondition_failed",
            "guard_read_inconclusive", "schedule_gap", "write_accepted_unverified", "network_policy_denied",
            "authorization_unattributed", "authentication_or_unknown_denial", "unknown"}


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def private_input(path: Path) -> Path:
    result = path.resolve(strict=True)
    if "private" not in {part.name for part in result.parents}:
        raise SafetyError("Evidence and review input must be explicit private files")
    return result


def parse(raw: bytes):
    return json.loads(raw.decode("utf-8-sig"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def source_digest(receipt: dict) -> str | None:
    hashes = receipt.get("source_hashes")
    if not isinstance(hashes, dict) or not hashes:
        return None
    if any(not isinstance(k, str) or not re.fullmatch(r"(?:src|scripts|playbooks)/[A-Za-z0-9_./-]+", k.replace("\\", "/"))
           or ".." in k.replace("\\", "/").split("/") or not isinstance(v, str) or not HEX.fullmatch(v) for k, v in hashes.items()):
        return None
    return digest(hashes)


def verify_git_blobs(receipt: dict, repository: Path | None) -> str:
    """Local Git only. Accept equivalent LF/CRLF checkout bytes explicitly."""
    if repository is None:
        return "not_checked"
    revision = receipt.get("source_commit", "")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision) or source_digest(receipt) is None:
        return "unavailable"
    normalized = False
    for name, expected in receipt["source_hashes"].items():
        try:
            result = subprocess.run(["git", "-C", str(repository.resolve()), "cat-file", "blob", revision + ":" + name.replace("\\", "/")],
                                    capture_output=True, timeout=10, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"
        if result.returncode:
            return "unavailable"
        if hashlib.sha256(result.stdout).hexdigest() == expected:
            continue
        # Source receipts hash checkout bytes; Git commonly stores LF on Windows.
        if hashlib.sha256(result.stdout.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")).hexdigest() == expected:
            normalized = True
        else:
            # A clean Windows checkout can contain mixed LF/CRLF after patching.
            # Its arbitrary mixture cannot be reconstructed from a Git blob
            # hash. Use actual checkout bytes only when they exactly match the
            # recorded raw hash, then compare normalized content with Git.
            try:
                current = repository.resolve() / name.replace("\\", "/")
                if current.stat().st_size > 5_000_000:
                    return "unavailable"
                recorded_bytes = current.read_bytes()
            except OSError:
                return "unavailable"
            if hashlib.sha256(recorded_bytes).hexdigest() != expected:
                return "unavailable"
            if recorded_bytes.replace(b"\r\n", b"\n") != result.stdout.replace(b"\r\n", b"\n"):
                return "mismatch"
            normalized = True
    return "verified_with_checkout_line_endings" if normalized else "verified"


def review_entries(review: dict | None) -> dict:
    if review is None:
        return {}
    if review.get("schema_version") != 1 or review.get("reviewer") != REVIEWER or not isinstance(review.get("runs"), list):
        raise SafetyError("Review allowlist must identify the explicit operator evidence review")
    entries, labels = {}, set()
    for row in review["runs"]:
        identity, label = row.get("run_id"), row.get("public_label")
        if (not isinstance(identity, str) or identity in entries or not isinstance(label, str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,31}", label) or label in labels):
            raise SafetyError("Review identities and public pseudonyms must be unique")
        entries[identity] = row
        labels.add(label)
    return entries


def classification(receipt: dict) -> tuple[str, str]:
    action, capability, path = receipt.get("action"), receipt.get("capability"), receipt.get("access_path")
    if action == "none":
        return "implementation-control", "no-action-control"
    if action == "role-delete":
        if receipt.get("orchestration_action") == "manual-executor" or receipt.get("response_transport") == "guarded_logic_app":
            return "CORE09", "manual-executor-role-removal"
        return ("CORE02", "direct-role-removal") if path == "direct_role_assignment" else ("CORE03", "group-role-removal") if path == "group_role_assignment" else ("unmapped", "unknown")
    mapping = {"group-member-remove": ("CORE04", "group-membership-removal"),
               "sp-disable": ("CORE12", "service-principal-disable") if capability == "blob-read" else ("CORE05", "service-principal-disable"),
               "secret-remove": ("CORE06", "tested-secret-removal"), "app-deactivate": ("extended", "application-deactivation")}
    return mapping.get(action, ("unmapped", "unknown"))


def request_fact(row: dict | None, anchor: float) -> dict | None:
    if row is None:
        return None
    began = evidence_time(row.get("request_started_at", row.get("timestamp")))
    ended = evidence_time(row.get("response_received_at", row.get("timestamp")))
    return {"request_started_at": datetime.fromtimestamp(began, timezone.utc).isoformat(),
            "response_received_at": datetime.fromtimestamp(ended, timezone.utc).isoformat(),
            "request_seconds_after_action_ack": round(began - anchor, 6),
            "response_seconds_after_action_ack": round(ended - anchor, 6)}


def assess(path: Path, index: int, entries: dict, repository: Path | None) -> tuple[dict, dict, tuple | None]:
    path = private_input(path)
    if path.name != "trial.json":
        raise SafetyError("This builder currently requires live_trial trial.json receipts")
    if any((path.parent / name).is_file() and (path.parent / name).stat().st_size > 20_000_000 for name in FILES):
        raise SafetyError("Evidence file exceeds the offline size limit")
    raw = {name: (path.parent / name).read_bytes() if (path.parent / name).is_file() else None for name in FILES}
    receipt = parse(raw["trial.json"])
    identity = receipt.get("run_id")
    entry = entries.get(identity, {})
    label = entry.get("public_label", f"attempt-{index:03d}")
    hashes = {name: hashlib.sha256(value).hexdigest() if value is not None else None for name, value in raw.items()}
    code_digest = source_digest(receipt)
    bundle = digest(hashes)
    candidate = {"run_id": identity, "public_label": label, "operator_reviewed": False, "decision": "pending",
                 "evidence_sha256": hashes, "source_hashes_sha256": code_digest,
                 "credential_identity_sha256": digest(receipt.get("credential_label"))}
    case, variant = classification(receipt)
    outcome = receipt.get("status")
    completion = outcome if outcome in {"observation_completed", "failed_or_incomplete", "interrupted", "started"} else "unknown"
    result = {"label": label, "credential": label + "-credential", "case": case, "configuration": variant,
              "capability": receipt.get("capability") if receipt.get("capability") in CAPABILITIES else "unknown",
              "auth": receipt.get("auth") if receipt.get("auth") in {"bearer", "sas", "shared-key"} else "unknown",
              "completion": completion, "publication_status": "unreviewed", "reasons": [],
              "evidence_bundle_sha256": bundle, "source_hashes_sha256": code_digest,
              "source_revision": receipt.get("source_commit") if re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("source_commit", ""))) else None,
              "cleanup_verified": receipt.get("credential_removed") is True}
    reasons = result["reasons"]
    if receipt.get("mode") != "live": reasons.append("not_live_evidence")
    if completion != "observation_completed": reasons.append("trial_incomplete")
    if receipt.get("token_refresh") is not False: reasons.append("frozen_credential_unverified")
    if receipt.get("source_changed_during_trial") is not False or code_digest is None: reasons.append("source_integrity_unverified")
    if not result["cleanup_verified"]: reasons.append("credential_cleanup_unverified")
    if case == "unmapped": reasons.append("configuration_unmapped")
    if receipt.get("action") in {"role-delete", "group-member-remove"} and receipt.get("capability") == "arm-read": reasons.append("invalid_writer_measurement")
    source_check = verify_git_blobs(receipt, repository) if code_digest and completion == "observation_completed" else "not_checked"
    result["git_blob_verification"] = source_check
    if source_check == "mismatch": reasons.append("source_commit_mismatch")
    summary, comparable = None, None
    try:
        model = Manifest.from_dict(parse(raw["manifest.json"]))
        phases = {name: [parse(line) for line in raw[name].splitlines() if line.strip()] if raw[name] else [] for name in ("baseline.jsonl", "action.jsonl", "post-action.jsonl")}
        baseline, actions, post = (phases[name] for name in ("baseline.jsonl", "action.jsonl", "post-action.jsonl"))
        result["baseline_allowed_count"] = sum(row.get("kind") == "probe" and row.get("outcome") == "allowed" for row in baseline)
        result["post_action_counts"] = {key: sum(row.get("kind") == "probe" and row.get("outcome") == key for row in post) for key in OUTCOMES if any(row.get("kind") == "probe" and row.get("outcome") == key for row in post)}
        assignment = receipt.get("action_target", {}).get("role_assignment_id")
        if receipt.get("action_target") != response_target(model, receipt["action"], assignment):
            raise SafetyError("Recorded target mismatch")
        for phase, rows in (("baseline", baseline), ("post_action", post)):
            ends = [row for row in rows if row.get("kind") == "run_end" and row.get("run_id") == receipt.get("probe_runs", {}).get(phase)]
            if len(ends) != 1 or ends[0].get("status") != "completed": reasons.append(phase + "_incomplete")
        if receipt["action"] != "none":
            if len(actions) != 1 or actions[0].get("postcondition_verified") is not True or actions[0].get("status") != "configuration_verified_capability_unproven":
                reasons.append("action_configuration_unverified")
            if case == "CORE09" and (receipt.get("executor_receipt", {}).get("cleanup_verified") is not True or
                    receipt.get("executor_receipt", {}).get("response_outcome") != "role_assignment_removed_access_unverified"):
                reasons.append("executor_execution_or_cleanup_unverified")
        summary = summarize_trial(receipt, baseline, actions, post)
        anchor = evidence_time(actions[0].get("acknowledged_at")) if actions else evidence_time(receipt.get("action_returned_at"))
        action_started = evidence_time(actions[0].get("request_started_at")) if actions else anchor
        probes = [r for r in baseline + post if r.get("kind") == "probe"]
        post_probes = [r for r in post if r.get("kind") == "probe"]
        qualified = [x for x in summary["denial_intervals"] if x["sustained"]]
        first = next((r for r in post_probes if qualified and r.get("outcome") == qualified[0]["outcome"] and
                      abs(evidence_time(r.get("request_started_at", r.get("timestamp"))) - anchor - qualified[0]["first_observed_seconds"]) < 0.00001), None)
        cutoff = evidence_time(first.get("request_started_at", first.get("timestamp"))) if first else float("inf")
        last_allowed = next((r for r in reversed(probes) if r.get("outcome") == "allowed" and evidence_time(r.get("request_started_at", r.get("timestamp"))) < cutoff), None)
        left, right = request_fact(last_allowed, anchor), request_fact(first, anchor)
        gaps = [r for r in post_probes if r.get("outcome") not in DENIAL_OUTCOMES | {"allowed", "expired"}]
        known_counts = {key: value for key, value in summary["outcomes"].items() if key in OUTCOMES}
        issuance = receipt.get("separate_new_token_check", {})
        issuance_status = issuance.get("status", "not_requested")
        if issuance_status not in {"not_requested", "issued", "provider_rejected", "rejected", "unknown_response", "transport_error_or_unknown", "service_error_or_unknown"}: issuance_status = "unknown"
        if issuance and issuance.get("replaces_probe_token") is not False: reasons.append("issuance_control_separation_unverified")
        interval = {"lower": left["request_seconds_after_action_ack"], "upper": right["response_seconds_after_action_ack"]} if left and right else None
        result.update(action_requested_at=datetime.fromtimestamp(action_started, timezone.utc).isoformat(),
                      action_acknowledged_at=datetime.fromtimestamp(anchor, timezone.utc).isoformat(),
                      baseline_allowed_count=sum(r.get("kind") == "probe" and r.get("outcome") == "allowed" for r in baseline),
                      post_action_counts=known_counts, last_allowed=left, first_denial_in_qualified_series=right,
                      observed_interval_seconds=interval, observation_end_reason=summary["observation_end_reason"],
                      expiry_observed=any(r.get("outcome") == "expired" for r in post_probes),
                      denial_onset_right_censored=summary["denial_onset_right_censored"], gap_count=len(gaps),
                      prerequisite_credential_rejection_observed=summary.get("prerequisite_credential_rejection_observed", False),
                      new_token_check={"status": issuance_status, "one_shot": issuance_status != "not_requested", "replaced_fixed_token": False},
                      action_causality="not_established_by_summary")
        # Unknown samples/gaps and a capped window exclude numeric aggregation.
        result["uncensored_interval"] = bool(interval and not gaps and not receipt.get("observation_window", {}).get("expiry_window_capped") and case != "implementation-control")
        action_shape = {k: v for k, v in receipt["action_target"].items() if k not in {"role_assignment_id", "credential_key_id"}}
        comparable = (case, variant, receipt["capability"], receipt["auth"], model.location, code_digest,
                      digest(action_shape), model.storage_id, receipt.get("observation_window", {}).get("mode"), receipt.get("probe_interval_seconds"))
    except (SafetyError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        reasons.append("phase_linkage_or_schema_unverified")
    if entry.get("operator_reviewed") is True and entry.get("decision") == "accepted":
        if entry.get("evidence_sha256") != hashes: reasons.append("reviewed_evidence_hash_mismatch")
        if entry.get("source_hashes_sha256") != code_digest or not code_digest: reasons.append("reviewed_source_hash_mismatch")
        result["publication_status"] = "accepted" if not reasons else "rejected"
    elif entry.get("decision") == "rejected":
        result["publication_status"] = "rejected"
        reasons.append("operator_rejected")
    result["reasons"] = sorted(set(reasons))
    return result, candidate, comparable


def build_report(paths: list[Path], review: dict | None = None, repository: Path | None = None) -> tuple[dict, dict]:
    entries = review_entries(review)
    report = {"schema_version": 1, "status": "candidate_not_publication_approval", "reviewer": REVIEWER,
              "implementation_checks": [], "accepted_trials": [], "unreviewed_trials": [], "failed_or_incomplete_trials": [], "rejected_trials": [], "aggregates": []}
    pending = {"schema_version": 1, "reviewer": REVIEWER, "runs": []}
    seen, labels, groups = set(), set(), {}
    for index, path in enumerate(paths, 1):
        result, candidate, key = assess(path, index, entries, repository)
        if candidate["run_id"] in seen or result["label"] in labels:
            raise SafetyError("Duplicate trial identity or public pseudonym")
        seen.add(candidate["run_id"]); labels.add(result["label"])
        pending["runs"].append(candidate)
        if result["completion"] != "observation_completed": bucket = "failed_or_incomplete_trials"
        elif result["publication_status"] == "accepted" and result["case"] == "implementation-control": bucket = "implementation_checks"
        else: bucket = {"accepted": "accepted_trials", "unreviewed": "unreviewed_trials", "rejected": "rejected_trials"}[result["publication_status"]]
        report[bucket].append(result)
        if bucket == "accepted_trials" and key:
            groups.setdefault(key, []).append((result, candidate["credential_identity_sha256"]))
    for key, rows in groups.items():
        frequencies = {identity: sum(other == identity for _, other in rows) for _, identity in rows}
        usable = [result for result, identity in rows if result.get("uncensored_interval") and frequencies[identity] == 1]
        aggregate = {"case": key[0], "configuration": key[1], "capability": key[2], "auth": key[3],
                     "accepted_trials": len(rows), "comparable_uncensored_trials": len(usable), "median_observed_interval_seconds": None,
                     "duplicate_credential_trials_excluded": sum(frequencies[identity] > 1 for _, identity in rows),
                     "labels": [result["label"] for result, _ in rows]}
        if len(usable) >= 3:
            aggregate["median_observed_interval_seconds"] = {bound: statistics.median(result["observed_interval_seconds"][bound] for result in usable) for bound in ("lower", "upper")}
        report["aggregates"].append(aggregate)
    report["limits"] = ["No-action controls are implementation checks, not response trials.",
                        "Expiry is an observation boundary, not action-caused denial. Gaps are inconclusive.",
                        "Interval bounds use last-allowed request start and first-denied response receipt; they are not an exact revocation instant.",
                        "Medians require three comparable uncensored accepted trials. One-shot issuance checks do not measure issuance propagation.",
                        "This adapter supports live_trial receipts; storage cohort receipts need a separately reviewed adapter."]
    return report, pending


def markdown(report: dict) -> str:
    lines = ["# Candidate measurement report", "", "Operator evidence review: " + REVIEWER + ". This file is not publication approval.", ""]
    for field, title in (("implementation_checks", "Reviewed implementation checks"), ("accepted_trials", "Accepted response trials"), ("unreviewed_trials", "Unreviewed observations"), ("failed_or_incomplete_trials", "Failed or incomplete attempts"), ("rejected_trials", "Rejected evidence")):
        lines += ["## " + title, "", "| Label | Case / configuration | Capability | Observed interval (seconds after action ACK) | Gaps |", "|---|---|---|---|---|"]
        for row in report[field]:
            span = row.get("observed_interval_seconds")
            display = f"({span['lower']}, {span['upper']}]" if span else "Not established"
            lines.append(f"| {row['label']} | {row['case']} / {row['configuration']} | {row['capability']} | {display} | {row.get('gap_count', 'not observed')} |")
        if not report[field]: lines.append("| None | | | | |")
        lines.append("")
    lines += ["## Aggregate intervals", ""]
    for row in report["aggregates"]:
        median = row["median_observed_interval_seconds"]
        lines.append(f"- {row['case']} / {row['capability']}: " + (f"median interval ({median['lower']}, {median['upper']}] seconds from {row['comparable_uncensored_trials']} comparable uncensored trials." if median else "No numeric median; fewer than three comparable uncensored accepted trials."))
    if not report["aggregates"]: lines.append("No accepted comparable response series.")
    lines += ["", "## Interpretation limits", ""] + ["- " + note for note in report["limits"]]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trial", required=True, action="append", type=Path)
    p.add_argument("--review-allowlist", type=Path)
    p.add_argument("--source-repository", type=Path, help="Optional local Git repository for blob/hash verification; never fetched")
    p.add_argument("--output-json", required=True, type=Path)
    p.add_argument("--output-markdown", required=True, type=Path)
    p.add_argument("--pending-review-output", type=Path, help="Optional PRIVATE pending review template containing raw run IDs/hashes; never accepted automatically")
    a = p.parse_args(argv)
    review = parse(private_input(a.review_allowlist).read_bytes()) if a.review_allowlist else None
    outputs = [a.output_json, a.output_markdown] + ([a.pending_review_output] if a.pending_review_output else [])
    if len({path.resolve() for path in outputs}) != len(outputs) or any(path.exists() for path in outputs):
        raise SafetyError("Use distinct new output files; evidence is never overwritten")
    if a.pending_review_output and "private" not in {part.name for part in a.pending_review_output.resolve().parents}:
        raise SafetyError("Pending review templates contain identifiers and must remain private")
    report, pending = build_report(a.trial, review, a.source_repository)
    for path in outputs: path.parent.mkdir(parents=True, exist_ok=True)
    a.output_json.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    a.output_markdown.write_text(markdown(report), encoding="utf-8")
    if a.pending_review_output: a.pending_review_output.write_text(json.dumps(pending, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({key: len(report[key]) for key in ("implementation_checks", "accepted_trials", "unreviewed_trials", "failed_or_incomplete_trials", "rejected_trials")}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print("Results build stopped; inspect private input integrity. No source evidence was changed.", file=sys.stderr)
        raise SystemExit(1)
