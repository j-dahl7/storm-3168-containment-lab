"""Offline publication gates and interval regressions with fabricated receipts."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_results as builder
from stormlab.core import Manifest, SafetyError, response_target
from test_core import fixture
from test_evidence_fixes import trial_fixture


class ResultsBuilderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "private"
        self.root.mkdir()

    def tearDown(self):
        self.directory.cleanup()

    def trial(self, *, first=10, outcomes=None, action="sp-disable", group=False, manual=False, source="a" * 64, status="observation_completed"):
        receipt, baseline, actions, post = trial_fixture(outcomes or [(first, "authorization_denied"), (first+30, "authorization_denied"), (first+60, "authorization_denied")])
        identity, credential = str(uuid.uuid4()), str(uuid.uuid4())
        data = fixture()
        if group:
            data["role_assignments"][0]["principal_id"] = data["group"]["object_id"]
        assignment = data["role_assignments"][0]["id"] if action == "role-delete" else None
        target = response_target(Manifest.from_dict(data), action, assignment)
        receipt.update(run_id=identity, credential_label=credential, mode="live", status=status,
                       action=action, access_path=target["access_path"], action_target=target, credential_removed=True,
                       source_changed_during_trial=False, source_commit="b" * 40, source_hashes={"src\\stormlab\\core.py": source},
                       observation_window={"mode": "until_token_expiry", "expiry_window_capped": False}, probe_interval_seconds=30,
                       separate_new_token_check={"status": "provider_rejected", "replaces_probe_token": False},
                       private_note="DO_NOT_PUBLISH_SECRET_OR_PROVIDER_BODY")
        for rows in (baseline, post):
            for row in rows: row["credential_label"] = credential
            rows.append({"kind": "run_end", "run_id": rows[0]["run_id"], "status": "completed"})
        if action == "none":
            actions = []
            receipt.pop("action_receipt", None)
            receipt["action_returned_at"] = "2026-01-01T00:00:00+00:00"
        else:
            actions[0].update(action=action, target=target)
            receipt["action_receipt"] = copy.deepcopy(actions[0])
        if manual:
            receipt.update(orchestration_action="manual-executor", response_transport="guarded_logic_app",
                           executor_receipt={"cleanup_verified": True, "response_outcome": "role_assignment_removed_access_unverified"})
        folder = self.root / identity
        folder.mkdir()
        (folder / "trial.json").write_text(json.dumps(receipt), encoding="utf-8")
        (folder / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
        for name, rows in (("baseline.jsonl", baseline), ("action.jsonl", actions), ("post-action.jsonl", post)):
            if rows: (folder / name).write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
        return folder / "trial.json"

    def approve(self, paths):
        _, pending = builder.build_report(paths)
        for i, row in enumerate(pending["runs"], 1):
            row.update(operator_reviewed=True, decision="accepted", public_label=f"reviewed-{i:02d}")
        return pending

    def test_no_allowlist_means_zero_accepted_even_for_valid_receipts(self):
        report, pending = builder.build_report([self.trial()])
        self.assertEqual(report["accepted_trials"], [])
        self.assertEqual(len(report["unreviewed_trials"]), 1)
        self.assertFalse(pending["runs"][0]["operator_reviewed"])
        self.assertEqual(pending["runs"][0]["decision"], "pending")

    def test_reviewed_and_pinned_trial_is_accepted_without_private_identifiers(self):
        path = self.trial()
        report, _ = builder.build_report([path], self.approve([path]))
        self.assertEqual(len(report["accepted_trials"]), 1)
        rendered = json.dumps(report) + builder.markdown(report)
        receipt, data = json.loads(path.read_text()), fixture()
        for secret in [receipt["run_id"], receipt["credential_label"], data["tenant_id"], data["subscription_id"], data["actor"]["client_id"], "DO_NOT_PUBLISH_SECRET_OR_PROVIDER_BODY", str(path)]:
            self.assertNotIn(secret, rendered)
        row = report["accepted_trials"][0]
        self.assertEqual(row["observed_interval_seconds"], {"lower": -30.0, "upper": 10.0})
        self.assertEqual(row["new_token_check"]["status"], "provider_rejected")
        self.assertTrue(row["new_token_check"]["one_shot"])

    def test_no_numeric_median_before_three_comparable_trials(self):
        paths = [self.trial(first=value) for value in (10, 20, 30)]
        for count in (1, 2):
            report, _ = builder.build_report(paths[:count], self.approve(paths[:count]))
            self.assertIsNone(report["aggregates"][0]["median_observed_interval_seconds"])
        report, _ = builder.build_report(paths, self.approve(paths))
        self.assertEqual(report["aggregates"][0]["median_observed_interval_seconds"], {"lower": -30.0, "upper": 20.0})

    def test_expiry_is_censoring_not_a_denial_even_with_three_accepted_trials(self):
        paths = [self.trial(outcomes=[(0, "allowed"), (30, "allowed"), (60, "expired")]) for _ in range(3)]
        report, _ = builder.build_report(paths, self.approve(paths))
        self.assertEqual(len(report["accepted_trials"]), 3)
        self.assertIsNone(report["aggregates"][0]["median_observed_interval_seconds"])
        for row in report["accepted_trials"]:
            self.assertTrue(row["denial_onset_right_censored"])
            self.assertTrue(row["expiry_observed"])
            self.assertIsNone(row["first_denial_in_qualified_series"])

    def test_gap_preserves_interval_but_excludes_numeric_aggregation(self):
        paths = [self.trial(outcomes=[(0, "authorization_denied"), (10, "transport_error"), (30, "authorization_denied"), (60, "authorization_denied")]) for _ in range(3)]
        report, _ = builder.build_report(paths, self.approve(paths))
        self.assertEqual(report["accepted_trials"][0]["gap_count"], 1)
        self.assertIsNotNone(report["accepted_trials"][0]["observed_interval_seconds"])
        self.assertEqual(report["aggregates"][0]["comparable_uncensored_trials"], 0)

    def test_source_or_capability_changes_do_not_get_combined_into_a_median(self):
        paths = [self.trial(source=value * 64) for value in ("a", "b", "c")]
        report, _ = builder.build_report(paths, self.approve(paths))
        self.assertEqual(len(report["aggregates"]), 3)
        self.assertTrue(all(row["median_observed_interval_seconds"] is None for row in report["aggregates"]))

    def test_evidence_change_after_operator_review_is_rejected(self):
        path = self.trial()
        review = self.approve([path])
        with (path.parent / "post-action.jsonl").open("a") as handle: handle.write("\n")
        report, _ = builder.build_report([path], review)
        self.assertEqual(report["accepted_trials"], [])
        self.assertIn("reviewed_evidence_hash_mismatch", report["rejected_trials"][0]["reasons"])

    def test_cleanup_source_or_token_failure_cannot_be_overridden_by_review(self):
        for field, value in (("credential_removed", False), ("source_changed_during_trial", True), ("token_refresh", True)):
            path = self.trial()
            receipt = json.loads(path.read_text()); receipt[field] = value
            path.write_text(json.dumps(receipt))
            report, _ = builder.build_report([path], self.approve([path]))
            self.assertEqual(report["accepted_trials"], [])
            self.assertEqual(len(report["rejected_trials"]), 1)

    def test_no_action_is_an_implementation_check_not_core05(self):
        path = self.trial(action="none", outcomes=[(0, "allowed"), (30, "allowed")])
        report, _ = builder.build_report([path], self.approve([path]))
        self.assertEqual(report["accepted_trials"], [])
        self.assertEqual(report["implementation_checks"][0]["case"], "implementation-control")
        self.assertEqual(report["aggregates"], [])

    def test_direct_group_and_manual_executor_are_distinct(self):
        paths = [self.trial(action="role-delete"), self.trial(action="role-delete", group=True), self.trial(action="role-delete", manual=True)]
        report, _ = builder.build_report(paths, self.approve(paths))
        self.assertEqual({row["case"] for row in report["accepted_trials"]}, {"CORE02", "CORE03", "CORE09"})
        self.assertEqual(len(report["aggregates"]), 3)

    def test_failed_attempts_are_separate_even_if_review_requests_acceptance(self):
        path = self.trial(status="failed_or_incomplete")
        (path.parent / "post-action.jsonl").unlink()
        report, _ = builder.build_report([path], self.approve([path]))
        self.assertEqual(len(report["failed_or_incomplete_trials"]), 1)
        self.assertEqual(report["accepted_trials"], [])

    def test_git_blob_comparison_handles_windows_source_paths_and_crlf(self):
        content = b"print('fixture')\n"
        receipt = {"source_commit": "b" * 40, "source_hashes": {"src\\stormlab\\core.py": hashlib.sha256(content.replace(b"\n", b"\r\n")).hexdigest()}}
        with patch.object(builder.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=content)) as git:
            self.assertEqual(builder.verify_git_blobs(receipt, self.root), "verified_with_checkout_line_endings")
        self.assertTrue(git.call_args.args[0][-1].endswith(":src/stormlab/core.py"))
        current = self.root / "src/stormlab/core.py"
        current.parent.mkdir(parents=True)
        current.write_bytes(content.replace(b"\n", b"\r\n"))
        with patch.object(builder.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"different")):
            self.assertEqual(builder.verify_git_blobs(receipt, self.root), "mismatch")

    def test_mixed_checkout_line_endings_are_verified_using_recorded_raw_bytes(self):
        content, mixed = b"first\nsecond\nthird\n", b"first\r\nsecond\nthird\r\n"
        current = self.root / "scripts/playbook_lab.py"
        current.parent.mkdir(parents=True)
        current.write_bytes(mixed)
        receipt = {"source_commit": "b" * 40, "source_hashes": {"scripts\\playbook_lab.py": hashlib.sha256(mixed).hexdigest()}}
        with patch.object(builder.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=content)):
            self.assertEqual(builder.verify_git_blobs(receipt, self.root), "verified_with_checkout_line_endings")
            current.write_bytes(b"changed since trial\n")
            self.assertEqual(builder.verify_git_blobs(receipt, self.root), "unavailable")

    def test_expiry_after_qualified_denial_does_not_erase_the_observed_onset(self):
        path = self.trial(outcomes=[(0, "authorization_denied"), (30, "authorization_denied"), (60, "authorization_denied"), (90, "expired")])
        report, _ = builder.build_report([path], self.approve([path]))
        row = report["accepted_trials"][0]
        self.assertTrue(row["expiry_observed"])
        self.assertFalse(row["denial_onset_right_censored"])
        self.assertEqual(row["observed_interval_seconds"]["upper"], 0)

    def test_reused_credential_labels_are_not_independent_for_medians(self):
        paths = [self.trial() for _ in range(3)]
        label = json.loads(paths[0].read_text())["credential_label"]
        for path in paths[1:]:
            receipt = json.loads(path.read_text()); receipt["credential_label"] = label
            path.write_text(json.dumps(receipt))
            for name in ("baseline.jsonl", "post-action.jsonl"):
                rows = [json.loads(line) for line in (path.parent / name).read_text().splitlines()]
                for row in rows:
                    if "credential_label" in row: row["credential_label"] = label
                (path.parent / name).write_text("\n".join(json.dumps(row) for row in rows))
        report, _ = builder.build_report(paths, self.approve(paths))
        self.assertEqual(report["aggregates"][0]["duplicate_credential_trials_excluded"], 3)
        self.assertIsNone(report["aggregates"][0]["median_observed_interval_seconds"])

    def test_review_does_not_override_known_git_blob_mismatch(self):
        path = self.trial()
        review = self.approve([path])
        with patch.object(builder, "verify_git_blobs", return_value="mismatch"):
            report, _ = builder.build_report([path], review, self.root)
        self.assertEqual(report["accepted_trials"], [])
        self.assertIn("source_commit_mismatch", report["rejected_trials"][0]["reasons"])


if __name__ == "__main__":
    unittest.main()
