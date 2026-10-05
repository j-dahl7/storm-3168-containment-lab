import copy
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from phase3_link import link
from stormlab.core import Manifest, SafetyError, response_target
from test_core import fixture
from test_evidence_fixes import trial_fixture

TRIAL = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def records():
    _, before, actions, after = trial_fixture([(0, "credential_rejected"), (30, "credential_rejected"), (60, "credential_rejected")])
    for row in before + after:
        row.update(capability="blob-read", auth="shared-key")
        row.pop("token_metadata", None)
    actions[0]["action"] = "rotate-key1"
    actions[0]["target"] = response_target(Manifest.from_dict(fixture()), "rotate-key1")
    return before, actions, after


class Phase3LinkTests(unittest.TestCase):
    def test_separate_channel_phases_share_one_exact_action(self):
        receipt, summary = link(fixture(), TRIAL, *records())
        self.assertEqual(receipt["probe_runs"], {"baseline": "before", "post_action": "after"})
        self.assertEqual(summary["action"], "rotate-key1")
        self.assertTrue(summary["sustained_denial_observed"])

    def test_multiple_responses_cannot_be_one_trial(self):
        before, actions, after = records()
        with self.assertRaises(SafetyError):
            link(fixture(), TRIAL, before, actions * 2, after)

    def test_mismatched_fixed_credential_is_rejected(self):
        before, actions, after = records()
        after[0]["credential_label"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(SafetyError):
            link(fixture(), TRIAL, before, actions, after)

    def test_wrong_storage_target_is_rejected(self):
        before, actions, after = records()
        actions[0]["target"]["storage_resource_id"] += "wrong"
        with self.assertRaises(SafetyError):
            link(fixture(), TRIAL, before, actions, after)
