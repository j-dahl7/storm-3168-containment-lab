import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import trial_state
from stormlab.core import SafetyError


class TrialStateTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "config/manifest.example.json").read_text())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        def save(path, data):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
        for name, value in (("ROOT", self.root), ("save", save)):
            p = patch.object(trial_state, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_concurrent_start_is_refused(self):
        trial_state.begin_trial(self.data, "first")
        with self.assertRaises(SafetyError):
            trial_state.begin_trial(self.data, "second")

    def test_confirmed_cleanup_releases_exact_lease(self):
        trial_state.begin_trial(self.data, "first")
        trial_state.finish_trial(self.data, "first", cleanup_confirmed=True, outcome="completed")
        trial_state.assert_idle(self.data)
        self.assertEqual(trial_state.read(trial_state.paths()[0])["state"], "finished")

    def test_incomplete_cleanup_does_not_unlock(self):
        trial_state.begin_trial(self.data, "first")
        trial_state.finish_trial(self.data, "first", cleanup_confirmed=False, outcome="interrupted")
        with self.assertRaises(SafetyError):
            trial_state.assert_idle(self.data)

    def test_other_trial_cannot_unlock(self):
        trial_state.begin_trial(self.data, "first")
        with self.assertRaises(SafetyError):
            trial_state.finish_trial(self.data, "second", cleanup_confirmed=True, outcome="completed")
        self.assertTrue(trial_state.paths()[1].exists())

    def test_settling_gate_blocks_then_requires_actual_baseline(self):
        with patch.object(trial_state.time, "time", return_value=1000):
            state = trial_state.record_access_settling(self.data, complete=True)
            with self.assertRaises(SafetyError):
                trial_state.begin_trial(self.data, "too-early")
        with patch.object(trial_state.time, "time", return_value=1601):
            trial_state.begin_trial(self.data, "after-settling")
        self.assertTrue(state["baseline_required"])

    def test_incomplete_access_state_refuses_trial(self):
        trial_state.record_access_settling(self.data, complete=False)
        with self.assertRaises(SafetyError):
            trial_state.begin_trial(self.data, "trial")
