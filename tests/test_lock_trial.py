"""CORE11 lock freshness and capability pairing; no provider calls."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'src'))
from lock_trial import fresh_readonly_lock
from live_trial import validate_pairing, observation_window
from stormlab.core import Manifest, Guard, Response, SafetyError, classify
from test_core import fixture


class FakeGuard:
    def __init__(self, model):
        self.m, self.calls, self.inventory = model, [], {'value': []}
        self.lock = Response(404)
    def ownership(self): pass
    def actor(self): pass
    checked = staticmethod(Guard.checked)
    def read(self, service, path):
        self.calls.append((service, path))
        return self.lock if path.startswith(self.m.lock_id + '?') else Response(200, json.dumps(self.inventory).encode())


class LockTrialTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.m = Manifest.from_dict(self.data)
        self.guard = FakeGuard(self.m)

    def test_exact_fresh_lock_is_recorded_without_mutation_or_unlock(self):
        evidence = fresh_readonly_lock(self.data, self.m.subscription_id, guard=self.guard)
        self.assertEqual(evidence['lock_id'], self.m.lock_id)
        self.assertEqual(evidence['scope'], self.m.storage_id)
        self.assertEqual(evidence['expected_level'], 'ReadOnly')
        self.assertTrue(evidence['absence_verified'])
        self.assertEqual(evidence['cleanup_policy'], 'manual_explicit_lock_remove_only')
        self.assertEqual(len(self.guard.calls), 3)

    def test_existing_foreign_or_owned_lock_blocks_new_trial(self):
        for notes in ('foreign', 'storm3168LabId=' + self.m.lab_id):
            self.guard.lock = Response(200, json.dumps({'id': self.m.lock_id, 'properties': {'notes': notes, 'level': 'ReadOnly'}}).encode())
            with self.assertRaises(SafetyError):
                fresh_readonly_lock(self.data, self.m.subscription_id, guard=self.guard)

    def test_partial_inventory_and_unknown_absence_never_allow_creation(self):
        for inventory in ({'value': [{}]}, {'value': [], 'nextLink': 'ignored'}, {}, {'value': None}):
            self.guard.inventory = inventory
            with self.assertRaises(SafetyError):
                fresh_readonly_lock(self.data, self.m.subscription_id, guard=self.guard)
        self.guard.inventory = {'value': []}
        for response in (Response(403), Response(429), Response(0, transport_error=True)):
            self.guard.lock = response
            with self.assertRaises(SafetyError):
                fresh_readonly_lock(self.data, self.m.subscription_id, guard=self.guard)

    def test_core11_accepts_only_listkeys_and_uses_bounded_default(self):
        validate_pairing('lock-readonly', 'listkeys')
        for capability in ('arm-read', 'arm-tag-write', 'blob-read'):
            with self.assertRaises(SafetyError):
                validate_pairing('lock-readonly', capability)
        self.assertEqual(observation_window('lock-readonly', None, False)['duration_seconds'], 300)

    def test_scope_locked_409_is_lock_prevention_not_identity_denial(self):
        response = Response(409, json.dumps({'error': {'code': 'ScopeLocked'}}).encode())
        self.assertEqual(classify(response, auth='bearer'), 'lock_denied')
        self.assertNotEqual(classify(response, auth='bearer'), 'authorization_denied')


if __name__ == '__main__':
    unittest.main()
