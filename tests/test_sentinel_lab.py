"""Native preparation and exact preview correlation; all provider calls inert."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import sentinel_lab as sl
from stormlab.core import Manifest, Response, SafetyError
from test_core import fixture, Operator

INCIDENT = "12345678-1234-4234-8234-123456789012"
EVENT = "22345678-1234-4234-8234-123456789012"
MI = "32345678-1234-4234-8234-123456789012"


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.data["budget_target_usd"] = 10
        self.m = Manifest.from_dict(self.data)
        responder = {"workflow_id": sl.pb.workflow_path(self.data), "assignment": dict(self.m.role_assignments[0])}
        now = datetime.now(timezone.utc)
        self.state = sl.planned_state(self.data, responder, (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=59)).isoformat())
        self.worker = sl.NativeLab(self.data, self.state, self, Operator())
        self.calls = []
        self.existing = False

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        return Response(200 if self.existing else 404)

    def acceptance_fixture(self):
        self.state.update(not_before_utc="2026-10-05T11:00:00+00:00", not_after_utc="2026-10-05T13:00:00+00:00")
        refs = sl.resources(self.m, self.state)
        incident_id = sl.workspace_id(self.m) + "/providers/Microsoft.SecurityInsights/incidents/" + INCIDENT
        details = {"LabId": [self.m.lab_id], "ActorObjectId": [self.m.actor["service_principal_object_id"]], "ResourceId": [self.m.storage_id], "ProviderEventId": [EVENT], "ProviderEventTime": ["2026-10-05T11:30:00Z"]}
        incident = {"id": incident_id, "properties": {"createdTimeUtc": "2026-10-05T11:40:00Z", "relatedAnalyticRuleIds": [refs["analytic"][0]]}}
        alerts = {"value": [{"kind": "SecurityAlert", "properties": {"alertType": self.state["ids"]["rule"], "additionalData": {"Custom Details": details}}}]}
        run_id = refs["dispatcher"][0] + "/runs/native-run"
        outputs = {"incidentId": incident_id, "providerEventId": EVENT, "providerEventTime": "2026-10-05T11:30:00Z", "dispatchMode": "preview_only"}
        run = {"id": run_id, "properties": {"status": "Succeeded", "trigger": {"name": "Microsoft_Sentinel_incident"}, "startTime": "2026-10-05T11:40:01Z", "endTime": "2026-10-05T11:40:02Z", "outputs": {k: {"type": "String", "value": v} for k, v in outputs.items()}}}
        return {incident_id: incident, incident_id + "/alerts": alerts, run_id: run}, run

    def test_plan_has_fresh_bound_ids_and_cross_scope_state_rejected(self):
        self.assertEqual(len(set(self.state['ids'].values())), 7)
        self.assertEqual(self.state['stage'], 'planned')
        changed = copy.deepcopy(self.state)
        changed['workspace_id'] += '-foreign'
        with self.assertRaises(SafetyError):
            sl.validate_state(self.m, changed)
        self.assertEqual(self.calls, [])

    def test_existing_component_blocks_every_deployment(self):
        self.existing = True
        with patch.object(self.worker, 'preflight'), patch.object(sl, 'az') as az:
            with self.assertRaisesRegex(SafetyError, 'refusing overwrite'):
                self.worker.deploy(lambda _: None)
        az.assert_not_called()
        self.assertEqual(self.state['stage'], 'planned')

    def test_deployment_is_disabled_and_grants_no_permissions(self):
        receipts = []
        with patch.object(self.worker, 'preflight'), patch.object(self.worker, 'verify_components', return_value=MI), patch.object(sl, 'az') as az:
            self.worker.deploy(lambda value: receipts.append(copy.deepcopy(value)))
        self.assertEqual(az.call_count, 3)
        commands = [call.args for call in az.call_args_list]
        self.assertTrue(any('enableRule=false' in args for args in commands))
        self.assertTrue(any('dispatchEnabled=false' in args and 'expectedExecutorDryRun=true' in args for args in commands))
        self.assertTrue(any('enableAutomationRule=false' in args for args in commands))
        self.assertFalse(any('grantDispatcherPermissions=true' in args or 'grantSentinelAutomationPermission=true' in args for args in commands))
        self.assertEqual(receipts[0]['stage'], 'deployment_requested_outcome_unverified')
        self.assertEqual(receipts[-1]['native_delivery'], 'not_tested')

    def test_partial_deployment_cannot_be_blindly_repeated(self):
        with patch.object(self.worker, 'preflight'), patch.object(sl, 'az', side_effect=RuntimeError('uncertain')):
            with self.assertRaises(RuntimeError):
                self.worker.deploy(lambda _: None)
        with patch.object(sl, 'az') as az:
            with self.assertRaisesRegex(SafetyError, 'already requested'):
                self.worker.deploy(lambda _: None)
        az.assert_not_called()

    def test_changed_template_fingerprint_blocks_deployment(self):
        self.state['source_hashes']['playbooks/sentinel-dispatcher.workflow.json'] = '0' * 64
        with patch.object(sl, 'az') as az:
            with self.assertRaisesRegex(SafetyError, 'templates changed'):
                self.worker.deploy(lambda _: None)
        az.assert_not_called()

    def test_preview_acceptance_requires_exact_incident_event_and_native_trigger(self):
        data, run = self.acceptance_fixture()
        with patch.object(self.worker, 'preflight'), patch.object(self.worker, 'verify_components'), patch.object(self.worker, 'object', side_effect=lambda rid, version, **kw: data[rid]):
            result = self.worker.accept_preview(INCIDENT, 'native-run')
        self.assertEqual(result['status'], 'preview_correlated')
        self.assertFalse(result['executor_invoked'])
        self.assertFalse(result['containment_tested'])

    def test_uncorrelated_success_or_forwarding_is_not_preview_acceptance(self):
        for change in (lambda r: r['properties']['outputs']['providerEventId'].update(value=INCIDENT),
                       lambda r: r['properties']['outputs']['dispatchMode'].update(value='forwarding_requested'),
                       lambda r: r['properties']['trigger'].update(name='manual'),
                       lambda r: r['properties'].update(outputs={}),
                       lambda r: r['properties']['outputs']['providerEventTime'].update(value='2026-10-05T11:31:00Z')):
            data, run = self.acceptance_fixture()
            change(run)
            with patch.object(self.worker, 'preflight'), patch.object(self.worker, 'verify_components'), patch.object(self.worker, 'object', side_effect=lambda rid, version, **kw: data[rid]):
                with self.assertRaises(SafetyError):
                    self.worker.accept_preview(INCIDENT, 'native-run')


if __name__ == '__main__':
    unittest.main()
