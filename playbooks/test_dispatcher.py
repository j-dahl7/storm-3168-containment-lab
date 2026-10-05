"""Inert incident/ARM fixtures for the native Sentinel dispatcher's actual JSON."""
import copy
import json
from pathlib import Path
import unittest

from test_workflow import Runner, Expression, fixture

DISPATCHER = json.loads(Path(__file__).with_name('sentinel-dispatcher.workflow.json').read_text())


def dispatcher_fixture(enabled=False):
    original = fixture()
    p = original['parameters']
    group = p['resourceGroupId']
    workspace = group + '/providers/Microsoft.OperationalInsights/workspaces/lab-workspace'
    rule = workspace + '/providers/Microsoft.SecurityInsights/alertRules/66666666-6666-4666-8666-666666666666'
    incident = workspace + '/providers/Microsoft.SecurityInsights/incidents/77777777-7777-4777-8777-777777777777'
    executor = group + '/providers/Microsoft.Logic/workflows/fixture-response'
    details = {
        'ActorObjectId': [p['actorObjectId']], 'LabId': [p['labId']],
        'ResourceId': [group + '/providers/Microsoft.Storage/storageAccounts/fixturestorage'],
        'ProviderEventId': ['88888888-8888-4888-8888-888888888888'],
        'ProviderEventTime': ['2026-10-05T11:58:00Z']
    }
    return {
        'parameters': {**p, 'workspaceResourceId': workspace, 'analyticRuleResourceId': rule,
                       'executorResourceId': executor, 'dispatchEnabled': enabled,
                       'notBeforeUtc': '2026-10-05T11:00:00Z', 'notAfterUtc': '2026-10-05T13:00:00Z',
                       'expectedExecutorDryRun': True,
                       'dispatchConfirmation': 'INVOKE_CONFIGURED_LAB_EXECUTOR' if enabled else ''},
        'trigger': {'object': {'id': incident}},
        'workflow': {'id': group + '/providers/Microsoft.Logic/workflows/fixture-dispatcher', 'run': {'name': 'fixture-dispatch-run'}},
        'replies': {
            'Read_lab_group': original['replies']['Read_group'],
            'Read_incident': {'statusCode': 200, 'body': {'id': incident, 'properties': {'status': 'New', 'relatedAnalyticRuleIds': [rule], 'createdTimeUtc': '2026-10-05T11:59:00Z'}}},
            'Read_incident_alerts': {'statusCode': 200, 'body': {'value': [{'kind': 'SecurityAlert', 'properties': {
                'alertType': rule.split('/')[-1], 'additionalData': {'Custom Details': json.dumps(details)}}}]}},
            'Read_executor': {'statusCode': 200, 'body': {'id': executor, 'tags': {'storm3168LabId': p['labId']}, 'properties': {
                'state': 'Enabled', 'parameters': {key: {'value': value} for key, value in p.items()}}}},
            'Invoke_executor': {'statusCode': 202}
        }
    }


def get_details(context):
    data = context['replies']['Read_incident_alerts']['body']['value'][0]['properties']['additionalData']
    return data, json.loads(data['Custom Details'])


class DispatcherSafetyTests(unittest.TestCase):
    def run_dispatch(self, context):
        return Runner(context, DISPATCHER).run()

    def rejected(self, context):
        run = self.run_dispatch(context)
        self.assertEqual(run.result, 'Failed')
        self.assertFalse(any(name == 'Invoke_executor' for name, _, _ in run.calls))
        return run

    def test_preview_validates_live_evidence_but_does_not_invoke(self):
        run = self.run_dispatch(dispatcher_fixture())
        self.assertEqual(run.result, 'Succeeded')
        self.assertFalse(any(name == 'Invoke_executor' for name, _, _ in run.calls))
        self.assertEqual(run.composed[-1]['status'], 'dispatch_preview_no_invocation')

    def test_confirmed_dispatch_invokes_only_exact_fixed_executor(self):
        context = dispatcher_fixture(True)
        run = self.run_dispatch(context)
        self.assertEqual(run.result, 'Succeeded')
        calls = [(method, uri) for name, method, uri in run.calls if name == 'Invoke_executor']
        self.assertEqual(calls, [('POST', 'https://management.azure.com' + context['parameters']['executorResourceId'] + '/triggers/manual/run?api-version=2016-06-01')])
        self.assertEqual(run.composed[-1]['status'], 'executor_invocation_requested_outcome_unverified')

    def test_wrong_workspace_fails_before_network(self):
        context = dispatcher_fixture(True)
        context['trigger']['object']['id'] = context['trigger']['object']['id'].replace('lab-workspace', 'foreign-workspace')
        self.assertEqual(self.rejected(context).calls, [])

    def test_wrong_rule_or_closed_incident_rejected(self):
        for field, value in [('status', 'Closed'), ('relatedAnalyticRuleIds', ['foreign-rule'])]:
            context = dispatcher_fixture(True)
            context['replies']['Read_incident']['body']['properties'][field] = value
            self.rejected(context)

    def test_stale_future_and_missing_incident_creation_never_invoke(self):
        for created in ('2026-10-05T10:59:59Z', '2026-10-05T12:00:01Z', '', None, 'not-a-timestamp'):
            context = dispatcher_fixture(True)
            context['replies']['Read_incident']['body']['properties']['createdTimeUtc'] = created
            self.rejected(context)

    def test_new_incident_cannot_replay_delayed_old_provider_event(self):
        for value in ('2026-10-05T10:59:59Z', '2026-10-05T12:00:01Z', 'invalid'):
            context = dispatcher_fixture(True)
            data, details = get_details(context)
            details['ProviderEventTime'] = [value]
            data['Custom Details'] = json.dumps(details)
            self.rejected(context)

    def test_window_rechecked_after_slow_upstream_reads(self):
        context = dispatcher_fixture(True)
        context['clock_by_action'] = {'Check_dispatch_confirmation': '2026-10-05T13:00:01Z'}
        self.rejected(context)

    def test_each_independent_guard_rejects_its_own_counterexample(self):
        # Evaluate the actual guard too: redundant downstream guards must not
        # let a mutation that removes this guard hide behind a passing flow test.
        cases = [
            ('Validate_dispatch_configuration', lambda c: c['parameters'].update(expectedSubscriptionId='foreign')),
            ('Validate_incident_address', lambda c: c['trigger']['object'].update(id=c['trigger']['object']['id']+'?x')),
            ('Check_trial_window', lambda c: c['parameters'].update(notAfterUtc='2026-10-06T12:00:00Z')),
            ('Check_lab_ownership', lambda c: c['replies']['Read_lab_group']['body'].update(id='/foreign')),
            ('Check_incident_freshness', lambda c: c['replies']['Read_incident']['body']['properties'].update(createdTimeUtc='2026-10-05T10:00:00Z')),
            ('Check_incident_rule', lambda c: c['replies']['Read_incident']['body']['properties'].update(status='Closed')),
            ('Check_single_alert', lambda c: c['replies']['Read_incident_alerts']['body'].update(nextLink='untrusted')),
            ('Check_alert_origin', lambda c: c['replies']['Read_incident_alerts']['body']['value'][0]['properties'].update(alertType='other-rule')),
            ('Check_evidence_scope', lambda c: c['replies']['Parse_custom_details']['body'].update(ActorObjectId=['foreign'])),
            ('Check_provider_event_freshness', lambda c: c['replies']['Parse_custom_details']['body'].update(ProviderEventTime=['2026-10-05T10:00:00Z'])),
            ('Check_executor', lambda c: c['replies']['Read_executor']['body'].update(id='/foreign')),
            ('Check_dispatch_confirmation', lambda c: c['parameters'].update(dispatchConfirmation='')),
        ]
        for name, mutate in cases:
            with self.subTest(guard=name):
                context = dispatcher_fixture(True)
                context['replies']['Parse_custom_details'] = {'body': get_details(context)[1]}
                mutate(context)
                action = DISPATCHER['actions'].get(name) or DISPATCHER['actions']['Dispatch_gate']['actions'][name]
                self.assertFalse(Expression(action['expression'], context).evaluate())

    def test_expired_future_or_unbounded_trial_refused_before_network(self):
        for start, end in [('2026-10-05T09:00:00Z', '2026-10-05T10:00:00Z'),
                           ('2026-10-05T12:01:00Z', '2026-10-05T13:00:00Z'),
                           ('2026-10-01T00:00:00Z', '2026-10-06T00:00:00Z'),
                           ('invalid', '2026-10-05T13:00:00Z')]:
            context = dispatcher_fixture(True)
            context['parameters'].update(notBeforeUtc=start, notAfterUtc=end)
            self.assertEqual(self.rejected(context).calls, [])

    def test_server_evidence_not_trigger_claims_controls_scope(self):
        for field, values in [('ActorObjectId', ['foreign']), ('ActorObjectId', ['first', 'second']),
                              ('LabId', ['foreign']), ('ResourceId', ['/subscriptions/foreign/resourceGroups/production']),
                              ('ResourceId', [fixture()['parameters']['resourceGroupId'] + '-production/providers/type/name'])]:
            with self.subTest(field=field, values=values):
                context = dispatcher_fixture(True)
                data, details = get_details(context)
                details[field] = values
                data['Custom Details'] = json.dumps(details)
                self.rejected(context)

    def test_missing_or_malformed_custom_details_rejected(self):
        for value in (None, '{}', 'invalid-json', json.dumps({'ActorObjectId': 'not-an-array'})):
            context = dispatcher_fixture(True)
            data, _ = get_details(context)
            data['Custom Details'] = value
            self.rejected(context)

    def test_multiple_alerts_and_changed_executor_are_not_accepted(self):
        context = dispatcher_fixture(True)
        alerts = context['replies']['Read_incident_alerts']['body']['value']
        alerts.append(copy.deepcopy(alerts[0]))
        self.rejected(context)
        for field in ('actorObjectId', 'targetRoleAssignmentId', 'targetRoleDefinitionId', 'targetRoleScope'):
            context = dispatcher_fixture(True)
            context['replies']['Read_executor']['body']['properties']['parameters'][field]['value'] = 'foreign'
            self.rejected(context)
        context = dispatcher_fixture(True)
        context['replies']['Read_executor']['body']['properties']['parameters']['dryRun']['value'] = False
        self.rejected(context)

    def test_confirmation_and_ownership_are_required(self):
        context = dispatcher_fixture(True)
        context['parameters']['dispatchConfirmation'] = ''
        self.rejected(context)
        context = dispatcher_fixture(True)
        context['replies']['Read_lab_group']['body']['tags']['storm3168LabId'] = 'foreign'
        self.rejected(context)

    def test_native_trigger_and_no_external_callback_output(self):
        trigger = DISPATCHER['triggers']['Microsoft_Sentinel_incident']
        self.assertEqual(trigger['type'], 'ApiConnectionWebhook')
        self.assertEqual(trigger['inputs']['path'], '/incident-creation')
        self.assertEqual(trigger['inputs']['body']['callback_url'], '@{listCallbackUrl()}')
        self.assertEqual(DISPATCHER['outputs'], {})
        self.assertFalse(DISPATCHER['parameters']['dispatchEnabled']['defaultValue'])
        self.assertNotIn('body', DISPATCHER['actions']['Dispatch_gate']['actions']['Invoke_executor']['inputs'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
