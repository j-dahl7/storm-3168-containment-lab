"""Inert incident/ARM fixtures for the native Sentinel dispatcher's actual JSON."""
import copy
import json
from pathlib import Path
import unittest

from test_workflow import Runner, fixture

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
        'ProviderEventId': ['88888888-8888-4888-8888-888888888888']
    }
    return {
        'parameters': {**p, 'workspaceResourceId': workspace, 'analyticRuleResourceId': rule,
                       'executorResourceId': executor, 'dispatchEnabled': enabled,
                       'expectedExecutorDryRun': True,
                       'dispatchConfirmation': 'INVOKE_CONFIGURED_LAB_EXECUTOR' if enabled else ''},
        'trigger': {'object': {'id': incident}},
        'workflow': {'id': group + '/providers/Microsoft.Logic/workflows/fixture-dispatcher', 'run': {'name': 'fixture-dispatch-run'}},
        'replies': {
            'Read_lab_group': original['replies']['Read_group'],
            'Read_incident': {'statusCode': 200, 'body': {'id': incident, 'properties': {'status': 'New', 'relatedAnalyticRuleIds': [rule]}}},
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
