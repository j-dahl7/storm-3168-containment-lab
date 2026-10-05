"""Offline behavioral checks of the actual workflow JSON, with inert ARM replies.

This small interpreter implements only the WDL operations used by this workflow.
It is not an Azure runtime validator and does not prove live containment.
Run: python playbooks/test_workflow.py
"""
import copy
import json
from pathlib import Path
import re
import unittest

DEFINITION = json.loads(Path(__file__).with_name('workflow.json').read_text())
TOKEN = re.compile(r"\s*('(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|\?\[|[\[\](),.])")


class Expression:
    def __init__(self, text, context):
        text = text.removeprefix('@')
        self.tokens = []
        pos = 0
        while pos < len(text):
            match = TOKEN.match(text, pos)
            if not match:
                raise AssertionError(f'Unsupported expression at {text[pos:]}')
            self.tokens.append(match[1])
            pos = match.end()
        self.i = 0
        self.context = context

    def pop(self):
        value = self.tokens[self.i]
        self.i += 1
        return value

    def require(self, token):
        assert self.pop() == token

    def value(self):
        token = self.pop()
        if token.startswith("'"):
            result = token[1:-1].replace("''", "'")
        elif token.isdigit():
            result = int(token)
        elif token in ('true', 'false', 'null'):
            result = {'true': True, 'false': False, 'null': None}[token]
        else:
            self.require('(')
            args = []
            if self.tokens[self.i] != ')':
                while True:
                    args.append(self.value())
                    if self.tokens[self.i] != ',':
                        break
                    self.pop()
            self.require(')')
            funcs = {
                'parameters': lambda name: self.context['parameters'][name],
                'workflow': lambda: self.context['workflow'],
                'body': lambda name: self.context['replies'][name].get('body'),
                'outputs': lambda name: self.context['replies'][name],
                'triggerBody': lambda: self.context.get('trigger', {}),
                'and': lambda *items: all(items),
                'or': lambda *items: any(items),
                'not': lambda item: not item,
                'equals': lambda a, b: type(a) is type(b) and a == b,
                'toLower': lambda item: item.lower(),
                'string': lambda item: '' if item is None else str(item),
                'split': lambda item, sep: item.split(sep),
                'concat': lambda *items: ''.join(items),
                'last': lambda items: items[-1],
                'first': lambda items: items[0],
                'coalesce': lambda *items: next((x for x in items if x is not None), None),
                'empty': lambda value: value is None or len(value) == 0,
                'json': json.loads,
                'length': len,
                'startsWith': lambda item, prefix: item.startswith(prefix),
                'contains': lambda item, fragment: fragment in item,
                'utcNow': lambda: '2026-10-05T12:00:00Z',
            }
            result = funcs[token](*args)
        while self.i < len(self.tokens) and self.tokens[self.i] in ('.', '[', '?['):
            op = self.pop()
            if op == '.':
                result = result[self.pop()]
            else:
                key = self.value()
                self.require(']')
                result = (None if result is None else result.get(key)) if op == '?[' else result[key]
        return result

    def evaluate(self):
        result = self.value()
        assert self.i == len(self.tokens)
        return result


class Stop(Exception):
    pass


class Runner:
    def __init__(self, context, definition=DEFINITION):
        self.context = context
        self.definition = definition
        self.status = {}
        self.calls = []
        self.composed = []
        self.result = None

    def evaluate(self, value):
        if isinstance(value, str) and value.startswith('@'):
            return Expression(value, self.context).evaluate()
        if isinstance(value, dict):
            return {k: self.evaluate(v) for k, v in value.items()}
        return value

    def actions(self, actions):
        for name, action in actions.items():
            if any(self.status.get(dep) not in allowed for dep, allowed in action.get('runAfter', {}).items()):
                self.status[name] = 'Skipped'
                continue
            kind = action['type']
            self.status[name] = 'Succeeded'
            if kind == 'If':
                self.actions(action['actions'] if self.evaluate(action['expression']) else action['else']['actions'])
            elif kind == 'Terminate':
                self.result = action['inputs']['runStatus']
                raise Stop()
            elif kind == 'Compose':
                self.composed.append(self.evaluate(action['inputs']))
            elif kind == 'Http':
                self.calls.append((name, action['inputs']['method'], self.evaluate(action['inputs']['uri'])))
                reply = self.context['replies'][name]
                self.status[name] = reply.get('status', 'Succeeded' if 200 <= reply.get('statusCode', 0) < 300 else 'Failed')
            elif kind == 'ParseJson':
                try:
                    content = self.evaluate(action['inputs']['content'])
                    parsed = json.loads(content) if isinstance(content, str) else content
                    schema = action['inputs']['schema']
                    if not isinstance(parsed, dict):
                        raise ValueError('Expected object')
                    for key in schema.get('required', []):
                        values = parsed[key]
                        prop = schema['properties'][key]
                        if not isinstance(values, list) or not prop['minItems'] <= len(values) <= prop['maxItems']:
                            raise ValueError('Expected singleton array')
                        if any(not isinstance(x, str) or len(x) < prop['items'].get('minLength', 0) for x in values):
                            raise ValueError('Expected nonempty string')
                    self.context['replies'][name] = {'body': parsed}
                except (KeyError, TypeError, ValueError):
                    self.status[name] = 'Failed'
            else:
                raise AssertionError(f'Unsupported action {kind}')

    def run(self):
        try:
            self.actions(self.definition['actions'])
        except Stop:
            pass
        if self.result is None:
            self.result = 'Failed' if any(v in ('Failed', 'TimedOut') for k, v in self.status.items() if k != 'Read_after_delete') else 'Succeeded'
        return self


def fixture(execute=False):
    sub = '11111111-1111-4111-8111-111111111111'
    lab = '22222222-2222-4222-8222-222222222222'
    actor = '33333333-3333-4333-8333-333333333333'
    group = f'/subscriptions/{sub}/resourceGroups/fixture-lab'
    role = f'/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/44444444-4444-4444-8444-444444444444'
    assignment = group + '/providers/Microsoft.Authorization/roleAssignments/55555555-5555-4555-8555-555555555555'
    group_reply = {'statusCode': 200, 'body': {'id': group, 'tags': {'storm3168LabId': lab}}}
    role_reply = {'statusCode': 200, 'body': {'id': assignment, 'properties': {'principalId': actor, 'principalType': 'ServicePrincipal', 'roleDefinitionId': role, 'scope': group}}}
    return {
        'parameters': {'expectedSubscriptionId': sub, 'labId': lab, 'resourceGroupId': group, 'actorObjectId': actor,
                       'targetRoleAssignmentId': assignment, 'targetRoleDefinitionId': role, 'targetRoleScope': group,
                       'dryRun': not execute, 'executionConfirmation': 'REMOVE_CONFIGURED_LAB_ROLE' if execute else ''},
        'workflow': {'id': group + '/providers/Microsoft.Logic/workflows/fixture-response', 'run': {'name': 'fixture-run'}},
        'replies': {'Read_group': copy.deepcopy(group_reply), 'Read_group_again': copy.deepcopy(group_reply),
                    'Read_assignment': copy.deepcopy(role_reply), 'Read_assignment_again': copy.deepcopy(role_reply),
                    'Delete_configured_assignment': {'statusCode': 204}, 'Read_after_delete': {'statusCode': 404}}
    }


class WorkflowSafetyTests(unittest.TestCase):
    def assert_no_delete(self, context):
        run = Runner(context).run()
        self.assertFalse(any(method == 'DELETE' for _, method, _ in run.calls))
        return run

    def test_dry_run_has_no_mutation(self):
        run = self.assert_no_delete(fixture())
        self.assertEqual(run.result, 'Succeeded')
        self.assertTrue(any(isinstance(x, dict) and x.get('status') == 'dry_run_no_mutation' for x in run.composed))

    def test_confirmed_execution_removes_only_exact_assignment_and_requires_probe(self):
        context = fixture(True)
        run = Runner(context).run()
        deletes = [uri for _, method, uri in run.calls if method == 'DELETE']
        self.assertEqual(deletes, ['https://management.azure.com' + context['parameters']['targetRoleAssignmentId'] + '?api-version=2022-04-01'])
        self.assertEqual(run.result, 'Succeeded')
        self.assertEqual(run.composed[-1]['status'], 'role_assignment_removed_access_unverified')

    def test_confirmation_cannot_be_omitted(self):
        context = fixture(True)
        context['parameters']['executionConfirmation'] = ''
        self.assertEqual(self.assert_no_delete(context).result, 'Failed')

    def test_replayed_incident_with_already_absent_exact_role_is_noop(self):
        context = fixture(True)
        context['replies']['Read_assignment'] = {'statusCode': 404}
        run = self.assert_no_delete(context)
        self.assertEqual(run.result, 'Succeeded')
        self.assertEqual(run.composed[-1]['status'], 'already_absent_access_unverified')
        self.assertTrue(any(name == 'Read_group' for name, _, _ in run.calls))

    def test_initial_assignment_failure_is_never_idempotent_success(self):
        for reply in ({'statusCode': 403}, {'statusCode': 429}, {'status': 'TimedOut'}):
            context = fixture(True)
            context['replies']['Read_assignment'] = reply
            self.assertEqual(self.assert_no_delete(context).result, 'Failed')

    def test_wrong_subscription_or_encoded_path_fails_before_network(self):
        for key, value in [('expectedSubscriptionId', '99999999-9999-4999-8999-999999999999'), ('targetRoleScope', '/other'), ('targetRoleAssignmentId', fixture()['parameters']['targetRoleAssignmentId'] + '%2f')]:
            with self.subTest(key=key):
                context = fixture(True)
                context['parameters'][key] = value
                run = self.assert_no_delete(context)
                self.assertEqual(run.result, 'Failed')
                self.assertEqual(run.calls, [])

    def test_ownership_and_assignment_drift_fail_closed(self):
        for name in ('Read_group', 'Read_group_again'):
            context = fixture(True)
            context['replies'][name]['body']['tags']['storm3168LabId'] = 'foreign'
            self.assertEqual(self.assert_no_delete(context).result, 'Failed')
        for name in ('Read_assignment', 'Read_assignment_again'):
            for field in ('principalId', 'principalType', 'scope', 'roleDefinitionId'):
                with self.subTest(name=name, field=field):
                    context = fixture(True)
                    context['replies'][name]['body']['properties'][field] = 'foreign'
                    self.assertEqual(self.assert_no_delete(context).result, 'Failed')

    def test_only_404_establishes_assignment_absence(self):
        for reply in ({'statusCode': 200}, {'statusCode': 403}, {'statusCode': 429}, {'status': 'TimedOut'}):
            with self.subTest(reply=reply):
                context = fixture(True)
                context['replies']['Read_after_delete'] = reply
                self.assertEqual(Runner(context).run().result, 'Failed')

    def test_action_names_unique_and_http_destinations_fixed(self):
        names = []
        def walk(actions):
            for name, action in actions.items():
                names.append(name)
                if action['type'] == 'Http':
                    self.assertEqual(action['inputs']['authentication']['type'], 'ManagedServiceIdentity')
                    self.assertTrue(action['inputs']['uri'].startswith("@concat('https://management.azure.com'"))
                    self.assertEqual(action['inputs']['retryPolicy']['type'], 'none')
                walk(action.get('actions', {}))
                walk(action.get('else', {}).get('actions', {}))
        walk(DEFINITION['actions'])
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(DEFINITION['parameters']['dryRun']['defaultValue'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
