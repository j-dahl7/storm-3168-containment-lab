"""All Activity queries normalize the same provider field before scoping."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from telemetry import canonical_resource_id

NORMALIZE = '| extend ResourceId = coalesce(tostring(column_ifexists("_ResourceId", "")), tostring(column_ifexists("ResourceId", "")))'


class ResourceIdContractTests(unittest.TestCase):
    def test_every_scoped_activity_query_normalizes_before_any_resource_predicate(self):
        sources = {p.name: p.read_text(encoding='utf-8') for p in (ROOT / 'detections').glob('[0-9][0-9]-*.kql')}
        workbook = json.loads((ROOT / 'workbooks/containment-evidence.workbook.json').read_text(encoding='utf-8'))
        sources.update({item['name']: item.get('content', {}).get('query', '') for item in workbook['items'] if item['type'] == 3})
        checked = 0
        for name, source in sources.items():
            if 'AzureActivity\n' not in source:
                continue
            with self.subTest(query=name):
                pipeline = source.split('AzureActivity\n', 1)[1]
                self.assertTrue(pipeline.startswith(NORMALIZE + '\n'))
                self.assertEqual(pipeline.count(NORMALIZE), 1)
                self.assertNotIn('| where tolower(_ResourceId)', pipeline)
                checked += 1
        self.assertEqual(checked, 9)

    def test_realshape_fixture_expectations_use_standard_id_authoritatively(self):
        fixture = json.loads((ROOT / 'fixtures/azureactivity.synthetic.json').read_text(encoding='utf-8'))
        checked = 0
        for row in fixture['events']:
            if 'ExpectedCanonicalResourceId' in row:
                self.assertEqual(canonical_resource_id(row), row['ExpectedCanonicalResourceId'], row['CaseId'])
                checked += 1
        self.assertEqual(checked, 7)

    def test_native_template_preserves_public_resource_alias_and_exact_query_body(self):
        source = (ROOT / 'detections/04-sensitive-operations.kql').read_text(encoding='utf-8')
        template = json.loads((ROOT / 'detections/sentinel-rule.arm.json').read_text(encoding='utf-8'))
        self.assertEqual(template['variables']['queryBody'], 'AzureActivity\n' + source.split('AzureActivity\n', 1)[1])
        props = template['resources'][0]['properties']
        self.assertEqual(props['customDetails']['ResourceId'], 'ResourceId')
        self.assertEqual(props['entityMappings'][0]['fieldMappings'][0]['columnName'], 'ResourceId')
        self.assertIn('CallerIpAddress, ResourceId, OperationNameValue', source)


if __name__ == '__main__':
    unittest.main()
