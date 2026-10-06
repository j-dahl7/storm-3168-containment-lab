"""Generated-query regression contracts, not a Kusto runtime acceptance claim."""
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from render_kql_replay import build


def replay_case_count():
    fixture = json.loads((ROOT / "fixtures/azureactivity.synthetic.json").read_text(encoding="utf-8"))
    return len(fixture["events"]) + 1


class ReplayGeneratorTests(unittest.TestCase):
    def test_union_receives_explicit_zero_argument_views_not_function_legs(self):
        query = build()
        union = query.split("\nunion\n", 1)[1].split("\n| project", 1)[0]
        names = [name.strip() for name in union.split(",")]
        self.assertEqual(len(names), replay_case_count())
        self.assertEqual(len(set(names)), replay_case_count())
        for name in names:
            self.assertRegex(name, r"^Replay(?:Case\d{3}|FullPipeline)$")
            self.assertIn("let " + name + "=view () {\n", query)
        self.assertNotIn("Evaluate", query)
        self.assertNotIn("| invoke", query)
        self.assertNotIn("isfuzzy", query)
        self.assertNotIn("best_effort", query)

    def test_actual_pipeline_is_preserved_except_clock_and_table_sources(self):
        source = (ROOT / "detections/04-sensitive-operations.kql").read_text(encoding="utf-8")
        actual = source.split("AzureActivity\n", 1)[1]
        actual = actual.replace("ingestion_time()", "SyntheticIngestedAt").replace("now()", "ReferenceTime")
        actual = re.sub(r"ago\((\d+[dhms])\)", r"(ReferenceTime - \1)", actual).rstrip()
        self.assertEqual(build().count(actual), replay_case_count())

    def test_every_fixture_and_batch_selection_remain_asserted(self):
        fixture = json.loads((ROOT / "fixtures/azureactivity.synthetic.json").read_text(encoding="utf-8"))
        expected = json.loads((ROOT / "fixtures/expected-cases.json").read_text(encoding="utf-8"))
        query = build()
        for row in fixture["events"]:
            self.assertIn("| where CaseId == " + json.dumps(row["CaseId"]), query)
            self.assertIn("| extend CaseId=" + json.dumps(row["CaseId"]) + ", ExpectedMatch=" + str(row["ExpectedMatch"]).lower(), query)
        self.assertIn("Returned == 1 and Selected == " + json.dumps(expected["expected_selected_event_id"]), query)

    def test_production_filter_change_flows_into_replay_without_copying_predicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "detections").mkdir()
            (root / "fixtures").mkdir()
            source = (ROOT / "detections/04-sensitive-operations.kql").read_text(encoding="utf-8")
            marker = '| where OperationId != "offline-regression-marker"'
            (root / "detections/04-sensitive-operations.kql").write_text(source.replace("AzureActivity\n", "AzureActivity\n" + marker + "\n"), encoding="utf-8")
            for name in ("azureactivity.synthetic.json", "expected-cases.json"):
                (root / "fixtures" / name).write_bytes((ROOT / "fixtures" / name).read_bytes())
            self.assertEqual(build(root).count(marker), replay_case_count())

    def test_committed_generated_replay_matches_generator(self):
        self.assertEqual((ROOT / "detections/replay-sensitive-operations.kql").read_text(encoding="utf-8"), build())

    def test_provider_timestamp_uses_supported_formats_and_separate_utc_literals(self):
        source = (ROOT / "detections/04-sensitive-operations.kql").read_text(encoding="utf-8")
        expected = 'strcat(format_datetime(TimeGenerated, "yyyy-MM-dd"), "T", format_datetime(TimeGenerated, "HH:mm:ss.fffffff"), "Z")'
        self.assertIn("ProviderEventTime = " + expected, source)
        self.assertNotIn('"yyyy-MM-ddTHH:mm:ss.fffffffZ"', source)
        template = json.loads((ROOT / "detections/sentinel-rule.arm.json").read_text(encoding="utf-8"))
        self.assertEqual(template["variables"]["queryBody"], "AzureActivity\n" + source.split("AzureActivity\n", 1)[1])
        self.assertEqual(build().count(expected), replay_case_count())

    def test_standard_resource_id_column_and_real_shape_conflicts_are_replayed(self):
        fixture = json.loads((ROOT / "fixtures/azureactivity.synthetic.json").read_text(encoding="utf-8"))
        rows = {row['CaseId']: row for row in fixture['events']}
        query = build()
        self.assertIn('ResourceId:string, _ResourceId:string', query)
        normalization = 'coalesce(tostring(column_ifexists("_ResourceId", "")), tostring(column_ifexists("ResourceId", "")))'
        self.assertEqual(query.count(normalization), replay_case_count())
        live_shape = rows['standard-resource-id-empty-legacy']
        self.assertEqual(live_shape['ResourceId'], '')
        self.assertEqual(live_shape['ActivityStatusValue'], 'Success')
        self.assertTrue(live_shape['ExpectedMatch'])
        self.assertFalse(rows['foreign-standard-id-cannot-fallback']['ExpectedMatch'])
        self.assertFalse(rows['malformed-standard-id-cannot-fallback']['ExpectedMatch'])
        self.assertTrue(rows['legacy-resource-id-fallback']['ExpectedMatch'])
        self.assertFalse(rows['standard-resource-id-start-not-terminal']['ExpectedMatch'])


if __name__ == "__main__":
    unittest.main()
