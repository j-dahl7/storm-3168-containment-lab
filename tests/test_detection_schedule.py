"""Independent scheduler counterexamples, not a Kusto compiler/runtime claim.

Model the platform event-time horizon separately from the KQL ingestion gate.
The old 5m gate must fail the fast-arrival regression, while the configured overlap
must cover the explicitly bounded delayed/skipped execution cases. Real query
execution is still a separately authorized workspace test.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = json.loads((ROOT / "detections/sentinel-rule.arm.json").read_text())
PROPS = TEMPLATE["resources"][0]["properties"]
QUERY = TEMPLATE["variables"]["queryBody"]
GATE_MINUTES = int(re.search(r"ArrivalTime > ago\((\d+)m\)", QUERY)[1])


def observed_at(event_minute, arrival_minute, runs, gate_minutes):
    # An independent schedule model: event-time range ends five minutes before
    # actual execution. This is intentionally separate from the row predicate.
    for actual_execution in runs:
        if (event_minute <= actual_execution - 5 and arrival_minute <= actual_execution
                and arrival_minute > actual_execution - gate_minutes):
            return actual_execution
    return None


class DetectionScheduleTests(unittest.TestCase):
    def test_fast_event_counterexample_old_gate_misses_new_gate_covers(self):
        self.assertIsNone(observed_at(1, 1.1, [5, 10, 15, 20, 25], 5))
        self.assertEqual(observed_at(1, 1.1, [5, 10, 15, 20, 25], GATE_MINUTES), 10)

    def test_overlap_covers_one_skipped_run_and_ten_minute_jitter_bound(self):
        self.assertEqual(observed_at(1, 1.1, [5, 15, 20], GATE_MINUTES), 15)
        self.assertEqual(observed_at(1, 1.1, [5, 20, 25], GATE_MINUTES), 20)
        # No false promise for a long scheduler outage.
        self.assertIsNone(observed_at(1, 1.1, [5, 30, 35], GATE_MINUTES))

    def test_delayed_ingestion_captured_without_moving_provider_event_clock(self):
        self.assertEqual(observed_at(1, 14, [5, 10, 15, 20], GATE_MINUTES), 15)
        self.assertEqual(observed_at(1, 19.9, [5, 10, 15, 20], GATE_MINUTES), 20)

    def test_alert_volume_is_bounded_for_overlap_and_probe_flood(self):
        self.assertIn("| take 1\n", QUERY)
        self.assertTrue(PROPS["suppressionEnabled"])
        suppression = int(re.fullmatch(r"PT(\d+)M", PROPS["suppressionDuration"])[1])
        frequency = int(re.fullmatch(r"PT(\d+)M", PROPS["queryFrequency"])[1])
        self.assertGreaterEqual(suppression, GATE_MINUTES + frequency)
        # A same-event duplicate visible throughout the overlap cannot produce
        # another scheduled alert before it ages out under this bounded model.
        first = observed_at(1, 1.1, range(5, 60, frequency), GATE_MINUTES)
        repeats = [t for t in range(first + suppression, 60, frequency)
                   if observed_at(1, 1.1, [t], GATE_MINUTES) is not None]
        self.assertEqual(repeats, [])

    def test_1000_denied_probes_do_not_become_automation_candidates(self):
        statuses = set(re.search(r'tolower\(ActivityStatusValue\) in \(([^\n]+)\)', QUERY)[1].replace('"', '').replace(' ', '').split(','))
        self.assertEqual(sum(status.lower() in statuses for status in ["Failed"] * 1000), 0)
        self.assertTrue({"success", "succeeded"} <= statuses)
        # Explicit actor equality excludes responder/operator identities before
        # signal selection; no wildcard or response-action broadening.
        self.assertIn("| where ActorOid == tolower(ActorObjectId)", QUERY)
        self.assertNotIn("microsoft.authorization/roleassignments/delete", QUERY.lower())

    def test_template_and_reviewable_query_are_identical(self):
        source = (ROOT / "detections/04-sensitive-operations.kql").read_text()
        self.assertEqual(source[source.index("AzureActivity\n"):], QUERY)
        self.assertFalse(TEMPLATE["parameters"]["enableRule"]["defaultValue"])


if __name__ == "__main__":
    unittest.main()
