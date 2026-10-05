"""Clock attribution regressions with fictional incident/provider metadata."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import sentinel_timing as st
from stormlab.core import Manifest, SafetyError
from test_core import fixture

INCIDENT = "12345678-1234-4234-8234-123456789012"
RULE = "22345678-1234-4234-8234-123456789012"
EVENT = "32345678-1234-4234-8234-123456789012"


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.m = Manifest.from_dict(fixture())
        workspace = st.workspace_id(self.m)
        self.incident = {"id": workspace + "/providers/Microsoft.SecurityInsights/incidents/" + INCIDENT,
                         "properties": {"relatedAnalyticRuleIds": [workspace + "/providers/Microsoft.SecurityInsights/alertRules/" + RULE],
                                        "createdTimeUtc": "2026-10-05T10:13:00Z", "lastModifiedTimeUtc": "2026-10-05T10:20:00Z"}}
        self.details = {"ActorObjectId": [self.m.actor["service_principal_object_id"]], "LabId": [self.m.lab_id],
                        "ResourceId": [self.m.storage_id], "ProviderEventId": [EVENT]}
        self.alerts = {"value": [{"kind": "SecurityAlert", "properties": {"alertType": RULE,
                            "timeGenerated": "2026-10-05T10:00:00Z", "processingEndTime": "2026-10-05T10:12:00Z",
                            "additionalData": {"Custom Details": self.details}}}]}
        self.activity = {"kind": "provider_telemetry", "mode": "live_read_only", "sources": [{"source": "AzureActivity", "status": "query_completed",
                         "selection": {"resource_id": workspace, "ownership_required": True}, "truncated": False,
                         "rows": [{"EventDataId": EVENT, "ResourceId": self.m.storage_id, "ActorObjectId": self.m.actor["service_principal_object_id"],
                                   "TimeGenerated": "2026-10-05T10:00:00Z", "EventSubmissionTimestamp": "2026-10-05T10:02:00Z", "WorkspaceIngestionTime": "2026-10-05T10:10:00Z"}]}]}

    def build(self, **kwargs):
        return st.build_evidence(self.m, self.incident, self.alerts, incident_id=INCIDENT, analytic_rule_id=RULE, activity=self.activity, **kwargs)

    def test_processing_end_not_event_time_is_alert_availability(self):
        evidence = self.build()
        self.assertEqual(evidence["durations"]["workspace_to_alert"]["seconds"], 120)
        self.assertEqual(evidence["durations"]["alert_to_incident"]["seconds"], 60)
        self.assertEqual(evidence["durations"]["event_to_workspace"]["seconds"], 600)
        self.assertEqual(evidence["containment"], "not_proven")

    def test_absent_publication_clock_never_falls_back_to_timegenerated(self):
        del self.alerts["value"][0]["properties"]["processingEndTime"]
        evidence = self.build()
        self.assertEqual(evidence["durations"]["workspace_to_alert"]["status"], "unavailable")
        self.assertIsNone(evidence["clocks"]["alert_available"])

    def test_unknown_provider_event_or_duplicate_never_averaged_or_guessed(self):
        original = self.activity["sources"][0]["rows"]
        self.activity["sources"][0]["rows"] = original * 2
        self.assertEqual(self.build()["provider_match"], "ambiguous")
        self.assertIsNone(self.build()["durations"]["event_to_workspace"]["seconds"])
        self.activity["sources"][0]["rows"] = []
        self.assertEqual(self.build()["provider_match"], "missing")

    def test_wrong_rule_actor_group_and_paginated_alerts_rejected(self):
        for mutate in [lambda: self.incident["properties"].update(relatedAnalyticRuleIds=[]),
                       lambda: self.details.update(ActorObjectId=[self.m.actor["client_id"]]),
                       lambda: self.details.update(ResourceId=[self.m.storage_id.replace(self.m.resource_group, self.m.resource_group + "-foreign")]),
                       lambda: self.alerts.update(nextLink="https://untrusted.example")]:
            self.setUp()
            mutate()
            with self.assertRaises(SafetyError):
                self.build()

    def test_negative_clock_difference_preserved_as_unknown(self):
        self.incident["properties"]["createdTimeUtc"] = "2026-10-05T10:11:00Z"
        result = self.build()["durations"]["alert_to_incident"]
        self.assertEqual(result, {"status": "clock_order_unknown", "seconds": -60})

    def test_recorded_run_does_not_establish_incident_causality(self):
        run = {"properties": {"startTime": "2026-10-05T10:14:00Z", "endTime": "2026-10-05T10:14:10Z"}}
        result = self.build(run=run)
        self.assertEqual(result["durations"]["incident_to_workflow"]["status"], "unattributed_clock_difference")
        self.assertEqual(result["durations"]["workflow_duration"]["seconds"], 10)


if __name__ == "__main__":
    unittest.main()
