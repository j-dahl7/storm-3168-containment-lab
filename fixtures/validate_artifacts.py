"""Offline structural and fixture-contract validation; no cloud calls or Kusto execution."""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from render_kql_replay import build as build_actual_replay


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def main():
    files = [p for folder in ("docs", "detections", "workbooks", "fixtures")
             for p in (ROOT / folder).glob("*.json")]
    documents = {p.relative_to(ROOT).as_posix(): read_json(p) for p in files}
    fixture = documents["fixtures/azureactivity.synthetic.json"]
    expected = documents["fixtures/expected-cases.json"]
    assert fixture["synthetic"] is True and fixture["not_live_azure_evidence"] is True
    ref = utc(fixture["reference_utc"])
    rg = "/subscriptions/11111111-1111-4111-8111-111111111111/resourcegroups/rg-storm3168-lab"
    principal = "22222222-2222-4222-8222-222222222222"
    sensitive = {
        "microsoft.storage/storageaccounts/listkeys/action",
        "microsoft.storage/storageaccounts/listaccountsas/action",
        "microsoft.storage/storageaccounts/listservicesas/action",
        "microsoft.storage/storageaccounts/regeneratekey/action",
        "microsoft.storage/storageaccounts/delete",
        "microsoft.authorization/locks/delete",
    }
    matched_ids = set()
    for row in fixture["events"]:
        claims = row["Claims_d"]
        oid = (claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier")
               or claims.get("oid") or row["Caller"]).lower()
        resource = row["ResourceId"].lower()
        arrival = (utc(row["SyntheticIngestedAt"])
                   or utc(row["EventSubmissionTimestamp"]) or utc(row["TimeGenerated"]))
        matched = bool(
            utc(row["TimeGenerated"]) >= ref - timedelta(days=1)
            and oid == principal
            and (resource == rg or resource.startswith(rg + "/"))
            and ref - timedelta(minutes=20) < arrival <= ref
            and row["ActivityStatusValue"].lower() in {"success", "succeeded"}
            and row["OperationNameValue"].lower() in sensitive
            and row["EventDataId"]
        )
        assert matched == row["ExpectedMatch"], row["CaseId"]
        if matched:
            matched_ids.add(row["EventDataId"])
    assert sorted(matched_ids) == sorted(expected["expected_unique_event_ids"])
    assert (ROOT / "detections/replay-sensitive-operations.kql").read_text(encoding="utf-8") == build_actual_replay()

    matrix = documents["fixtures/test-matrix.json"]["cases"]
    assert len({c["case_id"] for c in matrix}) == len(matrix)
    assert all(c["minimum_independent_trials"] >= 3 for c in matrix)
    assert all(c["status"] == "not_tested" and c["completed_trials"] == 0
               and c["observations"] == [] for c in matrix)
    assert len(matrix) == 12
    assert set(c["phase"] for c in matrix) == set(range(1, 6))
    assert sum(len(c["action_configurations"]) for c in matrix) == 13
    assert sum(c["minimum_independent_trials"] for c in matrix) == 39
    assert all(config["minimum_independent_trials"] == 3
               for c in matrix for config in c["action_configurations"])
    extended = documents["fixtures/test-matrix.extended.json"]["cases"]
    assert len(extended) == 66
    assert set(c["phase"] for c in extended) == set(range(1, 7))
    with (ROOT / "docs/test-matrix.csv").open(encoding="utf-8", newline="") as stream:
        csv_cases = list(csv.DictReader(stream))
    assert [r["case_id"] for r in csv_cases] == [c["case_id"] for c in matrix]
    assert all(r["status"] == "not_tested" and r["completed_trials"] == "0"
               for r in csv_cases)

    template = documents["detections/sentinel-rule.arm.json"]
    assert template["parameters"]["enableRule"]["defaultValue"] is False
    assert len(template["resources"]) == 1
    rule = template["resources"][0]
    assert rule["kind"] == "Scheduled" and rule["apiVersion"] == "2025-09-01"
    assert rule["properties"]["enabled"] == "[parameters('enableRule')]"
    assert "parameters('labResourceGroupId')" in rule["properties"]["query"]
    assert "parameters('actorObjectId')" in rule["properties"]["query"]
    assert "\\n" not in rule["properties"]["query"], "ARM header contains literal escape characters"
    kql = (ROOT / "detections/04-sensitive-operations.kql").read_text(encoding="utf-8")
    assert template["variables"]["queryBody"].rstrip() == kql[kql.index("AzureActivity\n"):].rstrip()
    assert len(rule["properties"]["entityMappings"]) == 2
    assert all(m["entityType"] != "Account" for m in rule["properties"]["entityMappings"])

    workbook = documents["workbooks/containment-evidence.workbook.json"]
    assert workbook["version"] == "Notebook/1.0"
    assert len({i["name"] for i in workbook["items"]}) == len(workbook["items"])
    queries = [i["content"] for i in workbook["items"] if i["type"] == 3]
    assert len(queries) == 4
    for query in queries:
        assert query["version"] == "KqlItem/1.0"
        assert query["queryType"] == 0
        assert query["resourceType"] == "microsoft.operationalinsights/workspaces"
        assert query["crossComponentResources"] == ["{Workspace}"]
        assert query["timeContextFromParameter"] == "TimeRange"
        assert "_CL" not in query["query"], "Do not invent a probe custom table"
        assert ("AzureActivity" in query["query"]
                or "AADServicePrincipalSignInLogs" in query["query"])
    print(json.dumps({
        "validation": "offline_structural_and_reference_fixture_checks",
        "json_files_parsed": len(documents),
        "synthetic_records_checked": len(fixture["events"]),
        "expected_unique_matches": len(matched_ids),
        "planned_action_cases": len(matrix),
        "minimum_independent_core_trials": sum(c["minimum_independent_trials"] for c in matrix),
        "core_action_configurations": sum(len(c["action_configurations"]) for c in matrix),
        "extended_optional_cases": len(extended),
        "trial_note": "Key1 and key2 rotations have separate fresh baselines and three trials each. Credential observations share a configuration trial.",
        "workbook_query_components": len(queries),
        "live_trials_completed": 0,
        "kusto_service_validation": "not_run",
        "arm_deployment_validation": "not_run",
        "workbook_portal_render": "not_run"
    }, indent=2))


if __name__ == "__main__":
    main()
