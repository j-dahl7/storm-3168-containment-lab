"""Run the fixed synthetic KQL replay in the owned workspace. No ingestion."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from lab_support import ROOT, guid, private_path, save
from telemetry import load_manifest, result_rows
from loganalytics_query import query_owned_workspace, QueryError
from render_kql_replay import build as build_actual_replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="private/manifest.json")
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--output", default="private/kql-replay.json")
    args = parser.parse_args()
    output = private_path(args.output)
    if output.exists():
        raise RuntimeError("Refusing to overwrite evidence")
    query_file = ROOT / "detections" / "replay-sensitive-operations.kql"
    query = query_file.read_text(encoding="utf-8")
    if query != build_actual_replay():
        raise RuntimeError("Synthetic replay is stale; regenerate from the actual deployed query before any cloud call")
    data, model = load_manifest(args.manifest, args.subscription)
    try:
        raw, transport = query_owned_workspace(data, model, query, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")
    except QueryError as exc:
        save(output, {"schema_version": 1, "evidence_type": "synthetic_query_attempt", "synthetic": True,
                      "service_execution_confirmed": False,
                      "provider_event_ingestion_tested": False, "containment_tested": False, "passed": False,
                      "query_sha256": hashlib.sha256(query_file.read_bytes()).hexdigest(),
                      "submitted_query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                      "observed_at": datetime.now(timezone.utc).isoformat(), "status": "query_failed",
                      "failure_kind": exc.kind, "http_status": exc.status, "error_codes": list(exc.codes)})
        raise
    rows = result_rows(raw)
    fixture = json.loads((ROOT / "fixtures" / "azureactivity.synthetic.json").read_text(encoding="utf-8"))
    expected_ids = {event["CaseId"] for event in fixture["events"]}
    expected_ids.add("__full_pipeline_selection__")
    passed = len(rows) == len(expected_ids) and {row.get("CaseId") for row in rows} == expected_ids and all(row.get("MatchesExpectation") in (True, "true", "True", 1) for row in rows)
    result = {"schema_version": 1, "evidence_type": "service_executed_synthetic_query", "synthetic": True,
              "provider_event_ingestion_tested": False, "containment_tested": False,
              "query_sha256": hashlib.sha256(query_file.read_bytes()).hexdigest(),
              "transport": transport,
              "observed_at": datetime.now(timezone.utc).isoformat(), "row_count": len(rows), "passed": passed,
              "cases": [{key: row.get(key) for key in ["CaseId", "ExpectedMatch", "ActualPredicate", "MatchesExpectation"]} for row in rows]}
    save(output, result)
    print(json.dumps({key: result[key] for key in ["evidence_type", "row_count", "passed", "provider_event_ingestion_tested", "containment_tested"]}))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit("Synthetic KQL service validation failed; no ingestion or containment result is claimed")
