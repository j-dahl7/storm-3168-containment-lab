# Synthetic fixtures

Every event in this directory is synthetic. Dates, GUIDs, resource paths and documentation-range IP addresses identify no real tenant. No record demonstrates a cloud action or measured containment.

- azureactivity.synthetic.json models selected AzureActivity columns plus explicit CaseId/ExpectedMatch/SyntheticIngestedAt fixture fields.
- aadserviceprincipal-signins.synthetic.json models two possible raw result representations; neither synthetic result code proves an actual Entra response.
- expected-cases.json defines predicate and deduplication expectations for the detection replay.
- test-matrix.json is the 12-case core plan (13 configurations, at least 39 independent trials). Key1 and key2 regeneration are separate child configurations. completed_trials is zero and observations are empty because this file is a planning template, not the execution ledger.
- test-matrix.extended.json preserves the 66-case optional catalog. Its credential-class observations are not a directive for 198 cloud mutations.

Open detections/replay-sensitive-operations.kql in a KQL-capable environment to inspect the self-contained datatable. It does not query cloud logs and substitutes a declared fixture arrival timestamp for ingestion_time(). A replay pass is query-logic evidence only. An actual Kusto parse/bind/run has not yet been performed here.

Important negative cases include sibling resource-group prefix collision, a different principal, AppId mistaken for object ID, started records, missing event ID, old arrival, out-of-horizon source events and an ordinary canary tag write. Late records within the declared source horizon and terminal denied operations remain visible. Duplicate provider EventDataId records should yield one output in the alert query.

Never upload these fixtures into AzureActivity or AADServicePrincipalSignInLogs. If a separate custom fixture table is introduced later, declare its schema, costs and synthetic identity and never describe it as native provider evidence.
