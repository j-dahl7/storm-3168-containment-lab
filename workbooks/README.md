# Containment evidence workbook

Import containment-evidence.workbook.json into an Azure Workbook's Advanced Editor associated with the intended Log Analytics workspace. This is serialized workbook content, not an ARM deployment template. Import/save is a separate cloud write; none has been performed here.

Replace the fictional Workspace, LabResourceGroupId, ActorObjectId and LabTenantId parameter values with the exact private manifest values. Choose the UTC start/end of one trial and enter its local TrialLabel. Repeat for all independent trials. The label is presentation-only; it is not joined to telemetry or stored in provider logs.

Four actual Log Analytics query components show:
1. all scoped control-plane events, including operator activity;
2. the actor's terminal activity grouped into ten-minute buckets;
3. service-principal sign-in events scoped by directory tenant and actor;
4. event/submission/approximate-ingestion delay per event.

Prerequisites: connected workspace, AzureActivity export and separately authorized service-principal sign-in export. A missing sign-in table yields a query error rather than invented zero activity. The workbook reads AzureActivity and AADServicePrincipalSignInLogs only; it never assumes a custom probe/phase table exists.

Every Activity component scopes the standard `_ResourceId`, falling back to
legacy `ResourceId` only if the standard field is absent/null/empty. The selected
identifier stays named `ResourceId` in displayed/exported results. Conflicting
legacy values cannot admit a foreign nonempty standard ID into the lab scope.

The initial placeholder workspace cannot resolve. Selecting a real permitted workspace and validating queries is required. JSON structure is locally parseable; service-side import/render/query behavior remains unverified.

No phase verdict, percentile or 'time to containment' is calculated from these logs. Compare against the private fixed-token probe JSONL. The default 24-hour display is a convenience, not proof that those events belong to one independent trial. Keep expected and observed results separate.

Azure Workbook format reference: docs/source-ledger.md S19; provider schemas S03/S04.
