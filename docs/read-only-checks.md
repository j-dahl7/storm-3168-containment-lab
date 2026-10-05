# Read-only telemetry and recovery checks

These helpers perform authenticated reads and write filtered metadata to new files under ignored private/. They do not create diagnostic settings, restore accounts, change permissions or delete resources. Querying can incur normal platform charges; ranges and returned rows are bounded.

Inspect the implemented interfaces:

    python scripts/telemetry.py --help
    python scripts/recovery_check.py --help

## Telemetry

Required arguments: --manifest, --subscription, --start, --end and --output. Timestamps must explicitly use UTC (Z or +00:00), with a positive interval no longer than 24 hours. --max-rows defaults to 1000 and is bounded to 1–5000 per source; a sentinel extra row marks truncation.

Example shape; replace angle-bracket values with the intended private selection:

    python scripts/telemetry.py --manifest private/manifest.json --subscription <subscription-uuid> --start <UTC-start> --end <UTC-end> --output private/telemetry-trial-01.json

The manifest is strictly validated and matched against the explicit subscription, tenant and server-side lab RG tag. The created workspace must match the manifest ID and lab tag. Its customerId is fetched from that exact live resource and rechecked immediately before running az monitor log-analytics query. No caller-provided workspace customer UUID is accepted.

By default only AzureActivity is queried, using the exact lab resource-group path boundary. To query service-principal sign-ins in the same owned workspace, add --include-signins. To use an existing identity-log workspace, supply --identity-workspace-resource-id with its exact ARM resource ID; it must be in the same tenant and is recorded as an explicitly selected external read-only source. This does not claim ownership or configure export in that workspace. Only the exact actor and directory tenant are queried there.

The log-analytics CLI extension must already be installed. The helper disables dynamic extension installation for its process and does not install one.

Outputs contain an explicit field allowlist, timestamps, row counts, scope selection and collection state. Raw Claims, HTTPRequest, provider payloads, credential-bearing responses and free-form sign-in error descriptions are omitted. Real resource/actor IDs and source IPs can remain in the private metadata; redact them before publication. Missing tables or query failures are recorded as failed sources and return a partial status rather than zero successful observations.

AzureActivity generally omits reads; sign-in events are not per-request authorization outcomes. Run the helper again with a new output file after an appropriate ingestion interval to inspect arrivals. It does not poll or refresh the fixed probe credential.

CLI reference: https://learn.microsoft.com/en-us/cli/azure/monitor/log-analytics?view=azure-cli-latest#az-monitor-log-analytics-query

## Recovery readiness

    python scripts/recovery_check.py --manifest private/manifest.json --subscription <subscription-uuid> --output private/recovery-readiness-01.json

Optional --deleted-at supplies an operator-asserted UTC timestamp. The report can calculate whether that assertion lies within 14 days but never treats it as provider-verified deletion evidence.

The helper inventories storage accounts only in the owned resource group, then reads configuration only for the exact manifest account if present and ownership-tagged. It never lists account keys. If absent, eligibility remains not_established: visit the documented Azure portal Restore deleted account pane, verify name-reuse and prerequisite conditions, and obtain the necessary write permission separately.

There is no guessed restore endpoint or automatic restoration. Best-effort recovery, required CMK dependencies and private endpoint/DNS recreation remain manual provider-documented checks. Verify actual canary bytes and application access after any separately authorized restore.

Provider procedure: https://learn.microsoft.com/en-us/azure/storage/common/storage-account-recover

## Local validation

    python -m unittest discover -s tests -p test_telemetry.py -v

The tests mock Azure operations. They cover ownership and scope refusals, live customer-ID binding, UTC and row bounds, optional source selection, result filtering, private-file no-overwrite behavior, and recovery's refusal to claim eligibility. Passing these tests is not a live Azure query or recovery result.
