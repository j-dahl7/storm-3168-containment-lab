# Detection and visibility queries

Status: **source-reviewed and packaged; not run in a live workspace**. Queries use the provider schemas documented in docs/source-ledger.md S03/S04. There is no claim of Kusto-service compilation or successful alert creation.

| File | Purpose |
| --- | --- |
| 00-visibility.kql | Exact-group export visibility, including operator events |
| 01-actor-activity.kql | Fixed actor's control-plane timeline |
| 02-sp-signins.kql | Exact actor/tenant authentication timeline |
| 03-arrival-delay.kql | Event/submission/ingestion differences |
| 04-sensitive-operations.kql | Recently arrived terminal ListKeys, key regeneration, account deletion or lock-deletion events |
| 05-repeated-sensitive-operations.kql | Repeated control-plane activity, with explicit threshold and bucket limits |
| replay-sensitive-operations.kql | Offline/synthetic KQL fixture demonstration; no provider table required |
| sentinel-rule.arm.json | Native Scheduled analytic resource, disabled by default |

## Scope and clocks

Use the service-principal **object ID**, not its application/client ID. Claims object-ID fields take precedence over Caller; ambiguous/missing matching evidence yields no match. The exact normalized resource-group ID plus slash-boundary prefix prevents a similarly named sibling group from matching. No subscription-wide wildcard is supplied.

TimeGenerated is provider event time. EventSubmissionTimestamp is a distinct provider submission/availability field. ingestion_time() is approximate workspace ingestion, nullable and not a globally ordered clock. The alert query uses a five-minute arrival gate within a one-day source lookback. Rows later than that source horizon will be missed; interrupted schedules can also miss windows. Overlap/fallback clocks and repeated ingestion can produce duplicates. This is not exactly-once detection. EventDataId is exposed for deduplication.

ResultType in sign-in logs is displayed as received; the schema describes Success/Failure while existing tenants/examples can expose numeric result codes. Do not assume all records use one encoding. AADTenantId is the directory tenant; TenantId in Log Analytics is the workspace identifier. Never substitute one for the other.

AzureActivity does not reliably record GET enumeration and cannot establish Blob read authorization. Lack of a sign-in event during fixed-token replay is expected to be possible. Directory changes require separate Graph receipts/AuditLogs; those are not supplied by these queries.

## Native analytic template

Explicit parameters: workspaceName, labResourceGroupId, actorObjectId, labId and ruleId; enableRule defaults false. The ARM deployment's target group must contain the existing Sentinel workspace; the monitored lab group may differ. This template creates only one workspace-scoped scheduled analytic rule. It does not onboard Sentinel, create a connector, enable a playbook or grant any role.

The optional separately deployed dispatcher contract uses the exact custom-detail keys ActorObjectId, LabId, ResourceId and ProviderEventId. LabId is the explicit configured lab UUID, not a tag inferred from an event. The dispatcher must fetch current incident/alert state and independently validate rule identity, singleton values and server-side ownership; a user-editable incident field is not authorization by itself.

The query embedded in the template is generated from 04-sensitive-operations.kql with the fictional literals replaced by ARM parameters. Preserve synchronization when editing. Stable API 2025-09-01 is used. The rule maps ResourceId and source IP, and keeps ActorObjectId in custom details; it does not pretend the service principal is a human Account.

A lab UUID-derived explicit rule ID avoids display-name adoption. Inspect any existing rule with the same ID before deployment; ARM upserts are not an ownership guard. Follow root setup/preflight instructions. Enabling a rule is a separate action and causes alert/incident writes and possible ingestion costs. Test read-only KQL first.

The local replay validates predicates only; synthetic records must never be injected into AzureActivity or AADServicePrincipalSignInLogs. Their schema pages do not support the ingestion API. A custom replay table would need its own explicit schema and is not created here.
