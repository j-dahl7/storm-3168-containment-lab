# Detection and visibility queries

Status: **source-reviewed and packaged; not run in a live workspace**. Queries use the provider schemas documented in docs/source-ledger.md S03/S04. There is no claim of Kusto-service compilation or successful alert creation.

| File | Purpose |
| --- | --- |
| 00-visibility.kql | Exact-group export visibility, including operator events |
| 01-actor-activity.kql | Fixed actor's control-plane timeline |
| 02-sp-signins.kql | Exact actor/tenant authentication timeline |
| 03-arrival-delay.kql | Event/submission/ingestion differences |
| 04-sensitive-operations.kql | One recently arrived successful ListKeys, key regeneration, account deletion or lock-deletion candidate |
| 05-repeated-sensitive-operations.kql | Repeated control-plane activity, with explicit threshold and bucket limits |
| 06-denied-sensitive-operations.kql | Failed/denied attempts aggregated for hunting, without an automation binding |
| replay-sensitive-operations.kql | Offline/synthetic KQL fixture demonstration; no provider table required |
| sentinel-rule.arm.json | Native Scheduled analytic resource, disabled by default |

## Scope and clocks

Activity queries select the standard `_ResourceId` when it is nonempty and use
legacy `ResourceId` only when the standard value is absent, null or empty. This
selection happens before every resource-scope predicate. The selected value is
published as `ResourceId`, preserving alert custom details and workbook/export
contracts. A foreign or malformed nonempty `_ResourceId` is never rescued by a
legacy canary ID; the query excludes it. `column_ifexists` also supports a schema
that lacks one of these columns. The real-shape fixtures cover empty legacy IDs,
legacy fallback, conflicts in both directions, and Success/Start status values.

Use the service-principal **object ID**, not its application/client ID. Claims object-ID fields take precedence over Caller; ambiguous/missing matching evidence yields no match. The exact normalized resource-group ID plus slash-boundary prefix prevents a similarly named sibling group from matching. No subscription-wide wildcard is supplied.

TimeGenerated is provider event time. EventSubmissionTimestamp is a distinct provider submission/availability field. ingestion_time() is approximate workspace ingestion, nullable and not a globally ordered clock. The alert query uses a **20-minute arrival gate**, a five-minute schedule, and a one-day source lookback. This intentionally overlaps executions: it allows for the scheduled-rule platform delay and a bounded amount of scheduler jitter. An event ingested quickly can fall beyond one execution's event-time horizon; the older five-minute arrival gate could discard it on the next execution. The independent scheduler regression tests include that counterexample, a skipped run and ten minutes of extra delay. These local tests model the documented timing contract; they do not execute Kusto or prove every possible platform delay.

The automation rule only considers **successful terminal** sensitive operations from the exact lab actor and group. It ranks destructive operations before key operations and selects one candidate. Failed/denied attempts remain in the actor timeline and `06-denied-sensitive-operations.kql`; they are deliberately not automatic-response candidates. This avoids repeated post-response denied probes activating the lab playbook, but also means an attacker's first failed ListKeys attempt alone will not activate this rule. Do not present this as complete Storm-3168 detection. The exact actor predicate also excludes operator/responder operations; no responder role-deletion operation is in the sensitive-operation list.

The analytic has 30-minute suppression enabled and one result per evaluation, keeping a burst and the 20-minute overlap from generating an incident for every event under the normal schedule. The chosen representative EventDataId is included for correlation; additional candidates remain in raw logs. This deliberately trades detection of separate operations during that cooldown for a bounded lab automation exercise. Serialize trials and allow cooldown to finish; do not shorten it to manufacture another successful test. An outage beyond the overlap, events older than one day, repeated re-ingestion after suppression, or platform behavior can still cause misses/duplicates. This is not an exactly-once incident-delivery guarantee. The executor treats an already-absent exact configured assignment as an idempotent no-op after configuration and group checks, without claiming access loss.

ResultType in sign-in logs is displayed as received; the schema describes Success/Failure while existing tenants/examples can expose numeric result codes. Do not assume all records use one encoding. AADTenantId is the directory tenant; TenantId in Log Analytics is the workspace identifier. Never substitute one for the other.

AzureActivity does not reliably record GET enumeration and cannot establish Blob read authorization. Lack of a sign-in event during fixed-token replay is expected to be possible. Directory changes require separate Graph receipts/AuditLogs; those are not supplied by these queries.

## Native analytic template

Explicit parameters: workspaceName, labResourceGroupId, actorObjectId, labId and ruleId; enableRule defaults false. The ARM deployment's target group must contain the existing Sentinel workspace; the monitored lab group may differ. This template creates only one workspace-scoped scheduled analytic rule. It does not onboard Sentinel, create a connector, enable a playbook or grant any role.

The optional dispatcher contract uses ActorObjectId, LabId, ResourceId, ProviderEventId and ProviderEventTime. ProviderEventTime is the source TimeGenerated formatted as UTC, allowing delayed events from an older trial to be rejected even when they create a new incident. LabId is the configured lab UUID. The dispatcher refetches server evidence and verifies the exact rule, singleton details, ownership and bounded trial window; incident text is not authorization. The candidate list includes ListKeys, listAccountSas and listServiceSas as well as key regeneration and destructive operations.

The query embedded in the template is generated from 04-sensitive-operations.kql with the fictional literals replaced by ARM parameters. Preserve synchronization when editing. Stable API 2025-09-01 is used. The rule maps ResourceId and source IP, and keeps ActorObjectId in custom details; it does not pretend the service principal is a human Account.

A lab UUID-derived explicit rule ID avoids display-name adoption. Inspect any existing rule with the same ID before deployment; ARM upserts are not an ownership guard. Follow root setup/preflight instructions. Enabling a rule is a separate action and causes alert/incident writes and possible ingestion costs. Test read-only KQL first.

`scripts/render_kql_replay.py` generates the replay from the complete deployed query body, substituting only the datatable and fixed clock. Each fixture is evaluated through that actual pipeline, followed by a full-batch candidate-selection check. The URI-form objectidentifier claim is used for the normal ARM cases, with explicit short-oid and Caller fallback cases. Local generation/synchronization is not Kusto parsing or execution; the newly generated replay still needs service acceptance after review. Never inject synthetic records into AzureActivity or AADServicePrincipalSignInLogs.

## Alert and incident timing evidence

First collect the scoped Activity Log export with `scripts/telemetry.py`. The
separate read-only helper then reads one explicitly selected Sentinel incident
and its one attributable alert, verifies the exact analytic-rule relationship,
lab/actor/resource custom details and provider event ID, and joins that event to
the existing private telemetry file:

```powershell
python scripts/sentinel_timing.py --manifest private/manifest.json `
  --subscription "<manifest subscription UUID>" `
  --incident-id "<exact incident UUID>" --analytic-rule-id "<exact rule UUID>" `
  --activity-evidence private/provider-telemetry.json --output private/sentinel-timing.json
```

The helper makes no incident update. Sentinel's incident-alert list API uses a
read-only POST. Missing/multiple provider matches remain missing/ambiguous.
`processingEndTime` supplies alert availability; `timeGenerated` is recorded
separately and is never substituted for alert publishing. Incident creation uses
`createdTimeUtc`. Negative clock differences remain uncertain instead of being
clamped or called negative latency. `--include-recorded-responder-run` can add the
exact run saved by the operator helper, but its incident-to-run difference stays
**unattributed**: temporal proximity alone does not prove the incident caused it.
Independent fixed-token measurements remain necessary for access-loss timing.
Live reads also wait for the current review and explicit live authorization.

References: [scheduled rule delay](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview),
[ingestion-delay handling](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay),
[alert clock definitions](https://learn.microsoft.com/en-us/azure/sentinel/security-alert-schema),
[incident alert read API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2025-09-01).
