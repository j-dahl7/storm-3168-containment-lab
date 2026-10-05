# Infrastructure boundaries

These templates are source artifacts. Successful compilation is not evidence of
a deployed Azure resource or a completed security experiment.

## Foundation interface

`main.bicep` runs at **resource-group scope** in an existing, dedicated lab group.

| Parameter | Required / default | Meaning |
| --- | --- | --- |
| `expectedSubscriptionId` | Required UUID | Explicit subscription; never use a CLI default implicitly. |
| `labId` | Required UUID | Must match the existing group tag `storm3168LabId`. |
| `location` | Required | Selected Azure region. |
| `storageAccountName` | Required | Fresh globally unique account name, 3–24 lowercase letters/digits. |
| `workspaceName` | Required | Fresh Log Analytics workspace name. |
| `workspaceDailyQuotaGb` | String, `"0.1"` | Allowed strings: `0.1`, `0.25`, `0.5`, `1`. |
| `enableSentinel` | Boolean, `false` | Optional Sentinel onboarding only. |

Outputs: `ownershipGatePassed`, `storageResourceId`, `workspaceResourceId`,
`sentinelRequested`. No credentials or storage keys are output.

The account is StorageV2, Standard LRS, HTTPS-only, TLS 1.2 minimum, anonymous
blob access disabled and Shared Key authorization disabled. The data-plane
firewall denies all networks. ARM management-plane probes still work according
to the actor's RBAC. A later Shared Key/data-plane experiment needs a separately
reviewed, recorded configuration change; this foundation does not enable it.
No containers or blobs are automatically populated, and no logs are connected.
The workspace uses PerGB2018, 30-day retention and the selected daily ingestion
quota. A daily quota is **not an enforced dollar spending cap**, and data sources
must remain bounded. Sentinel analytics, response bindings and tenant permissions
are separate deployments.

## Mandatory no-adoption preflight

ARM templates are upserts. A matching group tag is necessary but does **not**
prove ownership of pre-existing resources. Before an initial deployment:

1. Read the selected subscription and exact resource group through ARM using
   operator authentication. Require the manifest subscription and group ID to
   match, and `tags.storm3168LabId` to equal the manifest UUID.
2. GET the exact planned storage and workspace resource IDs. Both must return
   **404**. A 403, timeout or other error is not evidence of absence. Abort if
   either already exists; do not stamp ownership tags onto it.
3. Record the planned IDs, location and deployment name in ignored `private/`.
4. Deploy in Incremental mode with an explicit subscription and resource group.
5. Require `ownershipGatePassed == true`, nonempty expected outputs, and a fresh
   read of each created resource's ID/tag. An ownership mismatch deliberately
   deploys no resources and returns empty IDs; do not treat that as success.

On a retry, only update IDs already recorded as owned after a successful prior
creation, and re-read their lab tags. A failed or unknown deployment outcome must
be reconciled before retrying. Never switch to Complete mode or delete the group.

## Optional responder permission grant

Deploy `../playbooks/main.bicep` first. It creates an identity without any grants.
`responder-rbac.bicep` is a **separate resource-group deployment**. It has these
parameters:

- `expectedSubscriptionId`, `labId`
- `responderObjectId`: the workflow's system-assigned identity object ID
- `actorObjectId`: the exact lab service-principal object ID
- `targetRoleDefinitionId`: full subscription-qualified role definition ID
- `responderRoleDefinitionGuid`, `responderRoleAssignmentGuid`: fresh, privately
  recorded UUIDs whose exact planned ARM IDs must first return 404
- `grantResponderPermissions`: default `false`; set `true` only for this explicit
  permission deployment

The internal `responder-role-definition.bicep` module creates a custom role at
subscription scope, with only this lab group in `assignableScopes`. Do not deploy
the module independently. The role has exactly:

- `Microsoft.Resources/subscriptions/resourceGroups/read`
- `Microsoft.Authorization/roleAssignments/read`
- `Microsoft.Authorization/roleAssignments/delete`

The assignment is made at the lab-group scope with a condition restricting
DELETE to the configured actor principal, role-definition GUID, and principal
type `ServicePrincipal`. The workflow additionally checks the **exact assignment
resource ID and scope**. The Azure condition cannot distinguish two assignments
with the same principal/role pair under this group; the workflow provides that
additional boundary. No permission is granted to create assignments, remove
locks, delete resources, fetch storage keys or call Microsoft Graph.

Record both outputs, `responderRoleDefinitionId` and
`responderRoleAssignmentId`, in the private cleanup allowlist. This is a real
privilege grant even though it is narrow. It neither enables nor invokes the
workflow. The operator needs permission to create a subscription-level custom
role and a group-scoped conditioned role assignment. Existing broader grants on
the responder must be audited separately: Azure RBAC grants are additive.

## Offline validation

With Azure CLI/Bicep already installed, compile without submitting deployments:

```powershell
az bicep build --file infra/main.bicep --stdout | Out-Null
az bicep build --file infra/responder-rbac.bicep --stdout | Out-Null
az bicep build --file playbooks/main.bicep --stdout | Out-Null
python playbooks/test_workflow.py
```

Compilation validates Bicep/ARM structure. The behavioral tests interpret only
the workflow operations in this repository against inert ARM responses. Azure
provider acceptance, managed-identity authorization, conditional-role support,
trigger invocation and effective-access timing still need live validation.

References: [role assignment condition attributes](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-authorization-actions-attributes),
[conditional delegation examples](https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-examples).

## Optional subscription Activity Log export

`activity-export.bicep` and its internal subscription module describe a separate,
disabled-by-default export of the **Administrative** Activity Log category to the
exact owned lab workspace. The guarded `scripts/activity_export.py` helper issues
the equivalent exact REST request after live ownership and absence checks. Its
fresh setting name contains both the lab UUID and a newly recorded export UUID.
It never updates an existing central setting or redirects an existing workspace
such as `mcp-lab-law`. It makes no Entra diagnostic or permission changes.

Activity Log diagnostic settings are subscription-scoped. They cannot filter to
this lab resource group at collection time: the category can include unrelated
subscription operations, even though downstream KQL is strictly lab-scoped. This
is a separate opt-in and can add ingestion/retention charges. The quota and lab
budget target do not establish a dollar cap. Use the existing export for read-only
analysis when appropriate; do not enable another setting casually.

Offline review:

```powershell
python scripts/activity_export.py --manifest private/manifest.json
az bicep build --file infra/activity-export.bicep --stdout | Out-Null
```

Only after the current source review and explicit live authorization, creation
uses the selected manifest subscription and lab UUID:

```powershell
python scripts/activity_export.py --manifest private/manifest.json --operation create `
  --execute --subscription "<manifest subscription UUID>" `
  --confirm-lab-id "<manifest lab UUID>" --acknowledge-subscription-wide-export
```

The helper saves `private/activity-export-state.json` before PUT, rechecks the
workspace's exact resource ID/tag and requires the exact setting ID to return
404 twice. An existing setting, 403, timeout or unknown write outcome requires
reconciliation; it is never overwritten or adopted. The ARM API remains an upsert,
so serialize operators around the fresh UUID: these checks are not an atomic
conditional-create guarantee. Successful setting readback proves configuration,
not event delivery. Allow for source/export ingestion delay and independently
verify `AzureActivity` rows using `scripts/telemetry.py` before enabling an analytic.

Use `--operation status --execute` with the same subscription/lab confirmations
for an exact readback. For removal, use `--operation remove --execute` with those
confirmations. Removal validates the recorded setting's ID, destination and sole
Administrative category, then requires 404. Prefer removing the export before
deleting its workspace. Exact recorded removal also works after the destination
is gone: it checks the lab resource group's live tag and the setting's exact
destination/category, without adopting another workspace. Cleanup can use
`remove_recorded_export` with that same private state; it never enumerates exports.
Do not delete the private
record while the outcome is unknown. All other subscription exports stay outside
this helper's allowlist. The internal Bicep module must not be deployed directly;
the helper also checks the workspace tag, which cannot be used as an early Bicep
resource condition from an existing resource's runtime properties.

Primary reference: [Microsoft's Activity Log diagnostic-setting template](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/resource-manager-diagnostic-settings#diagnostic-setting-for-an-activity-log).
