# Source ledger and claim boundaries

Reviewed 2026-10-05. These are provider documentation and a published incident account, not results of this repository. Recheck before a live run; dates on Microsoft Learn are documentation updates rather than new-feature release dates.

| ID | Primary source | What it supports; boundary |
| --- | --- | --- |
| S01 | [Microsoft Storm-3168 research, 2026-09-25](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/) | June 2026 Azure activity involving two service principals, reconnaissance, resource destruction and key collection. The 90-minute interval separates their initial enumerations; it is not a warning-to-destruction interval. Initial use of the exposed secret, successful exfiltration and a ransom note were not confirmed. |
| S02 | [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log) | Control-plane event collection; reads generally absent; availability usually 3–20 minutes. A silent read query is not evidence of failed access. |
| S03 | [AzureActivity schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) | TimeGenerated, EventSubmissionTimestamp, Claims_d, Caller, ResourceId, OperationNameValue, EventDataId and status fields used here. |
| S04 | [Service-principal sign-in schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs) | ServicePrincipalId is the actor object ID, AppId is client ID, CreatedDateTime is sign-in activity time. A sign-in record is not a record of every resource request. Preserve ResultType rather than assuming all tenants expose one representation. |
| S05 | [Azure RBAC troubleshooting](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting) | Resource authorization changes can propagate asynchronously. Managed-identity group caches have different documented behavior; this lab uses an application service principal unless separately labelled. |
| S06 | [Contributor role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged#contributor) | Authorization write/delete actions are excluded. NotActions is not a deny assignment; another grant can authorize the operation. |
| S07 | [Storage Account Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage#storage-account-contributor) | Storage account management and key access, no direct blob DataActions and no lock deletion from this role alone. S01 attributes storage deletion to this group-granted role. |
| S08 | [Resource locks](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources) | Locks constrain control-plane operations; CanNotDelete does not stop data-plane deletion. ReadOnly blocks ListKeys and can disrupt normal operations. Holders of lock-delete permission can remove a lock. |
| S09 | [Storage account keys](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage) | Two independent account keys; regeneration invalidates signatures under that key, including associated account/service SAS. User-delegation SAS is a different mechanism. |
| S10 | [Prevent Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent) | False rejects account-key and service/account-SAS requests; Entra/user-delegation authorization remains distinct. Account management roles can change the setting unless separately constrained. |
| S11 | [User-delegation SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas) | Key revocation and RBAC/ACL changes are supported revocation paths, with caching delays. Do not equate account-key rotation with user-delegation-key revocation. |
| S12 | [Recover a storage account](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-recover) | Conditional best-effort recovery within 14 days, not a backup guarantee. Avoid name reuse, retain/recreate resource group, restore required CMK vault first; linked private endpoints are not recreated. |
| S13 | [Restore Azure Blobs](https://learn.microsoft.com/en-us/azure/backup/blob-restore) | Vaulted backups restore to a different target storage account; configure them before loss. This is an optional additional experiment. |
| S14 | [Sentinel scheduled-rule resource](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/2025-09-01/alertrules) | Native scheduled analytics resource and properties. Included rule starts disabled; deployability needs a Sentinel workspace and available source table. |
| S15 | [Sentinel playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/create-playbooks) | Logic Apps-based response orchestration. The included manual workflow is not automatically bound to an incident. |
| S16 | [Application update](https://learn.microsoft.com/en-us/graph/api/application-update?view=graph-rest-1.0) and [service-principal update](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update?view=graph-rest-1.0) | Application and service-principal objects are distinct. Actor client ID, application object ID and service-principal object ID must not be interchanged. Validate action semantics against the implemented handler. |
| S17 | [Remove application password](https://learn.microsoft.com/en-us/graph/api/application-removepassword?view=graph-rest-1.0) | Remove only the recorded lab credential key ID; removal of one secret does not remove other credentials or undo prior token issuance. |
| S18 | [Remove group member](https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0) | Removing a member reference is distinct from deleting a group role assignment. Use the member-reference operation, never delete the principal itself. |
| S19 | [Workbook source schema](https://github.com/microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json) | Serialized Azure workbook structure. The workbook queries provider tables; it does not ingest harness files. |
| S20 | [Kusto ingestion_time](https://learn.microsoft.com/en-us/kusto/query/ingestion-time-function?view=microsoft-fabric) | Approximate ingestion completion time, nullable and not a total ordering guarantee. |
| S21 | [Sentinel service-principal sign-in connector prerequisites](https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory) | Tenant diagnostic export and applicable Entra licensing/permissions are independent of subscription logging. Do not silently enable tenant-wide export. |

## Editorial rules

- Reproduce selected defensive behaviors, not the original actor's full operation or its reported timing.
- Do not attribute a failed deletion to a specific missing permission without the API result and effective grants.
- Do not label a successful ListKeys response as confirmed data theft.
- A previously fetched storage key is independent of the fetching principal's next sign-in.
- Do not assert unconditional revocation, recovery, exact-once alerting, or a provider SLA based on this lab.
- Documentation-supported expected behavior, synthetic cases, offline validation and observed Azure results are four separate categories.

