# Sentinel incident → guarded executor

The repository includes a real Consumption Logic App incident-trigger
dispatcher, not a generic HTTP endpoint labeled as a Sentinel playbook. It uses
the Microsoft Sentinel connector's `ApiConnectionWebhook` trigger at
`/incident-creation`, following Microsoft's published incident template.

Every workflow deployment starts **Disabled**. Dispatcher forwarding,
permission grants, the analytics rule and the automation rule are all separate
opt-ins. Offline validation does not establish connector or end-to-end success.

## Components and interfaces

Deploy all components in the same explicitly selected dedicated lab resource
group. Read its `storm3168LabId` tag before each deployment. Initial resource
IDs must return 404; unknown/forbidden responses must abort. Record resource and
deployment IDs privately before execution. Never adopt resources by tagging them.

### `sentinel-dispatcher.bicep`

Required parameters:

- `expectedSubscriptionId`, `labId`, `location`
- `workspaceName`: the existing, manifest-owned Sentinel workspace
- `analyticRuleId`: the GUID of the lab analytic, not its display name
- `dispatcherName`, `connectionName`: fresh names, both recorded in the manifest
- `executorName`: the existing manifest-owned guarded executor
- `actorObjectId`, `targetRoleAssignmentId`, `targetRoleDefinitionId`,
  `targetRoleScope`: must exactly match the executor configuration

Safety parameters:

- `dispatchEnabled=false`: validate evidence/configuration, then finish without
  invoking the executor
- `expectedExecutorDryRun=true`: reject an executor configured differently
- `dispatchConfirmation=''`: forwarding also requires the exact value
  `INVOKE_CONFIGURED_LAB_EXECUTOR`

Outputs: `ownershipGatePassed`, `dispatcherResourceId`, `dispatcherObjectId`,
`connectionResourceId`. The API connection uses `parameterValueType=Alternative`
and the workflow connection has `authentication.type=ManagedServiceIdentity`.
The connection is specific to this dispatcher; do not reuse an unrelated one.

The native webhook registers an internal connector callback with
`@{listCallbackUrl()}`. This is the standard connector handshake, not a URL exposed
as a deployment parameter/output or handed to an operator. Trigger inputs/outputs
use secure run-history settings. Do not disable the dispatcher's internal webhook
authentication or copy its callback URL. The manual executor independently has
SAS authentication disabled and is invoked only through ARM.

### `sentinel-dispatcher-rbac.bicep`

Required inputs: `expectedSubscriptionId`, `labId`, `workspaceName`,
`executorName`, `dispatcherObjectId`, plus these fresh, recorded GUIDs:

- `groupReaderRoleGuid`, `executorInvokerRoleGuid` (subscription role definitions)
- `groupReaderAssignmentGuid` (group scope)
- `sentinelReaderAssignmentGuid` (workspace scope)
- `executorInvokerAssignmentGuid` (exact executor scope)

`grantDispatcherPermissions=false` must be explicitly changed to true. It grants:

1. A custom role with only resource-group metadata read at this lab group.
2. The documented Microsoft Sentinel Reader role at this workspace, for the
   connector and fresh incident/alert reads. Review its built-in permissions;
   the role name alone is not a least-privilege guarantee.
3. A custom role with workflow configuration read and trigger-run permissions,
   assigned only on the exact executor workflow. It cannot enable, edit, or
   delete the executor and cannot modify role assignments.

The internal `dispatcher-role-definitions.bicep` module is not an independent
deployment entry point. Both custom roles have only the lab group in
`assignableScopes`. Record every output role definition and assignment ID for
exact cleanup; audit existing grants because Azure permissions are additive.

Sentinel's service account also needs its own invocation permission, separately
from the dispatcher's identity. Optional parameters
`grantSentinelAutomationPermission=false`, `sentinelAutomationObjectId=''`, and
`sentinelAutomationAssignmentGuid=''` make this explicit. When granted, the
existing, operator-verified Azure Security Insights enterprise application's
object ID receives Microsoft Sentinel Automation Contributor at the dedicated
lab group. This permits Sentinel to invoke playbooks in that group. No enterprise
application is registered and no Graph permissions are granted by these templates.

### `sentinel-automation.bicep`

Parameters: `expectedSubscriptionId`, `labId`, `workspaceName`, `analyticRuleId`,
`dispatcherName`, fresh `automationRuleId`, and an explicit `expiresAtUtc` for
the bounded trial session. `enableAutomationRule` defaults to false.

The rule handles **Incident Created** only, filters the incident's related
analytic rule IDs to the exact lab rule, and invokes the dispatcher. It never
arms either workflow, grants permissions or changes analytics. Its time expiry
is an additional operational boundary, not a substitute for disabling it after
the experiment.

## Evidence and identity guards

The dispatcher performs this sequence before any executor call:

1. Validate configured subscription/group/workspace/executor IDs. Reject query,
   fragment, traversal and percent-encoding characters in identifier paths.
2. Require the trigger incident's ARM ID to be under the exact workspace with a
   single incident GUID. Never trust a callback-provided host or response URL.
3. Read the lab group via ARM and validate its server-side ownership tag.
4. Fetch the incident again from ARM. Require its exact ID, a New/Active status,
   and exactly one related analytic rule, equal to the configured rule.
5. Fetch its alerts from the ARM incident-alerts API. Reject multiple alerts or
   pagination rather than selecting a convenient item from a mixed incident.
6. Require the alert's `kind=SecurityAlert` and `alertType` to equal the configured
   analytic rule GUID.
7. Parse `properties.additionalData['Custom Details']` as JSON. Require singleton,
   nonempty-string arrays for `ActorObjectId`, `LabId`, `ResourceId`, and
   `ProviderEventId`. The actor/lab must match exactly and the resource must be
   the exact lab group or a resource beneath its `/providers/` boundary.
8. Read the configured executor. Require its tag, actor, group, exact assignment,
   role definition, scope and dry-run setting to match the dispatcher.
9. Unless forwarding is explicitly enabled, record preview success and stop.
   Otherwise require the confirmation string and Enabled executor state, then
   call only its ARM `/triggers/manual/run` operation with managed identity.

The repository's `detections/sentinel-rule.arm.json` emits these custom details
and has incident grouping disabled. Confirm the actual live connector payload in
a dry-run before relying on the interface. Unsupported shapes fail closed; do
not replace exact parsing with substring matching against an entire JSON blob.
An incident's fields cannot select a principal, role, URL or deletion scope.

## Activation and live test order

1. Complete the manifest/no-adoption checks. Deploy the optional disabled analytic,
   executor, dispatcher/connection, and disabled automation rule. The foundation
   must have Sentinel explicitly onboarded before creating its rule resources.
2. Separately grant the executor's bounded role-removal permission and the
   dispatcher's read/invoke permissions. Verify actual identities, scopes,
   conditions and all returned ownership gates using fresh ARM reads.
3. Grant Sentinel's independently verified service account permission on the lab
   group if it does not already have the required, recorded lab grant.
4. Start with `dispatchEnabled=false`. Enable only the dispatcher and analytic,
   and arm the expiring automation binding for the controlled trial. Generate
   one scoped canary event. A manual run from **Sentinel's incident page** is also
   valid; the Logic Apps Overview Run button supplies no Sentinel incident body
   and is not a valid dispatcher test.
5. Inspect the real run: exact incident/alert and custom details must pass all
   guards; preview must not invoke the executor. Test foreign actor/group and
   mixed-incident fixtures offline rather than fabricating production evidence.
6. For an end-to-end dry run, keep the executor `dryRun=true`; set dispatcher
   `dispatchEnabled=true`, `expectedExecutorDryRun=true`, and the explicit
   dispatch confirmation. Redeployment returns the dispatcher to Disabled.
   Review it, enable both workflows, and repeat the controlled canary.
7. Only after that passes, configure the executor's explicit mutation parameters
   and `expectedExecutorDryRun=false` in the dispatcher for one allowlisted trial.
   Keep independent fixed-token verification running as described in README.md.
8. After every trial, disable the analytic/binding and both workflows, even on
   failure. Restore preview/dry-run parameters. Use a fresh recorded role
   assignment ID per trial; do not leave restored permissions targeted by a
   still-armed workflow or resubmit stale incidents.

`executor_invocation_requested_outcome_unverified` means the ARM run request
was accepted, not that deletion or containment succeeded. Inspect the executor
run and the independent fixed-token capability results. Preserve event time,
arrival time, incident time, dispatcher/executor times and final denied-operation
time separately. No component claims a seven-minute response guarantee.

## Offline validation

```powershell
az bicep build --file playbooks/sentinel-dispatcher.bicep --stdout | Out-Null
az bicep build --file playbooks/sentinel-dispatcher-rbac.bicep --stdout | Out-Null
az bicep build --file playbooks/sentinel-automation.bicep --stdout | Out-Null
python -m unittest discover -s playbooks -p 'test_*.py' -v
```

These tests execute the real workflow definitions with inert replies. They do
not replace Azure provider validation or a genuine Sentinel incident delivery.
All live outcomes remain `not_tested` until recorded by the operator.

## Primary implementation references

- [Microsoft's incident-trigger deployment template](https://github.com/Azure/Azure-Sentinel/blob/master/Playbooks/.template/incident-trigger/azuredeploy.json)
- [Sentinel connector trigger, permissions and Custom Details schema](https://learn.microsoft.com/en-us/connectors/azuresentinel/)
- [Read incident alerts through ARM](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2025-09-01)
- [Sentinel service-account invocation permission](https://learn.microsoft.com/en-us/azure/sentinel/automation/run-playbooks)
- [Automation-rule resource schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/automationrules)
