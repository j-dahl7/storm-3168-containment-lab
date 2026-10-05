# Bounded role-assignment response workflow

`main.bicep` deploys a Consumption Logic App with a system-assigned managed
identity. Every deployment starts **Disabled**. `dryRun` defaults to `true` and
`executionConfirmation` defaults to the empty string. There are no implicit
permission grants, Graph calls, Sentinel API connections or automation bindings.

## Interface

The deployment uses the same explicitly selected, tagged lab resource group as
the foundation. Required parameters:

| Parameter | Meaning |
| --- | --- |
| `expectedSubscriptionId`, `labId`, `location` | Match the private manifest and server-side group tag. |
| `workflowName` | Fresh lab workflow name. |
| `actorObjectId` | Exact service-principal object ID; not the application/client ID. |
| `targetRoleAssignmentId` | Complete ARM ID of one role assignment. |
| `targetRoleDefinitionId` | Complete subscription-qualified role-definition ID. |
| `targetRoleScope` | Exact scope of that assignment, inside this lab group. |
| `dryRun` | Boolean; `true` by default. |
| `executionConfirmation` | Empty by default; execution requires `REMOVE_CONFIGURED_LAB_ROLE`. |

Outputs are the ownership gate result, workflow resource ID and responder object
ID. No callback URL, SAS, key or token is returned. The initial workflow ID must
return 404 before creation. A later configuration update may touch only the same
privately recorded workflow after revalidating its ID and lab tag.

## Behavior

1. Reject identifiers outside the configured subscription/group and malformed
   path/query fragments before any ARM request.
2. Read the group and require its exact ID and `storm3168LabId` tag.
3. Read the configured role assignment and require its exact ID, principal ID,
   role definition, scope and service-principal type.
4. In dry-run mode, record `dry_run_no_mutation` and finish.
5. Otherwise require the exact execution-confirmation value, then re-read the
   group and assignment immediately before deletion.
6. DELETE **only the configured assignment**, without automatic retries.
7. Re-read that exact assignment. Only HTTP 404 establishes its absence. An
   unexpected success, forbidden response, throttling or timeout fails the run.
8. Record `role_assignment_removed_access_unverified`. This status does not
   mean that previously issued tokens have stopped authorizing operations.

HTTP action inputs/outputs use secure run-history settings. They contain only
ARM metadata and managed-identity authentication, never actor tokens. One run is
allowed concurrently. The workflow contains a fixed number of HTTP actions and
no polling/retry loop. Platform HTTP timeouts still apply; an operator should
cancel a run that exceeds the experiment's configured time budget.

The separate RBAC template enforces a narrower DELETE condition at Azure's
authorization boundary. Workflow checks alone are not a replacement for it.
No locks are removed. Inherited/group-granted authorization is not silently
removed; these are separate explicit experiments. Removal of this one assignment
cannot establish loss of capabilities obtained from other grants or credentials.

## Secure manual invocation

The Request trigger is named `manual`. Direct request-endpoint SAS authentication
is disabled and direct caller-IP access is restricted to the empty list. Use the
**ARM management operation**, with operator Entra authentication and appropriate
workflow RBAC, instead of distributing a callback URL:

```text
POST https://management.azure.com/{workflow-resource-id}/triggers/manual/run?api-version=2016-06-01
```

`{workflow-resource-id}` above means the ID without a leading slash when joined
to that URL. In actual code use `https://management.azure.com` plus the full ID.
Do not call `listCallbackUrl`. Do not put actor credentials in a request body.
The documented ARM Run API does not define a request payload contract, so the
workflow does **not** depend on that API forwarding an input body. The target,
dry-run flag and confirmation are workflow **deployment parameters**.

Operator sequence, with every resource ID taken from the private manifest:

1. Verify the workflow's tag, identity and configured target via ARM. Verify SAS
   authentication remains Disabled, the direct caller list is empty and the
   workflow state is Disabled.
2. Separately deploy the explicit bounded responder grant. Re-read the actual
   role and condition, and audit the identity for unintended additional grants.
3. Keep `dryRun=true`; explicitly enable the owned workflow with the ARM
   `/enable` operation, invoke `/triggers/manual/run`, and inspect its run status.
   Disable it again in a `finally`/cleanup step. Verify no DELETE was issued.
4. For a mutation trial, update the **owned** workflow with `dryRun=false` and
   `executionConfirmation=REMOVE_CONFIGURED_LAB_ROLE`. The Bicep deployment
   returns it to Disabled. Review the parameters again before explicitly
   enabling and invoking it.
5. Disable the workflow after the run, including failed/cancelled runs. Restore
   `dryRun=true` and empty confirmation on the owned workflow.
6. Run the independent fixed-token verifier using the token acquired **before**
   the role removal. Record each specific capability's result and latency.

The management POST being accepted is not proof that the workflow finished.
Inspect the run and the DELETE/404 verification actions. The role's disappearance
is also not proof of effective containment. A successful trial requires the
independent resource probe with no token refresh or redirects; its token must
remain valid throughout the observation period. Expiration, 429, transport
errors and unknown results are not containment successes.

## Native Sentinel integration

The executor above remains manual and does not appear as an incident-trigger
playbook. The separate `sentinel-dispatcher.bicep` provides a **native Sentinel
incident trigger**, managed-identity API connection and strict incident checks.
`sentinel-automation.bicep` provides its optional disabled automation binding.
`sentinel-dispatcher-rbac.bicep` supplies separately authorized, scoped permission
grants. See [the Sentinel integration runbook](sentinel-integration.md) for the
complete interfaces, activation order and live-validation requirements. Incident
fields never choose the executor's deletion target.

## Offline checks and evidence boundary

```powershell
python -m unittest discover -s playbooks -p 'test_*.py' -v
az bicep build --file playbooks/main.bicep --stdout | Out-Null
```

The tests execute the actual workflow's branching and expressions against mock
ARM replies. They test wrong subscriptions, ownership drift, mismatched
principals/roles/scopes, dry-run, confirmation, and ambiguous absence checks.
Their minimal interpreter is not the Azure Logic Apps runtime. Compile/test
success is **offline evidence only**; deployment, SAS/trigger controls, managed
identity authorization and timing remain `not_tested` until separately exercised.

References: [secure Consumption triggers](https://learn.microsoft.com/en-us/azure/logic-apps/set-up-security-permissions#disable-shared-access-signature-sas-authentication),
[ARM Workflow Triggers Run](https://learn.microsoft.com/en-us/rest/api/logic/workflow-triggers/run),
[managed identity authentication](https://learn.microsoft.com/en-us/azure/logic-apps/authenticate-with-managed-identity).
