# Measured manual execution and native preview preparation

These source adapters need independent review and provider acceptance before
use. They were developed in an isolated checkout; offline tests are not live
results. Use an immutable accepted revision for each measurement run.

## CORE09: measured manual executor

First migrate an existing legacy responder with the separately gated
`playbook_lab.py --operation disable-restore`, then verify a fresh manual dry run.
The existing responder receipt must bind the exact current direct Storage Account
Contributor assignment. An existing Reader grant remains a control and cannot be
the removal target. Unknown prior cleanup blocks the trial. Perform baseline
reset/settling before starting; never change access while a trial lease is active.

```powershell
python scripts/live_trial.py --manifest private/manifest.json `
  --subscription "<manifest subscription UUID>" --confirm-lab-id "<manifest lab UUID>" `
  --action manual-executor --role-assignment-id "<exact recorded assignment ARM ID>" `
  --capability arm-tag-write --duration 900
```

This is a plan until `--execute` is supplied. The actual trial creates one temporary
credential, freezes one ARM token, requires two allowed baseline requests, invokes
the guarded Logic App, and probes with that same token afterward. The adapter
receives no actor token, secret, or credential environment. It never falls back to
direct harness role deletion. The existing local trial lease covers the complete
sequence, including executor cleanup and credential removal.

The action is recorded canonically as `role-delete`, with
`orchestration_action: manual-executor` and `response_transport: guarded_logic_app`
to distinguish CORE09 from a direct operator deletion. Acceptance requires the
exact executor run's removal outcome, successful `Delete_configured_assignment`
action metadata, in-order UTC action start/end times inside this invocation,
independent exact assignment GET returning 404, and verified Disabled/dry-run
restoration. Already-absent, dry-run, forbidden, throttled, unknown or failed
outcomes are not valid removal trials. If shutdown is uncertain, the temporary
credential is still cleaned up and the trial lease remains for reconciliation.

The adapter uses Logic Apps HTTP-action start/end metadata as its action clock;
it does not invent an HTTP response code or fetch SAS-bearing run-history links.
There are no probes during workflow preparation/execution/cleanup. That gap is
recorded explicitly in the receipt/summary and remains inside the last-allowed
to first-denied uncertainty interval. A run with unavailable or inconsistent
action clocks is incomplete, not an invented precise latency measurement.

## Native Sentinel preview

`scripts/sentinel_lab.py` prepares **disabled** analytic, dispatcher/connection
and expiring automation resources and verifies their exact IDs/configuration.
It records fresh GUIDs and source fingerprints before deployment. It creates no
permissions and enables nothing. Existing IDs, changed templates, unknown partial
deployments, a missing owned workspace, or absent Sentinel onboarding fail closed.

Create the local plan with a fresh explicit UTC window, at most two hours:

```powershell
python scripts/sentinel_lab.py --manifest private/manifest.json --operation plan `
  --not-before-utc "<UTC trial start>" --not-after-utc "<UTC trial end>"
```

Review `private/sentinel-state.json`, including the exact generated resource IDs,
role/grant GUIDs and template fingerprints. Deployment is a separate operation:

```powershell
python scripts/sentinel_lab.py --manifest private/manifest.json --operation deploy `
  --subscription "<manifest subscription UUID>" --confirm-lab-id "<manifest lab UUID>" --execute
```

The dispatcher remains `dispatchEnabled=false`, the executor remains
Disabled/dry-run, and analytics/automation stay disabled. Use the existing
`sentinel-dispatcher-rbac.bicep` as a separately reviewed permission step. The
native state already records the five fresh GUID inputs: `group_role`,
`invoke_role`, `group_grant`, `reader_grant`, `invoke_grant`, mapped respectively
to `groupReaderRoleGuid`, `executorInvokerRoleGuid`, `groupReaderAssignmentGuid`,
`sentinelReaderAssignmentGuid`, `executorInvokerAssignmentGuid`. Record their
full resulting resource IDs before that grant request. The exact dispatcher
object ID is saved after verified deployment. Sentinel service-account invocation
permission is another explicit prerequisite; the helper neither discovers nor
grants it. Never adopt a similarly named enterprise application.

After permissions and schema are reviewed, the operator can explicitly enable
only the dispatcher, analytic and expiring binding for one successful controlled
canary event. The executor stays Disabled. Respect the rule's 30-minute suppression
window and record the exact event, incident and dispatcher run IDs. Disable the
recorded analytic/binding after the observation; they are not managed by the
reconciliation helper. Use `sentinel_reconcile.py` for exact recorded workflow/run
and incident cleanup. A partial deployment is not resumed automatically: inspect
the exact recorded IDs and reconcile its private stage/lease first.

The dispatcher definition now publishes only incident/event/time/mode correlation
outputs, never callback URLs or credentials. Read-only preview acceptance checks
the exact incident's rule/actor/lab/resource/event and trial window, the native
trigger name, a successful exact dispatcher run, and matching correlation outputs:

```powershell
python scripts/sentinel_lab.py --manifest private/manifest.json --operation accept-preview `
  --subscription "<manifest subscription UUID>" --confirm-lab-id "<manifest lab UUID>" `
  --incident-id "<exact incident UUID>" --dispatcher-run-name "<exact recorded run name>" `
  --output private/native-preview.json --execute
```

For this read-only operation, `--execute` permits provider reads; it does not
write an incident or enable a workflow. If the provider's `alertType`, Custom
Details, trigger or run-output schema differs, acceptance fails instead of
relaxing the guard. A successful preview proves that exact preview path only:
it explicitly records no executor invocation, role removal, or containment.
Forwarding and mutation remain subsequent independent acceptance steps.
