# Review remediation and recheck handoff

For the subsequent owner-authorized live acceptance pass, including the new
storage runner and transport/query fixes, see [live execution status](live-execution-status.md).
The round-two inventory below describes the earlier remediation checkpoint.

The second pass uses both full independent reports: the initial review of
`5c76c43` and round two at `f70569a`. The previous pass used the pasted summary
and missed findings; this table replaces its incomplete inventory. The reports
remain local because they include live-environment identifiers.

**Source changes and offline checks are not live acceptance. No Azure deployment,
diagnostic change, response action or recovery run was performed in this pass.**
See [verification status](verification-status.md) for exact completed checks and
historical receipts. Claude must recheck this revision before another live action.

## Measurement and safety findings

| Report item | Source behavior to recheck | Boundary |
|---|---|---|
| A1: observation windows | Token-bound actions default to the fixed token's remaining lifetime plus margin, with a two-hour cap and slower default polling. RBAC/group windows remain explicit and bounded. | Short/capped observations disclose their limit. Expiry is not action-caused containment. |
| A2: baseline and summary | Trial receipts bind baseline, response and post-action run IDs and targets. Qualified denial series survive neutral errors; gaps and the last confirmed sample remain explicit. Known credential rejection, onset and censoring have separate fields. | No inference of continuous denial across a missing sample. A rejected pre-read is not a denied PATCH. |
| A3: firewall classification | Source-IP/firewall and unattributed authorization failures stay separate from qualified denial. | A 403 alone is insufficient. Controls and action attribution still require review. |
| A4: invalid capability pairing | Writer-removal trials reject `arm-read` and reject the retained Reader assignment as the removal target. | Reader is the healthy read control, not evidence of remaining write access. |
| A5: Activity Log destination | Export creation is a separate opt-in. Cleanup handles only its exact recorded diagnostic-setting ID and validates its live configuration even if the destination workspace was already removed. | Existing exports and tenant-wide sign-in settings are not changed. Actual log delivery is pending. |
| A6: storage baseline | Explicit single-IP and Shared Key opt-in, create-only canary, rollback receipt, guarded restore retries and a manual recovery command. Receipt-write failure cannot skip rollback. | The retry budget cannot interrupt an in-flight provider call. Unknown restoration remains a reconciliation task. |
| A7: receipt identity | Exact role assignment, principal, scope, role, direct/group path and linked run IDs are retained. | Old receipts without linkage do not become accepted trials by re-summarizing them. |
| A8: detection and timing | Successful response candidates, bounded overlap and suppression; denied attempts remain hunting evidence. Exact-event alert/incident collection is separate from client timing. | The rule is Scheduled, not NRT. Alert schema and native incident delivery require a live preview. |
| B1: responder shutdown | Bounded retries target the workflow proven before activation in the same invocation. Proof age cannot prevent stopping it; readable identity drift refuses it. A separate `disable-restore` command requires fresh ownership. | The emergency exception never grants cancellation, deletion, redeployment or role changes. Failed readback is unknown. |
| B2: SAS disclosure | Sanitized HTTP failures, strict query-character validation and a final sanitized CLI error boundary. | No provider error body or credential-bearing URL belongs in a receipt. |
| B3: stale incident delivery | Explicit trial start/end plus fresh incident and provider-event evidence prevent replay from an earlier experiment. Recorded-run/incident reconciliation is separate from disablement. | Unrecorded work is not swept up by broad cleanup. Full native delivery is untested. |
| B4: cleanup interruption | Credential cleanup records failure and saves the trial receipt before re-raising an interrupt. | Process termination, power loss or an unwritable disk still require manual reconciliation. |
| Round-two transient read | A temporary operator read failure records an inconclusive probe; partial run IDs survive failure. Polling uses monotonic scheduling. | Successful ownership drift still fails closed; probes do not refresh their credentials. |
| Round-two missing Blob runner | CORE12 uses an explicit fixed Blob-audience token and an active storage-preparation receipt whose hold covers the full window. | Phase 3's multi-credential key/SAS series is a manual protocol; there is no automatic multi-channel trial runner. |

## Additional round-one findings

This pass also addresses recorded partial identity setup, grant IDs saved before
deployment, local trial/configuration concurrency, an access-settling interval,
read-only leftover inventory, distinct executor outcomes, real-query replay
generation, URI-form actor claims and public disclosure checks. These are source
changes, not retrospective claims that the historical pilots used this behavior.

Remaining limits must stay visible:

- The lab keeps its writer grant at resource-group scope for the lock-layout
  experiment. That grants more management authority than a storage-scoped role.
- A local trial lease does not prevent another machine or administrator from
  changing the tenant. Reconcile stale leases; do not delete one blindly.
- The SAS parser supports the deliberately narrow canary protocol, not every
  valid Storage SAS feature or timestamp form. Unsupported forms fail closed.
- Workflow expressions and query fixtures need provider acceptance; a small
  offline interpreter is not Logic Apps, and Python is not Kusto.
- Workload Conditional Access/risk policies, destructive prevention and recovery
  remain untested. Do not replace missing prerequisites with assumptions.

## Article and diagrams

Claude's supplied generator fixes are integrated: cross-platform fonts, existing
token on the cover, consistent colors, corrected action coverage, shared t3
labels, and a storage account connected to its assignment and lock. Two follow-up
labels avoid implying deletion of the Entra group or treating an inconclusive
request as continued access. The native, Arial and wide Verdana render checks
include panel boundaries. Site and public-repository SVG/PNG copies match.

The article uses lowercase tags, pinned canonical source links, a documented
expectation column, mobile result cards, the incident's group-granted role detail,
precise workflow status and reader takeaways. All measurement cells stay pending;
visibility and dispatcher-only cases mark access-loss timing not applicable.

At publication, update the article date and topic catalog, accept and pin the
actual evidence revision, and only then set source-review/lab-verification dates.
Both site pages remain draft. The unrelated site dependency audit belongs to the
existing dependency update PR.
