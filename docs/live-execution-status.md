# Live execution status

The owner authorized live measurements and the blog update on 2026-10-05.
All work uses the explicitly selected disposable Azure subscription, with an
aggregate under-USD-10 target, no VMs and no production resource deletion. The
target is a forecast, not a hard spending cap. Exact identifiers and raw evidence
remain in ignored private directories.

## Acceptance attempts before the repeated series

| Check | Observation | Interpretation |
|---|---|---|
| Primary ownership and role path | Exact tagged lab, direct writer and retained Reader verified. | Setup evidence only. |
| First new expiry pilot, source `aea75ae` | Seven baseline attempts: five operator-guard read errors and two actor pre-read transport failures. Zero successful baseline requests. No response action invoked. Temporary credential removal verified; lease released. | Invalid trial, excluded. No denied-access or revocation result. |
| Query service acceptance | The initial query wrapper failed service binding; an inline replay exposed an unsupported datetime format in the detector. After correction, all 19 synthetic checks passed through a direct JSON query request. | Service-executed synthetic cases; genuine event ingestion untested. |
| Replacement HTTPS client | Six consecutive operator GETs returned 200 with the expected resource IDs and ownership tags. | Live read-only transport acceptance. No actor response trial inferred. |
| ListKeys no-action control, source `e83c636` | Ten allowed and three transport-error baseline samples; two allowed and two transport-error post-control samples. Source unchanged, temporary credential removed and lease released. | Working fixed-credential control with visible gaps. No containment action or timing result. |
| Next disablement pilot | Five baseline requests succeeded and eight had transport errors. The response command started but no action receipt was produced. Credential cleanup was verified; the conservative lease remained incomplete. Fresh Graph readback later found the exact principal still enabled and the temporary credential absent. | Indeterminate response attempt, excluded. The stopped run was explicitly reconciled before releasing its local lease. |
| Activity Log export | Provider readback returned the exact recorded setting/destination and one enabled Administrative category, plus other explicitly disabled categories and null metrics. | Readback normalization corrected; no broader category or destination accepted. |
| Two isolated replicas | Fresh groups recorded for independent repetitions. Foundation requests encountered connection resets and require exact-state reconciliation before retry. | No adoption or blind deployment retry; no valid trial recorded. |

The replacement client retains trusted TLS/hostname verification, fixed Azure
hosts, no redirects/proxies, bounded responses and no probe authentication retry.
The trial obtains one credential before the action and never silently refreshes it.

Intermittent connection failures continued after the transport change. The
successful diagnostic reads do not establish that the network problem is solved.
Token-bound trials now give the temporary secret a three-hour expiry so its
automatic expiration does not become a second change during a two-hour observation.
The secret is still removed in cleanup; no credential is saved to a file.

## Current measurements, 2026-10-06 UTC

CORE05-A is one operator-reviewed completed observation at source
`b3d4541f1567d2722eb671eccd6231f3f5d6ccd0`. After verified service-principal
disablement, the fixed ARM token produced 35 successful ListKeys responses.
The last successful request began 3,420.9 seconds after the action acknowledgment.
There were also 23 inconclusive post-action samples. No qualified denial was
observed before the harness stopped locally at the token's recorded expiry;
the final successful request preceded that expiry by about 50 seconds. This is
a censored observation, not a measured revocation time or continuous access
through every gap. Temporary credential cleanup and unchanged source were verified.

A separate one-shot token request immediately after disablement returned a token.
It was discarded and never substituted into the measurement. That check does
not establish when issuance stopped. Two independent replica observations are
still running; no three-trial action series is accepted at this checkpoint.

The additional Activity Log export is working. Forty unique successful ListKeys
events from the exact principal/account fell inside CORE05-A's window, matching
the 40 successful baseline/post-action responses by count. A one-to-one request
join has not been established. Event-to-ingestion delays were 103.7-626.0 seconds
(median 369.5 seconds), descriptive event statistics from one trial, not alert or
containment timing. Actual rows populated `_ResourceId` while `ResourceId` was
empty. The corrected detector/workbook aliases the standard field before scope
filtering. Separately, all 26 synthetic service checks passed (25 cases and a
full-batch check); native incident creation remains untested.

Unauthenticated route diagnostics found repeated IPv6 TLS resets while IPv4
completed certificate-verified connections. The explicit IPv4 option records its
mode and preserves trusted TLS, host allowlists and no probe retries. The running
replicas retain their original source/transport; no results are backfilled.
See [transport protocol](transport-address-family.md).

Before the writer-removal runs, CORE02/03/04 were explicitly changed from tag
writes to ListKeys with a separate Reader grant retained. This tests an operation
authorized by the writer role without a read/merge/write sequence. Retaining the
Reader assignment is not a claim that a paired fixed-token Reader probe was run.
Source and cloud configuration stay frozen throughout each observation.

The storage runner automates six parallel credential channels per cohort and one
response. All six nonce/checksum baselines must pass first. A guarded executor
adapter preserves the fixed token and separately records actual workflow-action
times and its unobserved controller interval. Neither new adapter is a live result
until its own provider evidence is accepted.
