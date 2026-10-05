# Six-phase test plan

**Protocol, not a results ledger.** Consult the root README's current verification status and reviewed private evidence for completed work. The planning matrix and article placeholders do not automatically update when a run finishes.

## Objective and boundaries

Measure when a bounded application service principal loses specific capabilities after a selected response action. Keep separate: new token issuance; reuse of a previously issued ARM token; reuse of a Blob-audience Entra token; possession of copied storage keys/SAS; ingestion; alerts; and playbook execution.

The selected subscription must be explicit and the manifest must match the server-side storm3168LabId resource-group tag. The initial budget target is under USD 10, with no VMs and bounded polling; it is not an Azure spending cap. No tenant-wide role or policy mutation, destructive bulk operations, production data or resource-group deletion belongs in this run.

Use at least **three independent valid trials per action/configuration**, not three HTTP requests in one run. Restore a working baseline between trials, issue a fresh trial credential, and assign a new trial ID. Keep invalid trials and their reasons. Do not silently replace a failed trial. The CSV matrix records planned minimums, not completed counts.

The core study is 12 cases / 13 action configurations / at least 39 independent valid trials. CORE07 contains separate key1 and key2 configurations, each with a fresh baseline and three trials. Credential observations can share a configuration trial. The former 66-case catalog is retained in test-matrix-extended.csv as optional research, not the initial execution workload.

## Core study

| ID | Action / configuration | Minimum trials |
| --- | --- | ---: |
| CORE01 | Visibility baseline: bounded ARM read, tag-write and ListKeys observations | 3 |
| CORE02 | Direct writer assignment removal; retain independent Reader control | 3 |
| CORE03 | Group writer assignment removal; retain independent Reader control | 3 |
| CORE04 | Remove only actor membership in the lab group | 3 |
| CORE05 | Disable SP; fixed ARM token and separately labelled new-token control | 3 |
| CORE06 | Remove recorded secret; fixed ARM token and separate issuance control | 3 |
| CORE07 | Regenerate key1 and key2 as two fresh-baseline configurations | 6 |
| CORE08 | Shared Key disallow; compare copied-key/SAS and Entra controls | 3 |
| CORE09 | Manually invoke guarded executor on one exact writer assignment | 3 |
| CORE10 | Native incident dispatcher dry-run with exact lab evidence | 3 |
| CORE11 | ReadOnly lock versus fixed-token ListKeys capability | 3 |
| CORE12 | Disable SP; separately acquired fixed Blob-audience token | 3 |

These are planned runs, not completed results. CORE12 requires independently established canary data authorization. App-level deactivation, user-delegation-key revocation, actual account deletion, privileged lock removal and recovery remain extended/optional. The account-level CanNotDelete versus ancestor-RG assignment layout is a source-review comparison until a separately guarded experiment is accepted; do not represent it as an executed deletion test.

## Trial protocol

1. Identify exact actor/application/resource/group/assignment/credential IDs from the private manifest; independently verify their ownership and current scope.
2. Record initial effective roles including inherited and group-based paths. An unrelated role that still permits the capability invalidates a claim about removal of the tested path.
3. Acquire the intended probe credential once into process memory/environment; record only audience, issue/expiry times and a non-secret local trial label. Never persist a token, key, signature, SAS URI or client secret.
4. Run an allowed, harmless canary operation until at least two baseline requests succeed. Baseline failure is not successful containment.
5. At an operator-selected UTC time, apply exactly one response action using the separate operator identity. Save API status/request IDs without credential-bearing bodies.
6. Reuse the fixed probe credential with direct HTTPS, no redirects, retry-based reauthentication or SDK refresh. The live-trial runner defaults to a 900-second post-action window for RBAC assignment deletion and group-membership removal, and 300 seconds for other actions, at 20-second probe spacing. The 300-second window is a short, censored observation only; neither default promises that revocation completes within it. The lower-level probe command requires an explicitly selected duration for this protocol.
7. For CORE05, CORE06 and CORE12, explicitly select the live-trial runner's --until-token-expiry mode when testing continued access across the frozen credential's remaining lifetime. This mode is capped at 7200 seconds; record whether that cap prevents full-lifetime observation. Predeclare the window and budget before starting, never extend a live trial automatically. Classify persistent access at a short/capped deadline as right-censored, not infinite access. New-token issuance controls remain separate from fixed-token observations.
8. Stop on token expiry, scope/ownership drift or unexpected mutation. A 401 caused by expiry is not proof the action revoked access. Distinguish 403 authorization from firewall denial; preserve provider error code.
9. Continue collecting telemetry independently after probing stops. Missing or delayed telemetry does not change the recorded API capability outcome.
10. Reset only recorded lab objects. Revalidate baseline before the next trial.

## Phase 1 — Visibility and attribution

Perform a read-only ARM lookup, a bounded lab tag write, ListKeys without persisting keys, and a canary blob read with the intended mechanism. Run each visibility scenario three times.

Compare client request/response time, provider event time, submission time, approximate ingestion time, and alert time. Record missing events explicitly. AzureActivity generally omits reads; AADServicePrincipalSignInLogs reports sign-in activity, not each ARM/data request [S02–S04]. Blob access needs resource diagnostics if storage request attribution is part of the claim.

Execute detections/00-visibility.kql, 01-actor-activity.kql and 02-sp-signins.kql after substituting exact private IDs. Do not join sign-in and ARM CorrelationId as though they were a universal cross-service request key. Use identity/time overlap as context only.

## Phase 2 — Fixed-token containment

The core selects the action/audience configurations above. The full catalog describes separate three-trial series for:
- deletion of one direct RBAC assignment;
- deletion of one group-based RBAC assignment (other members of that group lose that assignment too);
- removal of the actor's membership reference from one lab group;
- service-principal account disablement;
- application-level deactivation, if the implemented handler and Graph contract support the intended operation;
- removal of one recorded application password credential.

Keep cached ARM requests, cached Blob requests and explicitly new token acquisition as separate evidence channels. Run only the channels selected for the core case; other combinations remain extended. Do not silently substitute new authentication for a cached-token channel.

Group membership removal and group-assignment deletion are different rows. Client-secret removal tests the recorded secret only; additional credentials are excluded from the initial lab. Application deactivation must remain not_tested if unavailable: do not infer it from service-principal disablement. Managed-identity cache behavior is outside the initial application-SP scope [S05–S07, S16–S18].

## Phase 3 — Copied storage credentials

Use synthetic content and isolate each action by returning to baseline. Test key1, key2, service SAS signed by key1, account SAS signed by key2, user-delegation SAS and a fixed Entra Blob token. Verify each works before the response being evaluated.

Use the optional storage baseline in storage-baseline.md to establish the nonce canary and an explicitly allowed source IP. The closed foundation's firewall/Shared-Key denial is not a valid success baseline. Stop additional live work until Claude recheck is accepted. The helper restores original settings after its bounded hold and does not prove actor access by itself.

For every Blob trial, including CORE12, explicitly set --hold-seconds to cover actor baseline establishment, the response action, the complete declared observation window and cleanup margin. The preparation default is only 600 seconds; its maximum is 7800 seconds. A 60–90-minute Blob-token experiment therefore needs a predeclared longer hold. Compare the announced restoration deadline with the proposed trial end before proceeding. Never interpret a denial at or after firewall restoration as proof of credential revocation; if the hold cannot cover the trial, do not start it.

Core configurations are regeneration of key1, regeneration of key2 and Shared Key disallow. Each needs three independent fresh-baseline trials across available credential classes. Principal disablement with copied credentials and user-delegation-key revocation remain optional extensions; do not include them implicitly in the initial workload.

Expected distinctions come from S09–S11; leave outcomes empty until observed. A service principal can lose future sign-in while a copied account key still works. Key regeneration affects signatures made with that key, whereas Shared Key disallow is an authorization setting. Neither removes valid Entra data permissions or prevents ARM account deletion. Broad storage-management roles can ordinarily re-enable Shared Key; an independently governed deny policy is a separate prevention control.

The harness implements fixed bearer, Shared Key and SAS probes through the explicit bearer, shared-key and sas authentication modes. SAS input is a read-only HTTPS query string from an environment variable, never a URL; the request targets only the manifest canary blob. This does not imply that a credential matrix has run. Unsupported issuance/revocation helpers and unmeasured matrix cells remain not_tested.

## Phase 4 — Response playbook

The guarded executor starts Disabled and dry-run with an ARM-authenticated manual entry. A separate optional native Sentinel incident dispatcher and automation template are now provided; their permissions, activation and exact alert-evidence contract are independent opt-ins. No deployment alone enables the detection-to-response chain. Follow playbooks/sentinel-integration.md.

Three trials each: dry-run leaves target unchanged; wrong lab ID/resource/actor is refused; valid exact assignment deletion; already-absent assignment; denied responder permission; provider failure/timeout; repeated request. Verify actual assignment state and cached-token resource outcomes separately. No broad role scan/delete and no automatic lock removal.

For the optional native dispatcher, validate the fresh incident/alert lookup, exact analytic GUID and singleton ActorObjectId/LabId/ResourceId/ProviderEventId details in a dry-run before forwarding. Test bad payload, unrelated/multiple alerts and duplicate handling independently. Native analytics can be tested while the executor remains disabled [S14–S15].

## Phase 5 — Prevention

Test the same allowed destructive-capability request against a dedicated disposable resource:
- no lock;
- CanNotDelete with actor lacking lock-delete permission;
- ReadOnly with the same actor;
- a separate controlled actor that has lock-delete permission, recording lock removal as its own operation;
- Shared Key disallowed, with Entra Blob access retained as a control.

The implemented actions lock-readonly and lock-cannotdelete create or update the manifest-owned ReadOnly and CanNotDelete lock respectively. The separate lock-remove action explicitly removes only the verified manifest-owned lock. Never remove a lock merely to make a test or cleanup pass.

No active resource/account deletion during initial runs unless that exact optional case is implemented and separately selected. A denied delete against a protected canary can be measured without deleting it; the unlocked baseline requires its own disposable resource. CanNotDelete does not protect blob content. ReadOnly blocks ListKeys and other management actions, so document compatibility costs [S08–S10].

## Phase 6 — Recovery

Optional destructive extension, not required for initial low-cost containment evidence:
1. Preserve the exact storage configuration and canary checksum outside the account.
2. Delete only the manifest-recorded, dedicated unlocked canary storage account; keep its resource group.
3. Promptly inspect the provider recovery list; do not recreate the account under the same name.
4. Attempt recovery if eligible, then verify canary bytes, configuration and authorization.
5. Record refusal/absence/failure as a valid recovery result, never omit it.
6. An optional private-endpoint run separately verifies re-creation of endpoint/DNS and actual client access; it is outside the initial no-VM budget plan.

Plan three independent recovery trials if recovery success/range will be published; otherwise retain NOT TESTED. Within 14 days is eligibility, not a guarantee. ARM account, no name reuse, existing RG and write permission are prerequisites; CMK adds a required restored key-vault dependency. Use platform-managed keys in the first protocol to isolate variables. Recovery is not independent backup; a preconfigured vaulted-backup restore to another account is a different experiment [S12–S13].

## Measurements and reporting

For every trial retain: protocol revision, trial ID, exact action, credential class, principal type, permission path, intended capability, region, bounded window, interval, token-expiry margin, baseline, action acceptance, first observed denied request, last observed success, outcome class, API request/correlation IDs, telemetry arrivals and cleanup verification.

If last success is at t1 and first verified denial is t2, report the observed transition interval (t1,t2], not an exact instant. Network failure, 429, 5xx, token expiry and unidentified errors are inconclusive. A single forbidden response should be followed by bounded repeated checks where safe to establish sustained denial. Report individual observations and min/median/max only for comparable valid trials; three trials do not establish an SLA, p95 or universality.

Graph directory changes are not proved by AzureActivity. Capture their operator receipts and, if separately authorized, AuditLogs. The provided workbook does not invent a phase table or ingest JSONL; set each trial time range manually and compare it with local evidence.

See operator-handbook.md, test-matrix.csv, source-ledger.md and review-checklist.md.
