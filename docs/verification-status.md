# Verification record

Date: 2026-10-05. This is an implementation-readiness record, not the article's results table.

## Current second-review remediation

Both full independent reports were available for this source pass. The
[tracker](review-remediation.md) identifies the measurement fixes, cleanup
changes and deliberate limits. The site also incorporates Claude's corrected
visuals and replaces the draft's missing expectations with primary-source
guidance. This revision is awaiting independent recheck, not accepted for the
repeated measurement series.

Final local checks for this pass: **262 tests passed** (238 harness/operator and
24 workflow tests), both asset validators passed, all ten Bicep files compiled,
and the offline demo and summary completed. The revised fixtures cover 18
synthetic records; the generated actual-query replay also checks the full-batch
selection. That new replay has not been executed in Kusto. The site's production
and preview builds passed, drafts remained excluded from production, and all
five visuals passed native/Arial/Verdana bounds checks. Desktop and 390px mobile
preview checks found no broken images or page/table horizontal overflow.

No Azure calls or mutations were made for this pass. CORE12 now has an explicit
Blob-token path with storage-window checks; live data authorization is still a
prerequisite. Phase 3 remains a manual multi-credential protocol. Provider event
delivery, workflow acceptance and all containment timings remain unmeasured.

## Previous review-remediation revision

The owner's independent review identified measurement and shutdown defects in
the initial implementation. The [remediation tracker](review-remediation.md)
now maps the full reports to changes and regression checks. That earlier revision had
205 passing offline tests (187 harness/operator tests and 18 workflow tests),
plus artifact validation and ten Bicep-file compilations. Those checks do not
establish Azure runtime behavior.

The article now includes a core results table, four explanatory vector figures
and a social cover. The core protocol is 12 cases, 13 configurations and 39
minimum independent trials. Source-review date labels were removed from the
unpublished site lab while this revision awaits recheck.

**No Azure changes or new live action runs were performed for these fixes.**
In particular, the new Activity Log export, revised detector, longer trial
windows and storage preparation helper have not been exercised live. The
historical receipts below describe their recorded revisions and do not validate
the revised code. Claude's recheck precedes the first live response action.

## Historical setup and initial verification

| Area | Evidence | Limit |
|---|---|---|
| Python harness/operator helpers | 125 offline tests pass for scope, ownership, credentials, failure classification, group paths, operator shutdown and cleanup. | Mocked provider responses do not establish Azure behavior. |
| Logic Apps executor/dispatcher | 16 offline behavioral tests pass against the actual workflow expressions and branches. | The small test interpreter is not the Logic Apps service. |
| GitHub CI | [Offline verification passed](https://github.com/j-dahl7/storm-3168-containment-lab/actions/runs/37375021086) at code revision `c6a71c354c2aadc4dd52f33f264bcf11c025e0e9`, including tests, assets, Bicep compilation and offline demo. | This is CI/source validation, not a cloud containment study. |
| Bicep | Deployment entry points and modules compile locally. | Compilation is separate from provider acceptance. |
| KQL/fixtures/workbook | JSON structure, query/template synchronization and synthetic predicate reference cases pass. The synthetic replay also executed in the lab's Log Analytics service: all 15 rows matched their expected predicates. | This is service-executed synthetic data, not genuine event ingestion or detection. Workbook rendering is pending. |
| Live foundation | A new tagged lab group, LRS storage, bounded-quota Log Analytics workspace and Sentinel onboarding were created in the selected lab subscription. | No VM or production-resource mutation. No new tenant-wide sign-in export was installed. |
| Live identity setup | Dedicated application, service principal and security group created; direct writer and separate Reader grants recorded privately. | This establishes setup, not revocation timing. |
| Live responder deployment | Disabled workflow and conditional grant accepted by ARM. The hardened operator helper completed an Azure runtime dry-run; exact permissions were read back, terminal state confirmed, Disabled verified, and dryRun=true/empty confirmation restored. | No destructive responder execution or containment result is claimed. Native Sentinel incident delivery remains untested. |
| Live probe pilots | Four earlier pilot attempts were incomplete. Initial temporary-credential issuance failed with AADSTS7000215; bounded initial retries later obtained a token. One pilot recorded successful canary tag writes before a subsequent failure. Temporary credentials were removed after every attempt. | Incomplete pilot runs and source changes during prototyping invalidate these as benchmark trials. No timing result is published. |
| Fixed-token control | One no-action ARM-read control completed at code revision `c6a71c354c2aadc4dd52f33f264bcf11c025e0e9`: three allowed baseline requests and three allowed post-control requests with the same frozen token; no source change during the run; temporary credential removal verified. | One control trial is not a three-trial response series or revocation measurement. |
| Retained review environment | Responder Disabled and dry-run defaults verified. Canary service-principal sign-in disabled after the control; this was a maintenance action, not a timed experiment. Storage/workspace retained for review. | These state checks do not claim that previously issued tokens were invalidated. Retained resources can incur ordinary usage charges. |
| Accepted containment series | **0 valid completed action series.** | Every scientific matrix case remains `not_tested` until three independent accepted trials and review. |
| Recovery | Read-only inventory/check helper and manual recovery protocol implemented. | No account deletion or restore result is claimed. |

Raw manifests, provider identifiers and pilot evidence remain under ignored
`private/`. Publish only a separately reviewed, sanitized evidence package pinned
to its tested source revision. The article and site lab stay draft.

## Remaining acceptance work

1. Freeze a reviewed source revision and complete a stable no-action baseline.
2. Validate provider-table KQL and explicitly configure the selected log routes; the synthetic replay is already service-checked.
3. Exercise real exact-target responder execution, then the native incident
   dispatcher, with independent fixed-token verification. The runtime dry-run
   and safe shutdown have already been checked.
4. Complete at least three independent trials for each claimed response action
   and credential type. Keep propagation/expiry/network failures visible.
5. Run optional destructive recovery only after its explicit canary inventory,
   loss acknowledgment and separate retained evidence are verified.
6. Reconcile cleanup, cost and residual access, then update source pins and the
   article's measured results. Conditional Access/risk experiments remain not
   tested without their separate prerequisites.
