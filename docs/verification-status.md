# Verification record

Date: 2026-10-05. This is an implementation-readiness record, not the article's results table.

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
| Live probe pilots | Initial temporary-credential issuance failed with AADSTS7000215; bounded initial retries later obtained a token. One pilot recorded successful canary tag writes before a subsequent failure. Temporary credentials were removed after every attempt. | Incomplete pilot runs and source changes during prototyping invalidate these as benchmark trials. No timing result is published. |
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
