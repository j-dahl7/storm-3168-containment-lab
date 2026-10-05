# Verification record

Date: 2026-10-05. This is an implementation-readiness record, not the article's results table.

| Area | Evidence | Limit |
|---|---|---|
| Python harness/operator helpers | Offline unit tests exercise strict scope, ownership, credentials, failure classification, group paths and cleanup. | Mocked provider responses do not establish Azure behavior. Exact current count is the CI run. |
| Logic Apps executor/dispatcher | Offline behavioral tests exercise the actual workflow expressions and branches. | The small test interpreter is not the Logic Apps service. |
| Bicep | Deployment entry points and modules compile locally. | Compilation is separate from provider acceptance. |
| KQL/fixtures/workbook | JSON structure, query/template synchronization and synthetic predicate reference cases pass. The synthetic replay also executed in the lab's Log Analytics service: all 15 rows matched their expected predicates. | This is service-executed synthetic data, not genuine event ingestion or detection. Workbook rendering is pending. |
| Live foundation | A new tagged lab group, LRS storage, bounded-quota Log Analytics workspace and Sentinel onboarding were created in the selected lab subscription. | No VM or production-resource mutation. No new tenant-wide sign-in export was installed. |
| Live identity setup | Dedicated application, service principal and security group created; direct writer and separate Reader grants recorded privately. | This establishes setup, not revocation timing. |
| Live responder deployment | Disabled response workflow accepted by ARM; configured target and trigger restrictions reread. Conditional responder grant deployed separately. One Azure runtime dry-run completed successfully and disable was acknowledged. | Final shutdown/readback hardening needs a fresh check. No destructive responder execution or containment result is claimed. |
| Live probe pilots | Initial temporary-credential issuance failed with AADSTS7000215; bounded initial retries later obtained a token. One pilot recorded successful canary tag writes before a subsequent failure. Temporary credentials were removed after every attempt. | Incomplete pilot runs and source changes during prototyping invalidate these as benchmark trials. No timing result is published. |
| Accepted containment series | **0 valid completed action series.** | Every scientific matrix case remains `not_tested` until three independent accepted trials and review. |
| Recovery | Read-only inventory/check helper and manual recovery protocol implemented. | No account deletion or restore result is claimed. |

Raw manifests, provider identifiers and pilot evidence remain under ignored
`private/`. Publish only a separately reviewed, sanitized evidence package pinned
to its tested source revision. The article and site lab stay draft.

## Remaining acceptance work

1. Freeze a reviewed source revision and complete a stable no-action baseline.
2. Validate provider-table KQL and explicitly configure the selected log routes; the synthetic replay is already service-checked.
3. Exercise responder dry-run and real exact-target execution, then the native
   incident dispatcher, with independent fixed-token verification.
4. Complete at least three independent trials for each claimed response action
   and credential type. Keep propagation/expiry/network failures visible.
5. Run optional destructive recovery only after its explicit canary inventory,
   loss acknowledgment and separate retained evidence are verified.
6. Reconcile cleanup, cost and residual access, then update source pins and the
   article's measured results. Conditional Access/risk experiments remain not
   tested without their separate prerequisites.
