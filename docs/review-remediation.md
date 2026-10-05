# Review remediation and recheck handoff

This tracks the findings supplied in the owner's pasted Claude review. The full
`storm3168-verification-report.md` was not present in the accessible workspace;
the reproductions below target the supplied findings. No Azure deployment,
diagnostic change, response action or recovery run was performed in this revision.

| Finding | Source change | Recheck |
|---|---|---|
| Malformed SAS can appear in a traceback | Sanitized SAS parsing and HTTP URL failures; no exception chain carrying query data. | `tests/test_evidence_fixes.py`: malformed signature and URL exceptions. |
| First denied post-action probe loses the baseline | `summarize --trial` binds the receipt, baseline, action and post-action phases; labels, capabilities, credentials and targets must match. | First-denial, mismatched phase and missing-proof regressions. Old receipts cannot silently gain new linkage evidence. |
| Later expiry erases an observed denial interval | Historical denial intervals, end state and censoring are separate fields. | Denial followed by expiry, renewed access and observation-window end. |
| Key rejection never counts; firewall can look like revocation | Contextual credential rejection is separate from network policy and unattributed 403/401 responses. Action causality stays unproven without the controls. | Rotated-key rejection, source-IP mismatch and generic AuthorizationFailure regressions. |
| Default/maximum windows too short | RBAC/group defaults use a longer bounded window; explicit `--until-token-expiry` uses the recorded remaining lifetime plus margin, capped at two hours. | Default, expiry, cap and subprocess-timeout tests; report censoring rather than claim no eventual denial. |
| Role-removal target absent from receipt | Exact assignment ID, principal, role, scope and direct/group access path recorded. | Target mismatch and direct/group distinction tests. |
| One failed ownership read can prevent DISABLE | Same-invocation immutable preactivation proof bounds an emergency stop. Successful identity drift refuses it; transient lookup failure still attempts the exact DISABLE. Readback failure remains unknown. | RG/leaf failure, identity drift, expired proof and disabled-state verification tests. |
| Missing Activity Log route | Separate guarded opt-in export helper and subscription-scoped template; fresh recorded setting, exact owned destination, explicit subscription-wide scope acknowledgment. | Guard tests and template compilation. Delivery is not yet verified live. Existing destinations and Entra export are not modified. |
| Shared Key/firewall defaults prevent a valid baseline | Optional preparation helper requires the exact lab, an explicit single public IPv4, authorization opt-in, create-only canary and rollback receipt. | Mocked preparation/restore tests. Successful seeding is not actor-access evidence. |
| Fast arrivals may be missed; denied events may flood automation | Wider arrival overlap, one response candidate, suppression and separate denied-attempt hunting; executor treats an exact already-absent assignment idempotently. | Revised synthetic KQL cases and workflow tests. Suppression affects later events and must be accounted for between trials. |
| Alert/incident times absent | Read-only exact incident/alert timing collector joins recorded provider-event identity and retains processing timestamps. | Exact-ID, ambiguous-result and timing tests. Live incident delivery remains pending. |
| Scope and article readiness unclear | Core reduced to 12 cases / 13 configurations / 39 independent trials; full 66-case catalog kept separately. Article gains an explicit results table and explanatory figures. | Review table against core matrix; all unmeasured cells remain pending. |

## Required independent recheck

Run both unit suites, artifact validators and all Bicep compilations. Review the
shutdown exception in `AGENTS.md` against its exact implementation. Inspect
`storage-baseline.md`, telemetry export scope, credential handling and the revised
trial-summary semantics. Do not infer provider behavior from mocked tests.

After this review, select a reviewed source revision and only then schedule the
first live action run. The earlier baseline and dry-run receipts are historical
checks of their stated revisions; they do not validate these new changes.

The website article and lab remain draft. Its premature source-review date
labels were removed. The pre-existing site npm-security failure is separate
from this lab change; dependency work belongs to the site's existing update PR.
