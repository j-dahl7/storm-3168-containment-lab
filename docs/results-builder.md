# Offline publication candidates

`scripts/build_results.py` reads only explicitly selected private `trial.json`
files and their sibling manifest/baseline/action/post files. It makes no Azure
calls and never changes raw evidence. The current adapter supports `live_trial`
ARM, Blob-token and manual-executor receipts; storage cohort receipts require a
separately reviewed adapter and are not silently treated as equivalent.

Example, with fictional paths and no automatic acceptance:

```text
python scripts/build_results.py --trial private/runs/RUN_UUID/trial.json --source-repository . --output-json private/results-candidate.json --output-markdown private/results-candidate.md --pending-review-output private/results-review.pending.json
```

The optional pending template contains private run IDs and exact file hashes.
Every entry starts with `operator_reviewed: false` and `decision: "pending"`.
After inspecting the raw evidence and source, the operator can make a separate
private allowlist with reviewer exactly **Codex operator evidence review**,
mark selected entries reviewed/accepted, and assign public pseudonyms. Supply
that file with `--review-allowlist`. This identifies the Codex operator review;
it does not imply human or Claude acceptance. Use fresh output paths each time.

Acceptance still requires a complete linked run, two successful baseline
requests, unchanged recorded source hashes, a fixed credential, verified action
configuration, and verified credential cleanup. Manual-executor trials also
require its recorded role-removal outcome and verified workflow cleanup.
Evidence changed after review fails its pinned file-hash comparison. A supplied
local Git repository is checked without fetching: each recorded source path is
compared with the commit's blob, allowing a documented LF/CRLF checkout
equivalence. A known mismatch blocks acceptance; unavailable Git objects remain
explicit and require the operator's recorded source-hash review.

Public candidates omit tenant, subscription, resource, principal, run and raw
credential-label identifiers. Only intentional public pseudonyms identify runs
and credentials. Failed/incomplete attempts and unreviewed observations remain
separate. Reviewed no-action controls are implementation checks, not CORE05 or
another response trial.

Intervals retain actual client timestamps. The lower bound uses the last
successful request's start; the upper bound uses the first denied response in a
series later qualified by the probe protocol. Both are relative to the action
acknowledgment; a baseline before the action can therefore produce a negative
lower bound. The tool never invents an exact revocation instant. Expiry without
a prior denial is an observation boundary; expiry after a qualified denial does
not erase the earlier onset. Gaps and one-shot new-token controls stay visible.

Numeric median interval endpoints require three accepted, comparable,
uncensored observations with distinct credential labels. Source, action path,
transport configuration, capability, authentication mode, resource/location,
window mode and sampling interval must agree. Any post-action gap or capped
window excludes that run from numeric aggregation. An accepted run can still
show continued access or an inconclusive observation; acceptance is not a claim
that containment succeeded or that this response caused a denial.
