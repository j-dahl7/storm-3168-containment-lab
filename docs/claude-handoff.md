# Claude Code review handoff

Review the checked-out commit of `j-dahl7/storm-3168-containment-lab` before expanding live testing. The article is **Storm-3168: When Does a Compromised Service Principal Actually Lose Access?**

Start with `AGENTS.md`, `SECURITY.md`, `docs/verification-status.md`, the six-phase
test plan and `docs/review-checklist.md`. Review code and primary sources, not the
earlier brainstorming summaries. In particular, 90 minutes is not a documented
warning-to-wipe interval, and the exposed secret was not confirmed as initial access.

## Reproduce the offline checks

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
python -m unittest discover -s playbooks -p 'test_*.py' -v
python scripts/validate_assets.py
python fixtures/validate_artifacts.py
```

Compile each Bicep entry point without deploying it. Inspect the CI workflow for
the full compilation loop. Offline fixture expectations are a reference predicate,
not a claim that Kusto compiled the queries.

## Highest-priority review targets

1. `src/stormlab/core.py`: fixed credentials, no probe/mutation retries, exact-ID
   guards, SAS handling, evidence classification and correct Shared Key signing.
2. `scripts/live_trial.py`: initial issuance retries happen **before** freezing
   a token; temporary credentials are removed in `finally`; separate baseline
   and post-action files need their trial receipt to be interpreted together.
3. `scripts/setup_lab.py`, `configure_access.py`, `lab_support.py`: no adoption,
   stage reconciliation, selected-tenant Graph authentication, exact private
   paths and direct/group permission isolation.
4. `playbooks/`: fresh incident/alert evidence, exact rule/custom-detail checks,
   guarded configured target, ABAC grant, safe dry-run and disable behavior.
5. `scripts/playbook_lab.py` and `cleanup_lab.py`: active-run handling, mutation
   acknowledgment versus verified state, residual roles and retained resources.
6. `detections/` and `workbooks/`: real schemas, delayed events, correct actor
   identification, source and ingestion clocks, false positives and duplication.

Return findings with severity, file/line, trigger, consequence, smallest fix and
what was actually verified. Do not turn an incomplete cloud pilot into a success.
The harness and playbooks are experimental; the intended outcome of this review
is a defensible version to use for the repeated measurement series.

## Live environment

The current local checkout has ignored `private/manifest.json`, trial receipts,
and responder state. Those files intentionally are not in GitHub. Use an explicit
selected subscription and bounded cost plan; do not infer cloud permissions from
repository access. Never display token, key, SAS or client-secret values.

Retained storage/workspace costs and standing lab permissions require deliberate
review. Cleanup is manifest-driven and never deletes the whole resource group.
The public post must remain draft until measured results and source provenance
are accepted.
