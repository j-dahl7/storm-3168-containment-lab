# Exact-resource cleanup

`cleanup_lab.py` previews its exact targets by default. It does not contact Azure, acquire tokens, write evidence, or change resources in plan mode. Run it from this checkout after all experiments and fixed-credential probes have stopped:

```powershell
python scripts/cleanup_lab.py --manifest private/manifest.json
```

The manifest must be inside **this checkout's ignored `private/` directory**. The optional responder record is always `private/responder-state.json` from that same checkout. Symlink escapes are rejected. Keep these files: they are the cleanup allowlist and the record needed to reconcile a partial run. Do not copy another lab's IDs into them, recreate missing fields from a portal name search, or change a resource's tags to make cleanup accept it.

The plan contains resource and object IDs; keep its output private. Review the `operations`, `retained`, and `skipped` arrays. `live_validation: not_performed` means the plan has not established that those objects still exist or are owned. Missing responder IDs are skipped rather than reconstructed from recorded GUIDs or discovered by enumeration. An inconsistent recorded grant fails closed because it cannot be validated safely.

To run the reviewed plan, supply the exact subscription and lab UUID already recorded by setup. The placeholders below are deliberately not runnable identities:

```powershell
python scripts/cleanup_lab.py --manifest private/manifest.json `
  --execute --subscription "<manifest subscription UUID>" `
  --confirm-lab-id "<manifest lab UUID>"
```

Execution uses the core `AzureCLI` operator credential provider. It checks the explicitly selected enabled subscription, tenant, token audience and expiry, and requires the operator to differ from the experiment actor. ARM and Graph requests use the core bounded HTTP client, with redirects disabled and credentials only in memory. The operator needs existing permission to remove these exact resources and Entra objects; the cleanup helper grants no permission.

Before the first write, the helper checks the resource group's exact ID and `storm3168LabId`, the exact lab lock ID, and every planned target. Each write repeats the group and target checks. Tagged ARM resources require the matching lab UUID and exact resource type and name. Role assignments require the recorded principal, scope and role definition. The custom responder role must match its lab-specific name, description, single assignable group and narrow permissions. The app, SP and group require exact names and object IDs, matching application/client IDs, the app ownership tag, group ownership description, and expected SP tenant/type.

The execution order is:

1. Disable the recorded responder workflow, verify its state, and verify no nonterminal runs remain. Disabling a workflow does not cancel an existing run; cleanup refuses to delete while one remains. A paginated or ambiguous run response also stops cleanup for review.
2. Delete and verify absence of only the role assignments recorded in the manifest and responder state, then the recorded custom responder role. Built-in role definitions are never deleted. If another unrecorded assignment still uses the custom role, a provider refusal must be reconciled; the helper will not find and delete that assignment.
3. Delete the recorded responder workflow. Azure manages its system-assigned identity's lifecycle; cleanup does not issue a separate Graph delete for that identity.
4. Delete the recorded actor SP, application, and security group, with grants checked absent again before identity deletion.
5. Delete storage and/or the workspace **only if separately included and acknowledged**.

There is no resource-group delete, purge, bulk resource enumeration, lock delete, callback URL, token output, automatic permission grant, or mutation retry. Serialize cleanup with all other lab operations; Azure does not provide an atomic transaction spanning ownership checks and multiple services.

## Locks and partial runs

An object at the exact manifest lab-lock ID stops cleanup before mutation. Review it and use the existing separately gated harness action only if it is the lab-owned lock:

```powershell
python -m stormlab respond --manifest private/manifest.json `
  --subscription "<manifest subscription UUID>" --action lock-remove

python -m stormlab respond --manifest private/manifest.json `
  --subscription "<manifest subscription UUID>" --action lock-remove `
  --execute --confirm-lab-id "<manifest lab UUID>"
```

The harness checks that lock's ID and ownership notes. Cleanup itself never removes any lock. Other locks, inherited locks, policies or permission restrictions may cause Azure to reject a write; do not remove them automatically to get past the failure.

Execution records only local plan/status metadata in `private/cleanup-state.json`, preserving the manifest and responder state. Each successful deletion requires a subsequent exact GET returning 404; an accepted request alone is not sufficient. Polling is bounded to six reads with at most five two-second waits per target. A timeout, 403, 429, transport failure, changed tag or unexpected response stops the sequence. `pending` identifies an operation whose outcome needs reconciliation; do not interpret it as either success or failure. Rerun the same reviewed command after verifying the problem: known targets already absent are recorded as `already_absent`, and no replacement targets are discovered.

This helper does not prove fixed-token revocation or revoke every credential. Cleanup results are lifecycle observations, separate from containment measurements. Offline unit tests prove only the local guard logic, not Azure provider acceptance or a completed live cleanup.

## Retained resources and costs

By default the lab resource group, storage account, and Log Analytics workspace remain. Resource groups themselves are not a usage meter, but retained storage data, transactions, Log Analytics ingestion/retention, enabled Sentinel services and connected telemetry can still generate charges. The workspace ingestion quota and the lab's under-$10 target are not an enforced spending cap. Check Cost Management and any connector or diagnostic settings left feeding the workspace. A successful default cleanup reports `completed_with_retained_resources`; this is not a zero-cost guarantee.

Optional Sentinel dispatcher workflows, API connections, analytics/automation rules, diagnostic settings and any other objects absent from the main manifest/responder state are **not managed by this helper**. It does not discover or disable them. Keep their separate deployment records and reconcile them explicitly; a caller who deployed those optional components must disable their automation before starting this cleanup. Likewise, cloud deployment-history records remain. Do not delete the resource group as a shortcut.

For data cleanup, archive the raw private trial evidence and any needed canary or workspace data first. The script cannot verify that archival is complete. `--acknowledge-data-loss` means the operator either completed that archival or intentionally accepts the loss; it is an acknowledgment, not a backup validation.

Preview inclusion of the **whole canary storage account**, not only its synthetic blob:

```powershell
python scripts/cleanup_lab.py --manifest private/manifest.json `
  --include-storage --confirm-storage-name "<exact manifest storage account>" `
  --acknowledge-data-loss
```

Add the same `--execute`, subscription and lab-confirmation options only after reviewing the plan. The literal account name must match exactly. The account's descendants and contents are part of that deletion; the helper does not acquire storage keys or enumerate blobs.

Preview inclusion of the workspace:

```powershell
python scripts/cleanup_lab.py --manifest private/manifest.json `
  --include-workspace --acknowledge-data-loss
```

Workspace deletion can remove contained Sentinel configuration and data access. This command requests an ordinary workspace delete, never a forced purge, and does not claim that data has been physically erased. Both inclusion flags can be combined with their acknowledgments. The resource group and private evidence remain regardless.

## Offline checks

```powershell
python -m unittest discover -s tests -p test_cleanup.py -v
python scripts/cleanup_lab.py --help
```

Tests use fictional identities and in-memory provider responses, including changed ownership, cross-tenant metadata, lock refusal, active runs, idempotent missing resources, delayed deletes, and transport failures. No test performs cloud writes.
