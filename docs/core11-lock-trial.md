# CORE11: ReadOnly lock versus fixed-token ListKeys

This case measures control-plane prevention, not identity revocation. The actor
keeps its current grants; the same fixed ARM token attempts ListKeys before and
after an account-scoped ReadOnly lock. Copied-key and blob-data access are not
measured by this case. `ScopeLocked` (including HTTP 409) remains `lock_denied`,
separate from identity/credential rejection.

After explicit access preparation and its settling period, plan one trial:

```powershell
python scripts/live_trial.py --manifest private/manifest.json `
  --subscription SUBSCRIPTION_UUID --confirm-lab-id LAB_UUID `
  --action lock-readonly --capability listkeys --duration 300
```

Add `--execute` only for the authorized live trial. The default observation is
300 seconds. The wrapper requires fresh absence of the exact manifest-derived
lock ID and empty resource-group/account lock inventories before baseline and
again before the response. Any lock, pagination, forbidden read or unknown
absence refuses the trial; nothing is adopted or unlocked. The receipt records
the exact lock ID, account scope, ownership notes and both checks. Two allowed
baseline requests and the normal linked action/post-action evidence are required.

The tested lock remains applied afterward, just like other response actions.
It is never removed in an automatic `finally` block or by general cleanup. After
the trial stops and its receipt is inspected, the operator can separately plan
and execute only the exact recorded lock removal:

```powershell
python -m stormlab respond --manifest private/manifest.json `
  --subscription SUBSCRIPTION_UUID --action lock-remove
python -m stormlab respond --manifest private/manifest.json `
  --subscription SUBSCRIPTION_UUID --action lock-remove `
  --execute --confirm-lab-id LAB_UUID
```

That existing operation verifies the exact lock ID and lab notes before DELETE
and verifies absence afterward. It removes no parent or unrelated locks. Do not
start the next trial until this explicit cleanup is verified; the next freshness
check will refuse a retained lock. General resource cleanup also refuses locks.

The results builder classifies accepted evidence as CORE11/account-readonly-lock
and marks `identity_revocation_tested: false`. `system`, forced `ipv4` and older
`unrecorded` transport configurations are reported and aggregated separately.
Network gaps and local token expiry never become proof that the lock blocked a
request. Source/offline tests are not a live CORE11 result.
