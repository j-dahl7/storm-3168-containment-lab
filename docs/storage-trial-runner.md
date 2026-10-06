# Automated storage cohorts

**Implemented and offline tested; runtime acceptance still depends on observed baselines and receipts.** This runner performs live changes only with explicit --execute, subscription and lab confirmation. It operates on the existing disposable account; it creates no VM, resource group, workspace, diagnostic setting or new cloud identity.

Run from the exact reviewed checkout. Do not edit its source while any live trial is running. Review AGENTS.md, the private manifest, source revision and accumulated cost first. The under-$10 target is not an enforced spending cap.

## Prepare the exact data control

The actor needs one recorded Storage Blob Data Reader assignment **at the exact canary storage account**, in addition to the existing management path. This role provides Blob reads and user-delegation-key generation. It does not grant Blob writes/deletes. Creating the role is a separate explicit setup operation:

    python scripts/configure_access.py --manifest private/manifest.json --subscription SUBSCRIPTION_UUID --confirm-lab-id LAB_UUID --data-reader-control add

Inspect that plan, then append --execute when executing the authorized setup. The helper persists the assignment UUID before PUT and refuses another principal or broader scope. Normal direct/group configuration preserves only this exact recorded data-reader control; an unrecorded or broader grant still stops preparation. After a successful configuration, wait for the recorded 600-second settling interval and establish actual baselines. The actor must already be enabled; adding this data role does not enable it.

At the end, the corresponding --data-reader-control remove action removes only that recorded assignment. Full cleanup also recognizes its exact manifest record.

## One action series

Generate a fresh series UUID locally. The following command is an offline plan and makes no Azure calls:

    python scripts/storage_trial.py --manifest private/manifest.json --subscription SUBSCRIPTION_UUID --action rotate-key1 --series-id SERIES_UUID --client-ip EXPLICIT_PUBLIC_IPV4 --trials 3

Execution additionally requires --execute --confirm-lab-id LAB_UUID. Actions are rotate-key1, rotate-key2 and disable-shared-key. Each action gets a separate series; each series targets three independent valid cohorts. Default post-action duration is 300 seconds at 20-second intervals. Duration is explicitly bounded to 60–900 seconds and interval to 5–30 seconds. A short window that ends with access allowed is censored, not universal persistence.

The runner:

1. Verifies exact IDs, live ownership, actor state, the recorded data-reader assignment, local trial lease/settling state and the closed network/Shared Key starting policy.
2. Writes a cohort receipt, opens the explicit single IPv4 source and enables Shared Key only on the canary account. It performs bounded read-only readiness checks before create-only container/blob operations. Restrictive firewall or Shared Key propagation is preparation evidence, not revocation.
3. Seeds a fresh nonce blob and verifies its full checksum. It obtains a temporary credential only on the recorded actor application, then one fixed Storage-audience actor token. No credential is printed or written to disk.
4. Captures key1/key2 in memory, creates a read-only HTTPS/IP-bound service SAS signed by key1, an account SAS signed by key2, and an actor-owned user-delegation SAS. It keeps the actor token as the sixth channel. The account SAS can read Blob objects across this disposable account; the harness still sends requests only to the exact canary path.
5. Requires full nonce/checksum reads and at least two successful baseline probes for **all six channels**, concurrently. No response runs after a failed baseline.
6. Applies exactly one selected response and records its exact receipt. Shared Key disablement additionally requires verified configuration readback before post-action probing. It never retries rotation or another response, including after an uncertain acknowledgment/readback. The credential values used by probes never change.
7. Runs the six post-action channels concurrently. Links each channel to the same action receipt and source-file hashes. User-delegation SAS and Entra Blob access are controls; the unrotated key and the SAS signed by that key are additional rotation controls. A failed/unknown control, expired credential or incomplete channel prevents a valid-trial count.
8. Restores the original closed network/Shared Key policy and removes the exact temporary secret. It verifies both, records source hashes and releases the local lease only when cleanup and action acknowledgment are known. The source remains unchanged between cohorts.

The runner leaves the actor's pre-existing management/data grants and the tiny recorded synthetic blobs intact. Key rotation is irreversible; cleanup does not restore an old key. Every subsequent cohort reacquires current keys and creates new SAS, token, labels and nonce before baseline. There is no automatic response compensation.

## Failure and resume

private/storage-series-SERIES_UUID.json indexes private/storage-runs/COHORT_UUID/. Each cohort contains source hashes, prepared-manifest reference, credential key ID (never secret), action receipt, six baseline/post-action JSONLs, per-channel linked summaries, checksum/control findings and restoration/cleanup status.

Any failure stops the series. Invalid attempts remain recorded and are not silently replaced. --resume may start a **new** cohort only when every prior cleanup/action outcome is unambiguous, the source/configuration matches, the local lease is idle, and live read-only guards confirm the closed starting policy and current actor/control assignment. It never resumes the middle of an old cohort or replays an action. Unknown secret cleanup, storage restoration or action acceptance requires explicit reconciliation; do not remove the lease just to continue.

The embedded storage hold is post-action duration plus 600 seconds. The runner checks remaining hold before credential work, before response and after response, and marks overruns incomplete. In-flight provider requests are bounded but cannot be interrupted by a hard Azure-side timer. Parent/operator termination can still require the receipt-based storage restore command.

These timings measure the API client observations. The existing range probes read one byte; separate full-body checks establish the nonce/checksum and control integrity. AzureActivity ingestion, alert delivery and any playbook timing require their own collection and do not come from this runner.

## Sources and tests

Signing uses explicit API version 2023-11-03 and Microsoft's [service SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas), [account SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas) and [user-delegation SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas) field ordering. New request/user-bound SAS fields are not used. The [Storage Blob Data Reader role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage#storage-blob-data-reader) defines the required control rights.

Service/account test vectors were generated independently with the locally installed Azure SDK. The user-delegation vector uses its canonical-string hook with the two newer, empty delegation fields removed to match the documented 2023 contract. No cloud authentication was used for vector checks; successful live checksums remain required before mutation.

    python -m unittest discover -s tests -p test_storage_trial.py -v
    python -m unittest discover -s tests -p test_storage_baseline.py -v
    python -m unittest discover -s tests -p test_access_setup.py -v

All regression tests use fictional identities, synthetic credentials and mocked providers. They verify sequencing, scope refusals, checksums, parallel channels, no response after bad baselines, no replay after lost action acknowledgment, control failure handling and credential-free evidence.
