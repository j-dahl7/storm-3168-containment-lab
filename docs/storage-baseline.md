# Optional storage baseline for key, SAS and Blob-token trials

**Implementation only; live preparation has not been validated by this helper's author. Do not run new live actions until the independent Claude recheck is accepted.** This helper is optional and defaults to plan-only. The root verification record governs completed work.

The foundation deliberately disables Shared Key and permits no data-plane source IP. A 403 from that closed foundation is not a working key baseline and cannot prove a later response revoked a credential.

## Interface

    python scripts/storage_baseline.py --help
    python scripts/storage_baseline.py prepare --manifest private/manifest.json --subscription SUBSCRIPTION_UUID --state private/storage-baseline-01.json --client-ip EXPLICIT_PUBLIC_IPV4 --seed-auth shared-key --enable-shared-key --hold-seconds 600

That is a plan, not preparation. After review/authorization, execution requires both --execute and --confirm-lab-id LAB_UUID. The supplied IP must be a single canonical public IPv4 address: no ranges, no 0.0.0.0/0, no automatic external-IP discovery. Check the actual egress path, including NAT/VPN, before the run.

Bearer seeding is the default when --seed-auth is omitted. It requires the separate operator to already have data-write rights on this exact canary container/account; this helper grants no roles. Shared-key seeding additionally requires the explicit --enable-shared-key opt-in and operator ListKeys permission. Keys and tokens stay in memory and are never written to a state or manifest file.

## What preparation does

1. Strictly load the private manifest, verify explicit subscription/tenant, then inspect the live resource-group and account ownership tags.
2. Require a closed starting configuration: Shared Key false, deny-default network ACLs, bypass None, and no IP/VNet/resource-access exceptions. Refuse existing broader or partly prepared state instead of adopting it.
3. Write a non-secret rollback receipt before changing the account. Preserve the original Shared Key, public endpoint and network-ACL settings.
4. Temporarily allow only the explicitly supplied IPv4 source, preserving default Deny. Turn on Shared Key only when separately selected.
5. Create only the manifest canary container if absent, using the data-plane Create Container operation, which fails if the name already exists. An existing container must carry the expected lab metadata and remain private; the helper never stamps metadata onto an existing foreign container.
6. Upload one unique baseline-UUID.txt blob with If-None-Match: *, lab metadata and a nonce. Read it back and verify the nonce metadata and full SHA-256.
7. Write a separate private prepared manifest selecting that exact blob. The original manifest is not overwritten. The helper announces the prepared-manifest path, not credentials.
8. Hold the network baseline for the selected 60–7800 seconds while another process performs the separately selected frozen-credential trial. The default is 600 seconds. Record the announced restoration deadline before starting the actor trial.
9. In finally, attempt to restore and verify the original closed settings after success, failure or an ordinary interrupt. Leave the recorded synthetic container/blob in place for evidence/explicit cleanup; never delete them implicitly.

The receipt and blob are synthetic preparation evidence. A successful **operator** seed does not prove that the **actor's** bearer token, copied key or SAS works. Require successful actor canary reads before the response action.

## What it deliberately does not do

- It does not change actor RBAC, grant broad tenant privileges, create an actor secret, mint SAS tokens or run containment actions.
- It does not hand credentials to another process. A manually prepared frozen credential uses the harness's --token-env, --key-env or --sas-env interface.
- It does not expose production accounts, adopt foreign containers, or bypass locks.
- It does not make the source-IP rule expire inside Azure. Process termination or loss of operator access can prevent finally from running.
- It does not wait indefinitely for firewall propagation or retry a mutation automatically. A failed upload remains an invalid baseline.
- It does not establish a working private-endpoint path. This is an explicitly selected public-endpoint canary test.

Do not run ReadOnly-lock experiments during the hold: the lock can block restoration. Finish the data-plane trial, verify restoration, then start a separately scoped prevention case.

## Restoration and interruption recovery

    python scripts/storage_baseline.py restore --manifest private/manifest.json --subscription SUBSCRIPTION_UUID --state private/storage-baseline-01.json

Inspect that plan. Execution again requires --execute and --confirm-lab-id LAB_UUID. The helper checks exact receipt identity and verifies that current network configuration still matches the prepared policy. The measured response may have changed Shared Key from true to false; that narrowing is accepted. Other drift stops blind restoration and requires reconciliation.

Restoration only returns to the validated closed policy; it will not restore a user-supplied broad allow policy. Read and retain the receipt's preparation_status, restoration_status and settings_restored separately. If restoration is unconfirmed, stop additional trials and reconcile the exact account immediately.

The restoration timestamp is part of the experiment boundary: after firewall closure, a blob denial can be caused by the network rather than the tested credential response. End probing before the hold deadline and compare with an independently healthy control during the observation window.

Select --hold-seconds **before** preparation to cover actor baseline establishment + response action + full post-action probe window + cleanup margin. The live-trial runner uses 900 seconds for RBAC/group response defaults and 300 seconds for other short observations. CORE05/CORE06/CORE12 lifetime observations require explicit --until-token-expiry, bounded to 7200 seconds. In particular, a 60–90-minute CORE12 Blob-token run cannot use the 600-second preparation default. The 7800-second maximum permits a bounded two-hour probe plus up to ten minutes of declared overhead; it does not guarantee that overhead is sufficient. Compare the receipt's hold_started_at/restoration_due_at with the trial plan and refuse to start a trial that cannot fit. Never extend the hold automatically during a live trial.

## Credential matrix and cost

Core key1 and key2 regeneration are **separate configurations**, each with a fresh successful baseline and at least three independent trials. Other credential classes can be observed in the same configuration trial, but a key2 observation after rotating key1 does not count as a key2-rotation trial.

Existing --auth bearer, shared-key and sas probes use the prepared manifest's exact blob. SAS must be read-only, HTTPS and explicitly expiring; no SAS URI or signature is saved.

The tiny nonce blob and a bounded number of requests keep storage usage small, but this is not a spending cap. Storage/Log Analytics/Sentinel and any later playbook charges remain applicable. No VM, private endpoint, new license or paid feed is provisioned by this helper.

## Local tests

    python -m unittest discover -s tests -p test_storage_baseline.py -v

Tests mock cloud operations. They check plan-only behavior, network restrictions, key opt-in, foreign-container refusal, exact receipts, drift refusal, conditional writes and restoration on seed failure/interrupt. They do not establish Azure API, firewall, Blob-signature or data-authorization runtime behavior.

## API references

The implementation follows Microsoft's [Create Container](https://learn.microsoft.com/en-us/rest/api/storageservices/create-container), [Put Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob), [Shared Key signing](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key) and [storage IP-network-rule](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-ip-address-range) contracts. Container creation is a create-only data-plane call; Blob upload uses the documented If-None-Match condition. The operator needs the corresponding permissions in the selected authentication mode. Source review and mocked tests do not verify live availability or propagation timing.
