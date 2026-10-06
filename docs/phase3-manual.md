# Phase 3 manual parallel-channel protocol

**Source-only fallback protocol; no live Phase 3 result is claimed.** The [automated storage runner](storage-trial-runner.md) now coordinates the six channels and issues bounded SAS in memory. The commands below remain a manual alternative using the fixed-credential probe/respond interfaces; scripts/phase3_link.py validates and summarizes its evidence afterward. Do not mix the two orchestration paths within a cohort.

## One configuration, one action

Use a fresh UUID as the cohort ID and a different random credential-label UUID for each channel. Keep the same channel label and credential environment value across its baseline/post phases. The six channels are key1, key2, service SAS signed by key1, account SAS signed by key2, user-delegation SAS, and a fixed Entra Blob token. Credential labels establish the recorded operator contract; they do not cryptographically prove unchanged secret bytes.

Prepare the nonce blob using storage-baseline.md, with explicit source IP and Shared Key opt-in. Establish all six actor/credential baselines while the receipt is active. Do not grant new roles, refresh a token, issue a replacement SAS or re-read a rotated key during observation. If a credential class is unavailable, retain that channel as not_tested and narrow the resulting claim.

The two rotation configurations are separate cohorts: rotate-key1 and rotate-key2. Each requires three independent trials with newly established baselines. disable-shared-key is a third configuration. Never perform two response actions in one cohort. Verify that the hold deadline covers all channels, the response and cleanup margin.

Acquire a local manual-trial lease before baseline probes; this blocks cooperating configure_access/live_trial/cleanup helpers in this checkout:

    python scripts/trial_state.py begin --manifest private/prepared-manifest.json --trial-id COHORT_UUID

This lease cannot stop portal changes, another checkout or arbitrary direct commands. Serialize those explicitly. Keep credentials only in already-populated process environment variables; the protocol deliberately includes no literal key, SAS or token value.

## Baseline, response, post-action

Run baseline probes in separate terminals/processes for all channels. Each needs at least two successful reads of the same canary. Example for key1 (repeat for key2 with its own variable, label and evidence directory):

    python -m stormlab probe --manifest private/prepared-manifest.json --subscription SUBSCRIPTION_UUID --capability blob-read --auth shared-key --key-env STORMLAB_KEY1 --credential-label KEY1_LABEL_UUID --interval 10 --duration 20 --output private/phase3/COHORT_UUID/key1/baseline.jsonl

SAS channels use --auth sas --sas-env STORMLAB_SERVICE_SAS (or STORMLAB_ACCOUNT_SAS / STORMLAB_UD_SAS). The Entra control uses --auth bearer --token-env STORMLAB_BLOB_TOKEN. Every channel gets a distinct label and directory. Source the canary read permission and credential expiry before the run; baseline 403, firewall denial, expired SAS or unavailable control invalidates that channel.

After all baseline files show at least two successes, execute **one** selected response, saving one shared action receipt:

    python -m stormlab respond --manifest private/prepared-manifest.json --subscription SUBSCRIPTION_UUID --action rotate-key1 --execute --confirm-lab-id LAB_UUID --output private/phase3/COHORT_UUID/action.jsonl

For another independently prepared configuration select rotate-key2 or disable-shared-key. Inspect the receipt's status and postcondition; a timeout or indeterminate response is not a completed mutation. Do not retry rotation in the same cohort.

Immediately start the six post-action probes in parallel, keeping each credential and label unchanged. Use the same command shape, --duration 300 --interval 20 and each channel's post-action.jsonl output. This is a short observation, not a guarantee of propagation. The actual recorded start offsets after response widen the observed transition interval; never invent a common start timestamp. Stop all channels before firewall restoration.

Keep the Entra/user-delegation control and unaffected key channel running concurrently where their expected authorization remains applicable. If every channel fails or the network changes, investigate the control failure before attributing a rejection to the tested action. A command exit alone is not sustained denial.

## Evidence linkage

Run the offline linker once for each available channel, referencing the **same** action.jsonl and cohort UUID:

    python scripts/phase3_link.py --manifest private/prepared-manifest.json --trial-id COHORT_UUID --baseline private/phase3/COHORT_UUID/key1/baseline.jsonl --action-receipt private/phase3/COHORT_UUID/action.jsonl --post private/phase3/COHORT_UUID/key1/post-action.jsonl --output private/phase3/COHORT_UUID/key1/linked.json

It rejects multiple action receipts, another storage target, mismatched credential labels/capabilities, missing successful baseline and invalid phase ordering through the core summarizer. It records raw-file hashes, original run IDs, action acknowledgment time, and per-channel summary without changing raw evidence. Compare the shared action-file hash and observation overlap across channel outputs. It does not automatically validate a cohort's healthy control, determine which key signed a SAS, prove credential immutability, or fill the publication matrix.

After every probe has stopped, verify storage restoration, preserve all linked evidence, and only then release the local lease:

    python scripts/trial_state.py finish --manifest private/prepared-manifest.json --trial-id COHORT_UUID --cleanup-confirmed

Without --cleanup-confirmed, the lease remains incomplete. Never release it solely because a clock elapsed. Reconcile uncertain action and restoration receipts first; preserve invalid trials and reasons.
