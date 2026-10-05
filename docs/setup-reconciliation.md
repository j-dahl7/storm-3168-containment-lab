# Setup, access changes and local trial state

These helpers remain source/offline tested until a reviewed live run confirms them. They never repair ownership by stamping tags.

## Partial identity setup

setup_lab.py --resume-identity now accepts exactly the recorded foundation-created, application-created, or service-principal-created prefix before group creation. An application-only manifest is validated as an intentionally partial receipt rather than loaded as a complete actor. Resume rereads the exact recorded app ID, appId, name and lab tag.

If the app is recorded and SP creation may have succeeded without a saved response, the helper queries the one exact recorded appId. A unique Application SP must match its app owner tenant and display name. Its exact ID is then recorded before later stages. Zero matches permits creation; ambiguity, pagination or different ownership refuses it. No existing application's tags are modified.

If application creation succeeded before its ID was recorded, the helper refuses a same-name unrecorded app instead of creating a duplicate or adopting it. Likewise, group-created or later partial failures are outside this resume path. Preserve the receipt and reconcile the exact server/audit evidence; do not invent IDs, discard a partial manifest, or rerun new setup over it. Complete manifests and recorded role IDs can be checked with configure_access after reconciliation.

## Concurrent trials and propagation

live_trial and configure_access use private/active-trial.lock with exclusive local creation plus active-trial.json. configure_access refuses an active/incomplete lease before mutation. Successful access configuration records access-state.json with a 600-second minimum settling interval. The next live_trial checks that interval before creating its temporary secret. Time passing does not prove effective access: every run still needs successful actor baseline requests and effective-role-path inventory.

An interrupted or unconfirmed configuration retains the lease and an incomplete receipt. Cleanup also refuses an active/incomplete lease. Stop the owning process and reconcile its exact pending writes/credentials before any explicit lease release. The manual trial_state finish command's --cleanup-confirmed is an operator assertion after verification, not a recovery oracle.

The lease only coordinates these helpers in this checkout. It does not synchronize another checkout, portal, ARM client or raw core respond/probe command. The 600-second gate is a minimum ARM role-change settling period, not a universal guarantee for group membership propagation. Preserve a failed baseline; do not reinterpret it as containment.
