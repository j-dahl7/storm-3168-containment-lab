# Operator handbook

**Operator protocol.** Check the root README's current verification status and reviewed evidence for completed runs. Setup, probe and response interfaces must be checked against current command help before execution.

## Before running

- Inspect AGENTS.md and the private manifest; explicitly select the intended subscription. Do not rely on the active CLI default.
- Record the cost target, stopping time, resources, region and minimum three-trial plan. The under-USD-10 target is a forecast, not a cloud-enforced cap.
- Ensure an independent operator identity can restore lab configuration and clean up recorded resources.
- Inspect exact server-side storm3168LabId tag, manifest allowlist, role scope and actor linkage.
- Read-only preflight must succeed before any response operation.
- Check that no token or key is passed on a command line, committed in a manifest, logged in a transcript, or printed in screenshots.
- Make sure the action and its blast radius are understood: group-assignment deletion affects the group's assignment, whereas member removal affects that membership reference.
- Keep log workspace, manifest and evidence independent of the canary account being tested.

## Discover the current interface

    python -m stormlab --help
    python -m stormlab preflight --help
    python -m stormlab probe --help
    python -m stormlab respond --help
    python -m stormlab summarize --help

The root README and actual help are canonical. Use only arguments implemented by that revision. A plan/dry-run is not a cloud result. The response command requires explicit execution and matching lab confirmation; never modify a default to bypass a refusal.

Expected interface families are offline demo/summarize, read-only preflight, bounded fixed-credential probe, and gated respond. The exact available actions may be narrower than the test matrix. Unimplemented actions remain not_tested.

## Probe credential handling

Obtain a credential for the specific resource audience before starting the trial, hold it in memory/environment, and pass only its environment-variable name. ARM and Blob audience tokens are not interchangeable. Keep operator credential acquisition separate. Review output redaction before sharing results.

A raw fixed-token request must not follow redirects or refresh a credential. Ordinary Azure CLI or SDK calls may acquire a fresh token and therefore cannot stand in for a cached-token experiment. Local token parsing is only metadata inspection, not verification that the resource will accept it.

The probe supports bearer, shared-key and sas authentication modes. Select the mode explicitly and pass only its credential environment-variable name. SAS mode accepts a bounded read-only HTTPS query string and never changes the manifest destination. Lock actions are lock-readonly, lock-cannotdelete and the separately gated lock-remove.

Use only canary reads or explicitly bounded tag writes. ListKeys requests must discard response key material unless the separate copied-key phase explicitly holds it in memory. Never export the ListKeys response into Sentinel or an evidence JSONL.

## Evidence handling

Private JSONL, configuration, raw receipts and screenshots stay in ignored private/. Produce a separate sanitized report with stable pseudonyms and no real tenant/subscription IDs, principal identifiers, IPs, keys, SAS query strings or token contents.

Do not edit raw evidence to manufacture a clean run. A valid report links a sanitized excerpt to a private evidence identifier and preserves failure reasons. Record source revision and collector query revision.

## Telemetry

AzureActivity is control-plane evidence, AADServicePrincipalSignInLogs is authentication evidence, and optional storage resource logs are data-plane evidence. They have different sources and delays. Authentication success is not resource authorization success; authentication failure is not proof that every old credential has stopped working.

Replace detection query placeholders with the exact lab group resource ID, actor object ID and tenant ID only in a private copy or deployment parameters. Keep Analytics-tier ingestion for scheduled rules. Empty/missing tables fail query compilation; do not turn that failure into a green visibility result.

The native rule is disabled by default. Enabling it or connecting a playbook is a separate operator choice. Alerts are experiment signals, not actor attribution. Repeated rule windows may duplicate alerts; correlate by provider event ID and preserve evidence.

## Playbook operation

Infrastructure and response documentation under infra/ and playbooks/ are authoritative. The guarded executor is manual, Disabled and dry-run initially. The optional native Sentinel incident dispatcher and automation rule are separate disabled opt-ins; see playbooks/sentinel-integration.md. Deployment alone does not create an active detection-response chain.

Before activation, inspect the exact target role assignment, principal, role definition and scope. Grant responder access separately at the smallest feasible scope. The workflow must verify ownership and exact assignment properties again immediately before mutation.

After a reported success, inspect the target assignment and run the fixed-token probe. Acceptance of a DELETE is not equivalent to the observed end of access. A retry must not broaden targets or remove another operator's assignment.

## Stop and cleanup

Stop on wrong subscription, ownership drift, missing baseline, token expiry, unexpected costs/resources, unredacted output, or external dependencies that invalidate the experiment.

Cleanup enumerates only the manifest's exact owned resources. Do not delete a resource group or adopt existing infrastructure. Do not automatically remove protection to make cleanup succeed. If a deliberately protected resource cannot be removed, record it and follow its predeclared recovery/retention plan.

Key rotation or Shared Key disallow can break clients; use the isolated account only. Recreate private endpoints/DNS deliberately after a recovery test. Keep audit evidence long enough for independent review; apply a documented retention/deletion policy to private evidence afterward.

## Reporting gate

Publish results only after three independent valid trials for each claimed action, raw API evidence, telemetry coverage classification, redaction review and exact cleanup confirmation. Where a phase was skipped, retain NOT TESTED. Use the root verification record to reconcile observed runs into the article.
