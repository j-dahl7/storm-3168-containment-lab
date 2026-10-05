# Storm-3168 containment lab

This repository is a defensive Azure lab. Never claim simulated or offline results are live Azure measurements.

- Keep tokens, keys, SAS values, client secrets, real tenant/subscription IDs and raw tenant evidence out of committed files. Live configuration/evidence belongs in ignored `private/`; credentials stay in process memory or environment only.
- No cloud deployment or mutation without session authorization, an explicitly selected subscription and a bounded cost plan. Do not infer permission from repository access or a default Azure CLI context. The initial protocol targets under $10, no VMs, bounded polling and resource allowlists. This target is not an Azure-enforced spending cap.
- Normal live mutations must verify exact subscription, resource IDs and a server-side `storm3168LabId` resource-group tag matching the manifest. Never adopt existing resources by stamping a tag.
- The only shutdown exception is a bounded emergency DISABLE retry sequence for the exact workflow verified before activation in the same invocation. It uses an immutable in-memory ownership proof confined to that invocation; proof age can prevent activation but must not prevent its shutdown; an unavailable RG/leaf lookup must not prevent the stop attempt. A successful leaf read showing identity drift refuses the stop. This exception never permits delete, unlock, cancel, enable, redeploy or RBAC changes; absent readback remains unknown, never safely stopped.
- Never delete a resource group, subscription, production object or unrecorded resource. Cleanup must use the exact manifest allowlist and revalidate ownership.
- Fixed-token probes use direct HTTP without token refresh or redirects. Operator authentication is separate from the probe credential.
- Unknown, expired, throttled and transport-error outcomes are not successful containment. Measure specific capabilities, not a blanket 'attacker stopped'.
- At least three independent live trials per action are planned. Empty/unrun results must remain `not_tested`.
- Changes to different directories may be built concurrently. Inspect current work before editing and preserve other contributors' changes.

## Shared implementation contract

Python 3.12 standard-library harness, importable `stormlab` package in `src/stormlab`, invoked after `python -m pip install -e .`. Public README command examples must match `python -m stormlab --help`.

`config/manifest.example.json` schema version 1 describes `tenant_id`, `subscription_id`, `resource_group`, UUID `lab_id`, `location`, `storage_account`, `workspace_name`, optional `actor` (application object ID, service-principal object ID and client ID), exact `role_assignments`, optional `group`, and optional owned secret key ID. Real manifests are ignored. UUID examples are fictional. Root will provide setup scripting and docs after interface integration.

Harness provides offline `demo` and `summarize`, read-only `preflight`, bounded fixed-credential `probe`, and explicitly gated `respond` commands. Configuration and destructive actions must be fail-closed. Keep README commands, CLI help, docs, test matrix and templates synchronized.

Infrastructure uses an existing dedicated lab resource group tagged `storm3168LabId`. Only explicit parameters choose the subscription, workspace and actor. Never deploy Entra permissions, live analytics rules or response role grants implicitly. The response Logic App starts Disabled and dry-run by default. A manual trigger is acceptable if secure: use ARM-authenticated management trigger invocation; do not distribute callback/SAS URLs. Sentinel incident trigger and automation binding must be documented accurately and optional. Prefer a managed identity with narrow scoped permissions over broad built-in grants.

Playbook core action should be deterministic, narrow and actually executable (e.g., delete one configured role assignment after exact identity/scope validation). Do not automatically remove resource locks. Graph app/tenant-wide changes are separate explicit harness experiments. Keep automation setup, responder role assignment and workflow activation separate from infrastructure deployment.

Article working title: **Storm-3168: When Does a Compromised Service Principal Actually Lose Access?** Correct timeline: 90 minutes is between identities' initial enumeration, not a warning-to-wipe window. Microsoft's report says further activity 16 hours later. Initial use of the exposed secret is unconfirmed. Source report: https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/
