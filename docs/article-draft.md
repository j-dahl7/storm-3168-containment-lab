---
title: "Storm-3168: When Does a Compromised Service Principal Actually Lose Access?"
date: 2026-10-05
lastmod: 2026-10-05
category: "Resilience & Recovery"
categories: ["Resilience & Recovery"]
tags: ["Microsoft Sentinel", "Azure", "Service Principals", "Incident Response", "Azure RBAC"]
images: ["visuals/og-storm3168-containment.png"]
featured_image: "visuals/og-storm3168-containment.png"
toc: true
draft: true
author: "Jerrad Dahlager"
description: "Build a guarded Sentinel response and measure when existing Azure tokens, copied storage keys and SAS credentials actually lose access."
---

> **Draft under review.** The implementation, explanatory diagrams and measurement protocol are ready for another review. The repeated containment study is not complete. Pending cells below are not measured results.

<figure class="media-panel media-panel--hero">
  <img src="visuals/og-storm3168-containment.png" alt="Storm-3168 containment lab: measure tokens, Azure RBAC and copied storage keys as separate access paths" width="1200" height="630" loading="eager" decoding="async" fetchpriority="high">
</figure>

Disabling a compromised service principal feels like the end of a response. The portal confirms the change, the playbook finishes, and the incident can look contained.

That conclusion needs a resource request behind it. An access token issued earlier, a copied storage key and a key-signed SAS do not all depend on the same authorization decision. A configuration change can close one route while another remains available.

This lab follows a narrower question: **after one response action, which exact request stops working, when do we observe that change, and what still works?** Microsoft Sentinel supplies the detection and orchestration context. A separate harness supplies the access evidence.

## The results table comes first

The final article will lead with observed intervals and remaining access. For now, the table is the reporting contract. Each configuration needs three independent valid trials with a working baseline; repeated HTTP requests inside one trial do not count as additional trials.

| Experiment | Credential or evidence path | Valid trials | Access-loss interval | What still worked |
|---|---|---:|---|---|
| Visibility baseline | Actor writes and ListKeys; provider logs | 0 / 3 | Pending | Pending |
| Remove direct writer grant | Existing ARM token | 0 / 3 | Pending | Pending |
| Remove group writer grant | Existing ARM token | 0 / 3 | Pending | Pending |
| Remove group membership | Existing ARM token | 0 / 3 | Pending | Pending |
| Disable service-principal sign-in | Existing ARM token; separate issuance check | 0 / 3 | Pending | Pending |
| Remove the tested application secret | Existing ARM token; separate issuance check | 0 / 3 | Pending | Pending |
| Regenerate key1 and key2 in separate runs | Copied keys and their SAS controls | 0 / 6 | Pending | Pending |
| Disallow Shared Key | Key/SAS matrix; Entra control | 0 / 3 | Pending | Pending |
| Execute the guarded response manually | Exact role removal; independent probe | 0 / 3 | Pending | Pending |
| Deliver a native Sentinel incident | Dispatcher dry run and event timing | 0 / 3 | Pending | Pending |
| Apply a ReadOnly account lock | Existing ARM token requesting ListKeys | 0 / 3 | Pending | Pending |
| Disable sign-in for a Blob-token test | Existing Entra Blob token | 0 / 3 | Pending | Pending |

That is 12 core cases, 13 action configurations and 39 minimum independent trials. The larger matrix remains an extension, including application deactivation, destructive prevention tests and recovery. It is not the minimum scope for this article.

One earlier no-action control did complete: three ARM reads before and three after the control point, using the same token. Four earlier pilot attempts were incomplete. Those receipts, the synthetic KQL replay and the responder dry run are implementation checks; none fills a revocation row in this table. The [verification record](https://github.com/j-dahl7/storm-3168-containment-lab/blob/main/docs/verification-status.md) keeps those distinctions visible.

## Why Storm-3168 is the right incident to examine

Microsoft's September 25 report describes June 2026 activity involving two compromised Azure service principals. The destructive phase included more than 100 storage-account deletion attempts in roughly seven minutes, with resource locks blocking some attempts. Credential collection created another concern: successful ListKeys requests could provide a separate route to data.

The timeline does not establish a 90-minute warning before destruction. That interval separates the identities' initial enumeration; the report describes further activity 16 hours later. Initial compromise through the exposed GitHub secret was unconfirmed, as were a ransom note and successful exfiltration. The observed timing supports automation; this lab does not independently prove how an AI system directed it. [Microsoft's investigation](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)

The useful response lesson is about authority. We need to account for the principal's current permissions and credentials already obtained through those permissions.

## Separate the three access paths

<figure class="media-panel media-panel--diagram">
  <a href="visuals/credential-paths.svg" target="_blank" rel="noopener" aria-label="Open full-size diagram: New token issuance, existing ARM-token authorization and copied storage credentials use separate access paths">
    <img src="visuals/credential-paths.svg" alt="New token issuance, existing ARM-token authorization and copied storage credentials use separate access paths" width="1280" height="800" loading="lazy" decoding="async">
  </a>
  <figcaption>Explanatory model. These are separate test channels, not measured response outcomes. Select the diagram for the full-size vector.</figcaption>
</figure>

**New token issuance** is an authentication question. Can the application use the tested credential to obtain another token? Disabling sign-in or removing that credential targets this route. Application-level deactivation and tenant-local service-principal disablement are distinct operations. [Application deactivation](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/deactivate-app-registration)

**An existing ARM token** is a resource-authorization question. The experiment retains one token and repeatedly requests the same bounded operation. Workload-identity continuous access evaluation currently supports Microsoft Graph as the resource provider; it should not be assumed to revoke ARM access the same way. [CAE scope](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload)

**A copied storage credential** is a third route. Regenerating one account key affects that key and SAS signed with it. User-delegation SAS is not revoked by account-key rotation. Disallowing Shared Key also has a different scope from removing Entra data permissions. The matrix keeps those controls separate. [Key rotation](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage), [Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)

A disabled principal with no remaining secrets is therefore not, by itself, evidence that every previously issued credential is unusable.

## Establish visibility before enabling a response

The first check is mundane and essential: does the selected workspace receive the intended source?

Creating a Sentinel workspace does not establish an Activity Log export. The lab needs an explicit route from the subscription, while preserving any existing destination. Service-principal sign-ins can be read from a separately selected authorized workspace. The collector records that choice rather than pretending both sources live in one place.

Azure Activity Log generally omits ordinary reads. Authentication logs also do not describe every operation performed with a token. We cannot recreate Microsoft's entire investigative view merely by enabling a connector. [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log)

This small query is a visibility check, not a threat-actor detector. Replace the placeholders only in a private copy:

```kusto
let LabGroup = tolower("/subscriptions/<subscription>/resourceGroups/<lab>");
AzureActivity
| where TimeGenerated > ago(1h)
| extend NormalizedId = tolower(ResourceId)
| where NormalizedId == LabGroup
    or NormalizedId startswith strcat(LabGroup, "/")
| project EventTime = TimeGenerated,
          SubmittedAt = EventSubmissionTimestamp,
          ArrivedAt = ingestion_time(),
          OperationNameValue, ActivityStatusValue, ResourceId
| order by EventTime asc
```

An absent table is a configuration or access problem. An empty result means the query returned no rows in that window. Neither is proof that the principal lacked access.

## Measure two clocks

<figure class="media-panel media-panel--diagram">
  <a href="visuals/measurement-clocks.svg" target="_blank" rel="noopener" aria-label="Open full-size diagram: The SOC event timeline is separate from the fixed-token last-allowed to first-denied observation interval">
    <img src="visuals/measurement-clocks.svg" alt="The SOC event timeline is separate from the fixed-token last-allowed to first-denied observation interval" width="1280" height="800" loading="lazy" decoding="async">
  </a>
  <figcaption>Timing model only. The positions and intervals are illustrative; no experiment durations are shown. Select the diagram for the full-size vector.</figcaption>
</figure>

The client records when it sends the tested request and receives the response. The telemetry collector records provider event time, submission time, workspace ingestion, and alert or incident processing evidence where available. The action receipt records the actual response request and its acknowledgment.

These timestamps answer different questions. Detection delay measures when the SOC could act. The fixed-token probe measures whether the selected operation still worked. A completed Logic App run belongs to neither category until its meaning is checked.

Polling produces an interval between the last allowed request and the first qualified denial. If the first post-action probe is denied, the earlier baseline still matters. If the token later expires, that expiry must not erase a denial interval already observed. If the observation ends with access still allowed, report that limit instead of inventing a revocation time.

The window should fit the experiment. The core plan allows a longer RBAC observation and an explicit token-expiry mode based on the token's remaining lifetime. A short run can still be useful, but its result may be censored. Azure documents propagation delays for role changes; it does not promise one universal cutoff for every request. [RBAC propagation](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting)

## Hold the token still

The harness acquires a probe token before the action and sends it through direct HTTP calls. The probe path does not refresh it or follow redirects. A separate operator identity performs the response.

An optional new-token check is a separate channel. Its result is recorded and any returned token is discarded; it never replaces the frozen probe token. The trial receipt binds the baseline, action and post-action files to one credential label and capability. It also records the exact role assignment, principal and scope for removal experiments.

Direct role removal, deleting a group's role assignment and removing one group membership are different tests. The writer-removal scenario retains a separate Reader grant so the write probe can inspect the canary without preserving write authority. The result must describe that capability, not claim the identity lost every permission.

Errors need the same care. Expiry, a transport failure, throttling and a firewall policy block are separate observations. An ambiguous storage authorization error cannot become a containment result just because it returned HTTP 403. A rotated key's rejection also needs its own credential context and healthy control.

## Build the Sentinel playbook around a fixed target

<figure class="media-panel media-panel--diagram">
  <a href="visuals/guarded-playbook.svg" target="_blank" rel="noopener" aria-label="Open full-size diagram: A six-step guarded Sentinel flow ends with an independent fixed-token capability check">
    <img src="visuals/guarded-playbook.svg" alt="A six-step guarded Sentinel flow ends with an independent fixed-token capability check" width="1280" height="828" loading="lazy" decoding="async">
  </a>
  <figcaption>Proposed response flow. The actor's token stays in the harness, outside the Logic App. Native incident delivery still needs live validation. Select the diagram for the full-size vector.</figcaption>
</figure>

The lab uses two workflows. A native Sentinel incident dispatcher fetches fresh incident and alert evidence and checks the expected rule, principal, resource and lab identifiers. A separate executor is configured to remove one exact role assignment.

The executor's managed identity has narrow resource-group permissions and a condition restricting role deletion. Azure's condition narrows the principal and role; the workflow additionally checks the exact assignment ID. It is still a privileged component. Review its grants, deployment access and use; having no client secret does not make the identity powerless.

Before mutation, the executor checks the group tag and the assignment's principal, role definition and scope. Successful removal is configuration evidence. The external probe determines whether the tested capability has changed. [Sentinel playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/create-playbooks), [conditional delegation](https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-overview)

The detection also needs a clear automation contract. Successful suspicious operations can be response candidates, while denied attempts remain useful hunting evidence. Arrival-window overlap reduces scheduling gaps, but it can create duplicates; the lab limits repeated responses and records the exact event used. Suppression has a cost: an independent trial must establish that its own event produced its own alert.

Shutdown is part of the design. Disabling a Consumption Logic App does not stop runs already in progress. A response wrapper must track the run it started, reconcile an uncertain start, cancel only a known run when required, and verify the final disabled state. [Logic Apps lifecycle behavior](https://learn.microsoft.com/en-us/azure/logic-apps/manage-logic-apps-with-azure-portal#considerations-for-disabling-a-deployed-consumption-logic-app)

## Keep locks effective while testing revocation

<figure class="media-panel media-panel--diagram">
  <a href="visuals/lock-scope-layout.svg" target="_blank" rel="noopener" aria-label="Open full-size diagram: An account-level lock sits below a resource-group role assignment, which the responder can target separately">
    <img src="visuals/lock-scope-layout.svg" alt="An account-level lock sits below a resource-group role assignment, which the responder can target separately" width="1280" height="820" loading="lazy" decoding="async">
  </a>
  <figcaption>A layout to validate, not a tested result. Compare the exact lock and assignment scopes before relying on the design. Select the diagram for the full-size vector.</figcaption>
</figure>

The tempting sequence is to unlock a resource, remove access and relock it. That introduces another exposure interval.

An alternative is to place the delete lock on the storage account and the tested role assignment at resource-group scope. Locks inherit downward, so this layout may allow parent-scope revocation while the account lock remains. That is a specific experiment, not a universal prescription.

Microsoft documents that a cannot-delete lock can prevent deletion of RBAC assignments under its scope. It also documents that resource locks do not protect data-plane operations. A surviving storage account is not proof that its blob contents are protected. [Lock scope and side effects](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources)

## Prepare a real storage baseline

The safe deployment starts with Shared Key disabled and a closed data-plane firewall. Those defaults protect the unused lab, but they cannot serve as a working baseline for a copied-key experiment.

Before that experiment, the preparation step needs an explicit test source, a private canary with a recorded checksum, and the chosen authorization mechanism. Enabling Shared Key is an experiment-specific opt-in. Preserve the original configuration and restore it afterward. A failed baseline stops the trial.

For key regeneration, start fresh for each signing key. Keep the other key and the Entra-based channels as controls where their prerequisites are satisfied. Do not combine several response actions and then attribute the result to just one of them.

## Recovery is a separate question

Recovery remains an optional extension to the core containment study. Azure offers conditional, best-effort recovery for eligible storage accounts deleted within 14 days. Name reuse, the resource group and customer-managed-key dependencies matter; private endpoints are not automatically recreated. [Storage-account recovery](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-recover)

A recovery result needs more than the account reappearing. Compare the canary checksum, required configuration and access from the intended network. Preserve an independent synthetic source copy so a failed restore remains an honest result.

## What has to happen before publication

The next step is an independent recheck of the measurement and shutdown fixes. Then the core trials can produce the intervals and remaining-access columns at the top of this article. No new live response action is part of the current editorial pass.

The final containment checklist must follow those observations. Until then, the reusable contribution is the reviewable implementation and protocol: a fixed credential, one response action, exact scope, explicit uncertainty and a separately verified outcome.

The [companion repository](https://github.com/j-dahl7/storm-3168-containment-lab) contains the harness, response workflows, KQL, workbook, core and extended matrices, cleanup guidance and the independent-review checklist. The explanatory figures are available there as editable SVGs. Keep this post in draft until the evidence supports its conclusions.
