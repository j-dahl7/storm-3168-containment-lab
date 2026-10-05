---
title: "Storm-3168: When Does a Compromised Service Principal Actually Lose Access?"
date: 2026-10-05
draft: true
author: "Jerrad Dahlager"
description: "A defensive test protocol for measuring token, RBAC, copied storage credential, detection and recovery boundaries after an Azure workload identity compromise."
---

# Storm-3168: When Does a Compromised Service Principal Actually Lose Access?

**DRAFT — results pending reconciliation. Do not publish this as a completed lab.** This article does not yet incorporate reviewed live measurements. Consult the root verification record; replace the placeholders below only with evidence-backed results.

Microsoft's September 25 report describes Azure activity observed in June 2026 involving two compromised service principals. Its useful lesson is the range of authority a workload identity can exercise: discovery, resource destruction and retrieval of credentials for other access paths. The report describes 90 minutes between the two identities' initial enumerations and further activity 16 hours later; it does not give defenders a 90-minute warning-to-wipe guarantee. Microsoft did not confirm that a previously exposed secret caused the intrusion, or confirm a ransom note or successful data exfiltration. [Incident research](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)

The response question is concrete: after we change an identity or permission, which requests still work? A new sign-in, an already-issued ARM token and a copied storage key pass through different authorization paths. This lab measures them independently. It does not introduce a new attack or claim to reproduce the original intrusion.

## What we intend to measure

| Phase | Question | Live status | Trials complete |
| --- | --- | --- | --- |
| Visibility | Which bounded operations appear in each log source, and when? | NOT TESTED | 0 |
| Fixed-token containment | When do each of the selected RBAC/directory actions change a specific capability? | NOT TESTED | 0 |
| Copied storage credentials | Which credentials stop working after each key/authorization action? | NOT TESTED | 0 |
| Playbook | Does exact-target response refuse unsafe inputs and verify its effect? | NOT TESTED | 0 |
| Prevention | Which operations do locks and authorization controls actually deny? | NOT TESTED | 0 |
| Recovery | Can this eligible canary account and its working access path be recovered? | NOT TESTED | 0 |

Each claimed action requires at least three independent valid trials. A 20-second probe interval produces a transition interval, not an exact revocation instant. A request that fails because its token expired or its network connection broke does not demonstrate successful containment.

## First establish the evidence

The lab uses a dedicated application service principal, one recorded resource group and synthetic blob content. A separate operator identity applies response actions. Probe credentials are held fixed and never refreshed during a trial.

AzureActivity records control-plane operations and generally omits reads. Service-principal sign-in logs record authentication activity rather than every request to Azure resources. Client observations therefore remain the primary evidence for the specific capability being tested; logs establish independently observed visibility and delay. [Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log)

The workbook shows event time, submission and approximate ingestion separately. It does not calculate containment from an empty chart or read local JSONL files into a fictional cloud table.

## Compare permission changes with identity changes

Removing a direct assignment, deleting a group's assignment and removing the principal from that group are separate experiments. Disabling a service principal is separate from removing one application secret. The lab also distinguishes a new token request from reuse of a previously issued token.

These distinctions matter because other permission paths, cached authorization and credential expiry can change a result. Record the effective grants and reset a working baseline before each trial. Do not turn a short observation window into a claim that access persists forever or ends instantly.

## Follow the copied credentials

The storage experiment compares both account keys, a service SAS, an account SAS, a user-delegation SAS and an Entra Blob token. Regeneration and Shared Key disallow have different scopes; they are measured separately.

Disabling the principal that obtained a storage key does not regenerate that independent key. An account-key rotation affects signatures made with that key; user-delegation SAS and Entra permissions require their own analysis. Shared Key disallow rejects key-authorized requests but does not stop valid Entra data access or ARM deletion, and a sufficiently privileged manager can ordinarily change that setting. [Key management](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage), [Shared Key control](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)

## Make response reviewable

The response executor starts disabled and dry-run, with an authenticated management entry. An optional native Sentinel incident dispatcher validates fresh alert evidence before invoking it. The narrow operation targets one exact role assignment after ownership, identity, role and scope checks. Each activation and permission grant is separate; deploying a detection does not automatically activate response.

The playbook experiment includes refused targets, missing permissions, provider failures, duplicate invocation and independent post-action checks. A successful management response does not by itself prove that the cached probe lost access.

## Test prevention and recovery separately

A delete lock can prevent account deletion while the actor lacks permission to remove it; it does not protect every operation against blob data. ReadOnly also blocks some apparently read-like operations such as ListKeys and can break legitimate management. The role's name is insufficient: inspect effective actions and all inherited assignments. [Lock boundaries](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources)

Storage account recovery is a conditional, best-effort facility within 14 days, not an independent backup promise. The optional recovery trial preserves the canary checksum and configuration outside the account, avoids name reuse and verifies actual restored reads. Private endpoints need separate recreation. [Recovery prerequisites](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-recover)

## Results pending

Measurements have not yet been incorporated into this draft. Do not replace this section with illustrative timings. Reconcile the root verification record into three trial rows per claimed action, observed transition intervals, missing telemetry, configuration limits and cleanup evidence before drawing a conclusion.

The companion repository contains the six-phase protocol, unrun trial matrix, scoped queries, disabled analytics template, provider-table workbook and synthetic replay cases. Check the repository's current help and README before running any command.

## Publication gate

This draft stays unpublished until live evidence, cost/cleanup results and an independent review are complete. If a phase is not run, keep its status visible and limit conclusions to what was observed.
