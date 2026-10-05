"""Read-only canary storage inventory and conditional recovery checklist; never restore/delete."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import json
import sys

from lab_support import assert_owned, az, guid, private_path
from telemetry import load_manifest, utc, write_private
from stormlab.core import Manifest, SafetyError

RECOVERY_DOC = "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-recover"


def check(data: dict, manifest: Manifest, deleted_at: str | None = None,
          now: datetime | None = None) -> dict:
    current_time = now or datetime.now(timezone.utc)
    claimed_deletion = utc(deleted_at) if deleted_at else None
    if claimed_deletion and claimed_deletion > current_time:
        raise ValueError("Deletion time cannot be in the future")
    assert_owned(data, manifest.subscription_id)
    resources = az("resource", "list", "--subscription", manifest.subscription_id,
                   "--resource-group", manifest.resource_group,
                   "--resource-type", "Microsoft.Storage/storageAccounts")
    if not isinstance(resources, list):
        raise RuntimeError("Invalid resource inventory")
    matches = [r for r in resources if isinstance(r, dict) and str(r.get("id", "")).lower() == manifest.storage_id.lower()]
    if len(matches) > 1:
        raise RuntimeError("Ambiguous canary identity")
    report = {"schema_version": 1, "kind": "recovery_readiness", "mode": "live_read_only",
              "cloud_mutations": False, "checked_at": current_time.isoformat(),
              "account_resource_id": manifest.storage_id, "resource_group_owned_and_present": True,
              "account_state": "not_observed_in_resource_list",
              "restore_eligibility": "not_established", "restore_attempted": False,
              "deletion_timestamp": claimed_deletion.isoformat() if claimed_deletion else None,
              "deletion_timestamp_source": "operator_asserted_unverified" if claimed_deletion else "not_supplied",
              "within_14_days_if_timestamp_correct": (timedelta(0) <= current_time - claimed_deletion <= timedelta(days=14)) if claimed_deletion else None,
              "same_name_not_reused": "not_verified", "restore_write_permission": "not_verified",
              "manual_recovery_documentation": RECOVERY_DOC,
              "manual_checks": ["Inspect the Azure portal Restore deleted account list; absence means unavailable.",
                                "Verify deletion within 14 days and no intervening same-name account.",
                                "Retain/recreate the original resource group; this helper never deletes it.",
                                "Restore a required deleted customer-managed-key vault before the account.",
                                "Recovery is best effort, not guaranteed; verify canary bytes and authorization afterward.",
                                "Linked private endpoints are not automatically recreated; verify endpoint/DNS separately."],
              "configuration": None}
    if matches:
        assert_owned(data, manifest.subscription_id)
        live = az("storage", "account", "show", "--ids", manifest.storage_id,
                  "--subscription", manifest.subscription_id)
        if not isinstance(live, dict) or str(live.get("id", "")).lower() != manifest.storage_id.lower():
            raise RuntimeError("Storage resource identity mismatch")
        if (not isinstance(live.get("tags"), dict)
                or live["tags"].get("storm3168LabId") != manifest.lab_id):
            raise RuntimeError("Storage ownership tag changed")
        encryption = live.get("encryption") or {}
        sku = live.get("sku") or {}
        network = live.get("networkRuleSet") or {}
        if not all(isinstance(item, dict) for item in (encryption, sku, network)):
            raise RuntimeError("Invalid storage configuration metadata")
        connections = live.get("privateEndpointConnections") or []
        if not isinstance(connections, list):
            raise RuntimeError("Invalid private endpoint metadata")
        # Export a bounded property allowlist only, never keys, connection strings or key-vault URLs.
        allowed = {"kind": live.get("kind"), "location": live.get("location"),
                   "sku": sku.get("name"), "creation_time": live.get("creationTime"),
                   "allow_shared_key_access": live.get("allowSharedKeyAccess"),
                   "public_network_access": live.get("publicNetworkAccess"),
                   "allow_blob_public_access": live.get("allowBlobPublicAccess"),
                   "network_default_action": network.get("defaultAction"),
                   "encryption_key_source": encryption.get("keySource"),
                   "private_endpoint_connection_count": len(connections)}
        for key, value in allowed.items():
            if value is not None and not isinstance(value, (str, bool, int)):
                allowed[key] = None
                continue
            if isinstance(value, str) and (len(value) > 128 or any(ord(c) < 32 for c in value)
                                           or any(c in value for c in "?&=@")):
                allowed[key] = None
        report.update(account_state="present_and_owned", restore_eligibility="not_applicable_account_present",
                      configuration=allowed)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--deleted-at", help="Optional operator-asserted UTC deletion timestamp; not independent evidence")
    parser.add_argument("--output", required=True, help="New JSON inside ignored private/")
    args = parser.parse_args(argv)
    try:
        if private_path(args.output).exists():
            raise ValueError("Refusing to overwrite evidence")
        if args.deleted_at:
            utc(args.deleted_at)
        data, manifest = load_manifest(args.manifest, args.subscription)
        report = check(data, manifest, args.deleted_at)
        write_private(args.output, report)
        print(json.dumps({"status": report["account_state"], "restore_eligibility": report["restore_eligibility"],
                          "restore_attempted": False, "cloud_mutations": False, "private_evidence_written": True}))
        return 0
    except (SafetyError, RuntimeError, ValueError, OSError, KeyError, TypeError):
        print("Recovery check stopped: verify private paths, selected subscription, exact resource identity and ownership.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
