"""Create a NEW isolated lab; never adopt or delete an existing resource group.

No client secrets or tokens are created by this script. A partial run leaves a
private manifest recording completed stages so an operator can reconcile it.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import sys
import uuid
from lab_support import ROOT, assert_context, assert_owned, az, guid, private_path, rg_id, save
from live_trial import graph_token, request


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", required=True, type=guid)
    parser.add_argument("--location", default="eastus2", choices=["eastus", "eastus2", "centralus"])
    parser.add_argument("--budget-usd", required=True, type=float, help="Planning target; NOT an Azure spending cap")
    parser.add_argument("--manifest", default="private/manifest.json")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume-empty-group", action="store_true", help="Resume only a recorded empty resource group after interrupted foundation setup")
    parser.add_argument("--resume-identity", action="store_true", help="Resume only a recorded foundation/application/SP stage, before group creation")
    parser.add_argument("--enable-sentinel", action="store_true")
    args = parser.parse_args()
    if not 0 < args.budget_usd <= 10:
        parser.error("Use a positive bounded lab usage target of at most 10 USD")
    path = private_path(args.manifest)
    if args.resume_empty_group and args.resume_identity:
        parser.error("Select one resume mode")
    if path.exists() and not (args.resume_empty_group or args.resume_identity):
        parser.error("Manifest exists. Reconcile that run; setup never overwrites/adopts existing state")
    account = assert_context(args.subscription)
    lab_id = str(uuid.uuid4())
    suffix = lab_id.replace("-", "")[:8]
    manifest = {
        "schema_version": 1, "lab_id": lab_id,
        "tenant_id": account["tenantId"], "subscription_id": args.subscription,
        "resource_group": f"nls-storm3168-{suffix}", "location": args.location,
        "storage_account": f"nlss3168{suffix}", "workspace_name": f"law-storm3168-{suffix}",
        "role_assignments": [], "blob": {"container": "canary", "name": "synthetic.txt"},
        "budget_target_usd": args.budget_usd, "stages": [],
        "evidence_status": "not_tested", "sentinel_enabled": args.enable_sentinel,
    }
    if args.resume_empty_group or args.resume_identity:
        if not path.exists() or not args.execute:
            parser.error("Resume requires --execute and the existing private manifest")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        assert_owned(manifest, args.subscription)
        expected_stages = ["resource-group-created"] if args.resume_empty_group else ["resource-group-created", "foundation-created", "application-created", "service-principal-created"]
        if manifest.get("stages") != expected_stages:
            raise RuntimeError("The recorded stage does not match the selected bounded resume mode")
        if manifest.get("location") != args.location or manifest.get("sentinel_enabled") != args.enable_sentinel:
            raise RuntimeError("Resume parameters must match the original recorded plan")
        lab_id = guid(manifest["lab_id"])
        suffix = lab_id.replace("-", "")[:8]
    print(json.dumps({"mode": "execute" if args.execute else "plan", "resource_group": manifest["resource_group"],
                      "services": ["Storage LRS", "Log Analytics", "optional Sentinel"],
                      "budget_target_usd": args.budget_usd, "enforced_spending_cap": False}))
    if not args.execute:
        return 0
    if not (args.resume_empty_group or args.resume_identity):
        if az("group", "exists", "--subscription", args.subscription, "--name", manifest["resource_group"]):
            raise RuntimeError("Resource group exists; refusing adoption")
        save(path, manifest)
        az("group", "create", "--subscription", args.subscription, "--name", manifest["resource_group"],
           "--location", args.location, "--tags", f"storm3168LabId={lab_id}", "purpose=storm3168-containment-lab", "disposable=true")
        assert_owned(manifest, args.subscription)
        manifest["stages"].append("resource-group-created")
        save(path, manifest)
    if not args.resume_identity:
        # A new group cannot contain pre-existing resources. Stop if that invariant changed.
        resources = az("resource", "list", "--subscription", args.subscription, "--resource-group", manifest["resource_group"])
        if resources:
            raise RuntimeError("New resource group is no longer empty; refusing upsert")
        assert_owned(manifest, args.subscription)
        az("deployment", "group", "create", "--subscription", args.subscription,
           "--resource-group", manifest["resource_group"], "--name", "storm3168-foundation",
           "--template-file", str(ROOT / "infra" / "main.bicep"), "--parameters",
           f"expectedSubscriptionId={args.subscription}", f"labId={lab_id}", f"location={args.location}",
           f"storageAccountName={manifest['storage_account']}", f"workspaceName={manifest['workspace_name']}",
           f"enableSentinel={str(args.enable_sentinel).lower()}", "workspaceDailyQuotaGb=0.1")
        manifest["stages"].append("foundation-created")
        save(path, manifest)
    display_name = f"storm3168-{lab_id}"
    if not args.resume_identity:
        assert_owned(manifest, args.subscription)
        application = request("POST", "https://graph.microsoft.com/v1.0/applications", graph_token(args.subscription),
                              {"displayName": display_name, "signInAudience": "AzureADMyOrg", "tags": ["storm3168LabId=" + lab_id]})
        manifest["actor"] = {"application_object_id": application["id"], "client_id": application["appId"]}
        manifest["stages"].append("application-created")
        save(path, manifest)
        assert_owned(manifest, args.subscription)
        service_principal = request("POST", "https://graph.microsoft.com/v1.0/servicePrincipals", graph_token(args.subscription), {"appId": application["appId"]})
        manifest["actor"]["service_principal_object_id"] = service_principal["id"]
        manifest["stages"].append("service-principal-created")
        save(path, manifest)
    else:
        sys.path.insert(0, str(ROOT / "src"))
        from stormlab.core import Manifest, AzureCLI, Guard, HTTP
        model = Manifest.from_dict(manifest)
        guard = Guard(model, HTTP(), AzureCLI(model, args.subscription))
        guard.ownership()
        guard.actor()
        service_principal = {"id": manifest["actor"]["service_principal_object_id"]}
    assert_owned(manifest, args.subscription)
    import urllib.parse
    query = urllib.parse.urlencode({"$filter": "displayName eq '" + display_name + "-access'", "$select": "id"})
    existing_groups = request("GET", "https://graph.microsoft.com/v1.0/groups?" + query, graph_token(args.subscription))
    if existing_groups.get("value"):
        raise RuntimeError("A matching group already exists but is not recorded; reconcile instead of adopting")
    assert_owned(manifest, args.subscription)
    group = request("POST", "https://graph.microsoft.com/v1.0/groups", graph_token(args.subscription),
                    {"displayName": display_name + "-access", "mailNickname": "storm3168" + suffix,
                     "mailEnabled": False, "securityEnabled": True, "description": "storm3168LabId=" + lab_id})
    manifest["group"] = {"object_id": group["id"]}
    manifest["stages"].append("security-group-created")
    save(path, manifest)
    role = az("role", "definition", "list", "--subscription", args.subscription, "--name", "Storage Account Contributor")
    if len(role) != 1 or role[0].get("roleName") != "Storage Account Contributor":
        raise RuntimeError("Cannot uniquely resolve the intended built-in role")
    role_id = f"/subscriptions/{args.subscription}/providers/Microsoft.Authorization/roleDefinitions/{role[0]['name']}"
    assignment_name = str(uuid.uuid4())
    assignment = {"id": rg_id(manifest) + "/providers/Microsoft.Authorization/roleAssignments/" + assignment_name,
                  "principal_id": service_principal["id"], "scope": rg_id(manifest), "role_definition_id": role_id}
    manifest["role_assignments"].append(assignment)
    save(path, manifest)
    assert_owned(manifest, args.subscription)
    az("role", "assignment", "create", "--subscription", args.subscription, "--name", assignment_name,
       "--assignee-object-id", assignment["principal_id"], "--assignee-principal-type", "ServicePrincipal",
       "--role", role[0]["name"], "--scope", assignment["scope"])
    manifest["stages"].append("direct-role-created")
    save(path, manifest)
    print(json.dumps({"status": "setup_completed", "manifest": str(path.relative_to(ROOT)), "credentials_created": False,
                      "live_experiments": "not_tested", "cleanup": "manifest-driven; no bulk group deletion"}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, KeyError) as exc:
        print(f"Setup stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
