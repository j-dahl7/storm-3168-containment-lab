"""Operator-only Azure CLI helpers. Never acquire or print probe credentials here."""
from __future__ import annotations
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRIVATE = ROOT / "private"


def guid(value: str) -> str:
    parsed = str(uuid.UUID(value))
    if value.lower() != parsed:
        raise ValueError("Expected a canonical UUID")
    return parsed


def private_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value).resolve()
    if PRIVATE.resolve() != ROOT.resolve() / "private":
        raise ValueError("The private directory must not redirect outside this checkout")
    if not path.is_relative_to(PRIVATE.resolve()):
        raise ValueError("Live state must stay inside this repository's ignored private directory")
    return path


def az(*arguments: str) -> object:
    sys.path.insert(0, str(ROOT / "src"))
    from stormlab.core import azure_cli_prefix
    command = azure_cli_prefix()
    read_prefixes = {("account", "show"), ("account", "get-access-token"), ("group", "show"),
                     ("group", "exists"), ("resource", "list"), ("role", "definition", "list")}
    read_only = any(tuple(arguments[:len(prefix)]) == prefix for prefix in read_prefixes)
    for attempt in range(3 if read_only else 1):
        result = subprocess.run([*command, *arguments, "--only-show-errors", "-o", "json"],
                                capture_output=True, text=True, timeout=300, check=False, shell=False)
        transient = any(marker in result.stderr for marker in ["ConnectionResetError", "Connection aborted", "Connection reset", "Read timed out"])
        if not result.returncode or not transient or not read_only or attempt == 2:
            break
        time.sleep(attempt + 1)
    if result.returncode:
        # CLI text is deliberately not copied into evidence or exception logs.
        codes = re.findall(r"\b(?:BCP\d+|[A-Za-z]+Error|AuthorizationFailed|InvalidTemplateDeployment|InvalidAuthenticationToken)\b", result.stderr)[:3]
        raise RuntimeError(f"Azure CLI operation failed ({' '.join(arguments[:3])}); exit {result.returncode}; codes={codes}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def save(path: pathlib.Path, value: dict) -> None:
    path = private_path(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = private_path(str(path.with_suffix(path.suffix + ".tmp")))
    temp.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def rg_id(manifest: dict) -> str:
    return f"/subscriptions/{guid(manifest['subscription_id'])}/resourceGroups/{manifest['resource_group']}"


def assert_context(subscription: str, tenant: str | None = None) -> dict:
    account = az("account", "show", "--subscription", guid(subscription))
    if not isinstance(account, dict) or account.get("id", "").lower() != subscription.lower():
        raise RuntimeError("Subscription context mismatch")
    if tenant and account.get("tenantId", "").lower() != tenant.lower():
        raise RuntimeError("Tenant context mismatch")
    return account


def assert_owned(manifest: dict, subscription: str) -> dict:
    if guid(subscription) != guid(manifest["subscription_id"]):
        raise RuntimeError("Subscription confirmation mismatch")
    name = manifest["resource_group"]
    if not re.fullmatch(r"nls-storm3168-[a-f0-9]{8}", name):
        raise RuntimeError("This setup helper only manages its generated lab resource groups")
    assert_context(subscription, manifest["tenant_id"])
    sys.path.insert(0, str(ROOT / "src"))
    from stormlab.core import configured_address_family
    if configured_address_family() == "ipv4":
        from stormlab.core import Manifest, AzureCLI, Guard, HTTP
        # Setup can hold a deliberately partial app-only actor receipt before
        # the SP exists. That does not authorize any actor mutation here.
        model_data = dict(manifest)
        actor = model_data.get("actor")
        if actor and "service_principal_object_id" not in actor:
            if model_data.get("role_assignments") or model_data.get("owned_secret_key_id"):
                raise RuntimeError("Incomplete actor has unexpected grant/credential records")
            model_data.pop("actor")
        model = Manifest.from_dict(model_data)
        guard = Guard(model, HTTP(), AzureCLI(model, subscription))
        group = guard.checked(guard.read("arm", rg_id(manifest) + "?api-version=2021-04-01"))
    else:
        group = az("group", "show", "--subscription", subscription, "--name", name)
    if group.get("id", "").lower() != rg_id(manifest).lower():
        raise RuntimeError("Resource group identity mismatch")
    if group.get("tags", {}).get("storm3168LabId") != guid(manifest["lab_id"]):
        raise RuntimeError("Server-side ownership tag missing or changed")
    return group


def load_owned(path: str, subscription: str, lab_id: str) -> tuple[pathlib.Path, dict]:
    resolved = private_path(path)
    manifest = json.loads(resolved.read_text(encoding="utf-8"))
    if guid(lab_id) != guid(manifest["lab_id"]):
        raise RuntimeError("Lab confirmation mismatch")
    assert_owned(manifest, subscription)
    return resolved, manifest
