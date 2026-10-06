"""Read-only CORE11 freshness checks; this helper never removes a lock."""
from __future__ import annotations
from stormlab.core import AzureCLI, Guard, HTTP, Manifest, SafetyError, utc_now

API = "?api-version=2016-09-01"


def fresh_readonly_lock(data: dict, subscription: str, *, guard=None) -> dict:
    m = Manifest.from_dict(data)
    guard = guard or Guard(m, HTTP(), AzureCLI(m, subscription))
    if subscription != m.subscription_id:
        raise SafetyError("CORE11 selected subscription differs from its manifest")
    guard.ownership()
    guard.actor()
    # The resource-group and account inventory are read only. No lock discovered
    # here becomes a mutation target, and pagination is not silently ignored.
    for scope in (m.rg_id, m.storage_id):
        response = guard.read("arm", scope + "/providers/Microsoft.Authorization/locks" + API)
        current = guard.checked(response)
        if current.get("nextLink") or not isinstance(current.get("value"), list):
            raise SafetyError("CORE11 lock inventory is incomplete")
        if current["value"]:
            raise SafetyError("CORE11 requires a fresh unlocked baseline at the checked scopes; no automatic unlock")
    response = guard.read("arm", m.lock_id + API)
    if response.status != 404 or response.transport_error:
        raise SafetyError("The exact recorded CORE11 lock is not proven absent")
    return {"lock_id": m.lock_id, "scope": m.storage_id, "expected_level": "ReadOnly",
            "ownership_notes": "storm3168LabId=" + m.lab_id,
            "absence_verified": True, "checked_scopes": [m.rg_id, m.storage_id],
            "checked_at": utc_now(), "cleanup_policy": "manual_explicit_lock_remove_only"}
