"""RBAC for VANTHEX (v1.2.4): roles on users, per-action enforcement matrix.

AUTHORIZED TESTING ONLY. Backward compatible:
- Legacy user rows (missing/unknown role, e.g. 'analyst') read as 'operator';
  rows with role 'admin' keep full power, so existing single-admin installs
  keep working unchanged.
- Sessions/tokens minted before roles existed keep working: the role is
  resolved from the store at check time (never cached in the session dict).
- PTK_DISABLE_RBAC=1 disables every check (escape hatch for CI/embedded).
"""
import os

ROLES = ("admin", "operator", "viewer")

# Actions every authenticated role may call (self-service / read-only).
_READONLY_PREFIXES = ("get", "export", "report")

# Operator = viewer + execution-level actions.
_OPERATOR_ACTIONS = {
    # scans / jobs
    "startScan", "cancelJob",
    "analyzeMobile", "startMobileUpload", "uploadMobileChunk",
    "finishMobileUpload", "cancelMobileUpload",
    # schedules
    "createSchedule", "deleteSchedule", "toggleSchedule",
    # findings / assets metadata
    "updateFinding", "setFindingStatus", "setAssetMeta",
    # suppressions
    "addSuppression", "deleteSuppression",
    # tokens
    "createToken", "deleteToken",
}


def rbac_disabled() -> bool:
    return os.environ.get("PTK_DISABLE_RBAC") == "1"


def normalize_role(role) -> str:
    """Map a stored role string to one of ROLES; legacy/unknown -> operator."""
    r = str(role or "").strip().lower()
    if r in ROLES:
        return r
    return "operator"


def role_for(username: str) -> str:
    """Resolve a user's effective role from the store (session-independent)."""
    if rbac_disabled():
        return "admin"
    try:
        import store
        users = store.list_users()
    except Exception:
        return "operator"
    for u in users:
        if u.get("username") == username:
            return normalize_role(u.get("role"))
    # API-token callers and unknown principals keep working as operators;
    # app2.py's own admin gates are unchanged for api:* principals.
    if str(username or "").startswith("api:"):
        return "admin"
    return "operator"


def allowed(role: str, action: str) -> bool:
    """Enforcement matrix: is `role` permitted to call `action`?"""
    if rbac_disabled():
        return True
    role = normalize_role(role)
    if role == "admin":
        return True
    if role == "operator":
        return action in _OPERATOR_ACTIONS
    # viewer: strictly read-only
    if action.startswith(_READONLY_PREFIXES):
        return True
    return action == "logout"


def check(username: str, action: str):
    """Return None when permitted, else the effective role (for the 403)."""
    role = role_for(username)
    if allowed(role, action):
        return None
    return role
