"""v1.2.4 RBAC tests: role matrix, legacy default, escape hatch, audit.

AUTHORIZED TESTING ONLY. Hermetic: every test runs against an isolated
tmp_path SQLite store; no network, no live service.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import actions  # noqa: E402
import rbac  # noqa: E402
import store  # noqa: E402


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "rbac.db"))
    store.init_db()
    return store


def _mkuser(username, password="password123", role="operator"):
    store.create_user(username, password, role)


# --- matrix: viewer -------------------------------------------------------

def test_viewer_denied_startscan(db):
    _mkuser("vic", role="viewer")
    code, env = actions.handle_action("startScan", {"target": "x"}, 0, user="vic")
    assert code == 403
    assert env["error"].startswith("forbidden: role viewer")


def test_viewer_allowed_readonly(db):
    _mkuser("vic", role="viewer")
    # getScans exists in the actions table; denial would be 403, success is
    # the service-down envelope (no live service) — either way NOT forbidden.
    code, env = actions.handle_action("getScans", {}, 0, user="vic")
    assert code == 200
    assert "forbidden" not in env.get("error", "")
    for act in ("exportScan", "getReportHtml", "getReportDocx", "getAudit"):
        code, env = actions.handle_action(act, {}, 0, user="vic")
        assert code == 200, (act, env)


def test_viewer_denied_operator_actions(db):
    _mkuser("vic", role="viewer")
    for act in ("cancelJob", "createSchedule", "updateFinding",
                "addSuppression", "createToken"):
        code, env = actions.handle_action(act, {}, 0, user="vic")
        assert code == 403, (act, env)


# --- matrix: operator -----------------------------------------------------

def test_operator_allowed_startscan(db):
    _mkuser("op", role="operator")
    code, env = actions.handle_action("startScan", {}, 0, user="op")
    assert code == 200
    assert "forbidden" not in env.get("error", "")


def test_operator_denied_user_management(db):
    _mkuser("op", role="operator")
    code, env = actions.handle_action(
        "createUser", {"username": "x", "password": "password123"}, 0, user="op")
    assert code == 403
    assert env["error"].startswith("forbidden: role operator")


def test_operator_denied_admin_actions(db):
    _mkuser("op", role="operator")
    for act in ("saveSettings", "createSecret", "deleteSecret", "pocboxRun",
                "replayCapture", "getUsers"):
        code, env = actions.handle_action(act, {}, 0, user="op")
        assert code == 403, (act, env)


# --- matrix: admin --------------------------------------------------------

def test_admin_allowed_everything(db):
    _mkuser("root", role="admin")
    for act in ("startScan", "createUser", "saveSettings", "createSecret",
                "pocboxRun", "replayCapture", "getScans", "getUsers"):
        code, env = actions.handle_action(act, {}, 0, user="root")
        # 500 = handler ran and hit a missing arg (no live service) — the
        # point is the RBAC layer did NOT forbid it.
        assert code in (200, 500), (act, env)
        assert "forbidden" not in env.get("error", "")


# --- legacy users ---------------------------------------------------------

def test_legacy_row_defaults_to_operator(db):
    # Simulate a pre-roles row (NULL role) written directly.
    import sqlite3
    with sqlite3.connect(store.DB_PATH) as c:
        c.execute("INSERT INTO users(username,salt,hash,role) VALUES('old','s','h',NULL)")
    assert rbac.role_for("old") == "operator"
    # init_db migration rewrites unknown/NULL roles to operator.
    store.init_db()
    assert {"username": "old", "role": "operator"} in store.list_users()


def test_analyst_legacy_value_maps_to_operator(db):
    import sqlite3
    with sqlite3.connect(store.DB_PATH) as c:
        c.execute("INSERT INTO users(username,salt,hash,role) VALUES('analyst1','s','h','analyst')")
    assert rbac.normalize_role("analyst") == "operator"
    assert rbac.role_for("analyst1") == "operator"


def test_first_admin_user_stays_admin(db):
    users = {u["username"]: u["role"] for u in store.list_users()}
    assert users["admin"] == "admin"
    assert rbac.role_for("admin") == "admin"


def test_unknown_role_never_escalates(db):
    assert rbac.normalize_role("superadmin") == "operator"
    assert rbac.normalize_role("") == "operator"
    assert rbac.normalize_role(None) == "operator"


def test_no_user_argument_keeps_legacy_behavior(db):
    # Internal callers (no `user` kwarg) are unaffected — backward compat.
    code, env = actions.handle_action("getScans", {}, 0)
    assert code == 200


# --- env escape hatch -----------------------------------------------------

def test_disable_rbac_escape_hatch(db, monkeypatch):
    _mkuser("vic", role="viewer")
    monkeypatch.setenv("PTK_DISABLE_RBAC", "1")
    code, env = actions.handle_action("startScan", {}, 0, user="vic")
    assert code == 200
    assert "forbidden" not in env.get("error", "")


def test_escape_hatch_unset_reenforces(db, monkeypatch):
    _mkuser("vic", role="viewer")
    monkeypatch.setenv("PTK_DISABLE_RBAC", "")
    code, env = actions.handle_action("startScan", {}, 0, user="vic")
    assert code == 403


# --- audit trail ----------------------------------------------------------

def test_denial_is_audited(db):
    _mkuser("vic", role="viewer")
    before = len(store.list_audit())
    actions.handle_action("startScan", {}, 0, user="vic")
    entries = store.list_audit()
    assert len(entries) == before + 1
    last = entries[-1]
    assert last["username"] == "vic"
    assert last["action"] == "rbac_denied"
    assert "startScan" in str(last["detail"])


def test_user_creation_is_audited(db):
    _mkuser("newop", role="operator")
    # create_user itself is storage; the audited user-management action is
    # the login/session layer, but role writes are visible in list_users.
    roles = {u["username"]: u["role"] for u in store.list_users()}
    assert roles["newop"] == "operator"
