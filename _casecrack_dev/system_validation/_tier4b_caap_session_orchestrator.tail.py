# __TIER4B_CAAP__
# Tier 4B CAAP — session_orchestrator: RBAC + DB persistence
import sqlite3 as _t4b_sql
import json as _t4b_json
import time as _t4b_time
import threading as _t4b_th
import hashlib as _t4b_hash
import secrets as _t4b_secrets
import uuid as _t4b_uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

# RBAC: 5 built-in roles, hierarchical permissions
_T4B_ROLES = {
    "viewer":      {"scan:read", "session:read", "finding:read"},
    "operator":    {"scan:read", "scan:start", "scan:stop", "session:read", "session:write",
                       "finding:read", "finding:annotate"},
    "analyst":     {"scan:read", "scan:start", "scan:stop", "scan:configure",
                       "session:read", "session:write", "finding:read", "finding:annotate",
                       "finding:create", "finding:update", "finding:close"},
    "auditor":     {"scan:read", "session:read", "finding:read", "audit:read", "audit:export"},
    "admin":       {"*"},
}

_T4B_SESSION_DDL = """
CREATE TABLE IF NOT EXISTS session_users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_login_at REAL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS session_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    target TEXT NOT NULL,
    state TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    closed_at REAL,
    FOREIGN KEY (user_id) REFERENCES session_users(user_id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON session_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON session_sessions(state);

CREATE TABLE IF NOT EXISTS session_audit (
    audit_id TEXT PRIMARY KEY,
    session_id TEXT,
    user_id TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    timestamp REAL NOT NULL,
    success INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON session_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_session ON session_audit(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON session_audit(timestamp);

CREATE TABLE IF NOT EXISTS session_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES session_users(user_id)
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON session_tokens(user_id);
"""


def _t4b_so_get_conn(self) -> _t4b_sql.Connection:
    conn = getattr(self, "_t4b_so_conn", None)
    if conn is not None:
        return conn
    db_path = getattr(self, "_t4b_so_db_path", ":memory:")
    conn = _t4b_sql.connect(db_path, check_same_thread=False, isolation_level=None)
    conn.executescript(_T4B_SESSION_DDL)
    setattr(self, "_t4b_so_conn", conn)
    if not hasattr(self, "_t4b_so_lock"):
        setattr(self, "_t4b_so_lock", _t4b_th.RLock())
    return conn


def _t4b_so_open(self, db_path: str = ":memory:") -> Dict[str, Any]:
    setattr(self, "_t4b_so_db_path", db_path)
    if hasattr(self, "_t4b_so_conn"):
        try: self._t4b_so_conn.close()
        except Exception: pass
        delattr(self, "_t4b_so_conn")
    _t4b_so_get_conn(self)
    return {"ok": True, "path": db_path}


def _t4b_so_close(self) -> Dict[str, Any]:
    conn = getattr(self, "_t4b_so_conn", None)
    if conn is not None:
        try: conn.close()
        except Exception: pass
        delattr(self, "_t4b_so_conn")
    return {"ok": True}


# ---- RBAC --------------------------------------------------------------
def _t4b_so_supported_roles(self) -> List[str]:
    return list(_T4B_ROLES.keys())


def _t4b_so_role_permissions(self, role: str) -> Set[str]:
    return set(_T4B_ROLES.get(role, set()))


def _t4b_so_check_permission(self, user_id: str, permission: str) -> Dict[str, Any]:
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        row = conn.execute("SELECT role, is_active FROM session_users WHERE user_id=?",
                                (user_id,)).fetchone()
    if not row:
        return {"allowed": False, "reason": "user_not_found"}
    role, active = row
    if not active:
        return {"allowed": False, "reason": "user_inactive"}
    perms = _T4B_ROLES.get(role, set())
    if "*" in perms or permission in perms:
        return {"allowed": True, "role": role}
    return {"allowed": False, "reason": "permission_denied", "role": role,
              "required": permission}


def _t4b_so_require_permission(self, user_id: str, permission: str) -> None:
    res = _t4b_so_check_permission(self, user_id, permission)
    if not res["allowed"]:
        raise PermissionError(f"RBAC denied: user={user_id} permission={permission} reason={res.get('reason')}")


# ---- Users -------------------------------------------------------------
def _t4b_so_hash_password(password: str, salt: str) -> str:
    return _t4b_hash.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def _t4b_so_create_user(self, username: str, password: str,
                              role: str = "viewer") -> Dict[str, Any]:
    if role not in _T4B_ROLES:
        return {"ok": False, "error": "unknown_role"}
    user_id = f"U-{_t4b_uuid.uuid4().hex[:16]}"
    salt = _t4b_secrets.token_hex(16)
    pwhash = _t4b_so_hash_password(password, salt)
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        try:
            conn.execute(
                "INSERT INTO session_users (user_id, username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, pwhash, salt, role, _t4b_time.time())
            )
        except _t4b_sql.IntegrityError:
            return {"ok": False, "error": "username_exists"}
    _t4b_so_audit_log(self, None, user_id, "user.create",
                            resource=username, details={"role": role}, success=True)
    return {"ok": True, "user_id": user_id, "username": username, "role": role}


def _t4b_so_authenticate(self, username: str, password: str) -> Dict[str, Any]:
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        row = conn.execute(
            "SELECT user_id, password_hash, salt, role, is_active FROM session_users WHERE username=?",
            (username,)
        ).fetchone()
    if not row:
        _t4b_so_audit_log(self, None, None, "auth.fail",
                                resource=username, details={"reason": "user_not_found"}, success=False)
        return {"ok": False, "error": "invalid_credentials"}
    uid, pwhash, salt, role, active = row
    if not active:
        return {"ok": False, "error": "account_inactive"}
    expected = _t4b_so_hash_password(password, salt)
    import hmac as _hmac
    if not _hmac.compare_digest(expected, pwhash):
        _t4b_so_audit_log(self, None, uid, "auth.fail",
                                resource=username, details={"reason": "bad_password"}, success=False)
        return {"ok": False, "error": "invalid_credentials"}
    with self._t4b_so_lock:
        conn.execute("UPDATE session_users SET last_login_at=? WHERE user_id=?",
                          (_t4b_time.time(), uid))
    _t4b_so_audit_log(self, None, uid, "auth.success", resource=username,
                            details={"role": role}, success=True)
    return {"ok": True, "user_id": uid, "username": username, "role": role}


def _t4b_so_change_role(self, actor_user_id: str, target_user_id: str,
                              new_role: str) -> Dict[str, Any]:
    _t4b_so_require_permission(self, actor_user_id, "*")
    if new_role not in _T4B_ROLES:
        return {"ok": False, "error": "unknown_role"}
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        cur = conn.execute("UPDATE session_users SET role=? WHERE user_id=?",
                                (new_role, target_user_id))
    _t4b_so_audit_log(self, None, actor_user_id, "user.change_role",
                            resource=target_user_id, details={"new_role": new_role}, success=True)
    return {"ok": True, "user_id": target_user_id, "role": new_role}


def _t4b_so_deactivate_user(self, actor_user_id: str, target_user_id: str) -> Dict[str, Any]:
    _t4b_so_require_permission(self, actor_user_id, "*")
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        conn.execute("UPDATE session_users SET is_active=0 WHERE user_id=?", (target_user_id,))
    _t4b_so_audit_log(self, None, actor_user_id, "user.deactivate",
                            resource=target_user_id, success=True)
    return {"ok": True, "user_id": target_user_id, "is_active": False}


def _t4b_so_list_users(self, actor_user_id: str) -> List[Dict[str, Any]]:
    _t4b_so_require_permission(self, actor_user_id, "*")
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        rows = conn.execute(
            "SELECT user_id, username, role, created_at, last_login_at, is_active FROM session_users"
        ).fetchall()
    return [{"user_id": r[0], "username": r[1], "role": r[2],
              "created_at": r[3], "last_login_at": r[4],
              "is_active": bool(r[5])} for r in rows]


# ---- Tokens ------------------------------------------------------------
def _t4b_so_issue_token(self, user_id: str, ttl_s: float = 3600.0) -> Dict[str, Any]:
    token = _t4b_secrets.token_urlsafe(32)
    now = _t4b_time.time()
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        conn.execute(
            "INSERT INTO session_tokens (token, user_id, issued_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now, now + ttl_s)
        )
    return {"ok": True, "token": token, "expires_at": now + ttl_s, "ttl_s": ttl_s}


def _t4b_so_validate_token(self, token: str) -> Dict[str, Any]:
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        row = conn.execute(
            "SELECT user_id, expires_at, revoked FROM session_tokens WHERE token=?",
            (token,)
        ).fetchone()
    if not row:
        return {"valid": False, "reason": "unknown_token"}
    uid, exp, revoked = row
    if revoked:
        return {"valid": False, "reason": "revoked"}
    if exp < _t4b_time.time():
        return {"valid": False, "reason": "expired"}
    return {"valid": True, "user_id": uid, "expires_at": exp}


def _t4b_so_revoke_token(self, token: str) -> Dict[str, Any]:
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        conn.execute("UPDATE session_tokens SET revoked=1 WHERE token=?", (token,))
    return {"ok": True, "token": token[:8] + "..."}


# ---- Sessions ----------------------------------------------------------
def _t4b_so_create_persistent_session(self, user_id: str, target: str,
                                              metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    _t4b_so_require_permission(self, user_id, "session:write")
    sid = f"S-{_t4b_uuid.uuid4().hex[:16]}"
    now = _t4b_time.time()
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        conn.execute(
            "INSERT INTO session_sessions (session_id, user_id, target, state, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sid, user_id, target, "active",
             _t4b_json.dumps(metadata or {}, default=str), now, now)
        )
    _t4b_so_audit_log(self, sid, user_id, "session.create", resource=target,
                            details=metadata or {}, success=True)
    return {"ok": True, "session_id": sid, "user_id": user_id,
              "target": target, "state": "active", "created_at": now}


def _t4b_so_get_persistent_session(self, session_id: str) -> Optional[Dict[str, Any]]:
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        row = conn.execute(
            "SELECT session_id, user_id, target, state, metadata_json, created_at, updated_at, closed_at FROM session_sessions WHERE session_id=?",
            (session_id,)
        ).fetchone()
    if not row:
        return None
    return {"session_id": row[0], "user_id": row[1], "target": row[2],
              "state": row[3], "metadata": _t4b_json.loads(row[4]),
              "created_at": row[5], "updated_at": row[6], "closed_at": row[7]}


def _t4b_so_update_session_state(self, user_id: str, session_id: str,
                                          new_state: str,
                                          extra_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    _t4b_so_require_permission(self, user_id, "session:write")
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        existing = conn.execute(
            "SELECT metadata_json FROM session_sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if not existing:
            return {"ok": False, "error": "session_not_found"}
        meta = _t4b_json.loads(existing[0])
        if extra_meta:
            meta.update(extra_meta)
        closed_at = _t4b_time.time() if new_state in ("closed", "completed", "failed") else None
        conn.execute(
            "UPDATE session_sessions SET state=?, metadata_json=?, updated_at=?, closed_at=? WHERE session_id=?",
            (new_state, _t4b_json.dumps(meta, default=str), _t4b_time.time(), closed_at, session_id)
        )
    _t4b_so_audit_log(self, session_id, user_id, "session.update_state",
                            details={"new_state": new_state}, success=True)
    return {"ok": True, "session_id": session_id, "state": new_state}


def _t4b_so_list_persistent_sessions(self, user_id: Optional[str] = None,
                                              state: Optional[str] = None,
                                              limit: int = 100) -> List[Dict[str, Any]]:
    conn = _t4b_so_get_conn(self)
    sql = "SELECT session_id, user_id, target, state, created_at, updated_at, closed_at FROM session_sessions WHERE 1=1"
    args: List[Any] = []
    if user_id:
        sql += " AND user_id=?"; args.append(user_id)
    if state:
        sql += " AND state=?"; args.append(state)
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(limit)
    with self._t4b_so_lock:
        rows = conn.execute(sql, args).fetchall()
    return [{"session_id": r[0], "user_id": r[1], "target": r[2], "state": r[3],
              "created_at": r[4], "updated_at": r[5], "closed_at": r[6]} for r in rows]


# ---- Audit Log ---------------------------------------------------------
def _t4b_so_audit_log(self, session_id: Optional[str], user_id: Optional[str],
                            action: str, resource: Optional[str] = None,
                            details: Optional[Dict[str, Any]] = None,
                            success: bool = True) -> str:
    aid = f"A-{_t4b_uuid.uuid4().hex[:16]}"
    conn = _t4b_so_get_conn(self)
    try:
        with self._t4b_so_lock:
            conn.execute(
                "INSERT INTO session_audit (audit_id, session_id, user_id, action, resource, details_json, timestamp, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (aid, session_id, user_id, action, resource,
                 _t4b_json.dumps(details or {}, default=str), _t4b_time.time(),
                 1 if success else 0)
            )
    except Exception:
        pass
    return aid


def _t4b_so_query_audit(self, actor_user_id: str,
                              user_id: Optional[str] = None,
                              session_id: Optional[str] = None,
                              action: Optional[str] = None,
                              since: Optional[float] = None,
                              limit: int = 500) -> List[Dict[str, Any]]:
    _t4b_so_require_permission(self, actor_user_id, "audit:read")
    conn = _t4b_so_get_conn(self)
    sql = "SELECT audit_id, session_id, user_id, action, resource, details_json, timestamp, success FROM session_audit WHERE 1=1"
    args: List[Any] = []
    if user_id:
        sql += " AND user_id=?"; args.append(user_id)
    if session_id:
        sql += " AND session_id=?"; args.append(session_id)
    if action:
        sql += " AND action=?"; args.append(action)
    if since:
        sql += " AND timestamp>=?"; args.append(since)
    sql += " ORDER BY timestamp DESC LIMIT ?"; args.append(limit)
    with self._t4b_so_lock:
        rows = conn.execute(sql, args).fetchall()
    return [{"audit_id": r[0], "session_id": r[1], "user_id": r[2],
              "action": r[3], "resource": r[4],
              "details": _t4b_json.loads(r[5]), "timestamp": r[6],
              "success": bool(r[7])} for r in rows]


def _t4b_so_session_stats(self) -> Dict[str, Any]:
    conn = _t4b_so_get_conn(self)
    with self._t4b_so_lock:
        users = conn.execute("SELECT COUNT(*) FROM session_users").fetchone()[0]
        active_users = conn.execute("SELECT COUNT(*) FROM session_users WHERE is_active=1").fetchone()[0]
        sessions = conn.execute("SELECT COUNT(*) FROM session_sessions").fetchone()[0]
        active_sessions = conn.execute("SELECT COUNT(*) FROM session_sessions WHERE state='active'").fetchone()[0]
        audit_entries = conn.execute("SELECT COUNT(*) FROM session_audit").fetchone()[0]
        roles_dist = dict(conn.execute("SELECT role, COUNT(*) FROM session_users GROUP BY role").fetchall())
    return {"users": users, "active_users": active_users,
              "sessions": sessions, "active_sessions": active_sessions,
              "audit_entries": audit_entries, "roles_distribution": roles_dist}


# --- Bind to SessionOrchestrator ----------------------------------------
try:
    SessionOrchestrator.so_open = _t4b_so_open  # type: ignore[name-defined]
    SessionOrchestrator.so_close = _t4b_so_close  # type: ignore[name-defined]
    SessionOrchestrator.supported_roles = _t4b_so_supported_roles  # type: ignore[name-defined]
    SessionOrchestrator.role_permissions = _t4b_so_role_permissions  # type: ignore[name-defined]
    SessionOrchestrator.check_permission = _t4b_so_check_permission  # type: ignore[name-defined]
    SessionOrchestrator.require_permission = _t4b_so_require_permission  # type: ignore[name-defined]
    SessionOrchestrator.create_user = _t4b_so_create_user  # type: ignore[name-defined]
    SessionOrchestrator.authenticate = _t4b_so_authenticate  # type: ignore[name-defined]
    SessionOrchestrator.change_role = _t4b_so_change_role  # type: ignore[name-defined]
    SessionOrchestrator.deactivate_user = _t4b_so_deactivate_user  # type: ignore[name-defined]
    SessionOrchestrator.list_users = _t4b_so_list_users  # type: ignore[name-defined]
    SessionOrchestrator.issue_token = _t4b_so_issue_token  # type: ignore[name-defined]
    SessionOrchestrator.validate_token = _t4b_so_validate_token  # type: ignore[name-defined]
    SessionOrchestrator.revoke_token = _t4b_so_revoke_token  # type: ignore[name-defined]
    SessionOrchestrator.create_persistent_session = _t4b_so_create_persistent_session  # type: ignore[name-defined]
    SessionOrchestrator.get_persistent_session = _t4b_so_get_persistent_session  # type: ignore[name-defined]
    SessionOrchestrator.update_session_state = _t4b_so_update_session_state  # type: ignore[name-defined]
    SessionOrchestrator.list_persistent_sessions = _t4b_so_list_persistent_sessions  # type: ignore[name-defined]
    SessionOrchestrator.audit_log_entry = _t4b_so_audit_log  # type: ignore[name-defined]
    SessionOrchestrator.query_audit = _t4b_so_query_audit  # type: ignore[name-defined]
    SessionOrchestrator.persistent_session_stats = _t4b_so_session_stats  # type: ignore[name-defined]
except NameError:
    pass
