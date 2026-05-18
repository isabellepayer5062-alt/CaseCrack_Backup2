

# __TIER4B_INTEGRATIONS__ webhook_dispatcher
# Tier 4B: Dead-letter queue with persistence (SQLite), exponential backoff with jitter,
#          HMAC signature verification, replay capability, circuit breaker per endpoint,
#          batch dispatch, retry policies

import os as _t4b_os
import json as _t4b_json
import time as _t4b_time
import hmac as _t4b_hmac
import hashlib as _t4b_hashlib
import random as _t4b_random
import sqlite3 as _t4b_sql
import threading as _t4b_threading
import urllib.request as _t4b_req
import urllib.error as _t4b_urlerr
from dataclasses import dataclass as _t4b_dataclass, field as _t4b_field, asdict as _t4b_asdict
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Dead-letter queue (SQLite-backed, thread-safe)
# ---------------------------------------------------------------------------
@_t4b_dataclass
class DLQEntry:
    id: Optional[int] = None
    endpoint: str = ""
    event_type: str = ""
    payload_json: str = ""
    headers_json: str = "{}"
    last_error: str = ""
    attempt_count: int = 0
    created_at: float = _t4b_field(default_factory=_t4b_time.time)
    last_attempted_at: float = 0.0
    next_retry_at: float = 0.0
    status: str = "pending"   # pending | retrying | dead | replayed


class _T4BDeadLetterQueue:
    """SQLite-backed dead-letter queue for failed webhook deliveries."""

    DDL = """
    CREATE TABLE IF NOT EXISTS dlq (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        headers_json TEXT DEFAULT '{}',
        last_error TEXT DEFAULT '',
        attempt_count INTEGER DEFAULT 0,
        created_at REAL NOT NULL,
        last_attempted_at REAL DEFAULT 0,
        next_retry_at REAL DEFAULT 0,
        status TEXT DEFAULT 'pending'
    );
    CREATE INDEX IF NOT EXISTS idx_dlq_status_next ON dlq(status, next_retry_at);
    CREATE INDEX IF NOT EXISTS idx_dlq_endpoint ON dlq(endpoint);
    """

    def __init__(self, db_path: str = ":memory:"):
        self._lock = _t4b_threading.RLock()
        self._db_path = db_path
        self._conn = _t4b_sql.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.executescript(self.DDL)

    def enqueue(self, endpoint: str, event_type: str, payload: Any,
                  headers: Optional[Dict[str, str]] = None, error: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO dlq(endpoint,event_type,payload_json,headers_json,last_error,created_at,next_retry_at,status) "
                "VALUES(?,?,?,?,?,?,?, 'pending')",
                (endpoint, event_type,
                 _t4b_json.dumps(payload) if not isinstance(payload, str) else payload,
                 _t4b_json.dumps(headers or {}),
                 error[:1000], _t4b_time.time(), _t4b_time.time()),
            )
            return cur.lastrowid or 0

    def get_due(self, limit: int = 50) -> List[DLQEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id,endpoint,event_type,payload_json,headers_json,last_error,attempt_count,"
                "created_at,last_attempted_at,next_retry_at,status FROM dlq "
                "WHERE status='pending' AND next_retry_at<=? ORDER BY next_retry_at LIMIT ?",
                (_t4b_time.time(), limit),
            )
            return [DLQEntry(**dict(zip(
                ("id", "endpoint", "event_type", "payload_json", "headers_json", "last_error",
                 "attempt_count", "created_at", "last_attempted_at", "next_retry_at", "status"), row
            ))) for row in cur.fetchall()]

    def mark_retrying(self, entry_id: int, next_retry_at: float, error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE dlq SET status='pending', last_attempted_at=?, next_retry_at=?, "
                "attempt_count=attempt_count+1, last_error=? WHERE id=?",
                (_t4b_time.time(), next_retry_at, error[:1000], entry_id),
            )

    def mark_dead(self, entry_id: int, error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE dlq SET status='dead', last_attempted_at=?, last_error=?, attempt_count=attempt_count+1 WHERE id=?",
                (_t4b_time.time(), error[:1000], entry_id),
            )

    def mark_replayed(self, entry_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE dlq SET status='replayed', last_attempted_at=? WHERE id=?",
                (_t4b_time.time(), entry_id),
            )

    def delete(self, entry_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM dlq WHERE id=?", (entry_id,))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT status, COUNT(*) FROM dlq GROUP BY status"
            )
            by_status = {row[0]: row[1] for row in cur.fetchall()}
            cur2 = self._conn.execute("SELECT endpoint, COUNT(*) FROM dlq GROUP BY endpoint ORDER BY 2 DESC LIMIT 10")
            top_endpoints = [{"endpoint": r[0], "count": r[1]} for r in cur2.fetchall()]
            return {"by_status": by_status, "top_failing_endpoints": top_endpoints,
                    "total": sum(by_status.values())}

    def list_dead(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id,endpoint,event_type,last_error,attempt_count,created_at,last_attempted_at "
                "FROM dlq WHERE status='dead' ORDER BY last_attempted_at DESC LIMIT ?",
                (limit,),
            )
            return [dict(zip(("id", "endpoint", "event_type", "last_error", "attempt_count",
                              "created_at", "last_attempted_at"), row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Backoff with jitter
# ---------------------------------------------------------------------------
def _t4b_compute_backoff(attempt: int, base: float = 1.0, factor: float = 2.0,
                           cap: float = 600.0, jitter: float = 0.5) -> float:
    """Exponential backoff with full jitter. Returns seconds to wait."""
    delay = min(cap, base * (factor ** max(0, attempt - 1)))
    if jitter > 0:
        delay = delay * (1.0 - jitter) + delay * jitter * _t4b_random.random()
    return max(0.1, delay)


# ---------------------------------------------------------------------------
# HMAC signing & verification
# ---------------------------------------------------------------------------
def _t4b_sign_payload(secret: str, payload: bytes, algo: str = "sha256") -> str:
    """Compute HMAC signature for outbound payload."""
    h = _t4b_hmac.new(secret.encode("utf-8"), payload, getattr(_t4b_hashlib, algo))
    return f"{algo}={h.hexdigest()}"


def _t4b_verify_signature(secret: str, payload: bytes, header_value: str) -> bool:
    """Verify HMAC signature on incoming payload (e.g. 'sha256=abc...' GitHub style)."""
    if "=" in header_value:
        algo, sig_hex = header_value.split("=", 1)
    else:
        algo, sig_hex = "sha256", header_value
    try:
        expected = _t4b_hmac.new(secret.encode("utf-8"), payload, getattr(_t4b_hashlib, algo)).hexdigest()
    except Exception:
        return False
    return _t4b_hmac.compare_digest(expected, sig_hex)


# ---------------------------------------------------------------------------
# Per-endpoint circuit breaker
# ---------------------------------------------------------------------------
class _T4BWebhookCircuit:
    """Simple per-endpoint circuit breaker."""

    def __init__(self, fail_threshold: int = 5, recovery_window_s: float = 60.0):
        self._lock = _t4b_threading.RLock()
        self._fail_count: Dict[str, int] = {}
        self._opened_at: Dict[str, float] = {}
        self._fail_threshold = fail_threshold
        self._recovery_window_s = recovery_window_s

    def is_open(self, endpoint: str) -> bool:
        with self._lock:
            opened = self._opened_at.get(endpoint)
            if not opened:
                return False
            if (_t4b_time.time() - opened) > self._recovery_window_s:
                # half-open: allow next attempt
                self._opened_at.pop(endpoint, None)
                self._fail_count[endpoint] = 0
                return False
            return True

    def record_success(self, endpoint: str) -> None:
        with self._lock:
            self._fail_count[endpoint] = 0
            self._opened_at.pop(endpoint, None)

    def record_failure(self, endpoint: str) -> None:
        with self._lock:
            self._fail_count[endpoint] = self._fail_count.get(endpoint, 0) + 1
            if self._fail_count[endpoint] >= self._fail_threshold:
                self._opened_at[endpoint] = _t4b_time.time()

    def state(self, endpoint: str) -> str:
        with self._lock:
            if endpoint in self._opened_at:
                if _t4b_time.time() - self._opened_at[endpoint] > self._recovery_window_s:
                    return "half_open"
                return "open"
            return "closed"

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "fail_counts": dict(self._fail_count),
                "open_endpoints": list(self._opened_at.keys()),
            }


# ---------------------------------------------------------------------------
# Bound methods
# ---------------------------------------------------------------------------
def _t4b_get_dlq(self) -> _T4BDeadLetterQueue:
    """Lazy-init DLQ on the dispatcher."""
    if not hasattr(self, "_t4b_dlq") or self._t4b_dlq is None:
        db_path = getattr(self, "_dlq_path", None) or _t4b_os.environ.get("CASECRACK_DLQ_DB", ":memory:")
        self._t4b_dlq = _T4BDeadLetterQueue(db_path)
    return self._t4b_dlq


def _t4b_get_circuit(self) -> _T4BWebhookCircuit:
    """Lazy-init circuit breaker."""
    if not hasattr(self, "_t4b_circuit") or self._t4b_circuit is None:
        self._t4b_circuit = _T4BWebhookCircuit()
    return self._t4b_circuit


def _t4b_dispatch_signed(self, endpoint_url: str, event_type: str, payload: Any,
                           secret: Optional[str] = None, max_attempts: int = 1,
                           timeout: int = 10, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Dispatch a single signed webhook with attempt counting; queues to DLQ on failure if max_attempts==1."""
    rs = self._check_dry_run("dispatch_signed", endpoint=endpoint_url, event_type=event_type)
    if rs is not None:
        return rs
    circuit = _t4b_get_circuit(self)
    if circuit.is_open(endpoint_url):
        return {"sent": False, "reason": "circuit_open", "endpoint": endpoint_url}
    body = _t4b_json.dumps(payload).encode() if not isinstance(payload, (bytes, bytearray)) else bytes(payload)
    headers = {"Content-Type": "application/json", "X-Event-Type": event_type,
               "X-Delivery-Id": _t4b_hashlib.sha256(body + str(_t4b_time.time()).encode()).hexdigest()[:32]}
    if extra_headers:
        headers.update(extra_headers)
    if secret:
        headers["X-Signature-256"] = _t4b_sign_payload(secret, body, "sha256")
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            req = _t4b_req.Request(endpoint_url, data=body, headers=headers, method="POST")
            with _t4b_req.urlopen(req, timeout=timeout) as resp:
                circuit.record_success(endpoint_url)
                return {"sent": True, "code": resp.status, "attempts": attempt,
                        "delivery_id": headers["X-Delivery-Id"]}
        except _t4b_urlerr.HTTPError as e:
            last_error = f"HTTP {e.code}: {e.reason}"
            if 400 <= e.code < 500 and e.code not in (408, 429):
                # client error → don't retry
                circuit.record_failure(endpoint_url)
                _t4b_get_dlq(self).enqueue(endpoint_url, event_type, payload, headers, last_error)
                return {"sent": False, "code": e.code, "error": last_error,
                        "attempts": attempt, "queued_to_dlq": True}
        except Exception as e:
            last_error = str(e)
        if attempt < max_attempts:
            _t4b_time.sleep(_t4b_compute_backoff(attempt))
    circuit.record_failure(endpoint_url)
    entry_id = _t4b_get_dlq(self).enqueue(endpoint_url, event_type, payload, headers, last_error)
    return {"sent": False, "error": last_error, "attempts": max_attempts,
            "queued_to_dlq": True, "dlq_entry_id": entry_id}


def _t4b_replay_dlq(self, max_attempts: int = 5, batch: int = 50,
                     base_backoff: float = 2.0, max_backoff_cap: float = 600.0) -> Dict[str, Any]:
    """Process due DLQ entries, retry with exponential backoff, mark dead after max_attempts."""
    rs = self._check_dry_run("replay_dlq", batch=batch)
    if rs is not None:
        return rs
    dlq = _t4b_get_dlq(self)
    circuit = _t4b_get_circuit(self)
    due = dlq.get_due(limit=batch)
    sent = 0
    failed = 0
    dead = 0
    skipped = 0
    for entry in due:
        if circuit.is_open(entry.endpoint):
            skipped += 1
            continue
        try:
            payload = _t4b_json.loads(entry.payload_json)
        except Exception:
            payload = entry.payload_json
        try:
            headers = _t4b_json.loads(entry.headers_json)
        except Exception:
            headers = {}
        try:
            body = _t4b_json.dumps(payload).encode() if not isinstance(payload, (bytes, bytearray)) else bytes(payload)
            req = _t4b_req.Request(entry.endpoint, data=body, headers=headers, method="POST")
            with _t4b_req.urlopen(req, timeout=10) as resp:
                dlq.mark_replayed(entry.id)
                circuit.record_success(entry.endpoint)
                sent += 1
                continue
        except Exception as e:
            err = str(e)
            new_attempt = entry.attempt_count + 1
            if new_attempt >= max_attempts:
                dlq.mark_dead(entry.id, err)
                dead += 1
            else:
                next_at = _t4b_time.time() + _t4b_compute_backoff(new_attempt, base=base_backoff, cap=max_backoff_cap)
                dlq.mark_retrying(entry.id, next_at, err)
                failed += 1
            circuit.record_failure(entry.endpoint)
    return {"processed": len(due), "sent": sent, "failed": failed, "dead": dead,
            "skipped_circuit_open": skipped}


def _t4b_dlq_stats(self) -> Dict[str, Any]:
    """Get DLQ statistics."""
    return _t4b_get_dlq(self).stats()


def _t4b_dlq_dead_letters(self, limit: int = 100) -> List[Dict[str, Any]]:
    """List entries that exceeded max retry attempts."""
    return _t4b_get_dlq(self).list_dead(limit=limit)


def _t4b_dlq_purge_dead(self, older_than_days: int = 30) -> Dict[str, Any]:
    """Purge dead letters older than N days."""
    rs = self._check_dry_run("dlq_purge_dead", older_than_days=older_than_days)
    if rs is not None:
        return rs
    cutoff = _t4b_time.time() - (older_than_days * 86400)
    dlq = _t4b_get_dlq(self)
    with dlq._lock:
        cur = dlq._conn.execute(
            "DELETE FROM dlq WHERE status='dead' AND last_attempted_at < ?", (cutoff,)
        )
        return {"purged": cur.rowcount, "older_than_days": older_than_days}


def _t4b_verify_incoming(self, secret: str, payload: bytes, header_value: str) -> bool:
    """Verify HMAC signature on incoming webhook payload."""
    return _t4b_verify_signature(secret, payload, header_value)


def _t4b_sign_outgoing(self, secret: str, payload: bytes, algo: str = "sha256") -> str:
    """Compute HMAC signature for outbound payload."""
    return _t4b_sign_payload(secret, payload, algo)


def _t4b_circuit_state(self, endpoint_url: str) -> str:
    """Get current circuit state for endpoint: closed | open | half_open."""
    return _t4b_get_circuit(self).state(endpoint_url)


def _t4b_circuit_snapshot(self) -> Dict[str, Any]:
    """Snapshot of all circuit breakers."""
    return _t4b_get_circuit(self).snapshot()


def _t4b_batch_dispatch(self, events: List[Tuple[str, str, Any]],
                         secret: Optional[str] = None) -> Dict[str, Any]:
    """Dispatch list of (endpoint_url, event_type, payload) tuples; return aggregate stats."""
    rs = self._check_dry_run("batch_dispatch", count=len(events))
    if rs is not None:
        return rs
    results = {"total": len(events), "sent": 0, "queued": 0, "failed": 0}
    for endpoint, evtype, payload in events:
        r = _t4b_dispatch_signed(self, endpoint, evtype, payload, secret=secret)
        if r.get("sent"):
            results["sent"] += 1
        elif r.get("queued_to_dlq"):
            results["queued"] += 1
        else:
            results["failed"] += 1
    return results


try:
    WebhookDispatcher.dispatch_signed = _t4b_dispatch_signed     # type: ignore[name-defined]
    WebhookDispatcher.replay_dlq = _t4b_replay_dlq               # type: ignore[name-defined]
    WebhookDispatcher.dlq_stats = _t4b_dlq_stats                 # type: ignore[name-defined]
    WebhookDispatcher.dlq_dead_letters = _t4b_dlq_dead_letters   # type: ignore[name-defined]
    WebhookDispatcher.dlq_purge_dead = _t4b_dlq_purge_dead       # type: ignore[name-defined]
    WebhookDispatcher.verify_incoming = _t4b_verify_incoming     # type: ignore[name-defined]
    WebhookDispatcher.sign_outgoing = _t4b_sign_outgoing         # type: ignore[name-defined]
    WebhookDispatcher.circuit_state = _t4b_circuit_state         # type: ignore[name-defined]
    WebhookDispatcher.circuit_snapshot = _t4b_circuit_snapshot   # type: ignore[name-defined]
    WebhookDispatcher.batch_dispatch = _t4b_batch_dispatch       # type: ignore[name-defined]
    WebhookDispatcher.DLQEntry = DLQEntry                         # type: ignore[name-defined,attr-defined]
except NameError:
    pass
