# Tier 4A primitives — appended to _recovered_support.py
# This is the source of truth; the install script appends to the helpers module
import asyncio
import hashlib
import hmac as _stdlib_hmac
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# 9. TTLCache — thread-safe time-bounded cache
# ─────────────────────────────────────────────────────────────────────────────
class TTLCache:
    """Lightweight TTL cache with maxsize eviction and thread safety.

    Used by dns_resolver / http_fingerprint / sonarqube / jira_client /
    defect_dojo to memoise idempotent reads.
    """

    __slots__ = ("_data", "_ttl", "_maxsize", "_lock", "hits", "misses")

    def __init__(self, ttl: float = 300.0, maxsize: int = 1024) -> None:
        self._data: Dict[Any, Tuple[float, Any]] = {}
        self._ttl = float(ttl)
        self._maxsize = int(maxsize)
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self.misses += 1
                return default
            expires, value = entry
            if expires < time.monotonic():
                self._data.pop(key, None)
                self.misses += 1
                return default
            self.hits += 1
            return value

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            if len(self._data) >= self._maxsize:
                # Evict oldest expiring entry
                try:
                    oldest = min(self._data.items(), key=lambda kv: kv[1][0])
                    self._data.pop(oldest[0], None)
                except ValueError:
                    pass
            self._data[key] = (time.monotonic() + (ttl or self._ttl), value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"hits": self.hits, "misses": self.misses, "size": len(self._data)}


# ─────────────────────────────────────────────────────────────────────────────
# 10. Cursor pagination iterator
# ─────────────────────────────────────────────────────────────────────────────
def paginate(
    fetch: Callable[..., Dict[str, Any]],
    *,
    page_param: str = "startAt",
    size_param: str = "maxResults",
    items_key: str = "issues",
    page_size: int = 100,
    max_items: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Iterator[Dict[str, Any]]:
    """Iterate paginated API responses.

    ``fetch(**params) -> {items_key: [...], 'total': N}`` is invoked
    repeatedly. Used by jira_client / sonarqube / defect_dojo searches.

    Yields one item at a time. Terminates when an empty page is returned,
    when ``max_items`` is hit, or when ``total`` is reached.
    """
    extra = dict(extra or {})
    offset = 0
    yielded = 0
    while True:
        params = dict(extra)
        params[page_param] = offset
        params[size_param] = page_size
        try:
            page = fetch(**params)
        except Exception:
            return
        if not isinstance(page, dict):
            return
        items = page.get(items_key) or []
        if not items:
            return
        for it in items:
            yield it
            yielded += 1
            if max_items is not None and yielded >= max_items:
                return
        if len(items) < page_size:
            return
        total = page.get("total")
        offset += len(items)
        if isinstance(total, int) and offset >= total:
            return


# ─────────────────────────────────────────────────────────────────────────────
# 11. HMAC-SHA256 signing
# ─────────────────────────────────────────────────────────────────────────────
def hmac_sign(secret: str, payload: Any, *, algorithm: str = "sha256") -> str:
    """Compute HMAC signature over a JSON-serialisable payload.

    Returns ``"<algo>=<hex>"`` to match GitHub/Slack convention.
    """
    if not secret:
        return ""
    if isinstance(payload, (bytes, bytearray)):
        body = bytes(payload)
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = _stdlib_hmac.new(
        secret.encode("utf-8"), body, getattr(hashlib, algorithm)
    ).hexdigest()
    return f"{algorithm}={digest}"


def verify_hmac(secret: str, payload: Any, signature: str) -> bool:
    """Constant-time verification of an HMAC signature produced by hmac_sign."""
    if not secret or not signature:
        return False
    try:
        algo = signature.split("=", 1)[0] if "=" in signature else "sha256"
    except Exception:
        algo = "sha256"
    expected = hmac_sign(secret, payload, algorithm=algo)
    return _stdlib_hmac.compare_digest(expected, signature)


# ─────────────────────────────────────────────────────────────────────────────
# 12. SQLite-backed persistence mixin
# ─────────────────────────────────────────────────────────────────────────────
class SQLitePersistMixin:
    """Mixin: persist and restore module state via SQLite.

    Subclasses set ``_persist_path`` (str) and ``_persist_table`` (str).
    State is stored as JSON in a single-row table per module instance,
    keyed by ``_persist_id`` (defaults to class name).

    Methods provided:
        _persist()        — write current state
        _restore()        — read state back
        _persist_state()  — override in subclass; return JSON-serialisable dict
        _restore_state()  — override in subclass; consume dict
    """

    _persist_path: Optional[str] = None
    _persist_table: str = "module_state"
    _persist_id: Optional[str] = None
    _persist_lock = threading.RLock()

    def _persist_conn(self) -> Optional[sqlite3.Connection]:
        path = self._persist_path or os.environ.get("CASECRACK_PERSIST_DB")
        if not path:
            return None
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            conn = sqlite3.connect(path, timeout=5.0, isolation_level=None)
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {self._persist_table} "
                f"(id TEXT PRIMARY KEY, state TEXT, updated REAL)"
            )
            return conn
        except Exception:
            return None

    def _persist_state(self) -> Dict[str, Any]:
        """Override: return JSON-serialisable snapshot of state."""
        return {}

    def _restore_state(self, state: Dict[str, Any]) -> None:
        """Override: consume previously persisted snapshot."""
        return

    def _persist(self) -> bool:
        with self._persist_lock:
            conn = self._persist_conn()
            if conn is None:
                return False
            try:
                state = self._persist_state()
                pid = self._persist_id or self.__class__.__name__
                conn.execute(
                    f"INSERT OR REPLACE INTO {self._persist_table} "
                    f"(id, state, updated) VALUES (?, ?, ?)",
                    (pid, json.dumps(state, default=str), time.time()),
                )
                return True
            except Exception:
                return False
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def _restore(self) -> bool:
        with self._persist_lock:
            conn = self._persist_conn()
            if conn is None:
                return False
            try:
                pid = self._persist_id or self.__class__.__name__
                row = conn.execute(
                    f"SELECT state FROM {self._persist_table} WHERE id = ?",
                    (pid,),
                ).fetchone()
                if not row or not row[0]:
                    return False
                self._restore_state(json.loads(row[0]))
                return True
            except Exception:
                return False
            finally:
                try:
                    conn.close()
                except Exception:
                    pass


# ─────────────────────────────────────────────────────────────────────────────
# 13. Per-module typed Error class factory
# ─────────────────────────────────────────────────────────────────────────────
def make_error_classes(module: str) -> Dict[str, type]:
    """Generate a per-module exception hierarchy.

    Returns a dict of ``{name: class}`` containing:
        ``{Module}Error``           — base (inherits Exception)
        ``{Module}ConfigError``     — invalid config / missing creds
        ``{Module}OperationError``  — runtime failure mid-operation
        ``{Module}TimeoutError``    — operation exceeded timeout
    """
    cap = "".join(p.capitalize() for p in module.split("_"))
    base = type(f"{cap}Error", (Exception,), {"__module__": module,
        "__doc__": f"Base exception for {module}."})
    cfg = type(f"{cap}ConfigError", (base,), {"__module__": module,
        "__doc__": f"Configuration error in {module}."})
    op = type(f"{cap}OperationError", (base,), {"__module__": module,
        "__doc__": f"Operational failure in {module}."})
    to = type(f"{cap}TimeoutError", (base,), {"__module__": module,
        "__doc__": f"Operation timeout in {module}."})
    return {
        f"{cap}Error": base,
        f"{cap}ConfigError": cfg,
        f"{cap}OperationError": op,
        f"{cap}TimeoutError": to,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 14. Dry-run event helper
# ─────────────────────────────────────────────────────────────────────────────
def emit_dry_run(module: str, method: str, **fields: Any) -> Dict[str, Any]:
    """Emit a MODULE_DRY_RUN event and return a stub success payload.

    Used by every action method when ``dry_run=True`` is passed.
    """
    payload = {"module": module, "method": method, "dry_run": True, **fields}
    if _bus_get is not None:
        try:
            bus = _bus_get()
            if bus is not None:
                emit = getattr(bus, "emit", None)
                if emit:
                    emit("module.dry_run", payload)
        except Exception:
            pass
    try:
        get_metrics().increment(f"{module}.{method}.dry_run")
    except Exception:
        pass
    return {"dry_run": True, "module": module, "method": method, "ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# 15. Lightweight dict validator (jsonschema if available)
# ─────────────────────────────────────────────────────────────────────────────
try:  # pragma: no cover
    import jsonschema as _jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except Exception:  # pragma: no cover
    _jsonschema = None  # type: ignore
    _HAS_JSONSCHEMA = False


def validate_dict(
    value: Any,
    schema: Optional[Dict[str, Any]] = None,
    *,
    required_keys: Optional[Iterable[str]] = None,
    types: Optional[Dict[str, type]] = None,
    name: str = "value",
) -> None:
    """Validate ``value`` is a dict satisfying basic constraints.

    Uses jsonschema when available + a schema is provided; otherwise falls
    back to required-keys + per-key type checks. Raises ``ValueError``
    on failure (callers can catch as ``{Module}ConfigError`` upstream).
    """
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a dict, got {type(value).__name__}")
    if required_keys:
        missing = [k for k in required_keys if k not in value]
        if missing:
            raise ValueError(f"{name} missing required keys: {missing}")
    if types:
        for k, t in types.items():
            if k in value and not isinstance(value[k], t):
                raise ValueError(
                    f"{name}[{k!r}] expected {t.__name__}, got {type(value[k]).__name__}"
                )
    if schema and _HAS_JSONSCHEMA:
        try:
            _jsonschema.validate(value, schema)  # type: ignore[union-attr]
        except _jsonschema.ValidationError as exc:  # type: ignore[union-attr]
            raise ValueError(f"{name} schema validation failed: {exc.message}") from exc


# ─────────────────────────────────────────────────────────────────────────────
# 16. Async mirror — wrap a sync method as an awaitable via asyncio.to_thread
# ─────────────────────────────────────────────────────────────────────────────
def async_mirror(sync_fn: Callable[..., Any]) -> Callable[..., Any]:
    """Return an async callable that invokes ``sync_fn`` on a worker thread.

    Used by the AST sweep to generate ``{name}_async`` mirrors for every
    public method without rewriting the underlying logic.
    """
    async def _wrapper(*args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(sync_fn, *args, **kwargs)
    _wrapper.__name__ = f"{sync_fn.__name__}_async"
    _wrapper.__doc__ = (sync_fn.__doc__ or "") + "\n\n(Async mirror via asyncio.to_thread.)"
    return _wrapper
