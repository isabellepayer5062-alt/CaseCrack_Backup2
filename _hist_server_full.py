"""Server module â€” ReconDashboard.

aiohttp + WebSocket server that provides the real-time browser
dashboard for Venator reconnaissance.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets as _secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from tools.burp_enterprise._design_tokens import DESIGN_TOKENS_CSS

from ._assets import (
    _DASH_CONFIG_TPL,
    _DASH_HEAD_TPL,
    _DASH_SCRIPT_TPL,
    _DASH_STATIC_END,
    _DASH_STATIC_MID,
    _STATIC_DIR,
)
from . import event_bridge
from . import infra_monitor
from . import llm_helpers
from . import session_store
from .state import (
    DEFAULT_HTTP_PORT,
    DEFAULT_MAX_PARALLEL_SLOTS,
    DEFAULT_WS_PORT,
    PORT_SCAN_RANGE,
    SNAPSHOT_INTERVAL_S,
    DashboardState,
)

logger = logging.getLogger(__name__)



# EventBus type mapping moved to event_bridge.py
_BUS_TO_DASHBOARD_TYPE = event_bridge.BUS_TO_DASHBOARD_TYPE

def _pkg_attr(name: str):
    """Resolve a package-level attribute at call time.

    This supports ``@patch("tools.burp_enterprise.recon_dashboard.X")``
    in the test suite â€” the patch modifies the *package* module's
    namespace, so we must look up patchable constants from there
    rather than from a locally imported name binding.
    """
    import sys
    return getattr(sys.modules[__package__], name)


class ReconDashboard:
    """
    WebSocket + HTTP dashboard server for real-time recon visualisation.

    Following the same pattern as InterceptDashboard but with HTTP POST
    ingestion for inter-process event delivery.
    """

    def __init__(
        self,
        target_url: str = "",
        http_port: int = DEFAULT_HTTP_PORT,
        ws_port: int = DEFAULT_WS_PORT,
        auto_open: bool = True,
        auth_token: str | None = None,
        restore_session: str | None = None,
        parallel: bool = False,
        max_parallel_slots: int = DEFAULT_MAX_PARALLEL_SLOTS,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
        auto_exit: bool = False,
    ):
        self.http_port = http_port
        self.ws_port = ws_port
        self.auto_open = auto_open
        self._auto_exit = auto_exit
        self._running = False
        self._start_time = time.time()
        self._ws_clients: set[Any] = set()
        self._sse_clients: set[Any] = set()  # SSE StreamResponse connections
        self._clients_lock = asyncio.Lock()  # FIX-P0-CONCMOD: guards _ws_clients & _sse_clients
        self._state = DashboardState(target_url)
        self._event_seq: int = 0
        self._runner: Any = None
        self._ws_server: Any = None
        self._standalone_runner: Any | None = None

        # â”€â”€ AssessmentEngine integration (Opp #3) â”€â”€
        self._assessment_engine: Any | None = None
        self._assessment_thread: threading.Thread | None = None

        # -- EventBus direct subscriber (Architecture Rec #1) --
        self._event_bus: Any | None = None
        self._bus_sub_ids: list[str] = []
        self._bus_loop: asyncio.AbstractEventLoop | None = None
        self._bus_seen_ids: set[str] = set()
        self._BUS_SEEN_MAX: int = 4000

        # -- Atlas Intelligence Dashboard API --
        try:
            from .atlas_api import AtlasDashboardAPI
            self._atlas_api = AtlasDashboardAPI()
        except (ImportError, RuntimeError) as exc:
            logger.debug("Atlas dashboard API unavailable: %s", exc)
            self._atlas_api = None

        # -- Atlas Nexus (EventBus ↔ Atlas cross-module hub) --
        # Deferred: only activated when a scan starts to avoid ~30-50 MB
        # of eager subsystem init (6 sub-engines + SQLite + learning timer).
        self._atlas_nexus: Any | None = None
        self._atlas_nexus_available: bool = True  # False if import fails

        # -- LLM Integration (lazy-initialised on first use) --
        # Stored as None until _ensure_llm_bridge() is called; avoids
        # startup failure when no API keys are configured.
        self._llm_bridge: Any | None = None
        self._llm_bridge_init_attempted: bool = False
        self._pending_scan_confirm: bool = False  # T2.4: confirmation gate
        self._llm_chat_lock: asyncio.Lock = asyncio.Lock()  # C-3: one chat at a time per client
        self._llm_chat_msg_seq: int = 0  # C-3: monotonic message ID counter
        self._llm_chat_task: asyncio.Task | None = None  # H-6: running generation task reference
        self._info_watcher_task: asyncio.Task | None = None  # info scan watcher task
        # Payout metrics tracker
        self._payout_tracker = None  # lazy init on scan start
        # C-5: LLM-specific rate limiter (10 req/min — GPU inference is expensive)
        self._llm_rate_window: float = 60.0  # seconds
        self._llm_rate_limit: int = 10  # max requests per window
        self._llm_rate_timestamps: list[float] = []
        self._rag_engine: Any | None = None  # T3.1: RAG context engine (lazy)
        self._ctx_cache: dict[str, Any] | None = None  # 7.3.3: TTL cache for context
        self._ctx_cache_ts: float = 0.0
        self._ctx_cache_count: int = -1
        self._ctx_cache_seq: int = -1  # track _change_seq for cache invalidation
        self._reasoning_engine: Any | None = None
        self._reasoning_engine_init_attempted: bool = False
        self._agent_memory: Any | None = None
        self._agent_memory_init_attempted: bool = False
        self._agent_loop: Any | None = None
        self._agent_loop_task: asyncio.Task | None = None


        # â”€â”€ Parallel execution defaults â”€â”€
        self._default_parallel: bool = parallel
        self._default_max_parallel_slots: int = max_parallel_slots

        # â”€â”€ Event coalescing buffer â”€â”€
        # High-frequency events (finding, endpoint, subdomain) are batched
        # into 250 ms windows and broadcast as a single ``event_batch``
        # message, reducing WS traffic from hundreds/sec to ~4/sec.
        self._COALESCABLE_TYPES: frozenset = frozenset((
            "finding", "endpoint", "subdomain", "log", "progress",
            "asset", "scan_update", "technology", "console_batch",
        ))
        self._event_batch: list[dict[str, Any]] = []
        self._event_batch_lock = threading.Lock()
        self._batch_flush_handle: asyncio.TimerHandle | None = None
        self._flush_in_progress: bool = False  # FIX-FREEZE: guard against overlapping flushes
        self._BATCH_INTERVAL: float = 0.25  # seconds
        self._BATCH_MAX: int = 80  # PERF FIX: raised from 40 to 80 â€” during Phase 21/22
                                    # bursts, 40-event batches flush every ~100ms causing
                                    # WS flood.  80 events/250ms reduces broadcast freq by 50%.

        # â”€â”€ Periodic state-diff push â”€â”€
        # Safety-net: every 5 s, broadcast a state_diff to all WS clients
        # so the frontend catches up even if individual event_batch pushes
        # are lost due to threading race conditions in the coalescing path.
        # PERF FIX: increased from 2s to 5s â€” during Phase 21/22 bursts all
        # field groups are dirty, causing to_dict_diff to degrade to near-full
        # state serialization.  5s reduces this overhead by 60%.
        self._diff_push_seq: int = 0       # last _change_seq we pushed
        self._diff_push_task: asyncio.Task | None = None
        self._DIFF_PUSH_INTERVAL: float = 5.0  # seconds

        # â”€â”€ TLS / HTTPS support â”€â”€
        self._ssl_context: ssl.SSLContext | None = None
        if ssl_certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(
                certfile=ssl_certfile,
                keyfile=ssl_keyfile,
            )
            self._ssl_context = ctx
            logger.info("TLS enabled (cert=%s)", ssl_certfile)

        # â”€â”€ Rate limiting for /api/event â”€â”€
        self._rate_limits: dict[str, dict[str, Any]] = {}
        self._status_rate_limits: dict[str, dict[str, Any]] = {}

        # Per-client connection limits (WS + SSE)
        self._ws_conn_count: dict[str, int] = {}   # peer -> active WS count
        self._sse_conn_count: dict[str, int] = {}  # peer -> active SSE count
        self._MAX_WS_PER_CLIENT: int = 10
        self._MAX_SSE_PER_CLIENT: int = 5

        # â”€â”€ Infrastructure probe cache (30s TTL) â”€â”€
        self._infra_cache: dict[str, Any] | None = None
        self._infra_cache_ts: float = 0.0
        _INFRA_CACHE_TTL = 30.0  # seconds
        self._infra_cache_ttl = _INFRA_CACHE_TTL

        # â”€â”€ Auth token (bearer) â”€â”€
        self._auth_token: str = auth_token or _secrets.token_urlsafe(32)
        # CC-S1: Per-session token rotation
        self._token_created_at: float = time.monotonic()
        self._token_rotation_interval: float = float(
            os.environ.get("VENATOR_TOKEN_ROTATION_SEC", "3600")
        )  # default 1 hour
        self._prev_auth_token: str | None = None  # grace period for in-flight requests

        # â”€â”€ Session tracking â”€â”€
        self._session_id: str = uuid.uuid4().hex
        self._snapshot_task: asyncio.Task[None] | None = None

        # â”€â”€ Database-backed persistence (NEW â€” SQLite via db_registry) â”€â”€
        self._db_persistence: Any | None = None
        try:
            from .db_persistence import DashboardPersistence
            self._db_persistence = DashboardPersistence()
            logger.debug("Dashboard DB persistence enabled (SQLite)")
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            logger.debug("Dashboard DB persistence unavailable: %s", exc)

        # â”€â”€ FIX-158: Run database maintenance on startup to prevent
        #    unbounded intel.db growth from prior sessions â”€â”€
        try:
            from ..db_registry import run_maintenance
            maint = run_maintenance()
            for action in maint.get("actions", []):
                if action != "No maintenance needed":
                    logger.info("FIX-158 startup maintenance: %s", action)
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            logger.debug("FIX-158: Startup maintenance skipped: %s", exc)

        # â”€â”€ Restore previous session if requested â”€â”€
        if restore_session:
            self._restore_session(restore_session)


    # -- Atlas Nexus lazy activation --

    def _ensure_atlas_nexus(self) -> Any | None:
        """Lazily initialize and activate Atlas Nexus on first use."""
        if self._atlas_nexus is not None:
            return self._atlas_nexus
        if not self._atlas_nexus_available:
            return None
        try:
            from ..atlas import get_nexus
            self._atlas_nexus = get_nexus()
            self._atlas_nexus.activate()
            logger.info("Atlas Nexus activated (lazy)")
        except (ImportError, RuntimeError) as exc:
            logger.debug("Atlas Nexus unavailable: %s", exc)
            self._atlas_nexus_available = False
            self._atlas_nexus = None
        return self._atlas_nexus

    def _deactivate_atlas_nexus(self) -> None:
        """Deactivate Atlas Nexus to free memory when scan is done."""
        if self._atlas_nexus is not None:
            try:
                self._atlas_nexus.deactivate()
                logger.info("Atlas Nexus deactivated (scan idle)")
            except Exception as exc:
                logger.debug("Atlas Nexus deactivate error: %s", exc)
            self._atlas_nexus = None

    # -- Scan lifecycle: activate/deactivate heavy subsystems --

    def _activate_scan_tasks(self) -> None:
        """Start periodic tasks and Atlas Nexus when a scan begins."""
        self._ensure_atlas_nexus()
        loop = asyncio.get_event_loop()
        if self._diff_push_task is None or self._diff_push_task.done():
            self._diff_push_task = loop.create_task(self._periodic_diff_push_loop())
        if not hasattr(self, '_eg_push_task') or self._eg_push_task is None or self._eg_push_task.done():
            self._eg_push_task = loop.create_task(self._periodic_exploit_graph_push())
        logger.debug("Scan tasks activated (diff push + exploit graph push)")

    def _deactivate_scan_tasks(self) -> None:
        """Stop periodic push tasks and Atlas Nexus when scan stops."""
        if self._diff_push_task and not self._diff_push_task.done():
            self._diff_push_task.cancel()
            self._diff_push_task = None
        if getattr(self, '_eg_push_task', None) and not self._eg_push_task.done():
            self._eg_push_task.cancel()
            self._eg_push_task = None
        self._deactivate_atlas_nexus()
        logger.debug("Scan tasks deactivated (diff push + exploit graph push)")

    # -- Session restore (delegated to session_store.py) --

    def _restore_session(self, session_id: str) -> None:
        session_store.restore_session(
            self._state, self._db_persistence, session_id,
            _pkg_attr("_STATE_DIR"),
        )

    # â”€â”€ Port auto-discovery helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def _is_port_available(port: int) -> bool:
        """Check if a TCP port is available for binding."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("localhost", port))
                return True
        except OSError:
            return False

    def _find_available_ports(self) -> bool:
        """
        Scan for available HTTP and WS port pair.

        Tries the requested ports first, then scans upward within
        PORT_SCAN_RANGE.  Updates self.http_port and self.ws_port
        to the first available pair.  Returns True if a pair was found.
        """
        # Try requested ports first
        http_ok = self._is_port_available(self.http_port)
        ws_ok = self._is_port_available(self.ws_port)
        if http_ok and ws_ok:
            return True

        # Scan for an available pair
        base_http = DEFAULT_HTTP_PORT
        base_ws = DEFAULT_WS_PORT
        for offset in range(PORT_SCAN_RANGE):
            candidate_http = base_http + (offset * 2)
            candidate_ws = base_ws + (offset * 2)
            if self._is_port_available(candidate_http) and self._is_port_available(candidate_ws):
                if candidate_http != self.http_port or candidate_ws != self.ws_port:
                    logger.info(
                        "Ports %d/%d in use â€” falling back to %d/%d",
                        self.http_port, self.ws_port,
                        candidate_http, candidate_ws,
                    )
                self.http_port = candidate_http
                self.ws_port = candidate_ws
                return True

        return False

    def _write_port_file(self) -> None:
        """
        Write a discovery file so CLI helpers can locate the running
        dashboard without hardcoded ports.  Also stores the auth token
        hash for secure reconnection.
        """
        try:
            _pkg_attr('_REPORTS_DIR').mkdir(parents=True, exist_ok=True)
            data = {
                "http_port": self.http_port,
                "ws_port": self.ws_port,
                "pid": os.getpid(),
                "session_id": self._session_id,
                "token_hash": hashlib.sha256(self._auth_token.encode()).hexdigest(),
                "started_at": datetime.now(timezone.utc).isoformat(),
                "target_url": self._state.target_url,
            }
            with open(_pkg_attr('_PORT_FILE'), "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:
            logger.debug("Could not write port file: %s", exc)

    @staticmethod
    def _remove_port_file() -> None:
        """Remove the port discovery file on shutdown."""
        try:
            _pkg_attr('_PORT_FILE').unlink(missing_ok=True)
        except OSError as exc:
            logger.debug("Could not remove port file: %s", exc)

    # â”€â”€ Auth middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _make_auth_middleware(self) -> Any:
        """
        aiohttp middleware that enforces Bearer token auth on mutating
        endpoints **and** sensitive GET endpoints.

        Exempt routes (no auth required):
          GET  /                       (dashboard HTML)
          GET  /health                 (health-check)
          GET  /api/infra-status       (infrastructure probe)
          GET  /api/standalone/status  (standalone status)
          GET  /api/standalone/console (console feed)
          GET  /api/report             (generated report)

        Auth-required GET routes:
          GET  /api/status             (full state snapshot)
          GET  /api/events/stream      (SSE event stream)
          GET  /api/export             (export data)
          GET  /api/sessions           (session history)
          GET  /api/token              (token endpoint)
          GET  /api/phase/settings     (phase config)

        Security hardening:
          - Query-string token auth REMOVED â€” tokens in URLs leak via
            access logs, browser history, and Referer headers.
          - POST/PUT/DELETE requests require a valid Origin header
            matching localhost to prevent cross-site request forgery.
        """
        token = self._auth_token
        http_port = self.http_port

        # GET paths that do NOT require auth
        _PUBLIC_GET_PATHS: set[str] = {
            "/",
            "/health",
            "/favicon.ico",
            "/api/infra-status",
            "/api/api-keys",
            "/api/standalone/status",
            "/api/standalone/console",
            "/api/report",
            "/api/token",  # handler enforces localhost-only check itself
            "/api/target-profile",  # read-only target profile overlay
            "/api/exploit-graph",  # read-only graph data for inline panel
            "/api/exploit-graph/paths",  # B13 critical paths read-only
            "/api/exploit-graph/trigger-maps",  # F10 canonical trigger maps
            "/api/exploit-graph/narrative",  # U1 attack narrative
            "/api/exploit-graph/timeline",   # U2 risk timeline
            "/api/exploit-graph/report",     # U3 combined report
            "/api/exploit-graph/goal",       # U4 goal-setting paths
            # Atlas Intelligence endpoints (read-only)
            "/api/atlas/health",
            "/api/atlas/summary",
            # Payout metrics (read-only, no auth)
            "/api/payout-metrics",
            "/api/payout-metrics/history",
            "/api/payout-metrics/consistency",
            "/api/payout-metrics/ttff",
            "/api/payout-metrics/chains",
            "/api/scan/status",
            "/api/atlas/patterns",
            "/api/atlas/archetypes",
            "/api/atlas/graph",
            "/api/atlas/graph/best-paths",
            "/api/atlas/defense",
            "/api/atlas/defense/advisory",
            "/api/atlas/observations",
            "/api/atlas/strategies",
            # LLM / Reasoning / Memory read-only status endpoints
            "/api/llm/status",
            "/api/reasoning/hypotheses",
            "/api/reasoning/traces",
            "/api/agent/cycles",
            "/api/memory/episodes",
            "/api/memory/stats",
            # Intelligence Experience read-only endpoints
            "/api/intelligence-experience/feed",
            "/api/intelligence-experience/summary",
            "/api/intelligence-experience/decisions",
            "/api/intelligence-experience/strategies",
            "/api/intelligence-experience/learning",
        }

        # Allowed Origin values for POST/PUT/DELETE (CSRF protection).
        # The dashboard is always served from localhost; any other origin
        # indicates a cross-site request and should be rejected.
        _ALLOWED_ORIGINS: set[str] = {
            f"http://localhost:{http_port}",
            f"http://127.0.0.1:{http_port}",
            f"http://[::1]:{http_port}",
            # Include without port for flexibility
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
        }

        @web.middleware
        async def auth_middleware(request: Any, handler: Any) -> Any:
            """Perform the auth middleware operation on this ``ReconDashboard``."""
            # Static assets are always public (CSS, JS, images)
            if request.method == "GET" and request.path.startswith("/static/"):
                resp = await handler(request)
                # Content-hashed files in /static/dist/ are immutable
                if "/dist/" in request.path:
                    resp.headers["Cache-Control"] = (
                        "public, max-age=31536000, immutable"
                    )
                else:
                    resp.headers["Cache-Control"] = (
                        "public, max-age=3600"
                    )
                return resp
            # Allow only explicitly public GET paths without auth
            if request.method == "GET" and request.path in _PUBLIC_GET_PATHS:
                return await handler(request)

            # â”€â”€ Origin validation for mutating requests (CSRF defence) â”€â”€
            # POST/PUT/DELETE must include an Origin header that matches
            # the dashboard's localhost binding.  Requests without an
            # Origin header are allowed only when X-Dashboard-Token is
            # present (programmatic / non-browser callers).
            if request.method in ("POST", "PUT", "DELETE"):
                origin = request.headers.get("Origin", "")
                if origin and origin not in _ALLOWED_ORIGINS:
                    logger.warning(
                        "Rejected %s %s â€” disallowed Origin: %s",
                        request.method, request.path, origin,
                    )
                    return web.json_response(
                        {"ok": False, "error": "Forbidden â€” Origin not allowed"},
                        status=403,
                    )

            # â”€â”€ Bearer token auth (header only â€” no query-string) â”€â”€
            # Query-string token auth has been REMOVED: tokens in URLs
            # leak via access logs, browser history, and Referer headers.
            # FIX-P0-TIMING: Use hmac.compare_digest to prevent
            # timing side-channel attacks on token comparison.
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer ") and (
                    hmac.compare_digest(auth_header[7:], token)
                    or (self._prev_auth_token and hmac.compare_digest(auth_header[7:], self._prev_auth_token))
                ):
                return await handler(request)
            # Also check X-Dashboard-Token header (CLI / programmatic)
            xdt = request.headers.get("X-Dashboard-Token", "")
            if xdt and (hmac.compare_digest(xdt, token) or (self._prev_auth_token and hmac.compare_digest(xdt, self._prev_auth_token))):
                return await handler(request)
            return web.json_response(
                {"ok": False, "error": "Unauthorized â€” provide Authorization: Bearer <token>"},
                status=401,
            )

        return auth_middleware

    @staticmethod
    def _make_security_headers_middleware() -> Any:
        """aiohttp middleware that adds defence-in-depth security headers
        to every HTTP response (API, static, and HTML alike).

        P1-14: Prevents click-jacking, MIME sniffing, and provides a
        baseline CSP for API responses.  The HTML dashboard page
        overrides CSP with a stricter nonce-based policy in
        ``_serve_dashboard()``.
        """

        @web.middleware
        async def security_headers_middleware(request: Any, handler: Any) -> Any:
            resp = await handler(request)
            h = resp.headers
            # Prevent click-jacking
            h.setdefault("X-Frame-Options", "DENY")
            # Prevent MIME-type sniffing attacks
            h.setdefault("X-Content-Type-Options", "nosniff")
            # Opt out of FLoC / Topics
            h.setdefault("Permissions-Policy", "interest-cohort=()")
            # Referrer leakage control
            h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
            # Baseline CSP for API/static responses (HTML page overrides)
            h.setdefault(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            )
            return resp

        return security_headers_middleware

    # -- State persistence (delegated to session_store.py) --

    def _save_state_snapshot(self) -> None:
        session_store.save_state_snapshot(
            self._state, self._db_persistence, self._session_id,
            self.http_port, self.ws_port, _pkg_attr("_STATE_DIR"),
        )

    def _prune_old_sessions(self, keep: int = 3) -> None:
        session_store.prune_old_sessions(_pkg_attr("_STATE_DIR"), keep)

    async def _periodic_snapshot_loop(self) -> None:
        """Background coroutine that saves state every SNAPSHOT_INTERVAL_S."""
        try:
            while self._running:
                await asyncio.sleep(SNAPSHOT_INTERVAL_S)
                if self._running:
                    loop = asyncio.get_running_loop()  # FIX-155
                    try:
                        await loop.run_in_executor(None, self._save_state_snapshot)
                    except Exception:
                        logger.debug("Snapshot save failed", exc_info=True)
                    # FIX-DISK-2: Prune stale session files every snapshot cycle
                    try:
                        await loop.run_in_executor(None, self._prune_old_sessions)
                    except Exception:
                        logger.debug("Session prune failed", exc_info=True)
        except asyncio.CancelledError:
            # Final save on shutdown
            self._save_state_snapshot()

    async def _periodic_diff_push_loop(self) -> None:
        """Push a state_diff to all WS clients every 2 seconds.

        Acts as a catch-all safety net: even if the event-based coalescing
        pipeline (``_enqueue_coalescable`` â†’ ``_flush_event_batch``) misses
        an update due to threading races or timer issues, this loop ensures
        the frontend receives the latest state within 2 seconds.

        Uses ``to_dict_diff(since_seq)`` which only includes field groups
        that changed since the last push, keeping payloads small.
        """
        try:
            while self._running:
                await asyncio.sleep(self._DIFF_PUSH_INTERVAL)
                if not self._running:
                    break
                if not self._ws_clients:
                    continue  # no clients â€” skip
                current_seq = self._state._change_seq
                if current_seq <= self._diff_push_seq:
                    continue  # nothing changed â€” skip
                diff = self._state.to_dict_diff(self._diff_push_seq)
                self._diff_push_seq = current_seq
                if diff.get("_full"):
                    # PERF FIX: Even when the diff falls back to a full
                    # state, send it as "state_diff" not "state_snapshot"
                    # so the client uses targeted dirty flags instead of
                    # markAllDirty().  The _full flag on state_snapshot
                    # was triggering full re-renders of ALL sections every
                    # 5s during Phase 21/22 â€” the biggest cause of 91% freeze.
                    diff["type"] = "state_diff"
                else:
                    # Only push if there are actual field changes (not just _change_seq)
                    if len(diff) <= 2:  # only _change_seq and _full
                        continue
                    diff["type"] = "state_diff"
                await self._broadcast(diff)
        except asyncio.CancelledError as _exc:
            logger.debug("Suppressed %s: %s", type(_exc).__name__, _exc)  # FIX-155
        except Exception as exc:
            logger.debug("Periodic diff push error: %s", exc)

    async def _periodic_exploit_graph_push(self) -> None:
        """Snapshot the exploit graph engine state every 10 seconds and push
        both into DashboardState (for state_diff inclusion) and as a direct
        ``exploit_graph.delta`` WebSocket event (for the existing JS handler).

        This bridges the gap between the ExploitGraphEngine singleton (which
        mutates on every finding ingestion) and the dashboard state container
        (which only updates via apply_event).
        """
        _eg_last_seq = 0
        try:
            while self._running:
                await asyncio.sleep(10)
                if not self._running or not self._ws_clients:
                    continue
                try:
                    from tools.burp_enterprise.exploit_graph import get_exploit_graph_engine
                    engine = get_exploit_graph_engine()
                    graph = engine.graph
                    current_seq = graph.change_seq
                    if current_seq <= _eg_last_seq:
                        continue  # nothing changed
                    _eg_last_seq = current_seq
                    pos = graph.get_current_position()
                    confirmed = graph.get_confirmed_transitions()
                    payload = {
                        "position": pos.to_dict(),
                        "risk_score": pos.risk_score,
                        "composite_risk_score": pos.composite_risk_score,
                        "confirmed_count": len(confirmed),
                        "total_count": len(graph._edges),
                        "change_seq": current_seq,
                        "cytoscape": graph.to_cytoscape(),
                        "critical_paths": graph.critical_paths()[:10],
                        "suggested_chains": graph.suggest_chains()[:10],
                        "next_tests": graph.suggest_next_tests()[:10],
                        "blast_radius": graph.calculate_blast_radius(),
                    }
                    # Feed into DashboardState for state_diff inclusion
                    self._state.apply_event({
                        "type": "exploit_graph_update",
                        **payload,
                    })
                    # Also push as direct WS event for exploit_graph.delta handler
                    payload["type"] = "exploit_graph.delta"
                    await self._broadcast(payload)
                except ImportError:
                    pass  # exploit_graph module not available
                except Exception as exc:
                    logger.debug("Exploit graph push error: %s", exc)
        except asyncio.CancelledError:
            pass

    def _list_sessions(self) -> list[dict[str, Any]]:
        return session_store.list_sessions(
            self._db_persistence, _pkg_attr("_STATE_DIR"),
        )

    async def _handle_sessions(self, _request: Any) -> Any:
        """List past session snapshots (GET /api/sessions)."""
        loop = asyncio.get_running_loop()  # FIX-155
        sessions = await loop.run_in_executor(None, self._list_sessions)
        return web.json_response({"ok": True, "sessions": sessions})

    async def _handle_token(self, request: Any) -> Any:
        """Return the auth token (GET /api/token â€” only from localhost)."""
        # Only serve token info to localhost.
        # Accept all common loopback representations including full IPv6.
        _LOOPBACK = {
            "127.0.0.1",
            "::1",
            "0:0:0:0:0:0:0:1",   # full IPv6 loopback
            "0.0.0.0",            # unspecified (some OS listeners)
            "localhost",
        }
        peername = request.transport.get_extra_info("peername")
        if peername and peername[0] not in _LOOPBACK:
            return web.json_response({"ok": False, "error": "Forbidden"}, status=403)
        return web.json_response({
            "ok": True,
            "token": self._auth_token,
            "session_id": self._session_id,
        })

    async def _handle_phase_settings_post(self, request: Any) -> Any:
        """Save phase settings (POST /api/phase/settings)."""
        try:
            body = await request.json()
            phase_name = body.get("phase", "")
            settings = body.get("settings", {})
            if not phase_name:
                return web.json_response(
                    {"ok": False, "error": "phase is required"}, status=400
                )
            # Validate settings structure
            if not isinstance(settings, dict):
                return web.json_response(
                    {"ok": False, "error": "settings must be an object"}, status=400
                )
            self._state.phase_settings[phase_name] = settings
            logger.info("Phase settings updated: %s â†’ profile=%s", str(phase_name).replace("\n", "").replace("\r", ""), str(settings.get("profile", "custom")).replace("\n", "").replace("\r", ""))
            return web.json_response({"ok": True, "phase": phase_name})
        except Exception as exc:
            logger.warning("Phase settings error: %s", exc)
            return web.json_response(
                {"ok": False, "error": str(exc)}, status=500
            )

    async def _handle_phase_settings_get(self, request: Any) -> Any:
        """Get phase settings (GET /api/phase/settings?phase=...)."""
        phase_name = request.query.get("phase", "")
        if phase_name:
            settings = self._state.phase_settings.get(phase_name, {})
            return web.json_response({"ok": True, "phase": phase_name, "settings": settings})
        return web.json_response({"ok": True, "all_settings": dict(self._state.phase_settings)})

    async def _handle_event_stream(self, request: Any) -> Any:
        """
        SSE endpoint (GET /api/events/stream).

        Streams real-time recon events to external consumers (e.g. the
        VS Code extension's ReconBridge) as Server-Sent Events.

        Protocol:
          - On connect: sends a ``state_snapshot`` event with the full state
          - Thereafter: every dashboard event is forwarded as an SSE line
          - Heartbeat ``ping`` sent every 15s to keep the connection alive
        """
        # Restrict CORS to the dashboard origin (configurable via env)
        allowed_origin = os.environ.get(
            "VENATOR_CORS_ORIGINS",
            f"http://localhost:{self.http_port}",
        )
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": allowed_origin,
                "X-Accel-Buffering": "no",
            },
        )

        # FIX-SSE-CONN-LOCK: Check and increment under lock to
        # prevent race where two connections both see cur=4 and
        # both proceed when max is 5.
        peer = request.remote or "unknown"
        async with self._clients_lock:
            cur = self._sse_conn_count.get(peer, 0)
            if cur >= self._MAX_SSE_PER_CLIENT:
                return web.json_response(
                    {"error": "Too many SSE connections"}, status=429,
                )
            self._sse_conn_count[peer] = cur + 1

        await response.prepare(request)

        # Send initial state snapshot
        # FIX-SNAP-TRUNC: Truncate heavy lists in the initial SSE
        # snapshot to avoid sending 50K findings on every connect.
        _sse_snap = self._state.to_dict()
        # FIX-SNAP-CAP: Raised caps from 500→5000 to prevent
        # finding loss on browser refresh.  The old 500 cap caused
        # scans with 1000+ findings to show only the tail end.
        _sse_snap["findings"] = _sse_snap.get("findings", [])[-5000:]
        _sse_snap["deduplicated_findings"] = _sse_snap.get("deduplicated_findings", [])[-5000:]
        _sse_snap["log_entries"] = _sse_snap.get("log_entries", [])[-2000:]
        for _pf_key in list((_sse_snap.get("phase_findings") or {}).keys()):
            _sse_snap["phase_findings"][_pf_key] = _sse_snap["phase_findings"][_pf_key][-5000:]
        snapshot = json.dumps({"type": "state_snapshot", **_sse_snap})
        await response.write(f"event: state_snapshot\ndata: {snapshot}\n\n".encode())

        # Register as SSE client
        async with self._clients_lock:
            self._sse_clients.add(response)
        logger.info("SSE client connected (total: %d)", len(self._sse_clients))

        try:
            # Keep-alive heartbeat loop â€” also detects disconnects
            while True:
                await asyncio.sleep(15)
                try:
                    await response.write(b": heartbeat\n\n")
                except (ConnectionResetError, ConnectionAbortedError, Exception):
                    break
        except asyncio.CancelledError:
            logger.debug("SSE client connection cancelled")
        finally:
            async with self._clients_lock:
                self._sse_clients.discard(response)
                # FIX-SSE-CONN-LOCK: Decrement under lock (paired with increment)
                self._sse_conn_count[peer] = max(0, self._sse_conn_count.get(peer, 1) - 1)
            logger.info("SSE client disconnected (remaining: %d)", len(self._sse_clients))

        return response

    # â”€â”€ WebSocket handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def _handle_websocket(self, websocket: Any) -> None:
        """Handle a WebSocket connection (browser or Copilot extension).

        Supports bidirectional commands from connected clients:
          - get_status  â†’ reply with state_snapshot
          - copilot_run_phase â†’ trigger a specific phase
          - copilot_pause    â†’ pause standalone recon
          - copilot_resume   â†’ resume standalone recon
          - copilot_stop     â†’ stop standalone recon
          - copilot_skip_phase â†’ skip a specific phase
          - subscribe        â†’ set event filter for this client

        A server-side keepalive ping is sent every 30s to detect stale
        connections and prevent intermediary proxies from timing out.

        Security: The client MUST send an ``auth`` message with the
        correct bearer token within 5 seconds of connecting.  Until
        authenticated the client receives nothing and commands are
        rejected.  Origin header is also validated to mitigate CSWSH.
        """
        # â”€â”€ Origin validation (CSWSH mitigation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        origin = None
        try:
            # websockets >= 13: request object with .headers mapping
            origin = websocket.request.headers.get("Origin", "")
        except (AttributeError, TypeError):
            try:
                # websockets 11-12: request_headers mapping
                origin = websocket.request_headers.get("Origin", "")
            except AttributeError:
                # websockets < 11: .origin property
                origin = getattr(websocket, "origin", "") or ""

        allowed_origins = {
            f"http://localhost:{self.http_port}",
            f"https://localhost:{self.http_port}",
            f"http://127.0.0.1:{self.http_port}",
            f"https://127.0.0.1:{self.http_port}",
            # FIX-WS2: browsers resolving localhost to ::1 (IPv6) send
            # Origin: http://[::1]:PORT â€” must be in the allowlist.
            f"http://[::1]:{self.http_port}",
            f"https://[::1]:{self.http_port}",
            "",  # empty = non-browser client (curl, Python, etc.)
        }
        if origin and origin not in allowed_origins:
            logger.warning("WebSocket rejected â€” bad Origin: %s", (origin or "").replace("\n", "").replace("\r", ""))
            await websocket.close(4003, "Origin not allowed")
            return

        # â”€â”€ Token-based authentication handshake â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Client must send: {"type": "auth", "token": "<bearer>"}
        # within _WS_AUTH_TIMEOUT seconds.
        _WS_AUTH_TIMEOUT = 5.0
        try:
            raw = await asyncio.wait_for(
                websocket.recv(), timeout=_WS_AUTH_TIMEOUT
            )
            auth_msg = json.loads(raw)
            if (
                auth_msg.get("type") != "auth"
                or not isinstance(auth_msg.get("token"), str)
                or not (
                    _secrets.compare_digest(auth_msg["token"], self._auth_token)
                    or (self._prev_auth_token and _secrets.compare_digest(auth_msg["token"], self._prev_auth_token))
                )
            ):
                await websocket.send(json.dumps(
                    {"type": "auth_error", "reason": "Invalid token"}
                ))
                await websocket.close(4001, "Authentication failed")
                return
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as exc:
            logger.debug("WebSocket auth handshake failed: %s", exc)
            try:
                await websocket.close(4002, "Auth timeout")
            except Exception as exc:
                logger.debug("%s suppressed: %s", "block", exc, exc_info=True)
            return

        # â”€â”€ Authenticated â€” add to broadcast set â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Per-client WS connection limit
        ws_peer = 'unknown'
        try:
            ws_peer = websocket.remote_address[0] if websocket.remote_address else ws_peer
        except (AttributeError, IndexError, TypeError):
            pass
        ws_cur = self._ws_conn_count.get(ws_peer, 0)
        if ws_cur >= self._MAX_WS_PER_CLIENT:
            await websocket.close(4029, 'Too many connections')
            return
        self._ws_conn_count[ws_peer] = ws_cur + 1

        async with self._clients_lock:
            self._ws_clients.add(websocket)
        client_filter: set[str] | None = None  # None = receive all events
        try:
            # Send initial state snapshot â€” include _seq so the client
            # can sync its sequence counter and accept subsequent events
            # (critical after server restarts where _seq resets to 0).
            self._event_seq += 1
            await websocket.send(json.dumps({
                "type": "auth_ok",
            }))
            # FIX-WS1: Guard snapshot serialisation â€” if to_dict()
            # or json.dumps() fails (e.g. non-serialisable bytes in
            # findings) we log the error and send a minimal snapshot
            # so the client still gets auth_ok + a usable connection.
            # FIX-STOP-6: Inject standalone_running / standalone_paused
            # so the frontend can restore Stop/Pause UI on page refresh.
            _runner_running = bool(
                self._standalone_runner and self._standalone_runner.is_running
            )
            _runner_paused = bool(
                self._standalone_runner and self._standalone_runner.is_paused
            )
            try:
                # FIX-SNAP-TRUNC: Truncate heavy lists in the initial
                # WS snapshot so connect is fast even with 50K+ findings.
                _ws_snap = self._state.to_dict()
                _ws_snap["findings"] = _ws_snap.get("findings", [])[-500:]
                _ws_snap["deduplicated_findings"] = _ws_snap.get("deduplicated_findings", [])[-500:]
                _ws_snap["log_entries"] = _ws_snap.get("log_entries", [])[-1000:]
                for _pf_key in list((_ws_snap.get("phase_findings") or {}).keys()):
                    _ws_snap["phase_findings"][_pf_key] = _ws_snap["phase_findings"][_pf_key][-500:]
                # FIX-STALE-4: Include recent console lines in the
                # initial snapshot so the console isn't blank on
                # page refresh / WS reconnect.  Console lines live
                # in the runner, not DashboardState, and are only
                # pushed via coalescable console_batch events — which
                # are lost on disconnect.  Cap at 200 lines.
                _snap_console = []
                _snap_console_total = 0
                if self._standalone_runner:
                    _get_total = getattr(self._standalone_runner, "get_console_total", None)
                    if callable(_get_total):
                        _snap_console_total = int(_get_total())
                    else:
                        _snap_console_total = len(getattr(self._standalone_runner, "_console_lines", []))
                    _snap_console = self._standalone_runner.get_console_lines(
                        max(0, _snap_console_total - 200)
                    )
                _snap_payload = json.dumps({
                    "type": "state_snapshot",
                    "_seq": self._event_seq,
                    "standalone_running": _runner_running,
                    "standalone_paused": _runner_paused,
                    "console_lines": _snap_console,
                    "console_total": _snap_console_total,
                    **_ws_snap,
                })
            except (TypeError, ValueError, OverflowError) as _ser_exc:
                logger.error(
                    "state_snapshot serialisation failed: %s â€” "
                    "sending minimal snapshot", _ser_exc,
                )
                _snap_payload = json.dumps({
                    "type": "state_snapshot",
                    "_seq": self._event_seq,
                    "target_url": self._state.target_url or "",
                    "phases": [],
                    "findings": [],
                    "log_entries": [],
                    "_serialisation_error": str(_ser_exc),
                })
            await websocket.send(_snap_payload)

            # Bidirectional command loop
            async for message in websocket:
                self._maybe_rotate_token()  # CC-S1: rotate token if interval elapsed
                try:
                    msg = json.loads(message)
                    msg_type = msg.get("type", "")

                    if msg_type == "get_status":
                        since_seq = msg.get("since_seq", 0)
                        if since_seq and isinstance(since_seq, int) and since_seq > 0:
                            diff = self._state.to_dict_diff(since_seq)
                            diff["type"] = "state_diff"
                            await websocket.send(json.dumps(diff))
                        else:
                            await websocket.send(json.dumps({
                                "type": "state_snapshot",
                                **self._state.to_dict(),
                            }))

                    elif msg_type == "subscribe":
                        # Allow client to filter which event types it receives
                        events = msg.get("events")
                        if isinstance(events, list):
                            client_filter = set(events)
                            await websocket.send(json.dumps({
                                "type": "subscribe_ack",
                                "events": list(client_filter),
                            }))

                    elif msg_type == "copilot_run_phase":
                        phase = msg.get("phase", "")
                        target = msg.get("target") or self._state.target_url
                        await websocket.send(json.dumps({
                            "type": "copilot_ack",
                            "command": "run_phase",
                            "phase": phase,
                            "status": "queued",
                        }))
                        logger.info("Copilot requested phase: %s for %s", str(phase).replace("\n", "").replace("\r", ""), str(target).replace("\n", "").replace("\r", ""))

                    elif msg_type == "copilot_pause":
                        if hasattr(self, '_standalone_runner') and self._standalone_runner:
                            self._standalone_runner.pause()
                        await websocket.send(json.dumps({
                            "type": "copilot_ack", "command": "pause", "status": "ok",
                        }))

                    elif msg_type == "copilot_resume":
                        if hasattr(self, '_standalone_runner') and self._standalone_runner:
                            self._standalone_runner.resume()
                        await websocket.send(json.dumps({
                            "type": "copilot_ack", "command": "resume", "status": "ok",
                        }))

                    elif msg_type == "copilot_stop":
                        if hasattr(self, '_standalone_runner') and self._standalone_runner:
                            self._standalone_runner.abort()
                        await websocket.send(json.dumps({
                            "type": "copilot_ack", "command": "stop", "status": "ok",
                        }))

                    elif msg_type == "copilot_skip_phase":
                        phase = msg.get("phase", "")
                        status = "error"
                        if hasattr(self, '_standalone_runner') and self._standalone_runner:
                            self._standalone_runner.skip_phase(phase)
                            status = "ok"
                        await websocket.send(json.dumps({
                            "type": "copilot_ack",
                            "command": "skip_phase",
                            "phase": phase,
                            "status": status,
                        }))

                    elif msg_type == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))

                    # ── LLM Integration WebSocket commands ──────────
                    elif msg_type == "llm_chat":
                        text = msg.get("message", "")
                        if not isinstance(text, str) or not text.strip():
                            await websocket.send(json.dumps({
                                "type": "llm_chat_error",
                                "error": "message is required",
                            }))
                        else:
                            bridge = self._ensure_llm_bridge()
                            if bridge is None:
                                await websocket.send(json.dumps({
                                    "type": "llm_chat_error",
                                    "error": "LLM bridge not available",
                                }))
                            elif not self._check_llm_rate_limit():
                                await websocket.send(json.dumps({
                                    "type": "llm_chat_error",
                                    "error": "Rate limit exceeded — please wait before sending another message",
                                }))
                            else:
                                _prompt = text.strip()[:10000]
                                # T3.2: Persist user message + add to state
                                self._state.apply_event({
                                    "type": "llm_chat_message",
                                    "role": "user",
                                    "content": _prompt[:500],
                                })
                                self._persist_chat_message("user", _prompt[:500])
                                # Server-side intent detection on user message
                                _user_intent = self._detect_user_intent(_prompt)

                                async def _do_llm_chat(_b=bridge, _p=_prompt, _intent=_user_intent):
                                    # C-3: Acquire mutex — only one chat generation at a time
                                    # per WebSocket client to prevent interleaved chunks.
                                    async with self._llm_chat_lock:
                                      try:
                                        # C-3: Assign a monotonic message ID for correlation
                                        self._llm_chat_msg_seq += 1
                                        _mid = self._llm_chat_msg_seq

                                        # Stage 1: Analyzing
                                        await websocket.send(json.dumps({
                                            "type": "llm_chat_thinking",
                                            "stage": "analyzing",
                                            "message": "Analyzing your message\u2026",
                                            "msg_id": _mid,
                                        }))

                                        # Auto-trigger scan BEFORE LLM response if user asked
                                        scan_started = False
                                        _not_running = not self._build_agent_chat_context().get("runner_running")

                                        # T2.4: Explicit scan keywords always trigger
                                        _targeted_phases: list[str] = []
                                        if _intent in ("start_scan", "info_scan") and _not_running:
                                            # Map info questions to specific phases
                                            if _intent == "info_scan":
                                                _targeted_phases = self._map_info_to_phases(_p)
                                            _phase_args = ",".join(_targeted_phases) if _targeted_phases else ""
                                            _thinking_msg = (
                                                f'Running targeted phases: {", ".join(_targeted_phases)}\u2026'
                                                if _targeted_phases
                                                else "Starting reconnaissance scan\u2026"
                                            )
                                            await websocket.send(json.dumps({
                                                "type": "llm_chat_thinking",
                                                "stage": "action",
                                                "message": _thinking_msg,
                                                "msg_id": _mid,
                                            }))
                                            try:
                                                await self._execute_chat_action({"action": "START_SCAN", "args": _phase_args}, websocket)
                                                scan_started = True
                                                self._pending_scan_confirm = False
                                            except Exception as scan_exc:
                                                logger.warning("Auto-scan trigger failed: %s", scan_exc)

                                        # T2.4: Ambiguous confirm triggers scan only if
                                        # a prior confirmation was pending
                                        elif _intent == "confirm_scan" and _not_running:
                                            if self._pending_scan_confirm:
                                                await websocket.send(json.dumps({
                                                    "type": "llm_chat_thinking",
                                                    "stage": "action",
                                                    "message": "Starting reconnaissance scan\u2026",
                                                    "msg_id": _mid,
                                                }))
                                                try:
                                                    await self._execute_chat_action({"action": "START_SCAN", "args": ""}, websocket)
                                                    scan_started = True
                                                except Exception as scan_exc:
                                                    logger.warning("Auto-scan trigger failed: %s", scan_exc)
                                                self._pending_scan_confirm = False
                                            # else: treat as normal chat — LLM will respond

                                        elif _intent == "stop_scan":
                                            await self._execute_chat_action({"action": "STOP_SCAN", "args": ""}, websocket)
                                        elif _intent == "pause_scan":
                                            await self._execute_chat_action({"action": "PAUSE_SCAN", "args": ""}, websocket)

                                        # Stage 2: Building context
                                        await websocket.send(json.dumps({
                                            "type": "llm_chat_thinking",
                                            "stage": "context",
                                            "message": "Gathering scan context & findings\u2026",
                                            "msg_id": _mid,
                                        }))
                                        _sc = self._build_agent_chat_context(query=_p)

                                        # Fast-path: scan just auto-triggered with no data yet
                                        # Skip LLM (it has nothing useful to say) and send a
                                        # context-aware canned acknowledgment instead.
                                        if scan_started and _sc.get('findings_count', 0) == 0:
                                            _is_targeted = bool(_targeted_phases)
                                            _target = _sc.get('target', 'the target')
                                            _pl = _p.lower()
                                            # Detect what the user is specifically asking about
                                            _is_tech = any(k in _pl for k in ("technolog", "framework", "tech stack", "cms", "server", "language", "running on"))
                                            _is_cve = any(k in _pl for k in ("cve", "vulnerabilit", "exploit"))
                                            _is_subdomain = any(k in _pl for k in ("subdomain", "dns", "mx record"))
                                            _is_endpoint = any(k in _pl for k in ("endpoint", "url", "path", "route"))
                                            _is_port = any(k in _pl for k in ("port", "service"))
                                            _is_tls = any(k in _pl for k in ("ssl", "tls", "cert", "https"))
                                            _is_header = any(k in _pl for k in ("header", "security header", "csp", "hsts"))
                                            # Build targeted response
                                            _parts = []
                                            if _is_tech or _is_cve:
                                                _parts.append(
                                                    "\U0001f50d **Scanning now!** I\'ve kicked off a reconnaissance scan of "
                                                    f"{_target} to identify "
                                                )
                                                _topics = []
                                                if _is_tech: _topics.append("technologies and frameworks")
                                                if _is_cve: _topics.append("known CVEs")
                                                _parts.append(" and ".join(_topics) + ".\n\n")
                                                _parts.append("Here\'s what\'s running right now:\n")
                                                _parts.append("- **Technology fingerprinting** (Wappalyzer, WhatWeb, headers analysis)\n")
                                                _parts.append("- **CMS detection** (WordPress, Drupal, Shopify, custom frameworks)\n")
                                                _parts.append("- **JS framework analysis** (React, Vue, Angular, jQuery detection)\n")
                                                if _is_cve:
                                                    _parts.append("- **CVE correlation** (matching detected versions against NVD/exploit-db)\n")
                                                _parts.append("\nI\'ll report back with specific findings as they come in. This usually takes 1-3 minutes for initial tech results.")
                                            elif _is_subdomain:
                                                _parts.append(
                                                    "\U0001f50d **Scanning now!** I\'ve started subdomain enumeration for "
                                                    f"{_target}.\n\n"
                                                    "Running DNS brute-force, certificate transparency logs, and passive sources. "
                                                    "I\'ll report discovered subdomains as they come in."
                                                )
                                            elif _is_port:
                                                _parts.append(
                                                    "\U0001f50d **Scanning now!** I\'ve started a scan of "
                                                    f"{_target} to discover open ports and services.\n\n"
                                                    "I\'ll report back with what\'s listening."
                                                )
                                            elif _is_targeted:
                                                # Targeted scan - list specific phases
                                                _phase_list = '\n'.join(f'- **{p}**' for p in _targeted_phases)
                                                _parts.append(
                                                    f"\U0001f50d **Running targeted scan** of {_target} with these specific phases:\n\n"
                                                    f"{_phase_list}\n\n"
                                                    "Results will appear as each phase completes. I\'ll analyze the findings and report back."
                                                )
                                            else:
                                                # Generic fallback - full scan
                                                _parts.append(
                                                    "\U0001f680 **Scan initiated!** I\'ve started a comprehensive security assessment of "
                                                    f"{_target}.\n\n"
                                                    "Results will stream in real-time as each phase completes:\n"
                                                    "- **Phase 1-5:** Technology fingerprinting, DNS enumeration, subdomain discovery\n"
                                                    "- **Phase 6-15:** Endpoint crawling, parameter discovery, JS analysis\n"
                                                    "- **Phase 16-30:** Vulnerability scanning, security header checks, TLS analysis\n"
                                                    "- **Phase 31-36:** Active testing, exploitation validation, report generation\n\n"
                                                    "I\'ll analyze findings as they arrive. Ask me anything while the scan runs!"
                                                )
                                            _canned = "".join(_parts)
                                            self._state.apply_event({
                                                "type": "llm_chat_message",
                                                "role": "assistant",
                                                "content": _canned[:500],
                                            })
                                            self._persist_chat_message('assistant', _canned[:2000])
                                            await websocket.send(json.dumps({
                                                "type": "llm_chat_chunk",
                                                "text": _canned,
                                                "msg_id": _mid,
                                            }))
                                            await websocket.send(json.dumps({
                                                "type": "llm_chat_done",
                                                "content": _canned,
                                                "msg_id": _mid,
                                            }))
                                            # Launch background watcher for live updates + auto-complete
                                            if _targeted_phases:
                                                self._info_watcher_task = asyncio.ensure_future(
                                                    self._info_scan_watcher(
                                                        websocket=websocket,
                                                        bridge=_b,
                                                        original_question=_p,
                                                        targeted_phases=_targeted_phases,
                                                    )
                                                )
                                            return

                                        # Stage 3: Generating (streaming)
                                        await websocket.send(json.dumps({
                                            "type": "llm_chat_thinking",
                                            "stage": "generating",
                                            "message": "Generating response\u2026",
                                            "msg_id": _mid,
                                        }))

                                        # CC-O1: Per-message telemetry
                                        _msg_start_time = time.monotonic()
                                        _chunk_count = 0
                                        _first_chunk_time = None
                                        # T1.2: Stream chunks to frontend
                                        collected_content = ""
                                        _hw = getattr(getattr(_b, 'config', None), 'chat_history_window', 6)
                                        async for chunk in _b.agent_chat_stream(
                                            message=_p,
                                            scan_context=_sc,
                                            chat_history=self._state.llm_chat_history[-_hw:],
                                        ):
                                            text_piece = chunk.get("text", "")
                                            is_done = chunk.get("done", False)
                                            if text_piece:
                                                collected_content += text_piece
                                                _chunk_count += 1
                                                if _first_chunk_time is None:
                                                    _first_chunk_time = time.monotonic()
                                                await websocket.send(json.dumps({
                                                    "type": "llm_chat_chunk",
                                                    "text": text_piece,
                                                    "msg_id": _mid,
                                                }))
                                            if is_done:
                                                break

                                        # Strip any residual action markers
                                        import re as _re
                                        content = _re.sub(r'\[ACTION:[^\]]+\]', '', collected_content).strip()
                                        if scan_started and "scan" not in content.lower()[:200]:
                                            content = "\U0001f680 **Scan initiated** \u2014 I've started the reconnaissance scan. Results will appear in real-time on the dashboard.\n\n" + content

                                        # T2.4: If the LLM offers to scan (and scan isn't running),
                                        # set a pending confirmation so "yes"/"do it" on the next
                                        # message will trigger it.
                                        if not scan_started and _not_running:
                                            _lower_content = content.lower()[:500]
                                            if any(kw in _lower_content for kw in ("start a scan", "start the scan", "begin scanning", "run a scan", "shall i scan")):
                                                self._pending_scan_confirm = True

                                        self._state.apply_event({
                                            "type": "llm_chat_message",
                                            "role": "assistant",
                                            "content": content[:500],
                                        })
                                        # T3.2: Persist assistant response
                                        self._persist_chat_message("assistant", content[:2000])
                                        # CC-O1: Compute telemetry metrics
                                        _msg_elapsed = time.monotonic() - _msg_start_time
                                        _ttft = (_first_chunk_time - _msg_start_time) if _first_chunk_time else _msg_elapsed
                                        _prompt_chars = len(_p)
                                        _response_chars = len(content)
                                        _chunks_per_sec = _chunk_count / _msg_elapsed if _msg_elapsed > 0 else 0
                                        logger.info(
                                            "CC-O1: msg_id=%d latency=%.1fs ttft=%.2fs chunks=%d rate=%.1f/s prompt_chars=%d response_chars=%d",
                                            _mid, _msg_elapsed, _ttft, _chunk_count, _chunks_per_sec, _prompt_chars, _response_chars,
                                        )
                                        await websocket.send(json.dumps({
                                            "type": "llm_chat_done",
                                            "content": content,
                                            "msg_id": _mid,
                                            "telemetry": {
                                                "latency_ms": round(_msg_elapsed * 1000),
                                                "ttft_ms": round(_ttft * 1000),
                                                "chunk_count": _chunk_count,
                                                "chunks_per_sec": round(_chunks_per_sec, 1),
                                                "prompt_chars": _prompt_chars,
                                                "response_chars": _response_chars,
                                            },
                                        }))
                                      except asyncio.CancelledError:
                                        # H-6: User requested cancellation — send partial content if any
                                        logger.info("H-6: llm_chat task cancelled, collected %d chars", len(collected_content))
                                        if collected_content:
                                            self._state.apply_event({
                                                "type": "llm_chat_message",
                                                "role": "assistant",
                                                "content": (collected_content[:500] + " [cancelled]"),
                                            })
                                            self._persist_chat_message("assistant", collected_content[:2000] + "\n\n*— Generation cancelled*")
                                        await websocket.send(json.dumps({
                                            "type": "llm_chat_done",
                                            "content": collected_content + "\n\n*— Generation cancelled*" if collected_content else "",
                                            "msg_id": _mid,
                                            "cancelled": True,
                                        }))
                                      except Exception as exc:
                                        logger.warning("WS llm_chat error: %s", exc)
                                        await websocket.send(json.dumps({
                                            "type": "llm_chat_error",
                                            "error": str(exc)[:500],
                                            "msg_id": getattr(self, '_llm_chat_msg_seq', 0),
                                        }))

                                # H-6: Store task reference for cancel support
                                self._llm_chat_task = asyncio.create_task(_do_llm_chat())

                    # ── H-6: Cancel in-progress LLM generation ─────
                    elif msg_type == "llm_chat_cancel":
                        task = self._llm_chat_task
                        if task and not task.done():
                            task.cancel()
                            logger.info("H-6: LLM chat generation cancelled by user")
                        self._llm_chat_task = None
                        # Also cancel info scan watcher if running
                        _wt = getattr(self, "_info_watcher_task", None)
                        if _wt and not _wt.done():
                            _wt.cancel()
                            logger.info("Info scan watcher cancelled by user")
                        self._info_watcher_task = None
                        await websocket.send(json.dumps({
                            "type": "llm_chat_cancelled",
                            "msg_id": self._llm_chat_msg_seq,
                        }))

                    # ── T3.5: Multi-turn planning agent ─────────────
                    elif msg_type == "llm_plan":
                        goal = msg.get("goal", "")
                        if not isinstance(goal, str) or not goal.strip():
                            await websocket.send(json.dumps({
                                "type": "llm_plan_error",
                                "error": "goal is required",
                            }))
                        else:
                            bridge = self._ensure_llm_bridge()
                            if bridge is None:
                                await websocket.send(json.dumps({
                                    "type": "llm_plan_error",
                                    "error": "LLM bridge not available",
                                }))
                            else:
                                _goal = goal.strip()[:2000]

                                async def _do_llm_plan(_b=bridge, _g=_goal):
                                    try:
                                        await websocket.send(json.dumps({
                                            "type": "llm_plan_status",
                                            "status": "planning",
                                            "message": "Generating reconnaissance plan\u2026",
                                        }))
                                        _sc = self._build_agent_chat_context(query=_g)
                                        result = await _b.plan_and_execute(
                                            goal=_g,
                                            scan_context=_sc,
                                        )
                                        await websocket.send(json.dumps({
                                            "type": "llm_plan_result",
                                            "plan": result.get("plan", []),
                                            "conclusion": result.get("conclusion", ""),
                                            "recommended_phases": result.get("recommended_phases", []),
                                            "goal": _g,
                                        }))
                                    except Exception as exc:
                                        logger.warning("WS llm_plan error: %s", exc)
                                        await websocket.send(json.dumps({
                                            "type": "llm_plan_error",
                                            "error": str(exc)[:500],
                                        }))

                                asyncio.create_task(_do_llm_plan())

                    elif msg_type == "llm_dedup":
                        bridge = self._ensure_llm_bridge()
                        if bridge is None:
                            await websocket.send(json.dumps({
                                "type": "llm_dedup_error",
                                "error": "LLM bridge not available",
                            }))
                        else:
                            async def _do_llm_dedup(_b=bridge):
                                try:
                                    await websocket.send(json.dumps({
                                        "type": "llm_dedup_status",
                                        "status": "running",
                                        "message": "Deduplicating findings\u2026",
                                    }))
                                    from ..agents.finding_dedup import FindingDedup
                                    dedup = FindingDedup(bridge=_b)
                                    findings = list(self._state.findings)
                                    result = await dedup.deduplicate(findings)
                                    self._state.deduplicated_findings = result.merged
                                    await websocket.send(json.dumps({
                                        "type": "llm_dedup_result",
                                        "original_count": len(findings),
                                        "merged_count": len(result.merged),
                                        "discarded_count": len(result.discarded),
                                        "borderline_count": len(result.borderline),
                                        "llm_calls": result.llm_calls,
                                    }))
                                except Exception as exc:
                                    logger.warning("WS llm_dedup error: %s", exc)
                                    await websocket.send(json.dumps({
                                        "type": "llm_dedup_error",
                                        "error": str(exc)[:500],
                                    }))

                            asyncio.create_task(_do_llm_dedup())

                    # ── Cognitive Bridge WebSocket commands ──────────
                    elif msg_type == "cognitive_reason":
                        prompt = msg.get("prompt", "")
                        if not prompt:
                            await websocket.send(json.dumps({
                                "type": "cognitive_error", "error": "prompt is required",
                            }))
                        else:
                            try:
                                bridge = self._get_cognitive_bridge()
                                result = await bridge.reason(
                                    prompt=prompt,
                                    context=msg.get("context"),
                                    include_memory=msg.get("include_memory", True),
                                    depth=msg.get("depth"),
                                )
                                await websocket.send(json.dumps({
                                    "type": "cognitive_reason_response", **result,
                                }, default=str))
                            except Exception as exc:
                                logger.warning("WS cognitive_reason error: %s", exc)
                                await websocket.send(json.dumps({
                                    "type": "cognitive_error", "error": str(exc)[:500],
                                }))

                    elif msg_type == "cognitive_query_memory":
                        query = msg.get("query", "")
                        if not query:
                            await websocket.send(json.dumps({
                                "type": "cognitive_error", "error": "query is required",
                            }))
                        else:
                            try:
                                bridge = self._get_cognitive_bridge()
                                result = await bridge.query_memory(
                                    query=query, limit=msg.get("limit", 10),
                                )
                                await websocket.send(json.dumps({
                                    "type": "cognitive_memory_response", **result,
                                }, default=str))
                            except Exception as exc:
                                logger.warning("WS cognitive_query_memory error: %s", exc)
                                await websocket.send(json.dumps({
                                    "type": "cognitive_error", "error": str(exc)[:500],
                                }))

                    elif msg_type == "cognitive_strategic":
                        question = msg.get("question", "")
                        if not question:
                            await websocket.send(json.dumps({
                                "type": "cognitive_error", "error": "question is required",
                            }))
                        else:
                            try:
                                bridge = self._get_cognitive_bridge()
                                result = await bridge.strategic_guidance(
                                    question=question,
                                    session_state=msg.get("session_state"),
                                )
                                await websocket.send(json.dumps({
                                    "type": "cognitive_strategic_response", **result,
                                }, default=str))
                            except Exception as exc:
                                logger.warning("WS cognitive_strategic error: %s", exc)
                                await websocket.send(json.dumps({
                                    "type": "cognitive_error", "error": str(exc)[:500],
                                }))

                    elif msg_type == "cognitive_status":
                        try:
                            bridge = self._get_cognitive_bridge()
                            await websocket.send(json.dumps({
                                "type": "cognitive_status_response",
                                **bridge.get_status(),
                            }, default=str))
                        except Exception as exc:
                            await websocket.send(json.dumps({
                                "type": "cognitive_error", "error": str(exc)[:500],
                            }))

                    elif msg_type == "cognitive_set_mode":
                        mode = msg.get("mode", "")
                        if not mode:
                            await websocket.send(json.dumps({
                                "type": "cognitive_error", "error": "mode is required",
                            }))
                        else:
                            bridge = self._get_cognitive_bridge()
                            result = bridge.set_mode(mode)
                            await websocket.send(json.dumps({
                                "type": "cognitive_mode_response", **result,
                            }, default=str))

                    elif msg_type == "llm_explain_finding":
                        finding = msg.get("finding")
                        if not isinstance(finding, dict):
                            await websocket.send(json.dumps({
                                "type": "llm_explain_error",
                                "error": "finding object is required",
                            }))
                        else:
                            bridge = self._ensure_llm_bridge()
                            if bridge is None:
                                await websocket.send(json.dumps({
                                    "type": "llm_explain_error",
                                    "error": "LLM bridge not available",
                                }))
                            else:
                                from ..llm_bridge import Finding as _Finding
                                _finding_obj = _Finding(
                                    id=finding.get("id", "unknown"),
                                    type=finding.get("type", "unknown"),
                                    title=finding.get("title", ""),
                                    severity=finding.get("severity", "medium"),
                                    endpoint=finding.get("url", ""),
                                    method=finding.get("method", "GET"),
                                    description=str(finding.get("detail", ""))[:3000],
                                    evidence=finding.get("evidence", []),
                                )

                                async def _do_llm_explain(_b=bridge, _f=_finding_obj):
                                    try:
                                        resp = await _b.explain_finding(_f)
                                        if hasattr(resp, "summary"):
                                            content = resp.summary
                                        elif hasattr(resp, "content"):
                                            content = resp.content
                                        else:
                                            content = str(resp)
                                        self._update_llm_state_from_response(resp)
                                        await websocket.send(json.dumps({
                                            "type": "llm_explain_response",
                                            "content": content,
                                        }))
                                    except Exception as exc:
                                        logger.warning("WS llm_explain error: %s", exc)
                                        await websocket.send(json.dumps({
                                            "type": "llm_explain_error",
                                            "error": str(exc)[:500],
                                        }))

                                asyncio.create_task(_do_llm_explain())
                    elif msg_type == "agent_start":
                        max_cycles = msg.get("max_cycles", 10)
                        if not isinstance(max_cycles, int) or max_cycles < 1:
                            max_cycles = 10
                        max_cycles = min(max_cycles, 100)
                        try:
                            bridge = self._ensure_llm_bridge()
                            if bridge is None:
                                await websocket.send(json.dumps({
                                    "type": "agent_error",
                                    "error": "LLM bridge not available — cannot start agent loop",
                                }))
                            elif self._agent_loop_task and not self._agent_loop_task.done():
                                await websocket.send(json.dumps({
                                    "type": "agent_error",
                                    "error": "Agent loop already running",
                                }))
                            else:
                                from ..agent_loop import AutonomousAgent
                                reasoning = self._ensure_reasoning_engine()
                                memory = self._ensure_agent_memory()
                                self._agent_loop = AutonomousAgent()
                                if reasoning:
                                    self._agent_loop._reasoning_engine = reasoning
                                if memory:
                                    self._agent_loop._memory = memory
                                _target = self._state.target_url or ""
                                _mc = max_cycles
                                self._agent_loop_task = asyncio.ensure_future(
                                    asyncio.get_event_loop().run_in_executor(
                                        None,
                                        lambda t=_target, mc=_mc: self._agent_loop.run(
                                            target_url=t, goal="find vulnerabilities",
                                        ),
                                    )
                                )
                                await websocket.send(json.dumps({
                                    "type": "agent_ack",
                                    "command": "start",
                                    "max_cycles": max_cycles,
                                    "status": "started",
                                }))
                        except Exception as exc:
                            logger.warning("WS agent_start error: %s", exc)
                            await websocket.send(json.dumps({
                                "type": "agent_error",
                                "error": str(exc)[:500],
                            }))

                    elif msg_type == "agent_stop":
                        if self._agent_loop:
                            self._agent_loop.stop()
                        if self._agent_loop_task and not self._agent_loop_task.done():
                            self._agent_loop_task.cancel()
                        await websocket.send(json.dumps({
                            "type": "agent_ack", "command": "stop", "status": "ok",
                        }))

                    elif msg_type == "agent_pause":
                        if self._agent_loop and hasattr(self._agent_loop, "pause"):
                            self._agent_loop.pause()
                        await websocket.send(json.dumps({
                            "type": "agent_ack", "command": "pause", "status": "ok",
                        }))

                    elif msg_type == "agent_resume":
                        if self._agent_loop and hasattr(self._agent_loop, "resume"):
                            self._agent_loop.resume()
                        await websocket.send(json.dumps({
                            "type": "agent_ack", "command": "resume", "status": "ok",
                        }))

                    elif msg_type == "reasoning_generate":
                        context = msg.get("context", "")
                        if not isinstance(context, str) or not context.strip():
                            await websocket.send(json.dumps({
                                "type": "reasoning_error",
                                "error": "context is required",
                            }))
                        else:
                            try:
                                engine = self._ensure_reasoning_engine()
                                if engine is None:
                                    await websocket.send(json.dumps({
                                        "type": "reasoning_error",
                                        "error": "Reasoning engine not available",
                                    }))
                                else:
                                    _ctx = context.strip()[:5000]
                                    loop = asyncio.get_event_loop()
                                    hypotheses = await loop.run_in_executor(
                                        None,
                                        lambda _e=engine: _e.hypothesize(
                                            target=self._state.target_url or "",
                                            technologies=self._state.technologies[:30],
                                        ),
                                    )
                                    result = hypotheses if isinstance(hypotheses, list) else [str(hypotheses)]
                                    await websocket.send(json.dumps({
                                        "type": "reasoning_hypotheses",
                                        "hypotheses": result,
                                    }))
                            except Exception as exc:
                                logger.warning("WS reasoning_generate error: %s", exc)
                                await websocket.send(json.dumps({
                                    "type": "reasoning_error",
                                    "error": str(exc)[:500],
                                }))

                    elif msg_type == "memory_query":
                        query = msg.get("query", "")
                        if not isinstance(query, str) or not query.strip():
                            await websocket.send(json.dumps({
                                "type": "memory_error",
                                "error": "query is required",
                            }))
                        else:
                            try:
                                mem = self._ensure_agent_memory()
                                if mem is None:
                                    await websocket.send(json.dumps({
                                        "type": "memory_error",
                                        "error": "Agent memory not available",
                                    }))
                                else:
                                    _q = query.strip()[:1000]
                                    _limit = min(int(msg.get("limit", 20)), 50)
                                    loop = asyncio.get_event_loop()
                                    results = await loop.run_in_executor(
                                        None,
                                        lambda _m=mem, q=_q, lim=_limit: _m.recall(query=q, limit=lim),
                                    )
                                    await websocket.send(json.dumps({
                                        "type": "memory_results",
                                        "results": [
                                            ep.to_dict() if hasattr(ep, "to_dict")
                                            else str(ep)
                                            for ep in (results or [])
                                        ],
                                    }))
                            except Exception as exc:
                                logger.warning("WS memory_query error: %s", exc)
                                await websocket.send(json.dumps({
                                    "type": "memory_error",
                                    "error": str(exc)[:500],
                                }))

                except json.JSONDecodeError as exc:
                    logger.debug("Invalid JSON from WebSocket client: %s", exc)

        except Exception as exc:
            logger.debug("WebSocket client disconnected: %s", exc)
        finally:
            async with self._clients_lock:
                self._ws_clients.discard(websocket)
            self._ws_conn_count[ws_peer] = max(0, self._ws_conn_count.get(ws_peer, 1) - 1)

    async def _broadcast(self, event: dict[str, Any]) -> None:
        """Push event to all connected WebSocket and SSE clients.

        FIX-FREEZE: Send to all clients CONCURRENTLY via asyncio.gather
        instead of sequentially.  Previously N slow clients × 3s timeout
        = N×3s per broadcast, causing event-loop backlog that blocks the
        runner thread and freezes the dashboard after ~5 minutes.
        """
        self._event_seq += 1
        event['_seq'] = self._event_seq
        msg = json.dumps(event)

        # FIX-P0-CONCMOD: snapshot and clean dead clients under lock
        async with self._clients_lock:
            ws_snapshot = list(self._ws_clients)
            sse_snapshot = list(self._sse_clients)

        # ── WebSocket clients — CONCURRENT sends ──
        if ws_snapshot:
            async def _send_ws(ws: Any) -> Any | None:
                try:
                    await asyncio.wait_for(ws.send(msg), timeout=2.0)
                    return None
                except (asyncio.TimeoutError, Exception):
                    return ws

            results = await asyncio.gather(
                *(_send_ws(ws) for ws in ws_snapshot),
                return_exceptions=True,
            )
            dead_ws = [r for r in results if r is not None and not isinstance(r, BaseException)]
            if dead_ws:
                async with self._clients_lock:
                    for ws in dead_ws:
                        self._ws_clients.discard(ws)

        # ── SSE clients — CONCURRENT writes ──
        if sse_snapshot:
            sse_data = f"data: {msg}\n\n"
            sse_bytes = sse_data.encode("utf-8")

            async def _send_sse(resp: Any) -> Any | None:
                try:
                    await asyncio.wait_for(resp.write(sse_bytes), timeout=2.0)
                    return None
                except (asyncio.TimeoutError, Exception):
                    return resp

            results = await asyncio.gather(
                *(_send_sse(resp) for resp in sse_snapshot),
                return_exceptions=True,
            )
            dead_sse = [r for r in results if r is not None and not isinstance(r, BaseException)]
            if dead_sse:
                async with self._clients_lock:
                    for resp in dead_sse:
                        self._sse_clients.discard(resp)

    # â”€â”€ Event coalescing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _enqueue_coalescable(self, event: dict[str, Any], loop: asyncio.AbstractEventLoop) -> None:
        """Thread-safe: buffer a high-frequency event for batched broadcast.

        Called from the runner thread.  Events are accumulated in
        ``_event_batch`` and flushed as a single ``event_batch`` WS
        message after 250 ms or when the buffer reaches ``_BATCH_MAX``.

        State mutation (``apply_event``) still happens immediately so
        that HTTP API queries always reflect the latest state.
        """
        flush_now = False
        with self._event_batch_lock:
            self._event_batch.append(event)
            if len(self._event_batch) >= self._BATCH_MAX:
                flush_now = True
        if flush_now:
            # Buffer full — flush immediately on the event loop.
            # FIX-FREEZE: call_soon_threadsafe + ensure_future (fire-and-forget)
            # avoids run_coroutine_threadsafe Future pile-up under backpressure.
            try:
                loop.call_soon_threadsafe(
                    lambda: asyncio.ensure_future(self._flush_event_batch()),
                )
            except RuntimeError as _exc:
                logger.debug("Suppressed %s: %s", type(_exc).__name__, _exc)  # FIX-155
        else:
            # Schedule a timer-based flush if not already pending
            try:
                loop.call_soon_threadsafe(self._schedule_batch_flush, loop)
            except RuntimeError as _exc:
                logger.debug("Suppressed %s: %s", type(_exc).__name__, _exc)  # FIX-155

    def _schedule_batch_flush(self, loop: asyncio.AbstractEventLoop) -> None:
        """Schedule a delayed flush on the event loop (must be called ON the loop)."""
        if self._batch_flush_handle is not None:
            return  # timer already pending
        self._batch_flush_handle = loop.call_later(
            self._BATCH_INTERVAL,
            lambda: asyncio.ensure_future(self._flush_event_batch()),
        )

    async def _flush_event_batch(self) -> None:
        """Drain the coalescing buffer and broadcast a single ``event_batch``.

        FIX-FREEZE: Skip if a previous flush is still broadcasting.
        This prevents unbounded queue buildup when broadcast takes longer
        than the batch interval (the core cause of the ~5min freeze).
        """
        self._batch_flush_handle = None

        # FIX-FREEZE: If a previous flush is still in-flight, skip.
        # Buffered events stay in _event_batch for the next flush.
        if self._flush_in_progress:
            return

        self._flush_in_progress = True
        try:
            with self._event_batch_lock:
                if not self._event_batch:
                    return
                batch = self._event_batch
                batch_was_full = len(batch) >= self._BATCH_MAX
                self._event_batch = []

            # Adaptive scaling: track consecutive full flushes
            if not hasattr(self, '_consecutive_full_flushes'):
                self._consecutive_full_flushes = 0
            if batch_was_full:
                self._consecutive_full_flushes += 1
                if self._consecutive_full_flushes >= 3 and self._BATCH_MAX < 250:
                    self._BATCH_MAX = min(250, self._BATCH_MAX + 50)
                    self._BATCH_INTERVAL = min(0.5, self._BATCH_INTERVAL + 0.05)
                    logger.debug(
                        "PERF: Scaling up batch params: max=%d interval=%.2fs",
                        self._BATCH_MAX, self._BATCH_INTERVAL,
                    )
            else:
                if self._consecutive_full_flushes > 0:
                    self._consecutive_full_flushes = 0
                if self._BATCH_MAX > 80:
                    self._BATCH_MAX = max(80, self._BATCH_MAX - 20)
                    self._BATCH_INTERVAL = max(0.25, self._BATCH_INTERVAL - 0.02)

            # Wrap the batch as a single message
            envelope: dict[str, Any] = {
                "type": "event_batch",
                "events": batch,
                "_change_seq": self._state._change_seq,
            }
            await self._broadcast(envelope)
        finally:
            self._flush_in_progress = False

    # â”€â”€ HTTP handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def _serve_dashboard(self, _request: Any) -> Any:
        """Serve the dashboard HTML page with per-request CSP nonce.

        Phase B optimisation: .replace() is applied only to the tiny
        template fragments (~600 bytes) â€” head, config script, and
        script tag â€” not to the ~600 KB static CSS/HTML/JS body.

        Phase C: In production mode (dist/manifest.json present), CSS
        and JS are served as external hashed files â€” the HTML response
        is ~46 KB instead of ~624 KB.  The design-tokens <style> tag
        uses a nonce for defence-in-depth.  Note: style-src still
        requires 'unsafe-inline' due to 19 inline style= attributes
        in the body HTML; removing it is a future remediation item.
        """
        nonce = _secrets.token_urlsafe(16)

        # â”€â”€ Template fragments (small â€” ~600 bytes total) â”€â”€â”€â”€â”€â”€â”€â”€
        head = _DASH_HEAD_TPL.replace("__DESIGN_TOKENS_CSS__", DESIGN_TOKENS_CSS)
        head = head.replace("CSP_NONCE_PLACEHOLDER", nonce)

        cfg = _DASH_CONFIG_TPL.replace("AUTH_TOKEN_PLACEHOLDER", self._auth_token)
        cfg = cfg.replace("SESSION_ID_PLACEHOLDER", self._session_id)
        cfg = cfg.replace("WS_PORT_PLACEHOLDER", str(self.ws_port))
        cfg = cfg.replace("CSP_NONCE_PLACEHOLDER", nonce)

        # Inject license tier info for frontend feature gating
        _lic_tier, _lic_valid, _lic_trial, _lic_days = "community", "false", "false", "0"
        try:
            from ..licensing import get_current_license
            _lic = get_current_license()
            _lic_tier = _lic.tier
            _lic_valid = "true" if _lic.valid else "false"
            _lic_trial = "true" if _lic.trial else "false"
            _lic_days = str(_lic.days_remaining)
        except ImportError:
            pass
        cfg = cfg.replace("LICENSE_TIER_PLACEHOLDER", _lic_tier)
        cfg = cfg.replace("LICENSE_VALID_PLACEHOLDER", _lic_valid)
        cfg = cfg.replace("LICENSE_TRIAL_PLACEHOLDER", _lic_trial)
        cfg = cfg.replace("LICENSE_DAYS_PLACEHOLDER", _lic_days)

        script_tag = _DASH_SCRIPT_TPL.replace("CSP_NONCE_PLACEHOLDER", nonce)

        # â”€â”€ Assemble: head | static CSS+body | config | <script> | static JS | tail
        html = (
            head
            + _DASH_STATIC_MID
            + cfg
            + script_tag
            + _DASH_STATIC_END
        )

        # Note: 'unsafe-inline' is required in both modes because the
        # body HTML contains 19 inline style="..." attributes.  Removing
        # it requires migrating those to CSS classes first.  The <style>
        # tag carrying design tokens uses a nonce for defence-in-depth.
        style_src = "'self' 'unsafe-inline'"
        csp = (
            f"default-src 'self'; "
            f"script-src 'nonce-{nonce}' 'unsafe-hashes'; "
            f"style-src {style_src}; "
            f"connect-src 'self' ws://localhost:* wss://localhost:*; "
            f"img-src 'self' data: blob: https:; "
            f"font-src 'self'"
        )
        return web.Response(text=html, content_type="text/html",
                            headers={"Content-Security-Policy": csp})

    async def _handle_favicon(self, _request: Any) -> Any:
        """Return a minimal 1x1 transparent ICO to silence browser 404s."""
        # 1x1 pixel ICO (62 bytes) â€” avoids repeated 404 log noise
        ico = (
            b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00"
            b"\x30\x00\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00"
            b"\x00\x00\x02\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00"
            b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00"
        )
        return web.Response(
            body=ico,
            content_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=604800"},
        )

    async def _handle_event(self, request: Any) -> Any:
        """Receive an event from a CLI command (POST /api/event)."""
        try:
            if request.content_length and request.content_length > 1_048_576:  # 1MB
                return web.json_response(
                    {"ok": False, "error": "Payload too large"}, status=413
                )
            # â”€â”€ Rate limiting: 100 events/sec per source â”€â”€â”€â”€â”€
            now = time.monotonic()
            peer = request.remote or "unknown"
            rl = self._rate_limits.get(peer)
            if rl is None:
                rl = {"count": 0, "window_start": now}
                self._rate_limits[peer] = rl
            if now - rl["window_start"] > 1.0:
                rl["count"] = 0
                rl["window_start"] = now
            rl["count"] += 1
            if rl["count"] > 100:
                return web.json_response(
                    {"ok": False, "error": "Rate limit exceeded (100/s)"}, status=429
                )

            event = await request.json()
            if not isinstance(event, dict) or "type" not in event:
                return web.json_response(
                    {"ok": False, "error": "Invalid event format"}, status=400
                )
            self._state.apply_event(event)
            # PERF FIX 10: Route coalescable events through the same
            # batching path used by the runner thread.  Previously,
            # HTTP POST events called _broadcast() directly, bypassing
            # the 250ms coalescing buffer and flooding the WebSocket
            # at full event rate.  During external-mode ingestion this
            # caused the client to process every event individually,
            # defeating all client-side batching optimizations.
            event_type = event.get("type", "")
            if event_type in self._COALESCABLE_TYPES:
                loop = asyncio.get_running_loop()
                # _enqueue_coalescable is thread-safe and schedules
                # the batch flush on the event loop via call_soon_threadsafe.
                # Since we're already on the event loop here, use the
                # lock-and-schedule path directly.
                flush_now = False
                with self._event_batch_lock:
                    self._event_batch.append(event)
                    if len(self._event_batch) >= self._BATCH_MAX:
                        flush_now = True
                if flush_now:
                    asyncio.ensure_future(self._flush_event_batch())
                else:
                    self._schedule_batch_flush(loop)
            else:
                # Non-coalescable events (phase_start, phase_complete,
                # complete, init, etc.) are broadcast immediately as
                # they are low-frequency and the client needs them ASAP.
                asyncio.ensure_future(self._broadcast(event))
            return web.json_response({"ok": True})
        except Exception as exc:
            logger.warning("Dashboard event error: %s", exc)
            return web.json_response(
                {"ok": False, "error": "Invalid event data"}, status=400
            )

    async def _handle_status(self, request: Any) -> Any:
        """Return current state snapshot (GET /api/status).

        Supports differential updates via ``?since=<seq>`` query param.
        When ``since`` is provided and valid, only changed field groups
        since that sequence number are returned (P2 perf optimisation).
        """
        # ── Rate limiting: 10 req/sec per client ──
        now = time.monotonic()
        peer = request.remote or "unknown"
        srl = self._status_rate_limits.get(peer)
        if srl is None:
            srl = {"count": 0, "window_start": now}
            self._status_rate_limits[peer] = srl
        if now - srl["window_start"] > 1.0:
            srl["count"] = 0
            srl["window_start"] = now
        srl["count"] += 1
        if srl["count"] > 10:
            return web.json_response(
                {"ok": False, "error": "Rate limit exceeded (10/s)"}, status=429
            )

        since_raw = request.query.get("since", "")
        since_seq = 0
        if since_raw:
            try:
                since_seq = int(since_raw)
            except (ValueError, TypeError) as _exc:
                logger.debug("Suppressed %s in _handle_status: %s", type(_exc).__name__, _exc, exc_info=True)
        if since_seq > 0:
            data = self._state.to_dict_diff(since_seq)
        else:
            data = self._state.to_dict()
        data['_seq'] = self._event_seq
        return web.json_response(data)

    async def _handle_target_profile(self, _request: Any) -> Any:
        """Return the progressive target profile (GET /api/target-profile)."""
        return web.json_response(self._state.target_profile.to_dict())

    async def _handle_health(self, _request: Any) -> Any:
        """Health check endpoint."""
        return web.json_response({"status": "ok", "uptime": round(time.time() - self._start_time, 1)})

    async def _handle_infra_status(self, _request: Any) -> Any:
        """Check Burp Suite, Docker, system/network health, and API keys (cached)."""
        _SAFE_FALLBACK = {
            "burp": {"connected": False, "detail": "Check timed out"},
            "docker": {"connected": False, "docker_available": False, "detail": "Check timed out"},
            "performance": {"score": 0, "grade": "?"},
            "api_keys": {"keys": [], "configured": 0, "total": 0},
        }
        try:
            now = time.monotonic()
            if self._infra_cache and (now - self._infra_cache_ts) < self._infra_cache_ttl:
                return web.json_response(self._infra_cache)
            loop = asyncio.get_running_loop()  # FIX-155

            async def _safe_check(coro: Any, key: str) -> Any:
                """Run a single infra check with a 10s timeout."""
                try:
                    return await asyncio.wait_for(coro, timeout=10.0)
                except asyncio.TimeoutError:
                    logger.warning("infra check %s timed out after 10s", key)
                    return _SAFE_FALLBACK.get(key, {})

            burp, docker, perf, api_keys = await asyncio.gather(
                _safe_check(loop.run_in_executor(None, self._check_burp), "burp"),
                _safe_check(loop.run_in_executor(None, self._check_docker), "docker"),
                _safe_check(loop.run_in_executor(None, self._check_performance), "perf"),
                _safe_check(loop.run_in_executor(None, self._check_api_keys), "api_keys"),
            )
            result = {
                "burp": burp,
                "docker": docker,
                "performance": perf,
                "api_keys": api_keys,
            }
            # Use shorter cache TTL (10s) when any check is degraded/failed
            _has_degraded = (
                not burp.get("connected")
                or not docker.get("connected")
                or (perf.get("score", 0) < 45)
            )
            self._infra_cache = result
            self._infra_cache_ts = now
            self._infra_cache_ttl = 10.0 if _has_degraded else 30.0
            return web.json_response(result)
        except Exception as exc:
            logger.exception("infra-status check failed: %s", exc)
            return web.json_response(
                {**_SAFE_FALLBACK, "error": str(exc)},
                status=200,
            )


    # -- Infrastructure probes (delegated to infra_monitor.py) --------

    _API_KEY_REGISTRY = infra_monitor._API_KEY_REGISTRY

    @staticmethod
    def _check_burp() -> dict[str, Any]:
        return infra_monitor.check_burp()

    @staticmethod
    def _check_docker() -> dict[str, Any]:
        return infra_monitor.check_docker()

    @staticmethod
    def _check_performance() -> dict[str, Any]:
        return infra_monitor.check_performance()

    @staticmethod
    def _check_api_keys() -> dict[str, Any]:
        return infra_monitor.check_api_keys()

    async def _handle_api_keys_get(self, _request: Any) -> Any:
        """Return current API key configuration status (GET /api/api-keys)."""
        loop = asyncio.get_running_loop()  # FIX-155
        result = await loop.run_in_executor(None, self._check_api_keys)
        return web.json_response({"ok": True, **result})

    async def _handle_api_keys_save(self, request: Any) -> Any:
        """Save API keys to .env file and update os.environ (POST /api/api-keys)."""
        try:
            body = await request.json()
            updates = body.get("keys", {})
            if not isinstance(updates, dict):
                return web.json_response({"ok": False, "error": "keys must be an object"}, status=400)

            # Validate: only allow known env vars
            known_vars = {entry[0] for entry in self._API_KEY_REGISTRY}
            invalid = set(updates.keys()) - known_vars
            if invalid:
                return web.json_response(
                    {"ok": False, "error": f"Unknown keys: {', '.join(sorted(invalid))}"}, status=400
                )

            # Find .env file (project root)
            # __file__ = tools/burp_enterprise/recon_dashboard/server.py
            # 4 x .parent â†’ project root
            project_root = Path(__file__).resolve().parent.parent.parent.parent
            env_file = project_root / ".env"

            # Read existing .env content
            existing_lines: list[str] = []
            existing_vars: dict[str, int] = {}  # var_name -> line_index
            if env_file.exists():
                existing_lines = env_file.read_text(encoding="utf-8").splitlines()
                for idx, line in enumerate(existing_lines):
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped:
                        var_name = stripped.split("=", 1)[0].strip()
                        existing_vars[var_name] = idx

            saved_count = 0
            for var_name, value in updates.items():
                value = value.strip() if isinstance(value, str) else ""
                # Update os.environ immediately
                if value:
                    os.environ[var_name] = value
                elif var_name in os.environ:
                    del os.environ[var_name]

                # Update .env file content
                new_line = f"{var_name}={value}" if value else f"#{var_name}="
                if var_name in existing_vars:
                    existing_lines[existing_vars[var_name]] = new_line
                else:
                    existing_lines.append(new_line)
                saved_count += 1

            # Write .env file
            env_file.write_text("\n".join(existing_lines) + "\n", encoding="utf-8")

            # Invalidate infra cache so next poll picks up changes
            self._infra_cache = None
            self._infra_cache_ts = 0.0

            logger.info("API keys updated: %d keys saved to %s", saved_count, env_file)
            return web.json_response({"ok": True, "saved": saved_count})
        except Exception as exc:
            logger.warning("API keys save error: %s", exc)
            return web.json_response({"ok": False, "error": str(exc)}, status=500)

    # â”€â”€ Standalone Recon API handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def _handle_standalone_run(self, request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_standalone_run(self, request)

    async def _handle_session_reset(self, _request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_session_reset(self, _request)

    async def _handle_annotate_finding(self, request: Any) -> Any:
        from . import routes_findings
        return await routes_findings.handle_annotate_finding(self, request)

    async def _handle_get_annotations(self, _request: Any) -> Any:
        from . import routes_findings
        return await routes_findings.handle_get_annotations(self, _request)

    async def _handle_unified_findings(self, request: Any) -> Any:
        from . import routes_findings
        return await routes_findings.handle_unified_findings(self, request)

    async def _handle_unified_findings_count(self, request: Any) -> Any:
        from . import routes_findings
        return await routes_findings.handle_unified_findings_count(self, request)

    async def _handle_unified_findings_sources(self, _request: Any) -> Any:
        from . import routes_findings
        return await routes_findings.handle_unified_findings_sources(self, _request)

    async def _handle_unified_findings_timeline(self, request: Any) -> Any:
        from . import routes_findings
        return await routes_findings.handle_unified_findings_timeline(self, request)

    async def _handle_exploit_graph(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph(self, _request)

    async def _handle_exploit_graph_trigger_maps(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_trigger_maps(self, _request)

    async def _handle_exploit_graph_paths(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_paths(self, _request)

    async def _handle_exploit_graph_transition(self, request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_transition(self, request)

    async def _handle_exploit_graph_narrative(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_narrative(self, _request)

    async def _handle_exploit_graph_timeline(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_timeline(self, _request)

    async def _handle_exploit_graph_report(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_report(self, _request)

    async def _handle_exploit_graph_goal(self, _request: Any) -> Any:
        from . import routes_exploit_graph
        return await routes_exploit_graph.handle_exploit_graph_goal(self, _request)

    async def _handle_assessment_run(self, request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_assessment_run(self, request)

    async def _handle_assessment_stop(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_assessment_stop(self, _request)

    async def _handle_assessment_pause(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_assessment_pause(self, _request)

    async def _handle_assessment_resume(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_assessment_resume(self, _request)

    async def _handle_assessment_status(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_assessment_status(self, _request)

    async def _handle_intelligence_severity(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_severity(self, _request)

    async def _handle_intelligence_confidence(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_confidence(self, _request)

    async def _handle_intelligence_vuln_intel(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_vuln_intel(self, _request)

    async def _handle_intelligence_risk(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_risk(self, _request)

    async def _handle_intelligence_bayesian(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_bayesian(self, _request)

    async def _handle_intelligence_threat_model(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_threat_model(self, _request)

    async def _handle_intelligence_error_intel(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_error_intel(self, _request)

    async def _handle_intelligence_collab(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_collab(self, _request)

    async def _handle_intelligence_cognitive(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_intelligence_cognitive(self, _request)

    async def _handle_agent_status(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_agent_status(self, _request)

    async def _handle_governor_status(self, _request: Any) -> Any:
        from . import routes_assessment
        return await routes_assessment.handle_governor_status(self, _request)

    async def _handle_execution_orchestrator_status(self, _request: Any) -> Any:
        """Return current ExecutionOrchestrator status."""
        from aiohttp import web as _web
        try:
            from .execution_orchestrator import get_execution_orchestrator
            eo = get_execution_orchestrator()
            return _web.json_response(eo.get_status())
        except Exception as exc:
            return _web.json_response({"error": str(exc)}, status=500)

    async def _handle_atlas_nexus_status(self, _request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_atlas_nexus_status(self, _request)

    async def _handle_performance_metrics(self, _request: Any) -> Any:
        """Return pipeline performance metrics for the performance dashboard."""
        from aiohttp import web as _web
        try:
            from ..pipeline.pipeline_tracing import get_phase_metrics, get_trace_id
            metrics = get_phase_metrics()
            data = metrics.snapshot()
            data["current_trace_id"] = get_trace_id()
        except ImportError:
            data = {"error": "pipeline_tracing module not available", "phases": {}, "scanners": {}}
        return _web.json_response(data)

    async def _handle_standalone_stop(self, _request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_standalone_stop(self, _request)

    async def _handle_standalone_pause(self, _request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_standalone_pause(self, _request)

    async def _handle_standalone_resume(self, _request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_standalone_resume(self, _request)

    async def _handle_standalone_skip_phase(self, request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_standalone_skip_phase(self, request)

    async def _handle_load_session(self, request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_load_session(self, request)

    async def _handle_standalone_status(self, _request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_standalone_status(self, _request)

    async def _handle_console_feed(self, request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_console_feed(self, request)

    async def _handle_report(self, request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_report(self, request)

    async def _handle_export(self, request: Any) -> Any:
        from . import routes_standalone
        return await routes_standalone.handle_export(self, request)

    async def _start_async(self) -> None:
        """Start both HTTP and WebSocket servers with auto port-finding."""
        self._running = True

        # â”€â”€ Auto port-finding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if not self._find_available_ports():
            print(
                f"Error: No available port pair found in range "
                f"{DEFAULT_HTTP_PORT}â€“{DEFAULT_HTTP_PORT + PORT_SCAN_RANGE * 2}. "
                f"Free up ports or specify --port / --ws-port."
            )
            self._running = False
            return

        # Start WebSocket server
        if WEBSOCKETS_AVAILABLE:
            try:
                self._ws_server = await websockets.serve(
                    self._handle_websocket,
                    "localhost",
                    self.ws_port,
                    # FIX C-1: Limit max concurrent WS clients to prevent
                    # resource exhaustion from unauthenticated connections.
                    max_size=2**20,  # 1 MiB max incoming message
                    # FIX-WS1: websockets v16 defaults ping_interval=20,
                    # ping_timeout=20 â€” too aggressive.  If the browser's
                    # main thread is busy rendering a large state_snapshot
                    # the protocol-level pong can be delayed past the
                    # deadline, causing the server to kill the connection.
                    # Relax to 30 s send / 30 s wait (60 s worst-case).
                    ping_interval=30,
                    ping_timeout=30,
                )
                logger.info("WebSocket server: ws://localhost:%d", self.ws_port)
            except OSError as e:
                logger.error("WebSocket port %d in use: %s", self.ws_port, e)
                print(f"Error: WebSocket port {self.ws_port} could not be bound: {e}")
                self._running = False
                return

        # Start HTTP server (with auth middleware)
        if AIOHTTP_AVAILABLE:
            app = web.Application(
                middlewares=[
                    self._make_security_headers_middleware(),
                    self._make_auth_middleware(),
                ],
                client_max_size=2 * 1024 * 1024,  # 2 MB global request body limit
            )
            app.router.add_get("/", self._serve_dashboard)
            app.router.add_get("/favicon.ico", self._handle_favicon)
            app.router.add_post("/api/event", self._handle_event)
            app.router.add_get("/api/status", self._handle_status)
            app.router.add_get("/api/target-profile", self._handle_target_profile)
            app.router.add_get("/health", self._handle_health)
            app.router.add_get("/api/infra-status", self._handle_infra_status)
            app.router.add_get("/api/api-keys", self._handle_api_keys_get)
            app.router.add_post("/api/api-keys", self._handle_api_keys_save)
            app.router.add_post("/api/session/reset", self._handle_session_reset)
            app.router.add_post("/api/standalone/run", self._handle_standalone_run)
            app.router.add_post("/api/standalone/stop", self._handle_standalone_stop)
            app.router.add_post("/api/standalone/pause", self._handle_standalone_pause)
            app.router.add_post("/api/standalone/resume", self._handle_standalone_resume)
            app.router.add_post("/api/standalone/skip-phase", self._handle_standalone_skip_phase)
            app.router.add_get("/api/standalone/status", self._handle_standalone_status)
            app.router.add_get("/api/standalone/console", self._handle_console_feed)
            app.router.add_post("/api/sessions/load", self._handle_load_session)
            app.router.add_get("/api/report", self._handle_report)
            app.router.add_get("/api/export", self._handle_export)
            app.router.add_get("/api/sessions", self._handle_sessions)
            app.router.add_get("/api/token", self._handle_token)
            app.router.add_get("/api/events/stream", self._handle_event_stream)
            app.router.add_post("/api/phase/settings", self._handle_phase_settings_post)
            app.router.add_get("/api/phase/settings", self._handle_phase_settings_get)
            # TIER 2 #10: Finding Annotations
            app.router.add_post("/api/findings/annotate", self._handle_annotate_finding)
            app.router.add_get("/api/findings/annotations", self._handle_get_annotations)
            # Unified Findings Layer — cross-module query/count/timeline
            app.router.add_get("/api/findings/unified", self._handle_unified_findings)
            app.router.add_get("/api/findings/unified/count", self._handle_unified_findings_count)
            app.router.add_get("/api/findings/unified/sources", self._handle_unified_findings_sources)
            app.router.add_get("/api/findings/unified/timeline", self._handle_unified_findings_timeline)
            # Exploit Graph â€” Cytoscape.js data + position
            app.router.add_get("/api/exploit-graph", self._handle_exploit_graph)
            app.router.add_get("/api/exploit-graph/paths", self._handle_exploit_graph_paths)
            app.router.add_get("/api/exploit-graph/trigger-maps", self._handle_exploit_graph_trigger_maps)
            app.router.add_post("/api/exploit-graph/transition", self._handle_exploit_graph_transition)
            # U1-U4: UX & Reporting endpoints
            app.router.add_get("/api/exploit-graph/narrative", self._handle_exploit_graph_narrative)
            app.router.add_get("/api/exploit-graph/timeline", self._handle_exploit_graph_timeline)
            app.router.add_get("/api/exploit-graph/report", self._handle_exploit_graph_report)
            app.router.add_get("/api/exploit-graph/goal", self._handle_exploit_graph_goal)
            # AssessmentEngine-backed run (Opp #3)
            app.router.add_post("/api/assessment/run", self._handle_assessment_run)
            app.router.add_post("/api/assessment/stop", self._handle_assessment_stop)
            app.router.add_post("/api/assessment/pause", self._handle_assessment_pause)
            app.router.add_post("/api/assessment/resume", self._handle_assessment_resume)
            app.router.add_get("/api/assessment/status", self._handle_assessment_status)
            # Intelligence module state endpoints
            app.router.add_get("/api/intelligence/severity", self._handle_intelligence_severity)
            app.router.add_get("/api/intelligence/confidence", self._handle_intelligence_confidence)
            app.router.add_get("/api/intelligence/vuln-intel", self._handle_intelligence_vuln_intel)
            app.router.add_get("/api/intelligence/risk", self._handle_intelligence_risk)
            app.router.add_get("/api/intelligence/bayesian", self._handle_intelligence_bayesian)
            app.router.add_get("/api/intelligence/threat-model", self._handle_intelligence_threat_model)
            app.router.add_get("/api/intelligence/error-intel", self._handle_intelligence_error_intel)
            app.router.add_get("/api/intelligence/collab", self._handle_intelligence_collab)
            app.router.add_get("/api/intelligence/cognitive", self._handle_intelligence_cognitive)
            app.router.add_get("/api/agent/status", self._handle_agent_status)
            app.router.add_get("/api/governor/status", self._handle_governor_status)
            app.router.add_get("/api/execution-orchestrator/status", self._handle_execution_orchestrator_status)
            # LLM Integration endpoints
            app.router.add_get("/api/llm/status", self._handle_llm_status)
            app.router.add_post("/api/llm/chat", self._handle_llm_chat)
            app.router.add_post("/api/llm/chat/stream", self._handle_llm_chat_stream)  # H-3: SSE fallback
            app.router.add_post("/api/llm/feedback", self._handle_llm_feedback)  # I-8: quality feedback
            app.router.add_post("/api/llm/explain-finding", self._handle_llm_explain_finding)
            app.router.add_post("/api/llm/suggest-next", self._handle_llm_suggest_next)
            app.router.add_get("/api/llm/history", self._handle_llm_history)
            app.router.add_post("/api/llm/clear-history", self._handle_llm_clear_history)
            app.router.add_post("/api/llm/dedup", self._handle_llm_dedup)
            # Cognitive Bridge (Unified Intelligence) endpoints
            app.router.add_get("/api/cognitive/status", self._handle_cognitive_status)
            app.router.add_post("/api/cognitive/reason", self._handle_cognitive_reason)
            app.router.add_post("/api/cognitive/memory", self._handle_cognitive_memory)
            app.router.add_post("/api/cognitive/strategic", self._handle_cognitive_strategic)
            app.router.add_post("/api/cognitive/mode", self._handle_cognitive_set_mode)
            app.router.add_post("/api/cognitive/context", self._handle_cognitive_update_context)
            app.router.add_get("/api/cognitive/context", self._handle_cognitive_get_context)
            app.router.add_get("/api/cognitive/traces", self._handle_cognitive_traces)
            app.router.add_get("/api/cognitive/trace", self._handle_cognitive_trace_detail)
            app.router.add_get("/api/cognitive/cache-stats", self._handle_cognitive_cache_stats)
            app.router.add_post("/api/cognitive/clear-caches", self._handle_cognitive_clear_caches)
            app.router.add_get("/api/cognitive/context-health", self._handle_cognitive_context_health)
            # Reasoning Engine endpoints
            app.router.add_get("/api/reasoning/hypotheses", self._handle_reasoning_hypotheses)
            app.router.add_post("/api/reasoning/generate", self._handle_reasoning_generate)
            app.router.add_post("/api/reasoning/trace", self._handle_reasoning_trace)
            app.router.add_post("/api/reasoning/what-if", self._handle_reasoning_what_if)
            app.router.add_get("/api/reasoning/traces", self._handle_reasoning_traces_list)
            # Intelligence Experience endpoints
            app.router.add_get("/api/intelligence-experience/feed", self._handle_ix_feed)
            app.router.add_get("/api/intelligence-experience/summary", self._handle_ix_summary)
            app.router.add_get("/api/intelligence-experience/decisions", self._handle_ix_decisions)
            app.router.add_get("/api/intelligence-experience/strategies", self._handle_ix_strategies)
            app.router.add_get("/api/intelligence-experience/learning", self._handle_ix_learning)
            # Payout Metrics endpoints
            app.router.add_get("/api/payout-metrics", self._handle_payout_metrics)
            app.router.add_get("/api/payout-metrics/history", self._handle_payout_history)
            app.router.add_get("/api/payout-metrics/consistency", self._handle_payout_consistency)
            app.router.add_get("/api/payout-metrics/ttff", self._handle_payout_ttff)
            app.router.add_get("/api/payout-metrics/chains", self._handle_payout_chains)
            app.router.add_post("/api/payout-metrics/submission", self._handle_payout_submission)
            app.router.add_post("/api/scan/start", self._handle_scan_start)
            app.router.add_post("/api/scan/stop", self._handle_scan_stop)
            app.router.add_get("/api/scan/status", self._handle_scan_status)
            # Agent Loop endpoints (enhanced)
            app.router.add_post("/api/agent/start", self._handle_agent_start)
            app.router.add_post("/api/agent/stop", self._handle_agent_stop)
            app.router.add_post("/api/agent/pause", self._handle_agent_pause)
            app.router.add_post("/api/agent/resume", self._handle_agent_resume_loop)
            app.router.add_get("/api/agent/cycles", self._handle_agent_cycles)
            # Agent Memory endpoints
            app.router.add_post("/api/memory/query", self._handle_memory_query)
            app.router.add_get("/api/memory/episodes", self._handle_memory_episodes)
            app.router.add_get("/api/memory/stats", self._handle_memory_stats)
            app.router.add_post("/api/memory/feedback", self._handle_memory_feedback)
            # Atlas Intelligence Dashboard API
            if self._atlas_api is not None:
                app.router.add_get("/api/atlas/health", self._atlas_api.handle_atlas_health)
                app.router.add_get("/api/atlas/summary", self._atlas_api.handle_atlas_summary)
                app.router.add_get("/api/atlas/patterns", self._atlas_api.handle_atlas_patterns)
                app.router.add_get("/api/atlas/archetypes", self._atlas_api.handle_atlas_archetypes)
                app.router.add_get("/api/atlas/graph", self._atlas_api.handle_atlas_graph)
                app.router.add_get("/api/atlas/graph/best-paths", self._atlas_api.handle_atlas_graph_paths)
                app.router.add_get("/api/atlas/defense", self._atlas_api.handle_atlas_defense)
                app.router.add_get("/api/atlas/defense/advisory", self._atlas_api.handle_atlas_defense_advisory)
                app.router.add_get("/api/atlas/observations", self._atlas_api.handle_atlas_observations)
                app.router.add_get("/api/atlas/strategies", self._atlas_api.handle_atlas_strategies)
                app.router.add_post("/api/atlas/learn", self._atlas_api.handle_atlas_learn)
            # Atlas Nexus status endpoint (always registered; nexus activates lazily)
            app.router.add_get("/api/atlas/nexus", self._handle_atlas_nexus_status)
            # Pipeline Performance Dashboarding (Phase 4 — Item 19)
            app.router.add_get("/api/performance", self._handle_performance_metrics)
            # Phase C: serve minified/hashed static assets from disk
            # Appliance REST API (scans, license, profiles, settings)
            try:
                from .appliance_api import register_appliance_routes
                register_appliance_routes(app)
            except Exception as _exc:
                logger.debug("Appliance API not loaded: %s", _exc)
            app.router.add_static("/static", str(_STATIC_DIR))
            # Serve screenshot captures so <img src="/screenshots/â€¦"> works
            _screenshots_dir = (
                Path(__file__).resolve().parent.parent.parent.parent / "screenshots"
            )
            _screenshots_dir.mkdir(parents=True, exist_ok=True)
            app.router.add_static("/screenshots", str(_screenshots_dir))
            runner = web.AppRunner(app)
            await runner.setup()
            self._runner = runner
            try:
                site = web.TCPSite(
                    runner, "localhost", self.http_port,
                    ssl_context=self._ssl_context,
                )
                await site.start()
                _scheme = "https" if self._ssl_context else "http"
                logger.info("%s dashboard: %s://localhost:%d", _scheme.upper(), _scheme, self.http_port)
            except OSError as e:
                logger.error("HTTP port %d in use: %s", self.http_port, e)
                print(f"Error: HTTP port {self.http_port} could not be bound: {e}")
                if self._ws_server:
                    self._ws_server.close()
                self._running = False
                return

        # â”€â”€ Write port discovery file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self._write_port_file()

        # â”€â”€ Set env var for child processes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        os.environ["VENATOR_DASHBOARD_PORT"] = str(self.http_port)
        os.environ["VENATOR_DASHBOARD_WS_PORT"] = str(self.ws_port)
        os.environ["VENATOR_DASHBOARD_TOKEN"] = self._auth_token

        _scheme = "https" if self._ssl_context else "http"
        url = f"{_scheme}://localhost:{self.http_port}"

        def _safe_print(msg: str) -> None:
            """Print msg, replacing unencodable chars so cp1252 terminals don't crash."""
            try:
                print(msg)
            except UnicodeEncodeError:
                print(msg.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii"))

        _safe_print(f"\n[*] Recon Dashboard: {url}")
        _ws_scheme = "wss" if self._ssl_context else "ws"
        _safe_print(f"[~] WebSocket:       {_ws_scheme}://localhost:{self.ws_port}")
        _safe_print(f"[>] Target:          {self._state.target_url or '(pending)'}")
        _masked = self._auth_token[:6] + "..." + self._auth_token[-4:] if len(self._auth_token) > 10 else "***"
        _safe_print(f"[k] Auth Token:      {_masked}")
        _safe_print(f"[s] Session ID:      {self._session_id}\n")

        # Auto-open browser
        if self.auto_open:
            try:
                webbrowser.open(url)
            except OSError as exc:
                logger.warning("Could not open browser: %s", exc)

        # â”€â”€ Start periodic state snapshot â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self._snapshot_task = asyncio.create_task(self._periodic_snapshot_loop())

        # Diff push + exploit graph push are deferred until a scan starts
        # to avoid ~30-50 MB of memory from exploit graph + state-diff
        # serialization cycles while the dashboard is idle.
        self._diff_push_task = None
        self._eg_push_task = None
        self._scan_tasks_active = False

        # -- Subscribe to EventBus for direct in-process event delivery --
        self._subscribe_event_bus()

        # Eagerly probe LLM bridge so the indicator shows online/offline
        # immediately rather than waiting for the first chat message.
        try:
            self._ensure_llm_bridge()
        except Exception as _llm_exc:
            logger.debug("Eager LLM probe failed: %s", _llm_exc)

        # Keep running
        _was_scan_running = False
        try:
            while self._running:
                await asyncio.sleep(1)
                # Detect scan lifecycle transitions
                _is_scan_running = bool(
                    self._standalone_runner and self._standalone_runner.is_running
                ) or bool(
                    self._assessment_engine and self._assessment_thread
                    and self._assessment_thread.is_alive()
                )
                if _is_scan_running and not _was_scan_running:
                    # Scan just started — activate heavy subsystems
                    self._activate_scan_tasks()
                    self._scan_tasks_active = True
                    # Payout metrics: start tracking
                    try:
                        _pt = self._ensure_payout_tracker()
                        _pt.start_scan(
                            scan_id=getattr(self, "_session_id", "auto"),
                            target_url=self._state.target_url or "",
                            target_type=getattr(self._state, "target_profile", "unknown"),
                        )
                    except Exception:
                        pass
                elif not _is_scan_running and _was_scan_running:
                    # Scan just stopped — deactivate to free memory
                    self._deactivate_scan_tasks()
                    self._scan_tasks_active = False
                    # Payout metrics: persist end-of-scan metrics
                    try:
                        _pt = self._ensure_payout_tracker()
                        _fs = self._state.findings
                        _BIZ = {"authentication","authorization","idor","privilege-escalation","session","csrf","business-logic","race-condition","ssrf"}
                        for _f in _fs:
                            _pt.record_finding(_f)
                            if _f.get("confirmed"):
                                _pt.record_confirmation("confirmed")
                        # Chain metrics from UAG + QuickCorrelator
                        _chain_n = 0
                        try:
                            from ..exploit_chains.exploit_graph import get_exploit_graph_engine
                            _eg = get_exploit_graph_engine()
                            _chain_n = len(getattr(_eg, "_transitions", []))
                        except Exception:
                            pass
                        # S3-FIX: Also count QuickCorrelator chains from runner
                        if self._standalone_runner is not None:
                            _qc = getattr(self._standalone_runner, "_correlation_attack_chains", 0)
                            if _qc > _chain_n:
                                _chain_n = _qc
                        for _ in range(_chain_n):
                            _pt.record_chain_detected()

                        _pt.end_scan()
                    except Exception:
                        pass
                _was_scan_running = _is_scan_running
                # FIX-PERSIST-8: Auto-exit when scan completes in headless mode.
                if self._auto_exit and self._standalone_runner is not None:
                    if not self._standalone_runner.is_running:
                        # Don't auto-exit when scan was aborted (e.g. RAM
                        # limit) — keep dashboard alive so the user can
                        # review partial results and findings.
                        if self._standalone_runner._abort.is_set():
                            logger.info("Scan aborted — keeping dashboard alive for review")
                            self._auto_exit = False  # one-shot disable
                        else:
                            logger.info("Scan finished — auto-exit enabled, stopping dashboard")
                            self._running = False
        finally:
            # Final snapshot on exit
            if self._snapshot_task and not self._snapshot_task.done():
                self._snapshot_task.cancel()
                try:
                    await self._snapshot_task
                except asyncio.CancelledError:
                    logger.debug("Snapshot task cancelled")
            if self._diff_push_task and not self._diff_push_task.done():
                self._diff_push_task.cancel()
                try:
                    await self._diff_push_task
                except asyncio.CancelledError:
                    logger.debug("Diff push task cancelled")
            if getattr(self, "_eg_push_task", None) and not self._eg_push_task.done():
                self._eg_push_task.cancel()
                try:
                    await self._eg_push_task
                except asyncio.CancelledError:
                    logger.debug("EG push task cancelled")
            self._deactivate_atlas_nexus()
            self._save_state_snapshot()
            self._remove_port_file()

    def start(self) -> None:
        """Start the dashboard (blocking)."""
        if not AIOHTTP_AVAILABLE:
            print("Error: aiohttp is required.  pip install aiohttp")
            return
        if not WEBSOCKETS_AVAILABLE:
            print("Error: websockets is required.  pip install websockets")
            return

        try:
            asyncio.run(self._start_async())
        except KeyboardInterrupt:
            print("\nDashboard stopped.")
        finally:
            self._running = False

    def start_background(self) -> threading.Thread:
        """Start dashboard in a background thread. Returns the thread."""
        t = threading.Thread(target=self.start, daemon=True, name="recon-dashboard")
        t.start()
        return t

    def stop(self) -> None:
        """Stop the dashboard."""
        self._running = False
        # Schedule async cleanup if loop is running
        try:
            loop = asyncio.get_running_loop()  # FIX-155
            if loop.is_running():
                loop.create_task(self._cleanup())
        except RuntimeError:
            logger.debug("No running event loop for async cleanup")

    async def _cleanup(self) -> None:
        """Clean up server resources."""
        self._unsubscribe_event_bus()
        self._deactivate_atlas_nexus()

        # FIX-PERSIST-7: Abort the standalone runner on server shutdown
        # to stop sweeper, ETA ticker, drain threads, and Docker containers.
        if hasattr(self, '_standalone_runner') and self._standalone_runner:
            try:
                self._standalone_runner.abort()
                logger.info("Standalone runner aborted during server cleanup")
            except Exception as exc:
                logger.debug("Runner abort on cleanup failed: %s", exc)

        # Stop agent loop if running
        if self._agent_loop is not None:
            try:
                self._agent_loop.stop()
            except Exception as exc:
                logger.debug("Agent loop stop error: %s", exc)
        if self._agent_loop_task is not None and not self._agent_loop_task.done():
            self._agent_loop_task.cancel()
            try:
                await self._agent_loop_task
            except asyncio.CancelledError:
                pass
        for ws in list(self._ws_clients):
            try:
                await ws.close()
            except Exception as exc:
                logger.debug("Error closing WebSocket: %s", exc)
        self._ws_clients.clear()
        if self._runner:
            await self._runner.cleanup()
        if self._ws_server:
            self._ws_server.close()

    # -- LLM Integration (delegated to llm_helpers.py) --


    def _maybe_rotate_token(self) -> None:
        """CC-S1: Rotate auth token if rotation interval has elapsed.

        The previous token is kept valid for 60s grace period so that
        in-flight requests using the old token are not rejected.
        """
        if self._token_rotation_interval <= 0:
            return
        elapsed = time.monotonic() - self._token_created_at
        if elapsed >= self._token_rotation_interval:
            self._prev_auth_token = self._auth_token
            self._auth_token = _secrets.token_urlsafe(32)
            self._token_created_at = time.monotonic()
            os.environ["VENATOR_DASHBOARD_TOKEN"] = self._auth_token
            logger.info("CC-S1: Auth token rotated (interval=%.0fs)", self._token_rotation_interval)

    def _check_llm_rate_limit(self) -> bool:
        """C-5: Return True if the LLM request is within rate limits.

        Uses a sliding window of timestamps. Returns False (and logs a
        warning) if the limit has been exceeded.
        """
        import time as _time
        now = _time.monotonic()
        cutoff = now - self._llm_rate_window
        # Prune old entries
        self._llm_rate_timestamps = [
            t for t in self._llm_rate_timestamps if t > cutoff
        ]
        if len(self._llm_rate_timestamps) >= self._llm_rate_limit:
            return False
        self._llm_rate_timestamps.append(now)
        return True

    def _ensure_llm_bridge(self) -> Any | None:
        if self._llm_bridge is not None:
            return self._llm_bridge
        if self._llm_bridge_init_attempted:
            return None
        self._llm_bridge_init_attempted = True
        self._llm_bridge = llm_helpers.init_llm_bridge(self._state)
        # T3.2: Load persisted chat history on first bridge init
        if self._llm_bridge is not None:
            self._load_chat_history()
        return self._llm_bridge

    # ── T3.2: Persistent Chat History ────────────────────────────────

    def _persist_chat_message(self, role: str, content: str, ts: str = "") -> None:
        """Persist a single chat message to SQLite (fire-and-forget)."""
        try:
            from ..database.db_registry import T, get_agent_db
            from datetime import datetime, timezone
            if not ts:
                ts = datetime.now(timezone.utc).isoformat()
            db = get_agent_db()
            with db.connect() as conn:
                conn.execute(
                    f"INSERT INTO {T.LLM_CHAT_HISTORY} "
                    f"(session_id, target_url, role, content, ts) "
                    f"VALUES (?, ?, ?, ?, ?)",
                    ("default", self._state.target_url or "", role, content[:2000], ts),
                )
        except Exception as exc:
            logger.debug("Chat history persist failed: %s", exc)

    def _load_chat_history(self) -> None:
        """Load persisted chat history from SQLite into state on startup."""
        try:
            from ..database.db_registry import T, get_agent_db
            db = get_agent_db()
            with db.connect() as conn:
                rows = conn.execute(
                    f"SELECT role, content, ts FROM {T.LLM_CHAT_HISTORY} "
                    f"WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                    ("default", self._state._LLM_CHAT_CAP),
                ).fetchall()
            if rows:
                # Rows come newest-first; reverse for chronological order
                rows.reverse()
                for role, content, ts in rows:
                    self._state.llm_chat_history.append({
                        "role": role, "content": content, "ts": ts,
                    })
                logger.info("T3.2: Loaded %d chat messages from history", len(rows))
        except Exception as exc:
            logger.debug("Chat history load failed: %s", exc)

    def _clear_chat_history(self) -> None:
        """Clear persisted chat history for current session."""
        try:
            from ..database.db_registry import T, get_agent_db
            db = get_agent_db()
            with db.connect() as conn:
                conn.execute(f"DELETE FROM {T.LLM_CHAT_HISTORY} WHERE session_id = ?", ("default",))
            self._state.llm_chat_history.clear()
        except Exception as exc:
            logger.debug("Chat history clear failed: %s", exc)

    # ── Agent Chat Context & Action Helpers ──────────────────────────

    def _build_agent_chat_context(self, query: str = "") -> dict[str, Any]:
        """Build rich scan context dict for agent_chat() from dashboard state.

        T3.1: When ``query`` is provided, RAG retrieval adds semantically
        relevant findings beyond the static top-15 severity list.
        7.3.3: Base context (non-RAG) is cached for 5 s to avoid re-computing
        on every message when findings haven't changed.
        Cache is also invalidated when _change_seq advances (new findings,
        assessment updates, state changes).
        """
        import time as _time

        s = self._state
        _now = _time.monotonic()
        _fc = len(s.findings)
        _seq = s._change_seq
        _CTX_TTL = 5.0  # seconds

        # Serve cached base context if still fresh and no state mutations
        if (
            self._ctx_cache is not None
            and (_now - self._ctx_cache_ts) < _CTX_TTL
            and self._ctx_cache_count == _fc
            and self._ctx_cache_seq == _seq
        ):
            ctx = dict(self._ctx_cache)  # shallow copy
        else:
            ctx = self._build_agent_chat_context_inner()
            self._ctx_cache = ctx
            self._ctx_cache_ts = _now
            self._ctx_cache_count = _fc
            self._ctx_cache_seq = _seq
            ctx = dict(ctx)

        # T3.1: RAG-enhanced context — retrieve findings relevant to query
        if query and s.findings:
            try:
                if self._rag_engine is None:
                    from ..agents.rag_context import RAGContextEngine
                    self._rag_engine = RAGContextEngine()
                self._rag_engine.index_findings(s.findings)
                rag_results = self._rag_engine.retrieve(query, top_k=5)
                if rag_results:
                    ctx["rag_findings"] = rag_results
                    ctx["rag_context"] = self._rag_engine.format_for_prompt(rag_results)
            except Exception as exc:
                logger.debug("RAG context retrieval failed: %s", exc)

        # ── Topic-detected deep context injection ──
        # Only inject detailed data for topics the user is actually asking
        # about, keeping the prompt lean for the 7B model.
        if query:
            self._inject_topic_context(ctx, query, s)

        return ctx

    # ── Synonym expansion map for topic detection ──────────────────
    # Maps semantic concepts → canonical topic key.  Each entry is a
    # tuple of (synonyms_frozenset, topic_key, priority_weight).
    # Priority: higher = injected first when budget is tight.
    _TOPIC_SYNONYMS: list[tuple[frozenset[str], str, int]] = [
        (frozenset({
            "ssl", "tls", "cert", "certificate", "cipher", "jarm",
            "encryption", "encrypted", "https config", "x509",
            "certificate authority", "ca cert", "pem", "key exchange",
            "secure connection",
        }), "ssl", 8),
        (frozenset({
            "dns", "nameserver", "mx", "spf", "dmarc", "dkim",
            "zone transfer", "dnssec", "record", "name resolution",
            "mail record", "email auth", "sender policy", "domain key",
            "txt record", "cname", "ns record", "a record",
        }), "dns", 7),
        (frozenset({
            "header", "cookie", "waf", "security header", "csp",
            "x-frame", "hsts", "cors", "x-content", "referrer-policy",
            "content-security", "web application firewall", "strict-transport",
            "same-origin", "http response", "server header",
        }), "headers", 6),
        (frozenset({
            "port", "open port", "service", "nmap", "network scan",
            "tcp", "udp", "listening", "port scan", "exposed service",
        }), "ports", 5),
        (frozenset({
            "subdomain", "sub-domain", "vhost", "virtual host",
            "host discovery", "subdomain enum",
        }), "subdomains", 4),
        (frozenset({
            "geo", "location", "country", "hosting", "asn", "isp",
            "cloud", "cdn", "data center", "ip address", "ip info",
            "where is it hosted", "infrastructure", "network provider",
        }), "geolocation", 3),
        (frozenset({
            "threat", "stride", "trust boundary", "threat model",
            "attack surface", "threat analysis", "threat vector",
            "attack vector", "spoofing", "tampering", "repudiation",
            "information disclosure", "denial of service", "elevation",
        }), "threat_model", 9),
        (frozenset({
            "cve", "epss", "vuln intel", "known vuln", "exploit db",
            "vulnerability intelligence", "vulnerability database",
            "known vulnerability", "patch", "advisory", "nvd",
        }), "cves", 9),
        (frozenset({
            "error", "architecture", "tech leak", "version leak",
            "error page", "stack trace", "debug info", "server error",
            "500 error", "information leak", "verbose error",
        }), "error_intel", 6),
        (frozenset({
            "assessment", "vuln scan", "vulnerability scan", "test cycle",
            "autonomous test", "assessment finding", "hypothesis",
            "active scan", "pentest", "penetration test",
        }), "assessment", 7),
        (frozenset({
            "bayesian", "priorit", "posterior", "most likely exploitable",
            "probability", "likelihood", "statistical",
        }), "bayesian", 4),
        (frozenset({
            "reasoning", "hypothes", "chain of thought", "what if",
            "why does", "logic", "inference", "deduction",
        }), "reasoning", 5),
        (frozenset({
            "agent", "thinking", "plan", "observation", "reflect",
            "autonomous", "agent loop", "agent thought",
            "what is the agent doing", "agent status",
        }), "agent", 3),
        (frozenset({
            "whois", "registrar", "registrant", "domain registration",
            "expir", "domain owner", "domain age", "registered",
        }), "whois", 2),
    ]

    # Pre-computed: largest synonym token count for substring-match length
    _MAX_TOPIC_BUDGET_TOKENS = 800  # hard cap for all deep-dive topics combined
    _SOFT_TOPIC_CAP = 3   # default simultaneous topic injections
    _HARD_TOPIC_CAP = 4   # allowed when 4th topic is high-confidence
    _HIGH_CONFIDENCE_THRESHOLD = 7  # priority >= this qualifies for hard-cap slot

    def _match_topics(self, query: str) -> list[tuple[str, int, str]]:
        """Return matched (topic_key, priority, matched_keyword) triples.

        Uses substring matching against expanded synonym sets.
        Returns results sorted by priority descending.
        Applies a soft/hard cap: normally 3 topics, but a 4th is allowed
        when it has high-confidence overlap (priority >= threshold).
        """
        _q = query.lower()
        hits: list[tuple[str, int, str]] = []
        seen_topics: set[str] = set()
        for synonyms, topic_key, priority in self._TOPIC_SYNONYMS:
            if topic_key in seen_topics:
                continue
            for kw in synonyms:
                if kw in _q:
                    hits.append((topic_key, priority, kw))
                    seen_topics.add(topic_key)
                    break
        # Sort by priority descending — highest-value topics first
        hits.sort(key=lambda x: x[1], reverse=True)
        # Soft cap at 3; allow 4th only if its priority is high-confidence
        if len(hits) <= self._SOFT_TOPIC_CAP:
            return hits
        result = hits[:self._SOFT_TOPIC_CAP]
        for extra in hits[self._SOFT_TOPIC_CAP:self._HARD_TOPIC_CAP]:
            if extra[1] >= self._HIGH_CONFIDENCE_THRESHOLD:
                result.append(extra)
        return result

    def _inject_topic_context(
        self,
        ctx: dict[str, Any],
        query: str,
        s: Any,
    ) -> None:
        """Inject detailed context for topics detected in the user query.

        Uses synonym expansion to catch semantic matches (e.g. "encryption"
        → ssl topic).  Applies priority ranking and token budget cap to
        prevent context overflow.  Each injected block includes confidence
        tags, injection reason, and cross-domain links.
        """
        import json as _json

        matched = self._match_topics(query)
        if not matched:
            return

        tp = s.target_profile
        deep: dict[str, Any] = {}
        _budget_used = 0

        for topic_key, _priority, matched_kw in matched:
            # Estimate remaining budget
            if _budget_used >= self._MAX_TOPIC_BUDGET_TOKENS:
                break

            block = self._build_topic_block(topic_key, s, tp)
            if not block:
                continue

            # Estimate token cost (~4 chars per token for English)
            _est_tokens = len(_json.dumps(block, default=str)) // 4
            if _budget_used + _est_tokens > self._MAX_TOPIC_BUDGET_TOKENS:
                # Truncate: take what fits
                _remaining = self._MAX_TOPIC_BUDGET_TOKENS - _budget_used
                if _remaining < 50:
                    break
                # Still inject but note it was truncated
                block["_truncated"] = True

            # Add metadata
            block["_meta"] = {
                "matched": matched_kw,
                "confidence": self._topic_data_confidence(topic_key, s, tp),
                "source": self._topic_data_source(topic_key),
            }

            # Cross-domain links
            links = self._cross_domain_links(topic_key, s, tp, deep)
            if links:
                block["_related"] = links

            deep[topic_key] = block
            _budget_used += _est_tokens

        if deep:
            ctx["deep_context"] = deep

    def _build_topic_block(
        self, topic: str, s: Any, tp: Any,
    ) -> dict[str, Any] | None:
        """Build the data block for a single topic.  Returns None if no data."""
        if topic == "ssl":
            if not tp.ssl_subject_cn:
                return None
            return {
                "subject": tp.ssl_subject_cn,
                "issuer": tp.ssl_issuer_cn,
                "grade": tp.ssl_grade,
                "valid_from": tp.ssl_not_before,
                "valid_until": tp.ssl_not_after,
                "san": tp.ssl_san[:10] if tp.ssl_san else [],
                "version": tp.ssl_version,
                "cipher": tp.ssl_cipher,
            }
        if topic == "dns":
            d: dict[str, Any] = {}
            if tp.dns_a:
                d["a"] = tp.dns_a
            if tp.dns_aaaa:
                d["aaaa"] = tp.dns_aaaa
            if tp.dns_mx:
                d["mx"] = tp.dns_mx[:5]
            if tp.dns_ns:
                d["ns"] = tp.dns_ns
            if tp.dns_txt:
                d["txt"] = tp.dns_txt[:5]
            if tp.dns_caa:
                d["caa"] = tp.dns_caa
            if tp.dnssec_enabled is not None:
                d["dnssec"] = tp.dnssec_enabled
            if tp.zone_transfer_possible is not None:
                d["zone_transfer"] = tp.zone_transfer_possible
            if tp.spf_record:
                d["spf"] = tp.spf_record
            if tp.dmarc_record:
                d["dmarc"] = tp.dmarc_record
            if tp.dkim_found is not None:
                d["dkim"] = tp.dkim_found
            return d or None
        if topic == "headers":
            h: dict[str, Any] = {}
            if tp.security_headers:
                h["security_headers"] = dict(tp.security_headers)
            if tp.cookies:
                h["cookies"] = [
                    {k: c[k] for k in ("name", "domain", "secure", "httponly", "samesite") if k in c}
                    for c in tp.cookies[:10]
                ]
            if tp.http_headers:
                _SKIP = frozenset({"date", "content-length", "connection", "keep-alive", "accept-ranges"})
                h["headers"] = {k: v for k, v in tp.http_headers.items() if k.lower() not in _SKIP}
            return h or None
        if topic == "ports":
            return {"ports": tp.open_ports[:20]} if tp.open_ports else None
        if topic == "subdomains":
            return {"subdomains": tp.subdomains_sample[:30]} if tp.subdomains_sample else None
        if topic == "geolocation":
            g: dict[str, Any] = {}
            for attr in ("geo_country", "geo_region", "geo_city", "asn", "asn_org", "isp",
                         "hosting_provider", "cloud_provider", "cdn_provider", "reverse_dns"):
                val = getattr(tp, attr, "")
                if val:
                    g[attr] = val
            return g or None
        if topic == "threat_model":
            if not s.threat_model_threats:
                return None
            return {
                "stride": dict(s.threat_model_stride_summary) if s.threat_model_stride_summary else {},
                "top_threats": [
                    {"category": t.get("category", ""), "title": t.get("title", ""), "severity": t.get("severity", "")}
                    for t in s.threat_model_threats[:10]
                ],
                "boundaries": [
                    {"name": b.get("name", ""), "type": b.get("type", "")}
                    for b in s.threat_model_boundaries[:5]
                ],
            }
        if topic == "cves":
            if not s.vuln_intel_cves:
                return None
            return {
                "cves": [
                    {
                        "cve_id": c.get("cve_id", ""),
                        "severity": c.get("severity", ""),
                        "epss": c.get("epss_score"),
                        "description": (c.get("description") or "")[:120],
                    }
                    for c in s.vuln_intel_cves[:10]
                ],
            }
        if topic == "error_intel":
            if not (s.error_intel_findings or s.error_intel_architecture):
                return None
            ei: dict[str, Any] = {}
            if s.error_intel_architecture:
                ei["architecture"] = s.error_intel_architecture
            if s.error_intel_tech_leaks:
                ei["tech_leaks"] = [
                    {"tech": l.get("technology", ""), "version": l.get("version", ""), "source": l.get("source", "")}
                    for l in s.error_intel_tech_leaks[:10]
                ]
            if s.error_intel_findings:
                ei["findings"] = [
                    {"title": f.get("title", ""), "severity": f.get("severity", "")}
                    for f in s.error_intel_findings[:5]
                ]
            return ei
        if topic == "assessment":
            if not (s.assessment_total_findings or s.assessment_cycles):
                return None
            asx: dict[str, Any] = {
                "mode": s.assessment_mode,
                "phase": s.assessment_phase,
                "cycles": s.assessment_cycles,
                "total_tests": s.assessment_total_tests,
                "findings_by_severity": dict(s.assessment_findings_by_severity),
            }
            if s.assessment_hypotheses:
                asx["hypotheses"] = [
                    {"description": h.get("description", ""), "status": h.get("status", "")}
                    for h in s.assessment_hypotheses[:5]
                ]
            if s.assessment_technologies:
                asx["technologies"] = s.assessment_technologies[:10]
            return asx
        if topic == "bayesian":
            if not s.bayesian_hypotheses:
                return None
            return {
                "hypotheses": [
                    {"tech": h.get("tech", ""), "vuln_type": h.get("vuln_type", ""), "posterior": h.get("posterior")}
                    for h in s.bayesian_hypotheses[:10]
                ],
            }
        if topic == "reasoning":
            if not s.reasoning_hypotheses:
                return None
            return {
                "hypotheses": [
                    {"description": h.get("description", ""), "confidence": h.get("confidence")}
                    for h in s.reasoning_hypotheses[:5]
                ],
                "active": s.reasoning_active,
            }
        if topic == "agent":
            if s.agent_state == "idle":
                return None
            ag: dict[str, Any] = {"state": s.agent_state, "cycle": s.agent_current_cycle}
            if s.agent_thoughts:
                ag["thoughts"] = [(t.get("content") or "")[:120] for t in s.agent_thoughts[-3:]]
            if s.agent_plans:
                ag["plans"] = [(p.get("content") or "")[:120] for p in s.agent_plans[-3:]]
            if s.agent_observations:
                ag["observations"] = [(o.get("content") or "")[:120] for o in s.agent_observations[-3:]]
            return ag
        if topic == "whois":
            w: dict[str, Any] = {}
            for attr in ("registrar", "registrant_org", "registrant_country",
                         "registration_date", "expiration_date", "nameservers", "domain_status"):
                val = getattr(tp, attr, None)
                if val:
                    w[attr] = val
            return w or None
        return None

    @staticmethod
    def _topic_data_confidence(topic: str, s: Any, tp: Any) -> str:
        """Return confidence level for a topic's data: high/medium/low.

        Confidence is dynamic — based on:
        - Data presence (empty data → low)
        - Data freshness (stale scan → downgrade)
        - Scan reliability (direct tool output vs inference)
        """
        import time as _time

        # ── Base tier from data source reliability ──
        _DIRECT_SCAN = {"ssl", "dns", "headers", "ports", "whois"}
        _ANALYSIS = {"assessment", "bayesian", "reasoning", "agent", "threat_model"}
        _DERIVED = {"geolocation", "subdomains", "cves", "error_intel"}

        if topic in _DIRECT_SCAN:
            level = "high"
        elif topic in _ANALYSIS:
            level = "medium"
        elif topic in _DERIVED:
            level = "medium"
        else:
            level = "medium"

        # ── Downgrade: empty or very sparse data ──
        if topic == "ssl" and not getattr(tp, "ssl_grade", None):
            level = "low"
        elif topic == "dns" and not getattr(tp, "dns_records", None):
            level = "low"
        elif topic == "ports" and not getattr(tp, "open_ports", None):
            level = "low"
        elif topic == "cves" and not getattr(s, "vuln_intel_cves", None):
            level = "low"
        elif topic == "assessment" and not getattr(s, "assessment_scores", None):
            level = "low"
        elif topic == "whois" and not getattr(tp, "whois_data", None):
            level = "low"

        # ── Downgrade: stale data (>30 min since last state change) ──
        if level != "low":
            _last_change = getattr(s, "_last_event_ts", 0)
            if _last_change and (_time.time() - _last_change) > 1800:
                level = "medium" if level == "high" else level

        return level

    @staticmethod
    def _topic_data_source(topic: str) -> str:
        """Return human-readable data source name for a topic."""
        _SOURCES = {
            "ssl": "TLS scan", "dns": "DNS enumeration", "headers": "HTTP probe",
            "ports": "port scan", "subdomains": "subdomain discovery",
            "geolocation": "IP intelligence", "threat_model": "STRIDE analysis",
            "cves": "CVE/EPSS database", "error_intel": "error page analysis",
            "assessment": "assessment engine", "bayesian": "Bayesian prioritizer",
            "reasoning": "reasoning engine", "agent": "agent loop",
            "whois": "WHOIS/RDAP lookup",
        }
        return _SOURCES.get(topic, "scan data")

    @staticmethod
    def _cross_domain_links(
        topic: str, s: Any, tp: Any, existing_deep: dict[str, Any],
    ) -> list[str]:
        """Generate cross-domain relationship hints for a topic block."""
        _MAX_LINKS = 3  # cap to prevent cross-domain explosion
        links: list[str] = []
        if topic == "ssl":
            if tp.http_server:
                links.append(f"Server: {tp.http_server}")
            if s.vuln_intel_cves:
                ssl_cves = [c for c in s.vuln_intel_cves[:20]
                            if "ssl" in (c.get("description") or "").lower()
                            or "tls" in (c.get("description") or "").lower()]
                if ssl_cves:
                    links.append(f"{len(ssl_cves)} TLS-related CVE(s) found")
        elif topic == "dns":
            if tp.subdomains_sample:
                links.append(f"{len(tp.subdomains_sample)} subdomains discovered")
            if tp.spf_record and "~all" in tp.spf_record:
                links.append("SPF uses softfail (~all) — spoofing risk")
        elif topic == "cves":
            if s.technologies:
                links.append(f"Technologies: {', '.join(str(t) for t in s.technologies[:5])}")
            if tp.http_server:
                links.append(f"Server: {tp.http_server}")
        elif topic == "headers":
            if not tp.security_headers.get("strict-transport-security"):
                if tp.ssl_grade:
                    links.append(f"SSL grade {tp.ssl_grade} but HSTS missing")
        elif topic == "threat_model":
            if s.exploit_graph_risk_score:
                links.append(f"Exploit graph risk: {s.exploit_graph_risk_score:.2f}")
        elif topic == "error_intel":
            if s.technologies:
                links.append(f"Confirmed tech: {', '.join(str(t) for t in s.technologies[:5])}")
        elif topic == "ports":
            if tp.http_server:
                links.append(f"Web server: {tp.http_server}")
        return links[:_MAX_LINKS]

    def _build_agent_chat_context_inner(self) -> dict[str, Any]:
        """Build the base agent chat context (without RAG)."""
        s = self._state
        # Severity summary
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in s.findings:
            sev = (f.get("severity") or "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
        findings_summary = ", ".join(f"{v} {k}" for k, v in sev_counts.items() if v) or "No findings"
        findings_summary += f" ({len(s.findings)} total)"

        # ── Tech-stack coherence validation ──
        tech_lower = {t.lower() for t in s.technologies}
        detected_platform = None
        if "shopify" in tech_lower:
            detected_platform = "shopify"
        elif "wordpress" in tech_lower:
            detected_platform = "wordpress"
        elif "django" in tech_lower and "shopify" not in tech_lower:
            detected_platform = "django"

        # Top critical/high findings (up to 15) with validation annotations
        top_findings: list[dict[str, Any]] = []
        for f in s.findings:
            sev = (f.get("severity") or "info").lower()
            if sev in ("critical", "high", "medium") and len(top_findings) < 15:
                entry: dict[str, Any] = {
                    "severity": sev,
                    "title": f.get("title") or f.get("detail") or "Untitled",
                    "url": f.get("url") or f.get("endpoint") or "",
                    "phase": f.get("phase") or f.get("source") or "",
                }
                # Validate against tech stack
                note = self._validate_finding_coherence(entry, tech_lower, detected_platform)
                if note:
                    entry["validation_note"] = note
                top_findings.append(entry)

        runner_running = bool(
            self._standalone_runner and self._standalone_runner.is_running
        ) if hasattr(self, "_standalone_runner") and self._standalone_runner else False

        ctx = {
            "target": s.target_url,
            "technologies": list(s.technologies[:20]),
            "findings_count": len(s.findings),
            "findings_summary": findings_summary,
            "endpoints_count": getattr(s, "endpoints_found", 0),
            "subdomains_count": getattr(s, "subdomains_found", 0),
            "phase_status": dict(s.phase_status),
            "top_findings": top_findings,
            "runner_running": runner_running,
        }

        # ── Build validation alerts for the LLM ──
        validation_alerts = self._build_validation_alerts(tech_lower, detected_platform, top_findings, s)
        ctx["validation_alerts"] = validation_alerts

        # Exploit Graph intelligence — attack paths, chains, risk score
        if s.exploit_graph_paths or s.exploit_graph_chains or s.exploit_graph_confirmed:
            eg: dict[str, Any] = {
                "risk_score": round(s.exploit_graph_risk_score, 3),
                "composite_risk": round(s.exploit_graph_composite_risk, 3),
                "confirmed": s.exploit_graph_confirmed,
                "total": s.exploit_graph_total,
            }
            if s.exploit_graph_position:
                eg["position"] = {
                    k: v for k, v in s.exploit_graph_position.items()
                    if k in ("label", "zone", "capabilities", "access_level")
                }
            if s.exploit_graph_paths:
                eg["critical_paths"] = s.exploit_graph_paths[:5]
            if s.exploit_graph_chains:
                eg["chains"] = s.exploit_graph_chains[:5]
            if s.exploit_graph_next_tests:
                eg["next_tests"] = s.exploit_graph_next_tests[:5]
            if s.exploit_graph_blast_radius:
                eg["blast_radius"] = s.exploit_graph_blast_radius
            if s.exploit_graph_verified_chains:
                eg["verified_chains"] = s.exploit_graph_verified_chains[:5]
            if s.exploit_graph_pocs:
                eg["pocs"] = [{"name": p.get("name", ""), "type": p.get("type", "")} for p in s.exploit_graph_pocs[:5]]
            ctx["exploit_graph"] = eg

        # ── Always-on compact target profile summary ──
        tp = s.target_profile
        tp_summary: dict[str, Any] = {}
        if tp.ssl_grade:
            tp_summary["ssl_grade"] = tp.ssl_grade
        if tp.http_server:
            tp_summary["server"] = tp.http_server
        if tp.cdn_provider:
            tp_summary["cdn"] = tp.cdn_provider
        if tp.cloud_provider:
            tp_summary["cloud"] = tp.cloud_provider
        if tp.cms:
            tp_summary["cms"] = tp.cms
        if tp.hosting_provider:
            tp_summary["hosting"] = tp.hosting_provider
        if tp.geo_country:
            tp_summary["country"] = tp.geo_country
        if tp.asn_org:
            tp_summary["asn_org"] = tp.asn_org
        if tp.open_ports:
            tp_summary["open_ports_count"] = len(tp.open_ports)
        sec_hdr_count = len(tp.security_headers) if tp.security_headers else 0
        if sec_hdr_count:
            tp_summary["security_headers_count"] = sec_hdr_count
        if tp.dnssec_enabled is not None:
            tp_summary["dnssec"] = tp.dnssec_enabled
        if tp_summary:
            ctx["target_profile"] = tp_summary

        # ── Always-on intelligence engine summary (compact stats) ──
        intel: dict[str, Any] = {}
        if any(s.severity_stats.values()):
            intel["severity"] = dict(s.severity_stats)
        if any(s.confidence_stats.values()):
            intel["confidence"] = dict(s.confidence_stats)
        if s.assessment_total_findings or s.assessment_cycles:
            intel["assessment"] = {
                "mode": s.assessment_mode,
                "phase": s.assessment_phase,
                "cycles": s.assessment_cycles,
                "findings": s.assessment_total_findings,
            }
        if s.threat_model_stride_summary:
            intel["stride"] = dict(s.threat_model_stride_summary)
        if s.error_intel_scan_count:
            intel["error_intel"] = {
                "findings": len(s.error_intel_findings),
                "tech_leaks": len(s.error_intel_tech_leaks),
            }
        if s.vuln_intel_enrichment_count:
            intel["cve_enrichments"] = s.vuln_intel_enrichment_count
        if s.bayesian_total_records:
            intel["bayesian_hypotheses"] = len(s.bayesian_hypotheses)
        if s.reasoning_hypotheses:
            intel["reasoning_hypotheses"] = len(s.reasoning_hypotheses)
        if intel:
            ctx["intelligence"] = intel

        return ctx

    @staticmethod
    def _map_info_to_phases(message: str) -> list[str]:
        """Map info-seeking question to targeted recon phases.

        Returns a list of phase names relevant to the user's question.
        The runner's selected_phases filter will run ONLY these.
        """
        msg = message.lower()
        phases: list[str] = []
        # Technology / framework detection
        if any(k in msg for k in ("technolog", "framework", "tech stack",
                                   "cms", "what server", "language", "running on",
                                   "built with", "powered by")):
            phases.append("Fingerprinting & Technology")
            phases.append("JS Analysis & Source Maps")
        # CVE / vulnerability lookup
        if any(k in msg for k in ("cve", "vulnerabilit", "exploit", "patch")):
            phases.append("Fingerprinting & Technology")  # need versions first
            phases.append("CVE Correlation")
            phases.append("Active Vulnerability Testing")
        # Subdomains
        if any(k in msg for k in ("subdomain", "sub-domain", "child domain")):
            phases.append("Subdomain Discovery")
            phases.append("DNS Resolution & Brute-force")
        # DNS records
        if any(k in msg for k in ("dns record", "mx record", "txt record",
                                   "ns record", "what dns")):
            phases.append("DNS Resolution & Brute-force")
            phases.append("DNS Security Testing")
        # Endpoints / URLs
        if any(k in msg for k in ("endpoint", "url", "path", "route",
                                   "api endpoint", "hidden page")):
            phases.append("Endpoint & Asset Discovery")
            phases.append("URL Aggregation & Dorking")
        # Ports / services
        if any(k in msg for k in ("port", "service", "listening", "open port")):
            phases.append("Network & Port Scanning")
        # TLS / SSL / certificates
        if any(k in msg for k in ("ssl", "tls", "cert", "https", "cipher")):
            phases.append("TLS & Certificate Analysis")
        # Security headers
        if any(k in msg for k in ("header", "security header", "csp",
                                   "hsts", "x-frame")):
            phases.append("Fingerprinting & Technology")
        # Secrets / keys
        if any(k in msg for k in ("secret", "api key", "leaked", "credential")):
            phases.append("Secrets Scanning")
        # WAF
        if any(k in msg for k in ("waf", "firewall", "protection", "cloudflare")):
            phases.append("WAF Detection & Fingerprinting")
        # Attack surface
        if any(k in msg for k in ("attack surface", "exposure", "perimeter")):
            phases.append("Fingerprinting & Technology")
            phases.append("Endpoint & Asset Discovery")
            phases.append("Subdomain Discovery")
            phases.append("Network & Port Scanning")
        # OSINT
        if any(k in msg for k in ("osint", "public info", "breach", "leak")):
            phases.append("OSINT Intelligence")
            phases.append("Passive Internet Search")
        # Cloud
        if any(k in msg for k in ("cloud", "aws", "azure", "gcp", "s3", "bucket")):
            phases.append("Cloud & Container Security")
        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for p in phases:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    @staticmethod
    def _detect_user_intent(message: str) -> str | None:
        """Detect scan-control intent from user message text.

        T2.4: Tightened keyword matching to reduce false positives.
        Ambiguous phrases like "proceed" or "go ahead" no longer trigger
        scans — only explicit scan-related phrases do.  Confirmation
        phrases ("yes", "do it", "proceed") are only recognised when
        a prior ``suggest_scan`` intent was returned.
        """
        msg = message.lower().strip()
        _STOP_KW = ("stop scan", "stop the scan", "abort scan", "cancel scan", "kill scan")
        _PAUSE_KW = ("pause scan", "pause the scan", "hold scan")
        # Explicit scan start — high confidence, no confirmation needed
        _START_KW = (
            "start scan", "run scan", "begin scan", "launch scan",
            "start the scan", "run the scan", "begin the scan",
            "let's scan", "lets scan", "go ahead and scan",
            "scan the target", "scan it", "start recon",
            "begin recon", "start the recon", "launch recon",
            "start testing", "run the test", "kick off the scan",
            "yes scan", "yes, scan",
        )
        # Ambiguous confirm phrases — only trigger if server previously suggested
        _CONFIRM_KW = (
            "yes", "do it", "proceed", "go ahead", "let's proceed",
            "lets proceed", "fire it up", "kick off", "go for it",
            "confirmed", "yes please", "absolutely",
        )
        for kw in _STOP_KW:
            if kw in msg:
                return "stop_scan"
        for kw in _PAUSE_KW:
            if kw in msg:
                return "pause_scan"
        for kw in _START_KW:
            if kw in msg:
                return "start_scan"
        # Implicit scan intent: assessment/audit/pentest requests
        _IMPLICIT_SCAN_KW = (
            "security assessment", "security audit", "security review",
            "vulnerability assessment", "vulnerability scan",
            "penetration test", "pentest", "pen test",
            "find vulnerabilities", "find vulns", "hunt for vulns",
            "test the security", "assess the security", "audit the security",
            "check for vulnerabilities", "look for vulnerabilities",
            "compromise assessment", "threat assessment",
            "full assessment", "comprehensive assessment",
            "comprehensive scan", "full scan", "deep scan",
            "test this site", "test this target", "hack this",
            "assess this", "audit this",
        )
        for kw in _IMPLICIT_SCAN_KW:
            if kw in msg:
                return "start_scan"
        # Info-seeking questions that need scan data to answer
        _INFO_SCAN_KW = (
            "what technologies", "what frameworks", "what tech",
            "technologies is", "technologies are", "tech stack",
            "known cve", "any cve", "cve ", "cves",
            "what vulnerabilities", "any vulnerabilities",
            "what subdomains", "any subdomains", "subdomains does",
            "what endpoints", "any endpoints", "open ports",
            "what services", "any services", "running on",
            "what cms", "what server", "what language",
            "ssl cert", "tls config", "security headers",
            "dns record", "what dns", "mx record",
            "attack surface", "exposure",
        )
        for kw in _INFO_SCAN_KW:
            if kw in msg:
                return "info_scan"
        # Ambiguous intent: suggest rather than auto-trigger
        for kw in _CONFIRM_KW:
            if msg == kw or msg.rstrip(".!") == kw:
                return "confirm_scan"
        return None

    def _extract_chat_action(self, content: str) -> dict[str, Any] | None:
        """Parse [ACTION:...] markers from LLM response (fallback)."""
        import re
        m = re.search(r'\[ACTION:(START_SCAN|PAUSE_SCAN|STOP_SCAN)(?::([^\]]+))?\]', content)
        if not m:
            return None
        return {"action": m.group(1), "args": m.group(2) or ""}

    async def _execute_chat_action(self, action: dict[str, Any], websocket: Any) -> None:
        """Execute a scan action detected from chat intent."""
        act = action["action"]
        if act == "START_SCAN":
            # If scan already running, skip
            if hasattr(self, "_standalone_runner") and self._standalone_runner:
                try:
                    if self._standalone_runner.is_running:
                        logger.info("Agent requested scan start but scan already running")
                        return
                except Exception:
                    pass  # Runner in bad state — allow restart
            try:
                from .runner import StandaloneReconRunner
                import asyncio as _aio

                target = self._state.target_url
                if not target:
                    logger.warning("Agent scan: no target URL")
                    return

                # Only reset state if no existing findings
                if not self._state.findings:
                    from .state import DashboardState
                    self._state = DashboardState(target)
                    self._diff_push_seq = 0

                loop = _aio.get_running_loop()

                def _event_push(event: dict[str, Any]) -> None:
                    try:
                        evt_type = event.get("type", "")
                        if evt_type not in ("console_output", "console_batch"):
                            self._state.apply_event(event)
                        self._enqueue_coalescable(event, loop)
                    except Exception as _exc:
                        logger.warning("Agent scan event push: %s", _exc)

                # Parse specific phases if provided
                phases_arg = action.get("args", "").strip()
                selected_phases = [p.strip() for p in phases_arg.split(",") if p.strip()] if phases_arg else None

                self._standalone_runner = StandaloneReconRunner(
                    target_url=target,
                    dashboard_port=self.http_port,
                    selected_phases=selected_phases if selected_phases else None,
                    event_callback=_event_push,
                    phase_settings=dict(self._state.phase_settings),
                    parallel=getattr(self, "_default_parallel", True),
                    max_parallel_slots=getattr(self, "_default_max_parallel_slots", 4),
                )
                self._standalone_runner.start()
                logger.info("Agent auto-started scan for %s", target)
                await websocket.send(json.dumps({
                    "type": "scan_status",
                    "status": "running",
                    "message": "Scan started by agent",
                }))
            except Exception as exc:
                logger.warning("Agent scan start failed: %s", exc, exc_info=True)
        elif act == "PAUSE_SCAN":
            if hasattr(self, "_standalone_runner") and self._standalone_runner:
                self._standalone_runner.pause()
                logger.info("Agent paused scan")
        elif act == "STOP_SCAN":
            if hasattr(self, "_standalone_runner") and self._standalone_runner:
                self._standalone_runner.abort()
                logger.info("Agent stopped scan")

    async def _info_scan_watcher(
        self,
        websocket,
        bridge,
        original_question: str,
        targeted_phases: list,
        poll_interval: float = 4.0,
        max_wait: float = 300.0,
    ):
        """Watch for findings during targeted scan; send batched live updates + auto-complete."""
        import time as _time

        _start = _time.monotonic()
        _last_findings_count = len(self._state.findings)
        _seen_titles: set = set()  # dedup across batches
        _reported_titles: list = []  # track what user has seen for anti-dup
        _total_reported = 0
        _PRIORITY_SEVS = {"critical", "high"}  # only surface these in live updates
        _significant_batch: list = []  # collect high-sev for mini-analysis
        _last_phase_snap: dict = {}  # track phase status changes

        # Extract domain for context-aware tips
        try:
            from urllib.parse import urlparse as _urlparse
            _target_domain = _urlparse(
                self._state.target_url or ""
            ).hostname or "the target"
        except Exception:
            _target_domain = "the target"

        def _exploitability(finding: dict) -> str:
            """Classify exploitability from finding metadata."""
            _cat = (finding.get("category") or "").lower()
            _conf = finding.get("confirmed")
            _param = finding.get("parameter", "")
            _pay = finding.get("payload", "")
            _sev2 = (finding.get("severity") or "").lower()
            if _conf or _cat in (
                "injection", "xss", "sqli", "rce",
                "command-injection",
            ):
                return "trivial (no auth required)"
            if _pay and _param:
                return "trivial (payload + parameter known)"
            if _cat in (
                "misconfiguration", "information-disclosure",
                "exposure", "source-map", "email-security",
                "dns", "cors", "headers",
            ):
                return "trivial (publicly accessible)"
            if _cat in (
                "authentication", "authorization", "idor",
                "privilege-escalation", "session", "csrf",
                "ssrf",
            ):
                return "moderate (requires valid session)"
            if _sev2 == "critical":
                return "trivial (critical severity)"
            return "moderate"

        def _proof_signal(finding: dict) -> str:
            """Build evidence snippet from finding metadata."""
            parts = []
            _ep = finding.get("url", "")
            if _ep:
                parts.append(f"Endpoint: `{_ep[:100]}`")
            _param = finding.get("parameter", "")
            if _param:
                parts.append(f"Param: `{_param}`")
            _pay = finding.get("payload", "")
            if _pay:
                parts.append(
                    f"Payload: `{str(_pay)[:80]}`"
                )
            _curl = finding.get("curl_command", "")
            if _curl:
                parts.append(
                    f"Reproduce: `{str(_curl)[:100]}`"
                )
            _confirmed = finding.get("confirmed")
            if _confirmed:
                parts.append("Confirmed: \u2705")
            _tool = finding.get("source_tool", "")
            if _tool:
                parts.append(f"Source: {_tool}")
            return " \u2502 ".join(parts) if parts else ""

        def _context_tip(finding: dict, domain: str) -> str:
            """Generate context-aware actionable tip."""
            _rem = (finding.get("remediation") or "").strip()
            _desc = (finding.get("description") or "").strip()
            _det = (finding.get("detail") or "").strip()
            _raw = _rem or _desc or _det
            if not _raw:
                return ""
            tip = _raw.split("\n")[0].strip()[:180]
            # Inject domain context
            if domain and domain != "the target":
                _placeholders = (
                    "the domain", "your domain",
                    "the site", "the target",
                    "the host", "your site",
                )
                _replaced = False
                for ph in _placeholders:
                    if ph in tip.lower():
                        tip = tip.replace(ph, domain)
                        tip = tip.replace(
                            ph.title(), domain
                        )
                        _replaced = True
                        break
                if not _replaced and domain not in tip.lower():
                    tip += f" for {domain}"
            return tip

        def _fix_effort(finding: dict) -> str:
            """Estimate fix effort from finding category."""
            _cat = (finding.get("category") or "").lower()
            _title = (finding.get("title") or "").lower()
            # DNS / email records
            if _cat in ("dns", "email-security") or any(
                k in _title for k in ("spf", "dmarc", "dkim", "dns")
            ):
                return "Low (5\u201310 min, DNS record change)"
            # Security headers
            if _cat in ("headers", "security-headers") or any(
                k in _title for k in (
                    "header", "hsts", "x-frame",
                    "content-security", "csp",
                )
            ):
                return "Low (10\u201315 min, server config)"
            # Source maps / info disclosure
            if _cat in (
                "source-map", "information-disclosure", "exposure",
            ) or "source map" in _title:
                return "Low (build config change)"
            # CORS / misc config
            if _cat in ("cors", "misconfiguration"):
                return "Low\u2013Medium (15\u201330 min, config change)"
            # Auth / session
            if _cat in (
                "authentication", "authorization", "session",
                "csrf", "idor", "privilege-escalation",
            ):
                return "Medium (1\u20132 hours, code change)"
            # Injection / RCE
            if _cat in (
                "injection", "xss", "sqli", "rce",
                "command-injection", "ssrf",
            ):
                return "High (2\u20134 hours, code refactor)"
            return "Medium (varies)"

        def _fmt_finding(
            finding: dict, sev: str, title: str,
            url: str, domain: str,
        ) -> str:
            """Format a finding with tip, exploitability, proof."""
            _line = f"- **[{sev.upper()}]** {title}"
            if url:
                _line += f" \u2014 `{url}`"
            _tip = _context_tip(finding, domain)
            if _tip:
                _line += f"\n  \u2192 *{_tip[:160]}*"
            _exploit = _exploitability(finding)
            _line += (
                f"\n  \u26a1 Exploitability: **{_exploit}**"
            )
            _proof = _proof_signal(finding)
            if _proof:
                _line += f"\n  \U0001f50d {_proof}"
            _effort = _fix_effort(finding)
            _line += f"\n  \U0001f527 Fix Effort: **{_effort}**"
            return _line

        try:
            while (_time.monotonic() - _start) < max_wait:
                await asyncio.sleep(poll_interval)

                runner_alive = bool(
                    self._standalone_runner and self._standalone_runner.is_running
                )

                # -- Progress visualization (only when changed) --
                _cur_snap = {p: self._state.phase_status.get(p, "pending") for p in targeted_phases}
                _progress_changed = _cur_snap != _last_phase_snap
                _phase_lines = []
                if _progress_changed:
                    _last_phase_snap = dict(_cur_snap)
                for p in targeted_phases:
                    _ps = self._state.phase_status.get(p, "pending")
                    if _ps == "completed":
                        _bar = "\u2588" * 10
                        _icon = "\u2705"
                    elif _ps == "running":
                        _bar = "\u2588" * 5 + "\u2591" * 5
                        _icon = "\u23f3"
                    elif _ps in ("error", "degraded"):
                        _bar = "\u2588" * 7 + "\u2591" * 3
                        _icon = "\u26a0\ufe0f"
                    else:
                        _bar = "\u2591" * 10
                        _icon = "\u23f8\ufe0f"
                    _phase_lines.append(f"{_icon} {p}: {_bar} ({_ps})")

                # -- Batch, dedup, priority-filter new findings --
                current_count = len(self._state.findings)
                update_parts = []
                if current_count > _last_findings_count:
                    new_findings = self._state.findings[_last_findings_count:]
                    _last_findings_count = current_count

                    for f in new_findings:
                        sev = (f.get("severity") or "info").lower()
                        title = f.get("title") or f.get("name") or f.get("type", "Finding")
                        url = f.get("url", "")
                        # Dedup by normalized title
                        _norm = title.strip().lower()
                        if _norm in _seen_titles:
                            continue
                        _seen_titles.add(_norm)

                        # Priority filter: only high/critical in live stream
                        if sev in _PRIORITY_SEVS:
                            _line = _fmt_finding(f, sev, title, url, _target_domain)
                            update_parts.append(_line)
                            _reported_titles.append(title)
                            _significant_batch.append(f)
                        elif sev == "medium":
                            _reported_titles.append(title)
                            # medium: count but only show if < 5 high/crit
                            if len(update_parts) < 3:
                                _line = _fmt_finding(f, sev, title, url, _target_domain)
                                update_parts.append(_line)

                    # Cap at 5 per message
                    _overflow = len(update_parts) - 5
                    if _overflow > 0:
                        update_parts = update_parts[:5]
                        update_parts.append(f"*...and {_overflow} more notable findings*")

                # Send update if we have findings OR progress actually changed
                if update_parts or (_phase_lines and _progress_changed):
                    self._llm_chat_msg_seq += 1
                    _update_mid = self._llm_chat_msg_seq
                    _total_reported += len(update_parts)

                    _msg_parts = []
                    if _phase_lines:
                        _msg_parts.append("**Scan Progress:**\n" + "\n".join(_phase_lines))
                    if update_parts:
                        _msg_parts.append("\U0001f4e1 **New findings:**\n" + "\n".join(update_parts))
                    update_text = "\n\n".join(_msg_parts)

                    try:
                        await websocket.send(json.dumps({
                            "type": "llm_chat_chunk",
                            "text": update_text,
                            "msg_id": _update_mid,
                        }))
                        await websocket.send(json.dumps({
                            "type": "llm_chat_done",
                            "content": update_text,
                            "msg_id": _update_mid,
                        }))
                        self._state.apply_event({
                            "type": "llm_chat_message",
                            "role": "assistant",
                            "content": update_text[:500],
                        })
                        self._persist_chat_message("assistant", update_text[:2000])
                    except Exception:
                        return

                # -- Mini-analysis burst: when significant findings accumulate --
                if len(_significant_batch) >= 3:
                    _sev_counts = {}
                    for _sf in _significant_batch:
                        _s = (_sf.get("severity") or "info").upper()
                        _sev_counts[_s] = _sev_counts.get(_s, 0) + 1
                    _sev_text = ", ".join(f"{v} {k}" for k, v in sorted(_sev_counts.items()))
                    _titles_sample = [_sf.get("title", "?")[:60] for _sf in _significant_batch[:3]]
                    _titles_joined = ", ".join(_titles_sample)
                    _mini = (
                        f"\U0001f9e0 **Initial observation:** {_sev_text} notable findings so far. "
                        f"Key issues include: {_titles_joined}. "
                        "I'm correlating these against your original question and will "
                        "provide prioritized remediation steps when all phases complete."
                    )
                    _significant_batch.clear()
                    self._llm_chat_msg_seq += 1
                    _mini_mid = self._llm_chat_msg_seq
                    try:
                        await websocket.send(json.dumps({
                            "type": "llm_chat_chunk",
                            "text": _mini,
                            "msg_id": _mini_mid,
                        }))
                        await websocket.send(json.dumps({
                            "type": "llm_chat_done",
                            "content": _mini,
                            "msg_id": _mini_mid,
                        }))
                        self._state.apply_event({
                            "type": "llm_chat_message",
                            "role": "assistant",
                            "content": _mini[:500],
                        })
                        self._persist_chat_message("assistant", _mini[:500])
                    except Exception:
                        return

                all_done = all(
                    self._state.phase_status.get(p, "pending")
                    in ("completed", "error", "degraded", "skipped")
                    for p in targeted_phases
                )

                if all_done or not runner_alive:
                    break

            # -- Final comprehensive LLM response --
            await asyncio.sleep(2)

            self._llm_chat_msg_seq += 1
            _final_mid = self._llm_chat_msg_seq

            try:
                await websocket.send(json.dumps({
                    "type": "llm_chat_thinking",
                    "stage": "generating",
                    "message": "Analyzing complete scan results\u2026",
                    "msg_id": _final_mid,
                }))
            except Exception:
                return

            _sc = self._build_agent_chat_context(query=original_question)

            # Context anchoring + anti-duplicate instruction
            _fc = len(self._state.findings)
            _already_shown = ", ".join(t[:60] for t in _reported_titles[:10])
            # Build severity breakdown for context
            _sev_breakdown = {}
            for _ff in self._state.findings:
                _fs = (_ff.get("severity") or "info").upper()
                _sev_breakdown[_fs] = _sev_breakdown.get(_fs, 0) + 1
            _sev_summary = ", ".join(
                f"{v} {k}" for k, v in sorted(_sev_breakdown.items())
            )
            # Collect unique categories
            _cats_final = set()
            for _ff in self._state.findings:
                _c = (_ff.get("category") or "").lower()
                if _c:
                    _cats_final.add(_c)
            _cats_str = ", ".join(sorted(_cats_final)[:8]) if _cats_final else "various"

            # Build evidence summary for proof grounding
            _evidence_items = []
            for _ef in self._state.findings:
                _et = (_ef.get("title") or "")[:60]
                _eu = _ef.get("url", "")
                _ep = _ef.get("payload", "")
                _ec = _ef.get("curl_command", "")
                _econf = _ef.get("confirmed")
                if _eu or _ep or _ec or _econf:
                    _ev_parts = [f'"{_et}"']
                    if _eu:
                        _ev_parts.append(f"endpoint={_eu[:80]}")
                    if _ep:
                        _ev_parts.append(f"payload={str(_ep)[:60]}")
                    if _ec:
                        _ev_parts.append(f"curl={str(_ec)[:80]}")
                    if _econf:
                        _ev_parts.append("confirmed=yes")
                    _evidence_items.append(" | ".join(_ev_parts))
            _evidence_block = "\n".join(_evidence_items[:15]) if _evidence_items else "No raw evidence captured"

            # ---- Auto-Grouping Engine ----
            _GROUP_MAP = {
                "auth_issues": (
                    "authentication", "authorization", "idor",
                    "privilege-escalation", "session", "csrf",
                ),
                "misconfigurations": (
                    "misconfiguration", "headers",
                    "security-headers", "cors", "dns",
                ),
                "exposure": (
                    "information-disclosure", "exposure",
                    "source-map", "email-security",
                ),
                "injection": (
                    "injection", "xss", "sqli", "rce",
                    "command-injection", "ssrf",
                ),
            }
            _grouped: dict = {g: [] for g in _GROUP_MAP}
            _grouped["other"] = []
            for _gf in self._state.findings:
                _gc = (_gf.get("category") or "").lower()
                _placed = False
                for _gname, _gcats in _GROUP_MAP.items():
                    if _gc in _gcats:
                        _grouped[_gname].append(_gf)
                        _placed = True
                        break
                if not _placed:
                    _grouped["other"].append(_gf)
            _group_summary_parts = []
            _GROUP_LABELS = {
                "auth_issues": "\U0001f510 Authentication & Authorization",
                "misconfigurations": "\u2699\ufe0f Misconfigurations",
                "exposure": "\U0001f4e1 Information Exposure",
                "injection": "\U0001f489 Injection & Code Execution",
                "other": "\U0001f4cb Other Findings",
            }
            for _gname in ("auth_issues", "misconfigurations",
                           "exposure", "injection", "other"):
                _glist = _grouped[_gname]
                if not _glist:
                    continue
                _glabel = _GROUP_LABELS[_gname]
                _gtitles = [(_gf.get("title") or "?")[:50]
                            for _gf in _glist[:6]]
                _gsevs = {}
                for _gf in _glist:
                    _gs = (_gf.get("severity") or "info").upper()
                    _gsevs[_gs] = _gsevs.get(_gs, 0) + 1
                _gsev_str = ", ".join(
                    f"{v} {k}" for k, v in sorted(_gsevs.items())
                )
                _gblock = (
                    f"{_glabel} ({len(_glist)} findings: {_gsev_str}):\n"
                    + "\n".join(f"  - {t}" for t in _gtitles)
                )
                if len(_glist) > 6:
                    _gblock += f"\n  ... and {len(_glist)-6} more"
                _group_summary_parts.append(_gblock)
            _grouped_findings_str = (
                "\n\n".join(_group_summary_parts)
                if _group_summary_parts
                else "No findings to group"
            )

            # ---- Severity Re-Evaluation via Chains ----
            _chain_upgrades = []
            # Check: exposure + misconfiguration chain
            _n_exposure = len(_grouped.get("exposure", []))
            _n_misconfig = len(_grouped.get("misconfigurations", []))
            _n_auth = len(_grouped.get("auth_issues", []))
            _n_injection = len(_grouped.get("injection", []))
            # Medium-severity chain detection
            _medium_findings = [
                f for f in self._state.findings
                if (f.get("severity") or "").lower() == "medium"
            ]
            if len(_medium_findings) >= 3:
                # Check if mediums span multiple groups (chain potential)
                _med_groups = set()
                for _mf in _medium_findings:
                    _mc = (_mf.get("category") or "").lower()
                    for _gn, _gcs in _GROUP_MAP.items():
                        if _mc in _gcs:
                            _med_groups.add(_gn)
                            break
                if len(_med_groups) >= 2:
                    _chain_titles = [(_mf.get("title") or "?")[:40]
                                     for _mf in _medium_findings[:4]]
                    _mg_str = ", ".join(sorted(_med_groups))
                    _ct_str = ", ".join(_chain_titles)
                    _chain_upgrades.append(
                        f"CHAIN UPGRADE: {len(_medium_findings)} medium "
                        f"findings across {len(_med_groups)} categories "
                        f"({_mg_str}) form a "
                        f"potential exploit chain. Combined severity: HIGH. "
                        f"Findings: {_ct_str}"
                    )
            if _n_exposure >= 2 and _n_misconfig >= 1:
                _chain_upgrades.append(
                    "CHAIN: Information exposure + misconfiguration = "
                    "attackers can map internal structure then exploit "
                    "weak configurations. Combined severity: HIGH."
                )
            if _n_auth >= 1 and _n_injection >= 1:
                _chain_upgrades.append(
                    "CHAIN: Auth weakness + injection = "
                    "attackers bypass auth then execute code. "
                    "Combined severity: CRITICAL."
                )
            _chain_block = (
                "\n".join(_chain_upgrades)
                if _chain_upgrades
                else "No cross-category chain upgrades detected"
            )

            _augmented_msg = (
                f"{original_question}\n\n"
                f"[SYSTEM CONTEXT: The scan of {self._state.target_url or 'the target'} has "
                f"completed with {_fc} total findings ({_sev_summary}). "
                f"Finding categories: {_cats_str}.\n\n"
                f"GROUPED FINDINGS (pre-organized by category):\n{_grouped_findings_str}\n\n"
                f"SEVERITY CHAIN ANALYSIS:\n{_chain_block}\n\n"
                f"EVIDENCE DATA (reference these to prove findings are real):\n{_evidence_block}\n\n"
                f"Findings already shown in live updates: {_already_shown}.\n\n"
                "RESPONSE FORMAT INSTRUCTIONS:\n\n"
                "1. RESTATE & CONFIRM: Start by restating what the user asked, "
                "confirm what was scanned, and state total findings.\n\n"
                "2. FINDING ANALYSIS (do NOT re-list what user already saw \u2014 instead, "
                "reference them: 'As observed in the live updates, the source map leak...'). "
                "Use the GROUPED FINDINGS above to organize your analysis by category. "
                "For each finding group:\n"
                "   - What it means in practical terms\n"
                "   - Real-world risk and business impact\n"
                "   - Exploitability: trivial/moderate/complex with explanation\n"
                "   - Evidence: cite the specific endpoint, payload, or proof\n"
                "   - Concrete fix with specifics (e.g. exact DNS record, exact header)\n\n"
                "3. \U0001f47e IF I WERE AN ATTACKER: Write a section from the attacker's perspective. "
                "Explain how an attacker would combine these findings into a realistic attack. "
                "Be specific: 'An attacker could use the exposed source map at [endpoint] to "
                "discover internal API routes, then combine with [misconfiguration] to...' "
                "This must reference actual findings and endpoints from the evidence data.\n\n"
                "4. ATTACK CHAINS: Present as numbered sequences. If the SEVERITY CHAIN ANALYSIS "
                "above shows chain upgrades, incorporate them and explain why the combined "
                "severity is elevated:\n"
                "   Attack Chain 1:\n"
                "   1. [Finding A] \u2192 enables [action]\n"
                "   2. [Finding B] \u2192 escalates to [impact]\n"
                "   \u2192 Combined Severity: [upgraded severity if applicable]\n"
                "   \u2192 Result: [ultimate impact]\n\n"
                "5. PRIORITIZED REMEDIATION PLAN with effort estimates:\n"
                "   \U0001f534 IMMEDIATE (fix today):\n"
                "     - [finding] \u2014 Fix Effort: [Low/Med/High] ([time estimate])\n"
                "   \U0001f7e1 SOON (this week):\n"
                "     - [finding] \u2014 Fix Effort: [Low/Med/High] ([time estimate])\n"
                "   \U0001f535 PLANNED (this month):\n"
                "     - [finding] \u2014 Fix Effort: [Low/Med/High] ([time estimate])\n\n"
                "6. \U0001f9ea WHAT TO TEST NEXT: Based on the findings, recommend specific "
                "follow-up tests. Examples:\n"
                "   - Test authentication on exposed endpoints found at [url]\n"
                "   - Attempt parameter tampering on [endpoint] using discovered [param]\n"
                "   - Check for privilege escalation using IDs/paths from source maps\n"
                "   - Fuzz [endpoint] with payloads targeting [vulnerability type]\n"
                "   Be specific to the actual findings \u2014 reference real endpoints and params.\n\n"
                "7. DIRECT ANSWER: Conclude by explicitly answering the user's "
                "original question with evidence gathered.]"
            )

            collected_content = ""
            _hw = getattr(getattr(bridge, "config", None), "chat_history_window", 6)
            try:
                async with self._llm_chat_lock:
                    async for chunk in bridge.agent_chat_stream(
                        message=_augmented_msg,
                        scan_context=_sc,
                        chat_history=self._state.llm_chat_history[-_hw:],
                    ):
                        text_piece = chunk.get("text", "")
                        is_done = chunk.get("done", False)
                        if text_piece:
                            collected_content += text_piece
                            await websocket.send(json.dumps({
                                "type": "llm_chat_chunk",
                                "text": text_piece,
                                "msg_id": _final_mid,
                            }))
                        if is_done:
                            break
            except Exception as exc:
                logger.warning("Info scan watcher LLM stream error: %s", exc)
                collected_content = collected_content or f"Scan completed but LLM analysis failed: {exc}"

            import re as _re
            content = _re.sub(r'\[ACTION:[^\]]+\]', '', collected_content).strip()
            content = _re.sub(r'\[SYSTEM CONTEXT:[^\]]*\]', '', content).strip()

            self._state.apply_event({
                "type": "llm_chat_message",
                "role": "assistant",
                "content": content[:500],
            })
            self._persist_chat_message("assistant", content[:2000])

            try:
                await websocket.send(json.dumps({
                    "type": "llm_chat_done",
                    "content": content,
                    "msg_id": _final_mid,
                }))
            except Exception:
                pass

            self._info_watcher_task = None

        except asyncio.CancelledError:
            logger.debug("Info scan watcher cancelled")
            self._info_watcher_task = None
        except Exception as exc:
            logger.warning("Info scan watcher error: %s", exc)
            self._info_watcher_task = None


    # \xe2\x94\x80\xe2\x94\x80 Payout Metrics Endpoints \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80

    def _ensure_payout_tracker(self):
        """Lazy-init the payout metrics tracker."""
        if self._payout_tracker is not None:
            return self._payout_tracker
        try:
            from .payout_metrics import PayoutMetricsTracker
            import pathlib as _pl
            _db = _pl.Path(self._state.target_url.replace("://", "_").replace("/", "_")[:40] + "_payout.db")
            self._payout_tracker = PayoutMetricsTracker(db_path=_db)
        except Exception as exc:
            logger.debug("PayoutMetrics init failed: %s", exc)
            from .payout_metrics import PayoutMetricsTracker
            self._payout_tracker = PayoutMetricsTracker()
        return self._payout_tracker

    async def _handle_payout_metrics(self, request) -> Any:
        """GET /api/payout-metrics - current session snapshot."""
        from aiohttp import web
        try:
            tracker = self._ensure_payout_tracker()
            # Compute from current state
            _findings = self._state.findings
            _sev = {}
            _biz = 0
            _misc = 0
            _BIZ_CATS = {"authentication","authorization","idor","privilege-escalation","session","csrf","business-logic","race-condition","ssrf"}
            _MISC_CATS = {"misconfiguration","headers","security-headers","cors","dns","email-security","information-disclosure","exposure","source-map"}
            for f in _findings:
                s = (f.get("severity") or "info").lower()
                _sev[s] = _sev.get(s, 0) + 1
                c = (f.get("category") or "").lower()
                if c in _BIZ_CATS:
                    _biz += 1
                elif c in _MISC_CATS:
                    _misc += 1
            total = max(len(_findings), 1)
            # Chain count from exploit graph + QuickCorrelator
            _chains_detected = 0
            try:
                from ..exploit_chains.exploit_graph import get_exploit_graph_engine
                _eg = get_exploit_graph_engine()
                _chains_detected = len(getattr(_eg, "_transitions", []))
            except Exception:
                pass
            # S3-FIX: Also check QuickCorrelator chains from runner
            if self._standalone_runner is not None:
                _qc = getattr(self._standalone_runner, "_correlation_attack_chains", 0)
                if _qc > _chains_detected:
                    _chains_detected = _qc
            result = {
                "scan_id": getattr(self, "_session_id", ""),
                "target_url": self._state.target_url,
                "scan_start": self._state.started_at,
                "first_finding_time": self._state.first_finding_time,
                "ttff_seconds": self._state.ttff_seconds,
                "total_findings": len(_findings),
                "severity_breakdown": _sev,
                "business_logic_findings": _biz,
                "misconfig_findings": _misc,
                "attacker_thinking_ratio": round(_biz / total, 4),
                "chains_detected": _chains_detected,
                "confirmed_findings": sum(
                    1 for f in _findings if f.get("confirmed")
                ),
                "confirmation_rate": round(
                    sum(1 for f in _findings if f.get("confirmed")) / total, 4
                ),
                "signal_quality": {
                    "high_value_ratio": round(
                        (_sev.get("critical", 0) + _sev.get("high", 0)) / total, 4
                    ),
                    "attacker_focus": round(_biz / total, 4),
                    "evidence_rate": round(
                        sum(1 for f in _findings if f.get("_has_evidence") or f.get("evidence") or f.get("curl_command") or f.get("url") or f.get("payload")) / total, 4
                    ),
                },
            }
            return web.json_response(result)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_payout_history(self, request) -> Any:
        """GET /api/payout-metrics/history - historical metrics."""
        from aiohttp import web
        try:
            tracker = self._ensure_payout_tracker()
            limit = int(request.query.get("limit", "50"))
            return web.json_response({"history": tracker.get_history(limit)})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_payout_consistency(self, request) -> Any:
        """GET /api/payout-metrics/consistency - cross-target consistency."""
        from aiohttp import web
        try:
            tracker = self._ensure_payout_tracker()
            return web.json_response({"consistency": tracker.get_cross_target_consistency()})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_payout_ttff(self, request) -> Any:
        """GET /api/payout-metrics/ttff - TTFF trend."""
        from aiohttp import web
        try:
            tracker = self._ensure_payout_tracker()
            return web.json_response({"ttff_trend": tracker.get_ttff_trend()})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_payout_chains(self, request) -> Any:
        """GET /api/payout-metrics/chains - chain conversion funnel."""
        from aiohttp import web
        try:
            tracker = self._ensure_payout_tracker()
            return web.json_response({"chain_funnel": tracker.get_chain_funnel()})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    async def _handle_payout_submission(self, request) -> Any:
        """POST /api/payout-metrics/submission - record a report submission."""
        from aiohttp import web
        try:
            body = await request.json()
            tracker = self._ensure_payout_tracker()
            tracker.record_submission(
                finding_id=body.get("finding_id", ""),
                platform=body.get("platform", ""),
                bounty_usd=float(body.get("bounty_usd", 0)),
                status=body.get("status", "pending"),
            )
            return web.json_response({"ok": True})
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=500)

    def _ensure_reasoning_engine(self) -> Any | None:
        if self._reasoning_engine is not None:
            return self._reasoning_engine
        if self._reasoning_engine_init_attempted:
            return None
        self._reasoning_engine_init_attempted = True
        llm = self._ensure_llm_bridge()
        self._reasoning_engine = llm_helpers.init_reasoning_engine(llm)
        return self._reasoning_engine

    def _ensure_agent_memory(self) -> Any | None:
        if self._agent_memory is not None:
            return self._agent_memory
        if self._agent_memory_init_attempted:
            return None
        self._agent_memory_init_attempted = True
        self._agent_memory = llm_helpers.init_agent_memory()
        return self._agent_memory

    def _update_llm_state_from_response(self, response: Any) -> None:
        llm_helpers.update_llm_state_from_response(self._state, response)

    # ── LLM API Endpoints (Phase 2) ─────────────────────────────────

    async def _handle_llm_status(self, _request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_status(self, _request)

    async def _handle_llm_chat(self, request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_chat(self, request)

    async def _handle_llm_chat_stream(self, request: Any) -> Any:
        """H-3: SSE streaming fallback for HTTP clients."""
        from . import routes_llm
        return await routes_llm.handle_llm_chat_stream(self, request)

    async def _handle_llm_feedback(self, request: Any) -> Any:
        """I-8: Store user quality feedback on LLM responses."""
        from . import routes_llm
        return await routes_llm.handle_llm_feedback(self, request)

    def _ensure_feedback_table(self) -> None:
        """I-8: Create the llm_feedback table if it doesn't exist."""
        import sqlite3
        db_path = getattr(self, "_agent_db_path", None)
        if not db_path:
            return
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS llm_feedback ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  ts REAL NOT NULL,"
                "  msg_idx INTEGER,"
                "  rating INTEGER NOT NULL,"
                "  prompt_hash TEXT,"
                "  prompt_preview TEXT,"
                "  response_preview TEXT"
                ")"
            )
            conn.commit()
        finally:
            conn.close()

    async def _handle_llm_explain_finding(self, request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_explain_finding(self, request)

    async def _handle_llm_suggest_next(self, request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_suggest_next(self, request)

    async def _handle_llm_history(self, request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_history(self, request)

    async def _handle_llm_clear_history(self, request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_clear_history(self, request)

    async def _handle_llm_dedup(self, request: Any) -> Any:
        from . import routes_llm
        return await routes_llm.handle_llm_dedup(self, request)

    # ── Cognitive Bridge (Unified Intelligence) endpoints ────────────

    def _get_cognitive_bridge(self):
        """Lazy-import the CognitiveBridge singleton."""
        from ..mcp.cognitive_bridge import CognitiveBridge
        return CognitiveBridge.get()

    async def _handle_cognitive_status(self, _request: Any) -> Any:
        from aiohttp import web
        bridge = self._get_cognitive_bridge()
        return web.json_response(bridge.get_status())

    async def _handle_cognitive_reason(self, request: Any) -> Any:
        from aiohttp import web
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        prompt = body.get("prompt", "")
        if not prompt:
            return web.json_response({"error": "prompt is required"}, status=400)
        bridge = self._get_cognitive_bridge()
        result = await bridge.reason(
            prompt=prompt,
            context=body.get("context"),
            include_memory=body.get("include_memory", True),
            depth=body.get("depth"),
        )
        return web.json_response(result)

    async def _handle_cognitive_memory(self, request: Any) -> Any:
        from aiohttp import web
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        query = body.get("query", "")
        if not query:
            return web.json_response({"error": "query is required"}, status=400)
        bridge = self._get_cognitive_bridge()
        result = await bridge.query_memory(query=query, limit=body.get("limit", 10))
        return web.json_response(result)

    async def _handle_cognitive_strategic(self, request: Any) -> Any:
        from aiohttp import web
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        question = body.get("question", "")
        if not question:
            return web.json_response({"error": "question is required"}, status=400)
        bridge = self._get_cognitive_bridge()
        result = await bridge.strategic_guidance(
            question=question,
            session_state=body.get("session_state"),
        )
        return web.json_response(result)

    async def _handle_cognitive_set_mode(self, request: Any) -> Any:
        from aiohttp import web
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        mode = body.get("mode", "")
        if not mode:
            return web.json_response({"error": "mode is required"}, status=400)
        bridge = self._get_cognitive_bridge()
        result = bridge.set_mode(mode)
        return web.json_response(result)

    async def _handle_cognitive_update_context(self, request: Any) -> Any:
        from aiohttp import web
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        key = body.get("key", "")
        if not key:
            return web.json_response({"error": "key is required"}, status=400)
        bridge = self._get_cognitive_bridge()
        ttl = body.get("ttl")
        bridge.update_shared_context(key, body.get("value"), ttl=float(ttl) if ttl is not None else None)
        return web.json_response({"ok": True, "key": key})

    async def _handle_cognitive_get_context(self, _request: Any) -> Any:
        from aiohttp import web
        key = _request.query.get("key")
        bridge = self._get_cognitive_bridge()
        ctx = bridge.get_shared_context(key)
        return web.json_response({"context": ctx})

    async def _handle_cognitive_traces(self, request: Any) -> Any:
        from aiohttp import web
        limit = int(request.query.get("limit", "10"))
        depth_filter = request.query.get("depth_filter")
        bridge = self._get_cognitive_bridge()
        traces = bridge.get_traces(limit=limit, depth_filter=depth_filter)
        return web.json_response({"traces": traces, "count": len(traces)})

    async def _handle_cognitive_trace_detail(self, request: Any) -> Any:
        from aiohttp import web
        trace_id = request.query.get("trace_id", "")
        if not trace_id:
            return web.json_response({"error": "trace_id is required"}, status=400)
        bridge = self._get_cognitive_bridge()
        trace = bridge.get_trace(trace_id)
        if trace is None:
            return web.json_response({"error": f"trace {trace_id} not found"}, status=404)
        return web.json_response({"trace": trace})

    async def _handle_cognitive_cache_stats(self, _request: Any) -> Any:
        from aiohttp import web
        bridge = self._get_cognitive_bridge()
        stats = bridge.get_cache_stats()
        return web.json_response(stats)

    async def _handle_cognitive_clear_caches(self, _request: Any) -> Any:
        from aiohttp import web
        bridge = self._get_cognitive_bridge()
        bridge.clear_caches()
        return web.json_response({"ok": True, "message": "All caches cleared"})

    async def _handle_cognitive_context_health(self, _request: Any) -> Any:
        from aiohttp import web
        bridge = self._get_cognitive_bridge()
        health = bridge.get_context_health()
        return web.json_response(health)

    # ── Reasoning Engine endpoints ───────────────────────────────────

    async def _handle_reasoning_hypotheses(self, request: Any) -> Any:
        from . import routes_reasoning
        return await routes_reasoning.handle_reasoning_hypotheses(self, request)

    async def _handle_reasoning_generate(self, request: Any) -> Any:
        from . import routes_reasoning
        return await routes_reasoning.handle_reasoning_generate(self, request)

    async def _handle_reasoning_trace(self, request: Any) -> Any:
        from . import routes_reasoning
        return await routes_reasoning.handle_reasoning_trace(self, request)

    async def _handle_reasoning_what_if(self, request: Any) -> Any:
        from . import routes_reasoning
        return await routes_reasoning.handle_reasoning_what_if(self, request)

    async def _handle_reasoning_traces_list(self, _request: Any) -> Any:
        from . import routes_reasoning
        return await routes_reasoning.handle_reasoning_traces_list(self, _request)

    # ── Intelligence Experience handlers ──────────────────────────────
    async def _handle_ix_feed(self, request: Any) -> Any:
        from . import routes_intelligence_experience
        return await routes_intelligence_experience.handle_thinking_feed(self, request)

    async def _handle_ix_summary(self, _request: Any) -> Any:
        from . import routes_intelligence_experience
        return await routes_intelligence_experience.handle_thinking_summary(self, _request)

    async def _handle_ix_decisions(self, request: Any) -> Any:
        from . import routes_intelligence_experience
        return await routes_intelligence_experience.handle_decision_detail(self, request)

    async def _handle_ix_strategies(self, _request: Any) -> Any:
        from . import routes_intelligence_experience
        return await routes_intelligence_experience.handle_strategy_simulations(self, _request)

    async def _handle_ix_learning(self, _request: Any) -> Any:
        from . import routes_intelligence_experience
        return await routes_intelligence_experience.handle_learning_trajectory(self, _request)

    async def _handle_agent_detailed_status(self, _request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_agent_detailed_status(self, _request)

    async def _handle_scan_start(self, request: Any) -> Any:
        """POST /api/scan/start"""
        import asyncio as _aio
        try:
            body = await request.json()
        except Exception:
            body = {}
        target = body.get("target") or self._state.target_url
        phases = body.get("phases")
        if not target:
            return web.json_response({"ok": False, "error": "No target URL"}, status=400)
        if hasattr(self, "_standalone_runner") and self._standalone_runner:
            try:
                if self._standalone_runner.is_running:
                    return web.json_response({"ok": False, "error": "Scan already running", "status": "running"}, status=409)
            except Exception:
                pass
        try:
            from .runner import StandaloneReconRunner
            if not self._state.findings:
                from .state import DashboardState
                self._state = DashboardState(target)
                self._diff_push_seq = 0
            elif self._state.target_url != target:
                from .state import DashboardState
                self._state = DashboardState(target)
                self._diff_push_seq = 0
            loop = _aio.get_running_loop()
            def _event_push(event):
                try:
                    evt_type = event.get("type", "")
                    if evt_type not in ("console_output", "console_batch"):
                        self._state.apply_event(event)
                    self._enqueue_coalescable(event, loop)
                except Exception as _exc:
                    logger.warning("Scan API event push: %s", _exc)
            selected = None
            if phases and isinstance(phases, list):
                selected = [str(p).strip() for p in phases if str(p).strip()]
            self._standalone_runner = StandaloneReconRunner(
                target_url=target,
                dashboard_port=self.http_port,
                selected_phases=selected if selected else None,
                event_callback=_event_push,
                phase_settings=dict(self._state.phase_settings),
                parallel=getattr(self, "_default_parallel", True),
                max_parallel_slots=getattr(self, "_default_max_parallel_slots", 4),
            )
            self._standalone_runner.start()
            logger.info("Scan API started for %s", target)
            return web.json_response({"ok": True, "status": "started", "target": target})
        except Exception as exc:
            logger.error("Scan API start failed: %s", exc, exc_info=True)
            return web.json_response({"ok": False, "error": str(exc)[:500]}, status=500)

    async def _handle_scan_stop(self, _request: Any) -> Any:
        """POST /api/scan/stop"""
        if hasattr(self, "_standalone_runner") and self._standalone_runner:
            try:
                self._standalone_runner.abort()
                return web.json_response({"ok": True, "status": "stopped"})
            except Exception as exc:
                return web.json_response({"ok": False, "error": str(exc)[:500]}, status=500)
        return web.json_response({"ok": False, "error": "No scan running"}, status=404)

    async def _handle_scan_status(self, _request: Any) -> Any:
        """GET /api/scan/status"""
        runner = getattr(self, "_standalone_runner", None)
        running = False
        current_phase = ""
        phases_completed = 0
        phases_total = 0
        if runner:
            try:
                running = runner.is_running
                current_phase = getattr(runner, "_current_phase", "")
                phases_completed = getattr(runner, "_phases_completed", 0)
                phases_total = getattr(runner, "_phases_total", 0)
            except Exception:
                pass
        fc = len(self._state.findings) if self._state.findings else 0
        return web.json_response({
            "ok": True,
            "scan_running": running,
            "target": self._state.target_url or "",
            "current_phase": current_phase,
            "phases_completed": phases_completed,
            "phases_total": phases_total,
            "findings_count": fc,
            "session_id": getattr(self, "_session_id", ""),
        })

    async def _handle_agent_start(self, request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_agent_start(self, request)

    async def _handle_agent_stop(self, _request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_agent_stop(self, _request)

    async def _handle_agent_pause(self, _request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_agent_pause(self, _request)

    async def _handle_agent_resume_loop(self, _request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_agent_resume_loop(self, _request)

    async def _handle_agent_cycles(self, request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_agent_cycles(self, request)

    async def _handle_memory_query(self, request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_memory_query(self, request)

    async def _handle_memory_episodes(self, request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_memory_episodes(self, request)

    async def _handle_memory_stats(self, _request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_memory_stats(self, _request)

    async def _handle_memory_feedback(self, request: Any) -> Any:
        from . import routes_agent
        return await routes_agent.handle_memory_feedback(self, request)

    def _subscribe_event_bus(self) -> None:
        bus, loop = event_bridge.subscribe(self._on_bus_event, self._bus_sub_ids)
        self._event_bus = bus
        self._bus_loop = loop

    def _unsubscribe_event_bus(self) -> None:
        event_bridge.unsubscribe(self._event_bus, self._bus_sub_ids)
        self._event_bus = None

    def _on_bus_event(self, event: Any) -> None:
        data = event_bridge.translate_bus_event(
            event, self._bus_seen_ids, self._BUS_SEEN_MAX,
        )
        if data is None:
            return
        loop = self._bus_loop
        if loop is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(self._process_bus_event, data)
            except RuntimeError:
                pass

    def _process_bus_event(self, event_dict: dict[str, Any]) -> None:
        try:
            self._state.apply_event(event_dict)
            event_type = event_dict.get("type", "")
            if event_type in self._COALESCABLE_TYPES:
                flush_now = False
                with self._event_batch_lock:
                    self._event_batch.append(event_dict)
                    if len(self._event_batch) >= self._BATCH_MAX:
                        flush_now = True
                if flush_now:
                    asyncio.ensure_future(self._flush_event_batch())
                else:
                    try:
                        loop = asyncio.get_running_loop()
                        self._schedule_batch_flush(loop)
                    except RuntimeError:
                        pass
            else:
                asyncio.ensure_future(self._broadcast(event_dict))
        except Exception as exc:
            logger.debug("EventBus->dashboard processing error: %s", exc)

