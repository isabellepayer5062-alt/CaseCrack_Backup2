"""Tier 4A unified horizontal sweep.

Runs 10 idempotent passes over the 27 recovered modules:
  4A.1  Per-module typed Error classes (factory injection)
  4A.2  async mirror methods via asyncio.to_thread
  4A.3  Blanket @_rs_retry on network + integrations public methods
  4A.4  validate_dict / _validate_payload availability
  4A.5  TTLCache instances on dns/http_fp/sonar/jira/dojo
  4A.6  RLock on proxy_chain/kg/session/regression/webhook
  4A.7  dry_run flag + _check_dry_run() helper on every class
  4A.8  paginate_search() on jira/sonar/dojo
  4A.9  HMAC signing in webhook_dispatcher + slack_notifier
  4A.10 SQLitePersistMixin on session/kg/regression/webhook

Markers used (one per sweep, idempotent):
  # __TIER4A_ERRORS__
  # __TIER4A_ASYNC_MIRRORS__
  # __TIER4A_RETRY_BLANKET__
  # __TIER4A_VALIDATORS__
  # __TIER4A_TTLCACHE__
  # __TIER4A_RLOCK__
  # __TIER4A_DRYRUN__
  # __TIER4A_PAGINATION__
  # __TIER4A_HMAC__
  # __TIER4A_PERSIST__
"""
from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import List, Tuple

ROOT = Path('CaseCrack/tools/burp_enterprise')

NETWORK = ['dns_resolver', 'http_fingerprint', 'proxy_chain', 'ssl_analyzer', 'traffic_analyzer']
INTEGRATIONS = ['ci_cd_pipeline', 'defect_dojo', 'jira_client', 'slack_notifier', 'sonarqube', 'webhook_dispatcher']
CAAP = ['caap_coordinator', 'chat_interface', 'compliance_checker', 'discovery_agent',
        'exploitation_agent', 'hypothesis_engine', 'knowledge_graph', 'recon_agent', 'session_orchestrator']
TESTING = ['api_fuzzer', 'benchmark_runner', 'compliance_validator', 'integration_harness',
           'load_tester', 'mock_server', 'regression_tracker']

ALL_MODULES: List[Tuple[str, str]] = (
    [('network', m) for m in NETWORK]
    + [('integrations', m) for m in INTEGRATIONS]
    + [('caap', m) for m in CAAP]
    + [('testing_tools', m) for m in TESTING]
)

# Modules targeted by specific sweeps
TTLCACHE_TARGETS = {'dns_resolver', 'http_fingerprint', 'sonarqube', 'jira_client', 'defect_dojo'}
RLOCK_TARGETS = {'proxy_chain', 'knowledge_graph', 'session_orchestrator', 'regression_tracker', 'webhook_dispatcher'}
PAGINATION_TARGETS = {'jira_client', 'sonarqube', 'defect_dojo'}
HMAC_TARGETS = {'webhook_dispatcher', 'slack_notifier'}
PERSIST_TARGETS = {'session_orchestrator', 'knowledge_graph', 'regression_tracker', 'webhook_dispatcher'}
RETRY_BLANKET_SUBS = {'network', 'integrations'}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def find_main_class(src: str):
    """Return (class_name, class_node) for the last non-dataclass class."""
    tree = ast.parse(src)
    main = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            is_dc = any(
                (isinstance(d, ast.Name) and d.id == 'dataclass') or
                (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == 'dataclass')
                for d in node.decorator_list
            )
            # Skip Enum-style classes too
            is_enum = any(
                (isinstance(b, ast.Name) and b.id in ('Enum', 'IntEnum', 'StrEnum')) or
                (isinstance(b, ast.Attribute) and b.attr in ('Enum', 'IntEnum', 'StrEnum'))
                for b in node.bases
            )
            if not is_dc and not is_enum:
                main = node
    return main


def get_class_lines(src: str, cls: ast.ClassDef) -> Tuple[int, int]:
    """Return 1-based (start_line, end_line) for a class."""
    return cls.lineno, getattr(cls, 'end_lineno', cls.lineno)


def append_to_class(src: str, cls: ast.ClassDef, block: str, marker: str) -> str:
    if marker in src:
        return src
    lines = src.splitlines()
    end = cls.end_lineno  # type: ignore[attr-defined]
    # Insert at end, preserving class indentation level (4 spaces)
    indent_block = '\n'.join('    ' + ln if ln.strip() else ln for ln in block.splitlines())
    insertion = '\n    ' + marker + '\n' + indent_block + '\n'
    # Insert AFTER the last line of class
    lines.insert(end, insertion)
    return '\n'.join(lines) + ('\n' if src.endswith('\n') else '')


def add_imports(src: str, imports: List[str]) -> str:
    """Add stdlib imports if missing. Adds after the first existing import block."""
    for imp in imports:
        if re.search(rf'^\s*{re.escape(imp)}\s*$', src, re.M):
            continue
        # Find last import line in first 60 lines
        lines = src.splitlines()
        last_import = 0
        for i, ln in enumerate(lines[:80]):
            if ln.startswith('import ') or ln.startswith('from '):
                last_import = i
        lines.insert(last_import + 1, imp)
        src = '\n'.join(lines) + ('\n' if src.endswith('\n') else '')
    return src


# ─────────────────────────────────────────────────────────────────────────────
# 4A.1 — Per-module Error classes
# ─────────────────────────────────────────────────────────────────────────────
def sweep_errors(sub: str, mod: str, src: str) -> str:
    if '# __TIER4A_ERRORS__' in src:
        return src
    cap = ''.join(p.capitalize() for p in mod.split('_'))
    block = f"""
# __TIER4A_ERRORS__
try:
    from .._recovered_support import make_error_classes as _rs_make_errors
    _RS_ERRORS = _rs_make_errors('{mod}')
    {cap}Error = _RS_ERRORS['{cap}Error']
    {cap}ConfigError = _RS_ERRORS['{cap}ConfigError']
    {cap}OperationError = _RS_ERRORS['{cap}OperationError']
    {cap}TimeoutError = _RS_ERRORS['{cap}TimeoutError']
except Exception:
    class {cap}Error(Exception): pass
    class {cap}ConfigError({cap}Error): pass
    class {cap}OperationError({cap}Error): pass
    class {cap}TimeoutError({cap}Error): pass
"""
    # Insert after the EventBus prelude block (look for __EVENTBUS_INJECTED_END__)
    if '# __EVENTBUS_INJECTED_END__' in src:
        return src.replace('# __EVENTBUS_INJECTED_END__',
                           '# __EVENTBUS_INJECTED_END__\n' + block, 1)
    # Fallback: after last import
    lines = src.splitlines()
    last_imp = 0
    for i, ln in enumerate(lines[:120]):
        if ln.startswith('import ') or ln.startswith('from '):
            last_imp = i
    lines.insert(last_imp + 1, block)
    return '\n'.join(lines) + ('\n' if src.endswith('\n') else '')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.2 — async mirrors
# ─────────────────────────────────────────────────────────────────────────────
LIFECYCLE_NAMES = {'health', 'reset', 'close', 'metrics_snapshot',
                   '__init__', '__enter__', '__exit__'}


def sweep_async_mirrors(src: str) -> str:
    if '# __TIER4A_ASYNC_MIRRORS__' in src:
        return src
    main = find_main_class(src)
    if main is None:
        return src
    src = add_imports(src, ['import asyncio'])
    # Re-parse since src changed
    tree = ast.parse(src)
    main = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            is_dc = any(
                (isinstance(d, ast.Name) and d.id == 'dataclass') or
                (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == 'dataclass')
                for d in node.decorator_list
            )
            is_enum = any(
                (isinstance(b, ast.Name) and b.id in ('Enum', 'IntEnum', 'StrEnum'))
                for b in node.bases
            )
            if not is_dc and not is_enum:
                main = node
    if main is None:
        return src
    # Collect public method names
    public_methods = []
    for item in main.body:
        if isinstance(item, ast.FunctionDef):
            n = item.name
            if n in LIFECYCLE_NAMES or n.startswith('_'):
                continue
            public_methods.append(n)
    if not public_methods:
        return src
    parts = []
    for n in public_methods:
        parts.append(
            f"async def {n}_async(self, *args, **kwargs):\n"
            f'    """Async mirror of :meth:`{n}` via asyncio.to_thread."""\n'
            f"    return await asyncio.to_thread(self.{n}, *args, **kwargs)\n"
        )
    block = '\n'.join(parts)
    return append_to_class(src, main, block, '# __TIER4A_ASYNC_MIRRORS__')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.3 — Blanket @_rs_retry on network/integrations
# ─────────────────────────────────────────────────────────────────────────────
def sweep_retry_blanket(sub: str, mod: str, src: str) -> str:
    if sub not in RETRY_BLANKET_SUBS:
        return src
    if '# __TIER4A_RETRY_BLANKET__' in src:
        return src
    main = find_main_class(src)
    if main is None:
        return src
    lines = src.splitlines()
    # For each public method that's not lifecycle and doesn't already have @_rs_retry,
    # insert decorator
    insertions: List[Tuple[int, str]] = []
    for item in main.body:
        if not isinstance(item, ast.FunctionDef):
            continue
        n = item.name
        if n in LIFECYCLE_NAMES or n.startswith('_'):
            continue
        # Skip pure getters
        if n.startswith(('get_', 'list_', 'is_', 'to_')):
            continue
        # Check existing decorators
        has_retry = False
        for d in item.decorator_list:
            try:
                src_d = ast.unparse(d)
            except Exception:
                src_d = ''
            if '_rs_retry' in src_d or 'retry' in src_d:
                has_retry = True
                break
        if has_retry:
            continue
        # Method definition line is item.lineno (1-based). Decorators precede it.
        first_line = item.decorator_list[0].lineno if item.decorator_list else item.lineno
        # Indentation of that line
        line_idx = first_line - 1
        indent = re.match(r'^(\s*)', lines[line_idx]).group(1)
        deco = (f"{indent}# __TIER4A_RETRY_BLANKET__\n"
                f"{indent}@_rs_retry(max_attempts=3, backoff=1.0, max_backoff=10.0, "
                f"on=(Exception,), operation='{mod}.{n}')")
        insertions.append((line_idx, deco))
    # Apply in reverse order to keep line indices stable
    for idx, dec in sorted(insertions, key=lambda x: -x[0]):
        lines.insert(idx, dec)
    if not insertions:
        # Add marker anyway so we don't reprocess
        return src + '\n# __TIER4A_RETRY_BLANKET__\n'
    return '\n'.join(lines) + ('\n' if src.endswith('\n') else '')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.4 — validators
# ─────────────────────────────────────────────────────────────────────────────
def sweep_validators(src: str) -> str:
    if '# __TIER4A_VALIDATORS__' in src:
        return src
    main = find_main_class(src)
    if main is None:
        return src
    block = """# __TIER4A_VALIDATORS__
def _validate_payload(self, value, *, required_keys=None, types=None, schema=None, name='payload'):
    \"\"\"Validate an inbound dict payload (Tier 4A).

    Wraps :func:`_recovered_support.validate_dict` so callers can do
    ``self._validate_payload(finding, required_keys=['id','severity'])``
    and receive a typed ``{Module}ConfigError`` on failure.
    \"\"\"
    try:
        from .._recovered_support import validate_dict as _rs_validate
        _rs_validate(value, schema=schema, required_keys=required_keys,
                     types=types, name=name)
    except ValueError as exc:
        cls = globals().get(self.__class__.__name__.replace('Client','').replace('Engine','')+'ConfigError')
        if cls is not None:
            raise cls(str(exc)) from exc
        raise
"""
    return append_to_class(src, main, block, '# __TIER4A_VALIDATORS__')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.5 — TTLCache instance on selected modules
# ─────────────────────────────────────────────────────────────────────────────
def sweep_ttlcache(mod: str, src: str) -> str:
    if mod not in TTLCACHE_TARGETS:
        return src
    if '# __TIER4A_TTLCACHE__' in src:
        return src
    main = find_main_class(src)
    if main is None:
        return src
    # Find __init__ and append cache init at its end
    init = None
    for item in main.body:
        if isinstance(item, ast.FunctionDef) and item.name == '__init__':
            init = item
            break
    lines = src.splitlines()
    if init is None:
        return src
    end = init.end_lineno  # type: ignore
    insert = (
        "        # __TIER4A_TTLCACHE__\n"
        "        try:\n"
        "            from .._recovered_support import TTLCache as _RsTTLCache\n"
        "            self._cache = _RsTTLCache(ttl=300.0, maxsize=1024)\n"
        "        except Exception:\n"
        "            self._cache = None"
    )
    lines.insert(end, insert)
    return '\n'.join(lines) + ('\n' if src.endswith('\n') else '')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.6 — RLock on selected modules
# ─────────────────────────────────────────────────────────────────────────────
def sweep_rlock(mod: str, src: str) -> str:
    if mod not in RLOCK_TARGETS:
        return src
    if '# __TIER4A_RLOCK__' in src:
        return src
    src = add_imports(src, ['import threading'])
    main = find_main_class(src)
    if main is None:
        return src
    init = None
    for item in main.body:
        if isinstance(item, ast.FunctionDef) and item.name == '__init__':
            init = item
            break
    if init is None:
        return src
    lines = src.splitlines()
    end = init.end_lineno  # type: ignore
    insert = (
        "        # __TIER4A_RLOCK__\n"
        "        self._lock = threading.RLock()"
    )
    lines.insert(end, insert)
    return '\n'.join(lines) + ('\n' if src.endswith('\n') else '')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.7 — dry_run flag + helper on every class
# ─────────────────────────────────────────────────────────────────────────────
def sweep_dryrun(mod: str, src: str) -> str:
    if '# __TIER4A_DRYRUN_METHODS__' in src:
        return src
    main = find_main_class(src)
    if main is None:
        return src
    init = None
    for item in main.body:
        if isinstance(item, ast.FunctionDef) and item.name == '__init__':
            init = item
            break
    lines = src.splitlines()
    if init is not None and '# __TIER4A_DRYRUN_INIT__' not in src:
        end = init.end_lineno  # type: ignore
        lines.insert(end, "        # __TIER4A_DRYRUN_INIT__\n        self._dry_run = False")
        src = '\n'.join(lines) + ('\n' if src.endswith('\n') else '')
        # Re-parse for class node
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == main.name:
                main = node
                break
    block = f"""# __TIER4A_DRYRUN_METHODS__
def enable_dry_run(self):
    \"\"\"Enable dry-run mode: action methods will emit MODULE_DRY_RUN events
    instead of executing side effects (Tier 4A).\"\"\"
    self._dry_run = True

def disable_dry_run(self):
    \"\"\"Disable dry-run mode (Tier 4A).\"\"\"
    self._dry_run = False

def _check_dry_run(self, method, **fields):
    \"\"\"Return a stub success payload + emit event if dry-run is active.

    Usage in action methods::

        def create_thing(self, ...):
            stub = self._check_dry_run('create_thing', target=target)
            if stub is not None:
                return stub
            # ... real implementation
    \"\"\"
    if not getattr(self, '_dry_run', False):
        return None
    try:
        from .._recovered_support import emit_dry_run as _rs_dry
        return _rs_dry('{mod}', method, **fields)
    except Exception:
        return {{'dry_run': True, 'module': '{mod}', 'method': method, 'ok': True}}
"""
    return append_to_class(src, main, block, '# __TIER4A_DRYRUN_METHODS__')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.8 — pagination on jira/sonar/dojo
# ─────────────────────────────────────────────────────────────────────────────
PAGINATION_BLOCKS = {
    'jira_client': '''# __TIER4A_PAGINATION__
def search_issues_paginated(self, jql, *, page_size=100, max_items=None):
    """Iterate Jira search results across pages (Tier 4A pagination).

    Yields :class:`JiraIssue` objects. Internally calls
    ``POST /rest/api/2/search`` with cursor-based offsets.
    """
    from .._recovered_support import paginate as _rs_paginate
    sess = self._create_session()
    if not sess or not self._config.base_url:
        return
    def _fetch(**params):
        try:
            resp = sess.post(
                self._api_url("search"),
                json={"jql": jql, "startAt": params.get("startAt", 0),
                      "maxResults": params.get("maxResults", page_size)},
                timeout=self._config.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {"issues": [], "total": 0}
    for raw in _rs_paginate(_fetch, page_param="startAt", size_param="maxResults",
                            items_key="issues", page_size=page_size, max_items=max_items):
        yield JiraIssue(
            key=raw.get("key", ""),
            summary=raw.get("fields", {}).get("summary", ""),
        )
''',
    'sonarqube': '''# __TIER4A_PAGINATION__
def search_issues_paginated(self, *, page_size=100, max_items=None,
                            severities=None, types=None):
    """Iterate SonarQube issues across pages (Tier 4A pagination)."""
    from .._recovered_support import paginate as _rs_paginate
    sess = self._create_session()
    if not sess or not self._config.base_url:
        return
    def _fetch(**params):
        q = {"componentKeys": self._config.project_key,
             "p": params.get("p", 1), "ps": params.get("ps", page_size)}
        if severities: q["severities"] = ",".join(severities)
        if types: q["types"] = ",".join(types)
        try:
            resp = sess.get(self._api_url("issues/search"), params=q,
                            timeout=self._config.timeout)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {"issues": [], "total": 0}
    # SonarQube uses 1-based 'p' page param
    for raw in _rs_paginate(_fetch, page_param="p", size_param="ps",
                            items_key="issues", page_size=page_size, max_items=max_items):
        yield raw
''',
    'defect_dojo': '''# __TIER4A_PAGINATION__
def get_findings_paginated(self, engagement_id=None, *, page_size=100, max_items=None):
    """Iterate DefectDojo findings across pages (Tier 4A pagination)."""
    from .._recovered_support import paginate as _rs_paginate
    sess = self._create_session()
    if not sess or not self._config.base_url:
        return
    def _fetch(**params):
        q = {"limit": params.get("limit", page_size),
             "offset": params.get("offset", 0)}
        if engagement_id: q["test__engagement"] = engagement_id
        try:
            resp = sess.get(self._api_url("findings/"), params=q,
                            timeout=self._config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                # DefectDojo wraps results in 'results' key
                data["issues"] = data.get("results", [])
                data["total"] = data.get("count", 0)
                return data
        except Exception:
            pass
        return {"issues": [], "total": 0}
    for raw in _rs_paginate(_fetch, page_param="offset", size_param="limit",
                            items_key="issues", page_size=page_size, max_items=max_items):
        yield raw
''',
}


def sweep_pagination(mod: str, src: str) -> str:
    if mod not in PAGINATION_TARGETS:
        return src
    if '# __TIER4A_PAGINATION__' in src:
        return src
    block = PAGINATION_BLOCKS[mod]
    main = find_main_class(src)
    if main is None:
        return src
    return append_to_class(src, main, block, '# __TIER4A_PAGINATION__')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.9 — HMAC signing in webhook + slack
# ─────────────────────────────────────────────────────────────────────────────
HMAC_BLOCKS = {
    'webhook_dispatcher': '''# __TIER4A_HMAC__
def _sign_payload(self, secret, payload):
    """Compute HMAC-SHA256 signature for outbound webhook payload (Tier 4A)."""
    try:
        from .._recovered_support import hmac_sign as _rs_hmac
        return _rs_hmac(secret or "", payload)
    except Exception:
        return ""

def verify_signature(self, secret, payload, signature):
    """Verify an inbound webhook signature (Tier 4A)."""
    try:
        from .._recovered_support import verify_hmac as _rs_verify
        return _rs_verify(secret or "", payload, signature or "")
    except Exception:
        return False
''',
    'slack_notifier': '''# __TIER4A_HMAC__
def _sign_payload(self, payload, *, signing_secret=None):
    """Sign Slack webhook payload with HMAC-SHA256 (Tier 4A).

    When ``signing_secret`` is provided, returns the ``v0=...`` Slack
    request-signature header value. Otherwise returns empty string.
    """
    secret = signing_secret or getattr(self._config, "signing_secret", "") or ""
    try:
        from .._recovered_support import hmac_sign as _rs_hmac
        return _rs_hmac(secret, payload)
    except Exception:
        return ""

def verify_slack_signature(self, payload, signature, *, signing_secret=None):
    """Verify Slack request signature (Tier 4A)."""
    secret = signing_secret or getattr(self._config, "signing_secret", "") or ""
    try:
        from .._recovered_support import verify_hmac as _rs_verify
        return _rs_verify(secret, payload, signature or "")
    except Exception:
        return False
''',
}


def sweep_hmac(mod: str, src: str) -> str:
    if mod not in HMAC_TARGETS:
        return src
    if '# __TIER4A_HMAC__' in src:
        return src
    main = find_main_class(src)
    if main is None:
        return src
    return append_to_class(src, main, HMAC_BLOCKS[mod], '# __TIER4A_HMAC__')


# ─────────────────────────────────────────────────────────────────────────────
# 4A.10 — SQLite persist mixin on session/kg/regression/webhook
# ─────────────────────────────────────────────────────────────────────────────
PERSIST_BLOCKS = {
    'session_orchestrator': ('SessionOrchestrator', '''# __TIER4A_PERSIST__
_persist_table = "session_orchestrator_state"

def _persist_state(self):
    out = {"sessions": []}
    for sid, sess in getattr(self, "_sessions", {}).items():
        try:
            out["sessions"].append({
                "id": sid,
                "name": getattr(sess, "name", ""),
                "targets": getattr(sess, "targets", []),
                "state": getattr(getattr(sess, "state", None), "value", str(getattr(sess, "state", ""))),
                "findings": getattr(sess, "findings", []),
                "phases_completed": getattr(sess, "phases_completed", []),
            })
        except Exception:
            pass
    return out

def _restore_state(self, state):
    # Best-effort restore: leave session reconstruction to caller; just
    # repopulate the IDs so list_sessions() works.
    sessions = state.get("sessions", []) if isinstance(state, dict) else []
    for s in sessions:
        sid = s.get("id")
        if sid and sid not in getattr(self, "_sessions", {}):
            try:
                from types import SimpleNamespace
                self._sessions[sid] = SimpleNamespace(**s)
            except Exception:
                pass
'''),
    'knowledge_graph': ('KnowledgeGraph', '''# __TIER4A_PERSIST__
_persist_table = "knowledge_graph_state"

def _persist_state(self):
    nodes = getattr(self, "_nodes", {})
    edges = getattr(self, "_edges", [])
    return {
        "nodes": [
            {"id": getattr(n, "id", k), "type": getattr(getattr(n, "node_type", None),
                                                          "value", ""),
             "label": getattr(n, "label", ""),
             "properties": getattr(n, "properties", {})}
            for k, n in nodes.items()
        ],
        "edges": [
            {"source": getattr(e, "source", ""), "target": getattr(e, "target", ""),
             "type": getattr(getattr(e, "edge_type", None), "value", ""),
             "weight": getattr(e, "weight", 1.0)}
            for e in edges
        ],
    }

def _restore_state(self, state):
    # Lightweight restore: callers can rebuild typed objects via add_node/connect.
    if not isinstance(state, dict):
        return
    self._restored_snapshot = state
'''),
    'regression_tracker': ('RegressionTracker', '''# __TIER4A_PERSIST__
_persist_table = "regression_tracker_state"

def _persist_state(self):
    snaps = getattr(self, "_snapshots", [])
    return {
        "snapshots": [
            {"scan_id": getattr(s, "scan_id", ""),
             "timestamp": getattr(s, "timestamp", 0),
             "findings": getattr(s, "findings", []),
             "metadata": getattr(s, "metadata", {})}
            for s in snaps
        ]
    }

def _restore_state(self, state):
    if not isinstance(state, dict):
        return
    self._restored_snapshot = state
'''),
    'webhook_dispatcher': ('WebhookDispatcher', '''# __TIER4A_PERSIST__
_persist_table = "webhook_dispatcher_state"

def _persist_state(self):
    return {
        "endpoints": [
            {"name": getattr(e, "name", ""), "url": getattr(e, "url", ""),
             "events": list(getattr(e, "events", [])),
             "active": getattr(e, "active", True)}
            for e in getattr(self, "_endpoints", {}).values()
        ],
        "delivery_log_size": len(getattr(self, "_delivery_log", [])),
    }

def _restore_state(self, state):
    if not isinstance(state, dict):
        return
    self._restored_snapshot = state
'''),
}


def sweep_persist(mod: str, src: str) -> str:
    if mod not in PERSIST_TARGETS:
        return src
    if '# __TIER4A_PERSIST__' in src:
        return src
    cls_name, block = PERSIST_BLOCKS[mod]
    # Modify class declaration to add SQLitePersistMixin to bases
    pat = re.compile(rf'^class\s+{re.escape(cls_name)}\s*(\(([^)]*)\))?\s*:', re.M)
    m = pat.search(src)
    if not m:
        return src
    bases = m.group(2) or ''
    if 'SQLitePersistMixin' not in bases:
        if bases.strip():
            new_bases = bases + ', SQLitePersistMixin'
        else:
            new_bases = 'SQLitePersistMixin'
        src = src[:m.start()] + f'class {cls_name}({new_bases}):' + src[m.end():]
    # Add import at top
    if 'from .._recovered_support import SQLitePersistMixin' not in src:
        # Insert near other helper imports
        if '# __TIER2_HELPERS_INJECTED__' in src:
            src = src.replace('# __TIER2_HELPERS_INJECTED__',
                              '# __TIER2_HELPERS_INJECTED__\n'
                              'try:\n'
                              '    from .._recovered_support import SQLitePersistMixin\n'
                              'except Exception:\n'
                              '    class SQLitePersistMixin: pass\n', 1)
        else:
            src = ('try:\n'
                   '    from .._recovered_support import SQLitePersistMixin\n'
                   'except Exception:\n'
                   '    class SQLitePersistMixin: pass\n\n' + src)
    # Append the persist methods inside the class
    main = find_main_class(src)
    if main is None or main.name != cls_name:
        # Find by name
        tree = ast.parse(src)
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef) and n.name == cls_name:
                main = n
                break
    if main is None:
        return src
    return append_to_class(src, main, block, '# __TIER4A_PERSIST__')


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────
def main():
    stats = {f'4A.{i}': 0 for i in range(1, 11)}
    for sub, mod in ALL_MODULES:
        p = ROOT / sub / f'{mod}.py'
        original = p.read_text(encoding='utf-8')
        src = original
        before = src

        # 4A.1 errors
        new = sweep_errors(sub, mod, src)
        if new != src:
            stats['4A.1'] += 1
            src = new

        # 4A.2 async mirrors
        new = sweep_async_mirrors(src)
        if new != src:
            stats['4A.2'] += 1
            src = new

        # 4A.3 retry blanket (network/integrations only)
        new = sweep_retry_blanket(sub, mod, src)
        if new != src:
            stats['4A.3'] += 1
            src = new

        # 4A.4 validators
        new = sweep_validators(src)
        if new != src:
            stats['4A.4'] += 1
            src = new

        # 4A.5 ttlcache
        new = sweep_ttlcache(mod, src)
        if new != src:
            stats['4A.5'] += 1
            src = new

        # 4A.6 rlock
        new = sweep_rlock(mod, src)
        if new != src:
            stats['4A.6'] += 1
            src = new

        # 4A.7 dry_run
        new = sweep_dryrun(mod, src)
        if new != src:
            stats['4A.7'] += 1
            src = new

        # 4A.8 pagination
        new = sweep_pagination(mod, src)
        if new != src:
            stats['4A.8'] += 1
            src = new

        # 4A.9 hmac
        new = sweep_hmac(mod, src)
        if new != src:
            stats['4A.9'] += 1
            src = new

        # 4A.10 persist
        new = sweep_persist(mod, src)
        if new != src:
            stats['4A.10'] += 1
            src = new

        if src != original:
            # Validate parses
            try:
                ast.parse(src)
            except SyntaxError as e:
                print(f'  SYNTAX ERROR in {sub}/{mod}: {e}')
                continue
            p.write_text(src, encoding='utf-8')
            delta = len(src.splitlines()) - len(original.splitlines())
            print(f'  [{sub}/{mod}] +{delta} LOC')

    print('\nSWEEP COUNTS:')
    for k, v in stats.items():
        print(f'  {k}: {v} modules touched')


if __name__ == '__main__':
    main()
