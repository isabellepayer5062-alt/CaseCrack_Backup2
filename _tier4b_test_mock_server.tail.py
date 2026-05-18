# __TIER4B_TESTING__
# Tier 4B Testing — mock_server: WebSocket/GraphQL/gRPC mocks + templating
import json as _t4b_json
import re as _t4b_re
import time as _t4b_time
import struct as _t4b_struct
import threading as _t4b_th
import socket as _t4b_socket
import hashlib as _t4b_hash
import base64 as _t4b_b64
import string as _t4b_string
import random as _t4b_rand
import http.server as _t4b_hs
import socketserver as _t4b_ss
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


# ---- Templating engine -------------------------------------------------
# Supports: {{ var }}, {{ var.path }}, {{ uuid }}, {{ now }}, {{ random_int(a,b) }},
#           {{ random_str(n) }}, {{ headers.X-Foo }}, {{ body.field }}
_T4B_TPL_VAR_RE = _t4b_re.compile(r'\{\{\s*([^}]+?)\s*\}\}')


def _t4b_tpl_resolve(path: str, ctx: Dict[str, Any]) -> Any:
    parts = path.split(".")
    cur: Any = ctx
    for p in parts:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list):
            try: cur = cur[int(p)]
            except (ValueError, IndexError): return None
        else:
            try: cur = getattr(cur, p)
            except AttributeError: return None
    return cur


def _t4b_tpl_render(template: str, context: Dict[str, Any]) -> str:
    """Render a string template against a context dict."""
    def repl(m):
        expr = m.group(1).strip()
        # Built-ins
        if expr == "uuid":
            import uuid as _u
            return str(_u.uuid4())
        if expr == "now":
            return str(int(_t4b_time.time()))
        if expr == "now_iso":
            return _t4b_time.strftime("%Y-%m-%dT%H:%M:%SZ", _t4b_time.gmtime())
        # random_int(a, b)
        rim = _t4b_re.match(r'random_int\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)', expr)
        if rim:
            return str(_t4b_rand.randint(int(rim.group(1)), int(rim.group(2))))
        rsm = _t4b_re.match(r'random_str\(\s*(\d+)\s*\)', expr)
        if rsm:
            n = int(rsm.group(1))
            return "".join(_t4b_rand.choice(_t4b_string.ascii_letters + _t4b_string.digits) for _ in range(n))
        # Variable lookup
        v = _t4b_tpl_resolve(expr, context)
        return "" if v is None else str(v)
    return _T4B_TPL_VAR_RE.sub(repl, template)


def _t4b_mock_render_template(self, template: str, context: Dict[str, Any]) -> str:
    return _t4b_tpl_render(template, context)


def _t4b_mock_render_json_template(self, obj: Any, context: Dict[str, Any]) -> Any:
    """Recursively render templates inside a JSON-shaped dict/list."""
    if isinstance(obj, str):
        return _t4b_tpl_render(obj, context)
    if isinstance(obj, dict):
        return {k: _t4b_mock_render_json_template(self, v, context) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_t4b_mock_render_json_template(self, v, context) for v in obj]
    return obj


# ---- WebSocket frame encoder/decoder (RFC 6455) ------------------------
_T4B_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _t4b_ws_handshake_response(client_key: str) -> bytes:
    accept_raw = (client_key + _T4B_WS_GUID).encode()
    accept = _t4b_b64.b64encode(_t4b_hash.sha1(accept_raw).digest()).decode()
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    ).encode()


def _t4b_ws_encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    """Encode a WS frame from server (no mask)."""
    header = bytearray()
    header.append(0x80 | opcode)
    pl = len(payload)
    if pl < 126:
        header.append(pl)
    elif pl < 65536:
        header.append(126)
        header += _t4b_struct.pack(">H", pl)
    else:
        header.append(127)
        header += _t4b_struct.pack(">Q", pl)
    return bytes(header) + payload


def _t4b_ws_decode_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """Decode a single WS frame from a client. Returns dict or None if incomplete."""
    if len(data) < 2:
        return None
    b0, b1 = data[0], data[1]
    fin = (b0 & 0x80) >> 7
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) >> 7
    pl = b1 & 0x7F
    offset = 2
    if pl == 126:
        if len(data) < 4: return None
        pl = _t4b_struct.unpack(">H", data[2:4])[0]
        offset = 4
    elif pl == 127:
        if len(data) < 10: return None
        pl = _t4b_struct.unpack(">Q", data[2:10])[0]
        offset = 10
    mask_key = b""
    if masked:
        if len(data) < offset + 4: return None
        mask_key = data[offset:offset+4]
        offset += 4
    if len(data) < offset + pl:
        return None
    payload = data[offset:offset+pl]
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return {"fin": fin, "opcode": opcode, "payload": payload,
              "consumed": offset + pl}


# ---- WebSocket mock route ----------------------------------------------
def _t4b_mock_register_ws_route(self, path: str,
                                       on_message: Callable[[bytes, Dict[str, Any]], bytes],
                                       on_connect: Optional[Callable[[Dict[str, Any]], Optional[bytes]]] = None) -> bool:
    routes: Dict[str, Dict[str, Any]] = getattr(self, "_t4b_mock_ws_routes", None) or {}
    routes[path] = {"on_message": on_message, "on_connect": on_connect}
    setattr(self, "_t4b_mock_ws_routes", routes)
    return True


def _t4b_mock_ws_serve_socket(self, sock: _t4b_socket.socket, path: str,
                                      headers: Dict[str, str], max_messages: int = 100,
                                      timeout: float = 30.0) -> Dict[str, Any]:
    """Serve a single WS connection until close or max_messages."""
    routes: Dict[str, Dict[str, Any]] = getattr(self, "_t4b_mock_ws_routes", {}) or {}
    route = routes.get(path)
    if not route:
        sock.close()
        return {"ok": False, "error": "no_ws_route"}
    key = headers.get("Sec-WebSocket-Key", "")
    sock.send(_t4b_ws_handshake_response(key))
    if route["on_connect"]:
        greeting = route["on_connect"]({"path": path, "headers": headers})
        if greeting:
            sock.send(_t4b_ws_encode_frame(greeting))
    sock.settimeout(timeout)
    msg_count = 0
    buf = b""
    try:
        while msg_count < max_messages:
            try:
                chunk = sock.recv(4096)
            except _t4b_socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while True:
                frame = _t4b_ws_decode_frame(buf)
                if not frame:
                    break
                buf = buf[frame["consumed"]:]
                if frame["opcode"] == 0x8:
                    sock.send(_t4b_ws_encode_frame(b"", 0x8))
                    return {"ok": True, "messages": msg_count, "closed": True}
                if frame["opcode"] == 0x9:  # ping
                    sock.send(_t4b_ws_encode_frame(frame["payload"], 0xA))
                    continue
                if frame["opcode"] in (0x1, 0x2):
                    response = route["on_message"](frame["payload"],
                                                          {"path": path, "headers": headers,
                                                            "msg_index": msg_count})
                    if response is not None:
                        sock.send(_t4b_ws_encode_frame(response,
                                                              0x2 if isinstance(response, (bytes, bytearray)) and frame["opcode"] == 0x2 else 0x1))
                    msg_count += 1
    finally:
        try: sock.close()
        except Exception: pass
    return {"ok": True, "messages": msg_count, "closed": False}


# ---- GraphQL mock ------------------------------------------------------
def _t4b_mock_register_graphql_schema(self, schema: Dict[str, Any]) -> bool:
    """Register a GraphQL mock schema.

    Schema format:
      {"Query": {"user": <fn or template>, "users": <fn or template>},
       "Mutation": {"createUser": <fn>}}

    Resolvers receive (args, context) and return the value.
    Templates are dicts/strings rendered via {{ var }}.
    """
    setattr(self, "_t4b_mock_gql_schema", schema)
    return True


def _t4b_mock_graphql_execute(self, query: str,
                                      variables: Optional[Dict[str, Any]] = None,
                                      context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a simplified GraphQL query against the registered mock schema.

    Supports: query/mutation, single field selection, args.
    NOT supported: fragments, directives, full AST.
    """
    schema: Dict[str, Any] = getattr(self, "_t4b_mock_gql_schema", {}) or {}
    variables = variables or {}
    context = context or {}
    q = query.strip()
    op_type = "Query"
    if q.lower().startswith("mutation"):
        op_type = "Mutation"
    elif q.lower().startswith("subscription"):
        op_type = "Subscription"
    # Strip operation prefix and braces
    inner = _t4b_re.sub(r'^(query|mutation|subscription)\s*\w*\s*(\([^)]*\))?\s*\{', '', q,
                            flags=_t4b_re.IGNORECASE)
    inner = inner.rstrip("} \n")
    inner = inner.strip().lstrip("{").strip()
    # Field with optional args: name(arg: value, ...) { subfields }
    field_match = _t4b_re.match(r'(\w+)(?:\(([^)]*)\))?', inner)
    if not field_match:
        return {"data": None, "errors": [{"message": "parse_failed"}]}
    field_name = field_match.group(1)
    args_str = field_match.group(2) or ""
    args: Dict[str, Any] = {}
    for am in _t4b_re.finditer(r'(\w+):\s*(?:"([^"]*)"|(\$\w+)|([\w.]+))', args_str):
        k = am.group(1)
        if am.group(2) is not None:
            args[k] = am.group(2)
        elif am.group(3) is not None:
            var_name = am.group(3)[1:]
            args[k] = variables.get(var_name)
        else:
            v = am.group(4)
            try: args[k] = int(v)
            except ValueError:
                try: args[k] = float(v)
                except ValueError: args[k] = v
    resolver = schema.get(op_type, {}).get(field_name)
    if resolver is None:
        return {"data": None,
                  "errors": [{"message": f"field_not_found: {op_type}.{field_name}"}]}
    try:
        if callable(resolver):
            value = resolver(args, context)
        else:
            full_ctx = dict(context)
            full_ctx["args"] = args
            full_ctx["variables"] = variables
            value = _t4b_mock_render_json_template(self, resolver, full_ctx)
        return {"data": {field_name: value}}
    except Exception as e:
        return {"data": None, "errors": [{"message": f"{type(e).__name__}: {e}"}]}


# ---- gRPC mock (HTTP/2-style framed JSON) ------------------------------
def _t4b_mock_register_grpc_service(self, service_name: str,
                                            methods: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]]) -> bool:
    services: Dict[str, Dict[str, Any]] = getattr(self, "_t4b_mock_grpc_services", None) or {}
    services[service_name] = methods
    setattr(self, "_t4b_mock_grpc_services", services)
    return True


def _t4b_mock_grpc_call(self, service_name: str, method_name: str,
                              request: Dict[str, Any],
                              metadata: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Simulate a unary gRPC call against the registered mock service."""
    services: Dict[str, Dict[str, Any]] = getattr(self, "_t4b_mock_grpc_services", {}) or {}
    svc = services.get(service_name)
    if not svc:
        return {"ok": False, "status": "UNIMPLEMENTED",
                  "message": f"service_not_found: {service_name}"}
    method = svc.get(method_name)
    if not method:
        return {"ok": False, "status": "UNIMPLEMENTED",
                  "message": f"method_not_found: {service_name}.{method_name}"}
    try:
        t0 = _t4b_time.time()
        response = method(request)
        return {"ok": True, "status": "OK", "service": service_name,
                  "method": method_name, "response": response,
                  "metadata": metadata or {},
                  "duration_s": round(_t4b_time.time() - t0, 6)}
    except Exception as e:
        return {"ok": False, "status": "INTERNAL",
                  "message": f"{type(e).__name__}: {e}"}


def _t4b_mock_encode_grpc_frame(self, message: Dict[str, Any],
                                         compressed: bool = False) -> bytes:
    """Encode a JSON-serialized message as a gRPC HTTP/2 frame body."""
    body = _t4b_json.dumps(message, default=str).encode()
    flag = 1 if compressed else 0
    return _t4b_struct.pack(">BI", flag, len(body)) + body


def _t4b_mock_decode_grpc_frame(self, data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 5:
        return None
    flag, length = _t4b_struct.unpack(">BI", data[:5])
    if len(data) < 5 + length:
        return None
    body = data[5:5+length]
    try:
        return _t4b_json.loads(body)
    except Exception:
        return None


# ---- Mock state inspection ---------------------------------------------
def _t4b_mock_supported_protocols(self) -> List[str]:
    return ["http", "websocket", "graphql", "grpc"]


def _t4b_mock_summary(self) -> Dict[str, Any]:
    return {
        "ws_routes": len(getattr(self, "_t4b_mock_ws_routes", {}) or {}),
        "graphql_loaded": bool(getattr(self, "_t4b_mock_gql_schema", None)),
        "grpc_services": list((getattr(self, "_t4b_mock_grpc_services", {}) or {}).keys()),
    }


# --- Bind to MockServer -------------------------------------------------
try:
    MockServer.render_template = _t4b_mock_render_template  # type: ignore[name-defined]
    MockServer.render_json_template = _t4b_mock_render_json_template  # type: ignore[name-defined]
    MockServer.register_ws_route = _t4b_mock_register_ws_route  # type: ignore[name-defined]
    MockServer.serve_ws_socket = _t4b_mock_ws_serve_socket  # type: ignore[name-defined]
    MockServer.register_graphql_schema = _t4b_mock_register_graphql_schema  # type: ignore[name-defined]
    MockServer.graphql_execute = _t4b_mock_graphql_execute  # type: ignore[name-defined]
    MockServer.register_grpc_service = _t4b_mock_register_grpc_service  # type: ignore[name-defined]
    MockServer.grpc_call = _t4b_mock_grpc_call  # type: ignore[name-defined]
    MockServer.encode_grpc_frame = _t4b_mock_encode_grpc_frame  # type: ignore[name-defined]
    MockServer.decode_grpc_frame = _t4b_mock_decode_grpc_frame  # type: ignore[name-defined]
    MockServer.supported_protocols = _t4b_mock_supported_protocols  # type: ignore[name-defined]
    MockServer.mock_summary = _t4b_mock_summary  # type: ignore[name-defined]
except NameError:
    pass
