# __TIER4B_CAAP__
# Tier 4B CAAP — knowledge_graph: SQLite-backed + Cypher-like query engine
import sqlite3 as _t4b_sql
import json as _t4b_json
import re as _t4b_re
import threading as _t4b_th
import time as _t4b_time
import hashlib as _t4b_hash
import os as _t4b_os
from typing import Any, Callable, Dict, List, Optional, Tuple, Iterator
from dataclasses import dataclass, field

_T4B_KG_DDL = """
CREATE TABLE IF NOT EXISTS kg_nodes (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_label ON kg_nodes(label);

CREATE TABLE IF NOT EXISTS kg_edges (
    id TEXT PRIMARY KEY,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    rel_type TEXT NOT NULL,
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    FOREIGN KEY (src) REFERENCES kg_nodes(id),
    FOREIGN KEY (dst) REFERENCES kg_nodes(id)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON kg_edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON kg_edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_rel ON kg_edges(rel_type);
"""


def _t4b_kg_get_conn(self) -> _t4b_sql.Connection:
    conn = getattr(self, "_t4b_kg_conn", None)
    if conn is not None:
        return conn
    db_path = getattr(self, "_t4b_kg_db_path", ":memory:")
    conn = _t4b_sql.connect(db_path, check_same_thread=False, isolation_level=None)
    conn.executescript(_T4B_KG_DDL)
    setattr(self, "_t4b_kg_conn", conn)
    if not hasattr(self, "_t4b_kg_lock"):
        setattr(self, "_t4b_kg_lock", _t4b_th.RLock())
    return conn


def _t4b_kg_open(self, db_path: str = ":memory:") -> Dict[str, Any]:
    """Open or create the knowledge graph DB."""
    setattr(self, "_t4b_kg_db_path", db_path)
    if hasattr(self, "_t4b_kg_conn"):
        try: self._t4b_kg_conn.close()
        except Exception: pass
        delattr(self, "_t4b_kg_conn")
    _t4b_kg_get_conn(self)
    return {"ok": True, "path": db_path}


def _t4b_kg_close(self) -> Dict[str, Any]:
    conn = getattr(self, "_t4b_kg_conn", None)
    if conn is not None:
        try: conn.close()
        except Exception: pass
        delattr(self, "_t4b_kg_conn")
    return {"ok": True}


def _t4b_kg_node_id(label: str, key_props: Dict[str, Any]) -> str:
    raw = label + "|" + _t4b_json.dumps(key_props, sort_keys=True, default=str)
    return f"N-{_t4b_hash.sha256(raw.encode()).hexdigest()[:16]}"


def _t4b_kg_add_node(self, label: str, properties: Optional[Dict[str, Any]] = None,
                          key_props: Optional[Dict[str, Any]] = None,
                          node_id: Optional[str] = None) -> Dict[str, Any]:
    """Add or merge a node. If key_props given, used for stable ID; else node_id required."""
    props = dict(properties or {})
    nid = node_id or _t4b_kg_node_id(label, key_props or props)
    now = _t4b_time.time()
    conn = _t4b_kg_get_conn(self)
    with self._t4b_kg_lock:
        cur = conn.execute("SELECT properties_json FROM kg_nodes WHERE id=?", (nid,))
        row = cur.fetchone()
        if row:
            existing = _t4b_json.loads(row[0])
            existing.update(props)
            conn.execute("UPDATE kg_nodes SET properties_json=?, updated_at=? WHERE id=?",
                              (_t4b_json.dumps(existing, default=str), now, nid))
            return {"ok": True, "id": nid, "label": label, "merged": True}
        conn.execute("INSERT INTO kg_nodes (id, label, properties_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                          (nid, label, _t4b_json.dumps(props, default=str), now, now))
    return {"ok": True, "id": nid, "label": label, "merged": False}


def _t4b_kg_add_edge(self, src: str, dst: str, rel_type: str,
                          properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    props = dict(properties or {})
    eid_raw = f"{src}|{rel_type}|{dst}|{_t4b_json.dumps(props, sort_keys=True, default=str)}"
    eid = f"E-{_t4b_hash.sha256(eid_raw.encode()).hexdigest()[:16]}"
    now = _t4b_time.time()
    conn = _t4b_kg_get_conn(self)
    with self._t4b_kg_lock:
        cur = conn.execute("SELECT id FROM kg_edges WHERE id=?", (eid,))
        if cur.fetchone():
            return {"ok": True, "id": eid, "merged": True}
        conn.execute("INSERT INTO kg_edges (id, src, dst, rel_type, properties_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                          (eid, src, dst, rel_type, _t4b_json.dumps(props, default=str), now))
    return {"ok": True, "id": eid, "src": src, "dst": dst, "rel_type": rel_type, "merged": False}


def _t4b_kg_get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
    conn = _t4b_kg_get_conn(self)
    with self._t4b_kg_lock:
        row = conn.execute("SELECT id, label, properties_json, created_at, updated_at FROM kg_nodes WHERE id=?",
                                (node_id,)).fetchone()
    if not row:
        return None
    return {"id": row[0], "label": row[1], "properties": _t4b_json.loads(row[2]),
              "created_at": row[3], "updated_at": row[4]}


def _t4b_kg_find_nodes(self, label: Optional[str] = None,
                            properties: Optional[Dict[str, Any]] = None,
                            limit: int = 1000) -> List[Dict[str, Any]]:
    conn = _t4b_kg_get_conn(self)
    sql = "SELECT id, label, properties_json, created_at, updated_at FROM kg_nodes"
    args: List[Any] = []
    where = []
    if label:
        where.append("label = ?")
        args.append(label)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " LIMIT ?"
    args.append(limit)
    with self._t4b_kg_lock:
        rows = conn.execute(sql, args).fetchall()
    out = []
    for r in rows:
        props = _t4b_json.loads(r[2])
        if properties:
            if not all(props.get(k) == v for k, v in properties.items()):
                continue
        out.append({"id": r[0], "label": r[1], "properties": props,
                       "created_at": r[3], "updated_at": r[4]})
    return out


def _t4b_kg_neighbors(self, node_id: str, rel_type: Optional[str] = None,
                           direction: str = "out") -> List[Dict[str, Any]]:
    """direction: 'out', 'in', or 'both'."""
    conn = _t4b_kg_get_conn(self)
    sqls = []
    args_list = []
    if direction in ("out", "both"):
        s = "SELECT e.id, e.src, e.dst, e.rel_type, e.properties_json, n.label, n.properties_json FROM kg_edges e JOIN kg_nodes n ON n.id = e.dst WHERE e.src = ?"
        a = [node_id]
        if rel_type:
            s += " AND e.rel_type = ?"
            a.append(rel_type)
        sqls.append(s); args_list.append(a)
    if direction in ("in", "both"):
        s = "SELECT e.id, e.src, e.dst, e.rel_type, e.properties_json, n.label, n.properties_json FROM kg_edges e JOIN kg_nodes n ON n.id = e.src WHERE e.dst = ?"
        a = [node_id]
        if rel_type:
            s += " AND e.rel_type = ?"
            a.append(rel_type)
        sqls.append(s); args_list.append(a)
    out = []
    with self._t4b_kg_lock:
        for s, a in zip(sqls, args_list):
            for row in conn.execute(s, a).fetchall():
                out.append({
                    "edge_id": row[0], "src": row[1], "dst": row[2],
                    "rel_type": row[3], "edge_props": _t4b_json.loads(row[4]),
                    "neighbor_label": row[5], "neighbor_props": _t4b_json.loads(row[6]),
                })
    return out


def _t4b_kg_path(self, src_id: str, dst_id: str, max_depth: int = 5) -> Optional[List[str]]:
    """BFS shortest path between two nodes (returns list of node ids)."""
    conn = _t4b_kg_get_conn(self)
    if src_id == dst_id:
        return [src_id]
    visited = {src_id}
    queue = [(src_id, [src_id])]
    with self._t4b_kg_lock:
        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            for row in conn.execute("SELECT dst FROM kg_edges WHERE src=?", (current,)).fetchall():
                nxt = row[0]
                if nxt == dst_id:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))
    return None


def _t4b_kg_subgraph(self, root_id: str, depth: int = 2,
                          rel_filter: Optional[List[str]] = None) -> Dict[str, Any]:
    """Extract a subgraph rooted at node, BFS to given depth."""
    conn = _t4b_kg_get_conn(self)
    visited_nodes = {root_id}
    edges: List[Dict[str, Any]] = []
    frontier = [root_id]
    for d in range(depth):
        nxt_frontier = []
        with self._t4b_kg_lock:
            for nid in frontier:
                sql = "SELECT id, src, dst, rel_type, properties_json FROM kg_edges WHERE src=?"
                args: List[Any] = [nid]
                if rel_filter:
                    sql += " AND rel_type IN (" + ",".join("?" * len(rel_filter)) + ")"
                    args.extend(rel_filter)
                for row in conn.execute(sql, args).fetchall():
                    edges.append({"id": row[0], "src": row[1], "dst": row[2],
                                       "rel_type": row[3], "props": _t4b_json.loads(row[4])})
                    if row[2] not in visited_nodes:
                        visited_nodes.add(row[2])
                        nxt_frontier.append(row[2])
        frontier = nxt_frontier
    nodes = []
    for nid in visited_nodes:
        n = _t4b_kg_get_node(self, nid)
        if n:
            nodes.append(n)
    return {"root": root_id, "depth": depth, "nodes": nodes, "edges": edges}


# ---- Mini Cypher-like query parser -------------------------------------
# Supports: MATCH (a:Label1)-[r:REL]->(b:Label2) WHERE a.prop = "value" RETURN a, b
# Limited but powerful for KG navigation.

_T4B_CY_NODE_RE = _t4b_re.compile(r'\((\w*)(?::(\w+))?\)')
_T4B_CY_EDGE_RE = _t4b_re.compile(r'-\[(\w*)(?::(\w+))?\]->')
_T4B_CY_FULL_RE = _t4b_re.compile(
    r'MATCH\s+\((\w+)(?::(\w+))?\)(?:\s*-\s*\[(\w*)(?::(\w+))?\]\s*->\s*\((\w+)(?::(\w+))?\))?'
    r'(?:\s+WHERE\s+(.+?))?'
    r'\s+RETURN\s+(.+?)(?:\s+LIMIT\s+(\d+))?\s*$',
    _t4b_re.IGNORECASE | _t4b_re.DOTALL,
)


def _t4b_kg_cypher(self, query: str) -> List[Dict[str, Any]]:
    """Execute a simplified Cypher-like query.
    Examples:
      MATCH (n:Endpoint) RETURN n LIMIT 10
      MATCH (a:Endpoint)-[r:HAS_VULN]->(b:Vulnerability) WHERE a.method = "POST" RETURN a, b
    """
    m = _T4B_CY_FULL_RE.match(query.strip())
    if not m:
        return [{"error": "parse_failed", "query": query}]
    a_var, a_lbl, r_var, r_type, b_var, b_lbl, where, ret, limit = m.groups()
    limit_i = int(limit) if limit else 1000
    return_vars = [v.strip() for v in ret.split(",")]

    # Parse WHERE clauses: var.prop = "value" (single conj only)
    where_filters: Dict[str, Dict[str, Any]] = {}
    if where:
        for clause in where.split("AND"):
            cm = _t4b_re.match(r'\s*(\w+)\.(\w+)\s*=\s*(.+?)\s*$', clause.strip())
            if cm:
                v, p, val = cm.groups()
                val = val.strip()
                if val.startswith(("'", '"')):
                    val = val.strip("'\"")
                else:
                    try: val = int(val)
                    except ValueError:
                        try: val = float(val)
                        except ValueError: pass
                where_filters.setdefault(v, {})[p] = val

    # Single-node MATCH
    if not b_var:
        a_props = where_filters.get(a_var, {})
        a_nodes = _t4b_kg_find_nodes(self, label=a_lbl or None, properties=a_props or None, limit=limit_i)
        return [{a_var: n} for n in a_nodes][:limit_i]

    # Edge MATCH
    a_props = where_filters.get(a_var, {})
    b_props = where_filters.get(b_var, {})
    conn = _t4b_kg_get_conn(self)
    sql = "SELECT e.src, e.dst, e.rel_type FROM kg_edges e JOIN kg_nodes a ON a.id=e.src JOIN kg_nodes b ON b.id=e.dst WHERE 1=1"
    args: List[Any] = []
    if a_lbl:
        sql += " AND a.label = ?"; args.append(a_lbl)
    if b_lbl:
        sql += " AND b.label = ?"; args.append(b_lbl)
    if r_type:
        sql += " AND e.rel_type = ?"; args.append(r_type)
    sql += " LIMIT ?"; args.append(limit_i)
    out = []
    with self._t4b_kg_lock:
        for row in conn.execute(sql, args).fetchall():
            a_node = _t4b_kg_get_node(self, row[0])
            b_node = _t4b_kg_get_node(self, row[1])
            if a_props and not all(a_node["properties"].get(k) == v for k, v in a_props.items()):
                continue
            if b_props and not all(b_node["properties"].get(k) == v for k, v in b_props.items()):
                continue
            entry = {a_var: a_node, b_var: b_node, r_var or "r": {"rel_type": row[2]}}
            out.append({k: v for k, v in entry.items() if k in return_vars or "*" in return_vars})
    return out


def _t4b_kg_stats(self) -> Dict[str, Any]:
    conn = _t4b_kg_get_conn(self)
    with self._t4b_kg_lock:
        node_count = conn.execute("SELECT COUNT(*) FROM kg_nodes").fetchone()[0]
        edge_count = conn.execute("SELECT COUNT(*) FROM kg_edges").fetchone()[0]
        by_label = dict(conn.execute("SELECT label, COUNT(*) FROM kg_nodes GROUP BY label").fetchall())
        by_rel = dict(conn.execute("SELECT rel_type, COUNT(*) FROM kg_edges GROUP BY rel_type").fetchall())
    return {"nodes": node_count, "edges": edge_count,
              "by_label": by_label, "by_rel_type": by_rel}


def _t4b_kg_clear(self) -> Dict[str, Any]:
    conn = _t4b_kg_get_conn(self)
    with self._t4b_kg_lock:
        conn.execute("DELETE FROM kg_edges")
        conn.execute("DELETE FROM kg_nodes")
    return {"ok": True}


def _t4b_kg_export_cypher(self) -> str:
    """Export the entire graph as a Cypher CREATE script."""
    conn = _t4b_kg_get_conn(self)
    lines = []
    with self._t4b_kg_lock:
        for row in conn.execute("SELECT id, label, properties_json FROM kg_nodes").fetchall():
            props = _t4b_json.loads(row[2])
            ps = ", ".join(f'{k}: {_t4b_json.dumps(v)}' for k, v in props.items())
            lines.append(f'CREATE (`{row[0]}`:{row[1]} {{{ps}}})')
        for row in conn.execute("SELECT src, dst, rel_type, properties_json FROM kg_edges").fetchall():
            props = _t4b_json.loads(row[3])
            ps = ", ".join(f'{k}: {_t4b_json.dumps(v)}' for k, v in props.items())
            lines.append(f'MATCH (a {{id:"{row[0]}"}}), (b {{id:"{row[1]}"}}) CREATE (a)-[:{row[2]} {{{ps}}}]->(b)')
    return ";\n".join(lines)


def _t4b_kg_export_json(self) -> Dict[str, Any]:
    conn = _t4b_kg_get_conn(self)
    out: Dict[str, Any] = {"nodes": [], "edges": []}
    with self._t4b_kg_lock:
        for row in conn.execute("SELECT id, label, properties_json FROM kg_nodes").fetchall():
            out["nodes"].append({"id": row[0], "label": row[1],
                                      "properties": _t4b_json.loads(row[2])})
        for row in conn.execute("SELECT id, src, dst, rel_type, properties_json FROM kg_edges").fetchall():
            out["edges"].append({"id": row[0], "src": row[1], "dst": row[2],
                                      "rel_type": row[3],
                                      "properties": _t4b_json.loads(row[4])})
    return out


def _t4b_kg_import_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    n_nodes = 0
    n_edges = 0
    for n in nodes:
        _t4b_kg_add_node(self, n.get("label", "Node"), properties=n.get("properties", {}),
                              node_id=n.get("id"))
        n_nodes += 1
    for e in edges:
        _t4b_kg_add_edge(self, e["src"], e["dst"], e["rel_type"],
                              properties=e.get("properties", {}))
        n_edges += 1
    return {"ok": True, "nodes_imported": n_nodes, "edges_imported": n_edges}


# --- Bind to KnowledgeGraph ---------------------------------------------
try:
    KnowledgeGraph.kg_open = _t4b_kg_open  # type: ignore[name-defined]
    KnowledgeGraph.kg_close = _t4b_kg_close  # type: ignore[name-defined]
    KnowledgeGraph.kg_add_node = _t4b_kg_add_node  # type: ignore[name-defined]
    KnowledgeGraph.kg_add_edge = _t4b_kg_add_edge  # type: ignore[name-defined]
    KnowledgeGraph.kg_get_node = _t4b_kg_get_node  # type: ignore[name-defined]
    KnowledgeGraph.kg_find_nodes = _t4b_kg_find_nodes  # type: ignore[name-defined]
    KnowledgeGraph.kg_neighbors = _t4b_kg_neighbors  # type: ignore[name-defined]
    KnowledgeGraph.kg_path = _t4b_kg_path  # type: ignore[name-defined]
    KnowledgeGraph.kg_subgraph = _t4b_kg_subgraph  # type: ignore[name-defined]
    KnowledgeGraph.kg_cypher = _t4b_kg_cypher  # type: ignore[name-defined]
    KnowledgeGraph.kg_stats = _t4b_kg_stats  # type: ignore[name-defined]
    KnowledgeGraph.kg_clear = _t4b_kg_clear  # type: ignore[name-defined]
    KnowledgeGraph.kg_export_cypher = _t4b_kg_export_cypher  # type: ignore[name-defined]
    KnowledgeGraph.kg_export_json = _t4b_kg_export_json  # type: ignore[name-defined]
    KnowledgeGraph.kg_import_json = _t4b_kg_import_json  # type: ignore[name-defined]
except NameError:
    pass
