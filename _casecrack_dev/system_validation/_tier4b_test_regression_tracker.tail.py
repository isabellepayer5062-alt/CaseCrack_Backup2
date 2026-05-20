# __TIER4B_TESTING__
# Tier 4B Testing — regression_tracker: persistent baseline + SLA tracking
import sqlite3 as _t4b_sql
import json as _t4b_json
import time as _t4b_time
import statistics as _t4b_stat
import csv as _t4b_csv
import io as _t4b_io
import os as _t4b_os
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

_T4B_REG_DDL = """
CREATE TABLE IF NOT EXISTS baselines (
    metric_name TEXT PRIMARY KEY,
    value REAL NOT NULL,
    target_p50 REAL,
    target_p95 REAL,
    target_p99 REAL,
    sla_threshold_pct REAL DEFAULT 10.0,
    direction TEXT DEFAULT 'lower_is_better',
    metadata_json TEXT,
    recorded_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    p50 REAL, p95 REAL, p99 REAL,
    metadata_json TEXT,
    recorded_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_metric ON runs(metric_name, recorded_at);
CREATE TABLE IF NOT EXISTS sla_breaches (
    breach_id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    run_id INTEGER,
    breach_type TEXT NOT NULL,
    expected REAL,
    actual REAL,
    delta_pct REAL,
    severity TEXT,
    detected_at REAL NOT NULL,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_breaches_metric ON sla_breaches(metric_name, detected_at);
"""


def _t4b_rt_db_open(self, path: str = ":memory:") -> Dict[str, Any]:
    """Open or create the persistent baseline DB."""
    conn = _t4b_sql.connect(path, check_same_thread=False)
    conn.row_factory = _t4b_sql.Row
    conn.executescript(_T4B_REG_DDL)
    conn.commit()
    setattr(self, "_t4b_rt_db", conn)
    setattr(self, "_t4b_rt_db_path", path)
    return {"ok": True, "path": path}


def _t4b_rt_db_close(self) -> Dict[str, Any]:
    conn = getattr(self, "_t4b_rt_db", None)
    if conn:
        try: conn.close()
        except Exception: pass
        setattr(self, "_t4b_rt_db", None)
    return {"ok": True}


def _t4b_rt_save_baseline(self, metric_name: str, value: float,
                                  target_p50: Optional[float] = None,
                                  target_p95: Optional[float] = None,
                                  target_p99: Optional[float] = None,
                                  sla_threshold_pct: float = 10.0,
                                  direction: str = "lower_is_better",
                                  metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return {"ok": False, "error": "db_not_open"}
    md = _t4b_json.dumps(metadata or {})
    now = _t4b_time.time()
    conn.execute(
        "INSERT OR REPLACE INTO baselines "
        "(metric_name, value, target_p50, target_p95, target_p99, "
        " sla_threshold_pct, direction, metadata_json, recorded_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (metric_name, value, target_p50, target_p95, target_p99,
         sla_threshold_pct, direction, md, now)
    )
    conn.commit()
    return {"ok": True, "metric_name": metric_name, "value": value,
              "recorded_at": now}


def _t4b_rt_load_baseline(self, metric_name: str) -> Optional[Dict[str, Any]]:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return None
    row = conn.execute(
        "SELECT * FROM baselines WHERE metric_name=?", (metric_name,)
    ).fetchone()
    if not row:
        return None
    return dict(row)


def _t4b_rt_list_baselines(self) -> List[Dict[str, Any]]:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return []
    return [dict(r) for r in conn.execute("SELECT * FROM baselines ORDER BY metric_name")]


def _t4b_rt_record_run(self, metric_name: str, value: float,
                              p50: Optional[float] = None,
                              p95: Optional[float] = None,
                              p99: Optional[float] = None,
                              metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return {"ok": False, "error": "db_not_open"}
    md = _t4b_json.dumps(metadata or {})
    now = _t4b_time.time()
    cur = conn.execute(
        "INSERT INTO runs (metric_name, value, p50, p95, p99, metadata_json, recorded_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (metric_name, value, p50, p95, p99, md, now)
    )
    conn.commit()
    return {"ok": True, "run_id": cur.lastrowid, "metric_name": metric_name,
              "value": value}


def _t4b_rt_compare_to_baseline(self, metric_name: str, current_value: float,
                                          override_threshold_pct: Optional[float] = None) -> Dict[str, Any]:
    """Compare current value to baseline, flag regression if outside threshold."""
    bl = _t4b_rt_load_baseline(self, metric_name)
    if not bl:
        return {"ok": False, "error": "no_baseline", "metric_name": metric_name}
    baseline_value = bl["value"]
    direction = bl.get("direction", "lower_is_better")
    threshold_pct = override_threshold_pct if override_threshold_pct is not None else bl.get("sla_threshold_pct", 10.0)
    delta = current_value - baseline_value
    delta_pct = (delta / baseline_value * 100.0) if baseline_value else 0.0
    if direction == "lower_is_better":
        regressed = delta_pct > threshold_pct
        improved = delta_pct < -threshold_pct
    else:
        regressed = delta_pct < -threshold_pct
        improved = delta_pct > threshold_pct
    return {
        "ok": True, "metric_name": metric_name,
        "baseline": baseline_value, "current": current_value,
        "delta": delta, "delta_pct": delta_pct,
        "threshold_pct": threshold_pct, "direction": direction,
        "regressed": regressed, "improved": improved,
        "verdict": "regression" if regressed else ("improvement" if improved else "stable"),
    }


def _t4b_rt_check_sla(self, metric_name: str,
                            current_p50: Optional[float] = None,
                            current_p95: Optional[float] = None,
                            current_p99: Optional[float] = None,
                            run_id: Optional[int] = None) -> Dict[str, Any]:
    """Check current percentiles against SLA targets in baseline.

    Records breaches in sla_breaches table.
    """
    bl = _t4b_rt_load_baseline(self, metric_name)
    if not bl:
        return {"ok": False, "error": "no_baseline"}
    breaches: List[Dict[str, Any]] = []
    conn = getattr(self, "_t4b_rt_db", None)
    now = _t4b_time.time()
    targets = [("p50", current_p50, bl.get("target_p50")),
                  ("p95", current_p95, bl.get("target_p95")),
                  ("p99", current_p99, bl.get("target_p99"))]
    for name, actual, target in targets:
        if target is None or actual is None:
            continue
        if actual > target:
            delta_pct = ((actual - target) / target * 100.0) if target else 0.0
            severity = "critical" if delta_pct > 50 else ("high" if delta_pct > 25 else "medium")
            b = {
                "metric_name": metric_name, "breach_type": name,
                "expected": target, "actual": actual,
                "delta_pct": delta_pct, "severity": severity,
                "run_id": run_id, "detected_at": now,
            }
            breaches.append(b)
            if conn:
                conn.execute(
                    "INSERT INTO sla_breaches "
                    "(metric_name, run_id, breach_type, expected, actual, "
                    " delta_pct, severity, detected_at, notes) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (metric_name, run_id, name, target, actual,
                     delta_pct, severity, now,
                     f"{name} exceeded target by {delta_pct:.2f}%")
                )
    if conn and breaches:
        conn.commit()
    return {
        "ok": True, "metric_name": metric_name,
        "sla_pass": not breaches,
        "breaches": breaches,
        "breach_count": len(breaches),
    }


def _t4b_rt_list_breaches(self, metric_name: Optional[str] = None,
                                  severity: Optional[str] = None,
                                  since_ts: Optional[float] = None,
                                  limit: int = 100) -> List[Dict[str, Any]]:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return []
    sql = "SELECT * FROM sla_breaches WHERE 1=1"
    args: List[Any] = []
    if metric_name:
        sql += " AND metric_name=?"; args.append(metric_name)
    if severity:
        sql += " AND severity=?"; args.append(severity)
    if since_ts:
        sql += " AND detected_at>=?"; args.append(since_ts)
    sql += " ORDER BY detected_at DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in conn.execute(sql, args)]


def _t4b_rt_regression_report(self, metric_name: str,
                                       last_n: int = 10) -> Dict[str, Any]:
    """Build a regression report comparing recent runs to the baseline."""
    bl = _t4b_rt_load_baseline(self, metric_name)
    if not bl:
        return {"ok": False, "error": "no_baseline"}
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return {"ok": False, "error": "db_not_open"}
    rows = conn.execute(
        "SELECT * FROM runs WHERE metric_name=? "
        "ORDER BY recorded_at DESC LIMIT ?",
        (metric_name, last_n)
    ).fetchall()
    runs = [dict(r) for r in rows]
    baseline_value = bl["value"]
    threshold_pct = bl.get("sla_threshold_pct", 10.0)
    direction = bl.get("direction", "lower_is_better")
    regressions = []
    improvements = []
    deltas = []
    for r in runs:
        cmp = _t4b_rt_compare_to_baseline(self, metric_name, r["value"])
        deltas.append(cmp["delta_pct"])
        if cmp["regressed"]:
            regressions.append({"run_id": r["run_id"], "value": r["value"],
                                    "delta_pct": cmp["delta_pct"],
                                    "recorded_at": r["recorded_at"]})
        if cmp["improved"]:
            improvements.append({"run_id": r["run_id"], "value": r["value"],
                                      "delta_pct": cmp["delta_pct"],
                                      "recorded_at": r["recorded_at"]})
    breaches = _t4b_rt_list_breaches(self, metric_name, limit=last_n)
    summary = {
        "metric_name": metric_name,
        "baseline_value": baseline_value,
        "direction": direction,
        "threshold_pct": threshold_pct,
        "runs_analyzed": len(runs),
        "regressions": regressions,
        "improvements": improvements,
        "regression_count": len(regressions),
        "improvement_count": len(improvements),
        "mean_delta_pct": _t4b_stat.mean(deltas) if deltas else 0.0,
        "max_delta_pct": max(deltas) if deltas else 0.0,
        "min_delta_pct": min(deltas) if deltas else 0.0,
        "stability_score": 1.0 - (len(regressions) / len(runs) if runs else 0),
        "recent_breaches": breaches,
    }
    return {"ok": True, **summary}


def _t4b_rt_export_csv(self, metric_name: Optional[str] = None) -> str:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return ""
    sql = "SELECT * FROM runs"
    args: List[Any] = []
    if metric_name:
        sql += " WHERE metric_name=?"; args.append(metric_name)
    sql += " ORDER BY recorded_at DESC"
    rows = list(conn.execute(sql, args))
    if not rows:
        return ""
    buf = _t4b_io.StringIO()
    keys = list(rows[0].keys())
    w = _t4b_csv.writer(buf)
    w.writerow(keys)
    for r in rows:
        w.writerow([r[k] for k in keys])
    return buf.getvalue()


def _t4b_rt_prune_old_runs(self, keep_per_metric: int = 100) -> Dict[str, Any]:
    """Trim run history per metric to the most recent N rows."""
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return {"ok": False, "error": "db_not_open"}
    metrics = [r[0] for r in conn.execute("SELECT DISTINCT metric_name FROM runs")]
    pruned = 0
    for m in metrics:
        cutoff = conn.execute(
            "SELECT recorded_at FROM runs WHERE metric_name=? "
            "ORDER BY recorded_at DESC LIMIT 1 OFFSET ?",
            (m, keep_per_metric)
        ).fetchone()
        if cutoff:
            cur = conn.execute(
                "DELETE FROM runs WHERE metric_name=? AND recorded_at<?",
                (m, cutoff[0])
            )
            pruned += cur.rowcount
    conn.commit()
    return {"ok": True, "pruned_rows": pruned, "metrics": len(metrics)}


def _t4b_rt_db_summary(self) -> Dict[str, Any]:
    conn = getattr(self, "_t4b_rt_db", None)
    if not conn:
        return {"ok": False, "error": "db_not_open"}
    bl_count = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
    run_count = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    breach_count = conn.execute("SELECT COUNT(*) FROM sla_breaches").fetchone()[0]
    sev_breakdown = {}
    for r in conn.execute("SELECT severity, COUNT(*) c FROM sla_breaches GROUP BY severity"):
        sev_breakdown[r["severity"]] = r["c"]
    return {
        "ok": True,
        "path": getattr(self, "_t4b_rt_db_path", "?"),
        "baselines": bl_count,
        "runs": run_count,
        "breaches": breach_count,
        "breaches_by_severity": sev_breakdown,
    }


# --- Bind to RegressionTracker -------------------------------------------
try:
    RegressionTracker.db_open = _t4b_rt_db_open  # type: ignore[name-defined]
    RegressionTracker.db_close = _t4b_rt_db_close  # type: ignore[name-defined]
    RegressionTracker.save_baseline = _t4b_rt_save_baseline  # type: ignore[name-defined]
    RegressionTracker.load_baseline = _t4b_rt_load_baseline  # type: ignore[name-defined]
    RegressionTracker.list_baselines = _t4b_rt_list_baselines  # type: ignore[name-defined]
    RegressionTracker.record_run = _t4b_rt_record_run  # type: ignore[name-defined]
    RegressionTracker.compare_to_baseline = _t4b_rt_compare_to_baseline  # type: ignore[name-defined]
    RegressionTracker.check_sla = _t4b_rt_check_sla  # type: ignore[name-defined]
    RegressionTracker.list_breaches = _t4b_rt_list_breaches  # type: ignore[name-defined]
    RegressionTracker.regression_report = _t4b_rt_regression_report  # type: ignore[name-defined]
    RegressionTracker.export_csv = _t4b_rt_export_csv  # type: ignore[name-defined]
    RegressionTracker.prune_old_runs = _t4b_rt_prune_old_runs  # type: ignore[name-defined]
    RegressionTracker.db_summary = _t4b_rt_db_summary  # type: ignore[name-defined]
except NameError:
    pass
