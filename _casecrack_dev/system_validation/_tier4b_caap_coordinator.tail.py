# __TIER4B_CAAP__
# Tier 4B CAAP — caap_coordinator: parallel phases + LLM bridge + streaming
import concurrent.futures as _t4b_cf
import threading as _t4b_th
import time as _t4b_time
import queue as _t4b_queue
import uuid as _t4b_uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Iterator
from dataclasses import dataclass, field

# --- Phase dependency graph ---------------------------------------------
_T4B_PHASE_DEPS = {
    "recon": [],
    "discovery": ["recon"],
    "hypothesis": ["discovery"],
    "exploitation": ["hypothesis"],
    "compliance": ["discovery"],
    "reporting": ["exploitation", "compliance"],
}

_T4B_PHASE_TIMEOUTS = {
    "recon": 600,
    "discovery": 900,
    "hypothesis": 300,
    "exploitation": 1800,
    "compliance": 600,
    "reporting": 300,
}


@dataclass
class _T4BPhaseSlot:
    name: str
    deps: List[str]
    runner: Optional[Callable[..., Any]] = None
    timeout_s: float = 600.0
    status: str = "pending"  # pending|running|completed|failed|skipped|cancelled
    started_at: float = 0.0
    completed_at: float = 0.0
    result: Any = None
    error: Optional[str] = None


def _t4b_caap_topo_sort(slots: Dict[str, _T4BPhaseSlot]) -> List[List[str]]:
    """Return waves (list of phases that may run in parallel)."""
    indeg = {n: 0 for n in slots}
    fwd = {n: [] for n in slots}
    for n, s in slots.items():
        for d in s.deps:
            if d in slots:
                indeg[n] += 1
                fwd[d].append(n)
    waves: List[List[str]] = []
    remaining = set(slots)
    while remaining:
        ready = sorted([n for n in remaining if indeg[n] == 0])
        if not ready:
            # cycle — emit remaining as final wave
            waves.append(sorted(remaining))
            break
        waves.append(ready)
        for n in ready:
            remaining.discard(n)
            for nxt in fwd[n]:
                indeg[nxt] -= 1
    return waves


def _t4b_register_phase(self, name: str, runner: Callable[..., Any],
                          deps: Optional[List[str]] = None,
                          timeout_s: Optional[float] = None) -> None:
    slots = getattr(self, "_t4b_phase_slots", None)
    if slots is None:
        slots = {}
        setattr(self, "_t4b_phase_slots", slots)
    eff_deps = list(deps) if deps is not None else list(_T4B_PHASE_DEPS.get(name, []))
    eff_to = float(timeout_s) if timeout_s is not None else float(_T4B_PHASE_TIMEOUTS.get(name, 600.0))
    slots[name] = _T4BPhaseSlot(name=name, deps=eff_deps, runner=runner, timeout_s=eff_to)


def _t4b_run_parallel_phases(self, target: Any = None,
                                max_workers: int = 4,
                                fail_fast: bool = False,
                                progress_cb: Optional[Callable[[str, str], None]] = None) -> Dict[str, Any]:
    """Execute registered phases respecting dependency DAG and timeouts."""
    slots: Dict[str, _T4BPhaseSlot] = getattr(self, "_t4b_phase_slots", {}) or {}
    if not slots:
        return {"phases": {}, "waves": [], "completed": 0, "failed": 0}
    waves = _t4b_caap_topo_sort(slots)
    completed = 0
    failed = 0
    cancelled = False
    for wi, wave in enumerate(waves):
        if cancelled:
            for n in wave:
                slots[n].status = "cancelled"
            continue
        # Skip if any dep failed
        runnable = []
        for n in wave:
            slot = slots[n]
            if any(slots[d].status in ("failed", "cancelled", "skipped") for d in slot.deps if d in slots):
                slot.status = "skipped"
                continue
            runnable.append(n)
        if not runnable:
            continue
        with _t4b_cf.ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
            futs: Dict[Any, str] = {}
            for n in runnable:
                slot = slots[n]
                slot.status = "running"
                slot.started_at = _t4b_time.time()
                if progress_cb:
                    try: progress_cb(n, "running")
                    except Exception: pass
                fut = ex.submit(slot.runner, target) if slot.runner else ex.submit(lambda: None)
                futs[fut] = n
            for fut in _t4b_cf.as_completed(futs):
                n = futs[fut]
                slot = slots[n]
                try:
                    slot.result = fut.result(timeout=slot.timeout_s)
                    slot.status = "completed"
                    completed += 1
                except _t4b_cf.TimeoutError:
                    slot.status = "failed"
                    slot.error = f"timeout after {slot.timeout_s}s"
                    failed += 1
                except Exception as e:
                    slot.status = "failed"
                    slot.error = f"{type(e).__name__}: {e}"
                    failed += 1
                slot.completed_at = _t4b_time.time()
                if progress_cb:
                    try: progress_cb(n, slot.status)
                    except Exception: pass
                if slot.status == "failed" and fail_fast:
                    cancelled = True
    return {
        "phases": {n: {"status": s.status, "error": s.error,
                          "duration_s": round(s.completed_at - s.started_at, 3) if s.completed_at else 0.0,
                          "result": s.result}
                       for n, s in slots.items()},
        "waves": waves,
        "completed": completed,
        "failed": failed,
        "cancelled": cancelled,
    }


def _t4b_phase_status(self) -> Dict[str, Any]:
    slots: Dict[str, _T4BPhaseSlot] = getattr(self, "_t4b_phase_slots", {}) or {}
    return {n: {"status": s.status, "deps": s.deps, "timeout_s": s.timeout_s,
                  "error": s.error} for n, s in slots.items()}


def _t4b_cancel_phase(self, name: str) -> bool:
    slots = getattr(self, "_t4b_phase_slots", {}) or {}
    if name in slots and slots[name].status in ("pending", "running"):
        slots[name].status = "cancelled"
        return True
    return False


# --- LLM bridge wire-up + streaming -------------------------------------
def _t4b_set_llm_bridge(self, bridge: Any) -> None:
    """Wire an LLM bridge object (must expose .complete(prompt, **kw) or .stream(prompt, **kw))."""
    setattr(self, "_t4b_llm_bridge", bridge)


def _t4b_llm_complete(self, prompt: str, system: Optional[str] = None,
                        max_tokens: int = 1024, temperature: float = 0.2,
                        timeout: float = 30.0) -> Dict[str, Any]:
    bridge = getattr(self, "_t4b_llm_bridge", None)
    if bridge is None:
        return {"ok": False, "error": "no_llm_bridge", "text": ""}
    fn = getattr(bridge, "complete", None) or getattr(bridge, "generate", None) or getattr(bridge, "__call__", None)
    if fn is None:
        return {"ok": False, "error": "bridge_missing_complete", "text": ""}
    t0 = _t4b_time.time()
    try:
        out = fn(prompt, system=system, max_tokens=max_tokens, temperature=temperature, timeout=timeout) \
            if hasattr(fn, "__code__") and "system" in fn.__code__.co_varnames else fn(prompt)
        text = out if isinstance(out, str) else (out.get("text") if isinstance(out, dict) else str(out))
        return {"ok": True, "text": text or "", "duration_s": round(_t4b_time.time() - t0, 3)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "text": "", "duration_s": round(_t4b_time.time() - t0, 3)}


def _t4b_llm_stream(self, prompt: str, system: Optional[str] = None,
                      max_tokens: int = 1024, temperature: float = 0.2,
                      on_token: Optional[Callable[[str], None]] = None,
                      timeout: float = 60.0) -> Iterator[str]:
    """Generator yielding chunks. Falls back to complete() split into pseudo-chunks if no .stream()."""
    bridge = getattr(self, "_t4b_llm_bridge", None)
    if bridge is None:
        return
    sfn = getattr(bridge, "stream", None) or getattr(bridge, "stream_complete", None)
    if sfn is not None:
        try:
            for chunk in sfn(prompt, system=system, max_tokens=max_tokens, temperature=temperature, timeout=timeout) \
                    if hasattr(sfn, "__code__") and "system" in sfn.__code__.co_varnames else sfn(prompt):
                if isinstance(chunk, dict):
                    text = chunk.get("text") or chunk.get("delta") or ""
                else:
                    text = str(chunk)
                if text:
                    if on_token:
                        try: on_token(text)
                        except Exception: pass
                    yield text
        except Exception as e:
            yield f"[stream_error:{type(e).__name__}:{e}]"
        return
    # Fallback: pseudo-stream by splitting complete() output
    res = _t4b_llm_complete(self, prompt, system=system, max_tokens=max_tokens, temperature=temperature, timeout=timeout)
    if not res.get("ok"):
        return
    text = res.get("text", "")
    chunk_size = 64
    for i in range(0, len(text), chunk_size):
        c = text[i:i+chunk_size]
        if on_token:
            try: on_token(c)
            except Exception: pass
        yield c


def _t4b_llm_health(self) -> Dict[str, Any]:
    bridge = getattr(self, "_t4b_llm_bridge", None)
    if bridge is None:
        return {"connected": False, "reason": "no_bridge"}
    out = {"connected": True, "type": type(bridge).__name__}
    for attr in ("model", "provider", "name", "endpoint"):
        v = getattr(bridge, attr, None)
        if v is not None:
            out[attr] = v
    out["has_complete"] = callable(getattr(bridge, "complete", None) or getattr(bridge, "generate", None))
    out["has_stream"] = callable(getattr(bridge, "stream", None) or getattr(bridge, "stream_complete", None))
    return out


# --- Phase event broadcast ----------------------------------------------
def _t4b_subscribe_phase_events(self, listener: Callable[[Dict[str, Any]], None]) -> None:
    listeners = getattr(self, "_t4b_phase_listeners", None)
    if listeners is None:
        listeners = []
        setattr(self, "_t4b_phase_listeners", listeners)
    listeners.append(listener)


def _t4b_emit_phase_event(self, event: Dict[str, Any]) -> int:
    listeners = getattr(self, "_t4b_phase_listeners", []) or []
    delivered = 0
    for ln in listeners:
        try:
            ln(event)
            delivered += 1
        except Exception:
            pass
    return delivered


def _t4b_run_correlated(self, target: Any, max_workers: int = 4) -> Dict[str, Any]:
    """Run all registered phases and emit per-phase events."""
    def cb(name: str, status: str):
        _t4b_emit_phase_event(self, {"phase": name, "status": status, "ts": _t4b_time.time()})
    return _t4b_run_parallel_phases(self, target=target, max_workers=max_workers, progress_cb=cb)


# --- Bind to CAAPCoordinator --------------------------------------------
try:
    CAAPCoordinator.register_phase = _t4b_register_phase  # type: ignore[name-defined]
    CAAPCoordinator.run_parallel_phases = _t4b_run_parallel_phases  # type: ignore[name-defined]
    CAAPCoordinator.phase_status = _t4b_phase_status  # type: ignore[name-defined]
    CAAPCoordinator.cancel_phase = _t4b_cancel_phase  # type: ignore[name-defined]
    CAAPCoordinator.set_llm_bridge = _t4b_set_llm_bridge  # type: ignore[name-defined]
    CAAPCoordinator.llm_complete = _t4b_llm_complete  # type: ignore[name-defined]
    CAAPCoordinator.llm_stream = _t4b_llm_stream  # type: ignore[name-defined]
    CAAPCoordinator.llm_health = _t4b_llm_health  # type: ignore[name-defined]
    CAAPCoordinator.subscribe_phase_events = _t4b_subscribe_phase_events  # type: ignore[name-defined]
    CAAPCoordinator.emit_phase_event = _t4b_emit_phase_event  # type: ignore[name-defined]
    CAAPCoordinator.run_correlated = _t4b_run_correlated  # type: ignore[name-defined]
except NameError:
    pass
