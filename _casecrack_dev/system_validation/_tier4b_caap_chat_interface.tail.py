# __TIER4B_CAAP__
# Tier 4B CAAP — chat_interface: LLM bridge wire-up + streaming + commands
import json as _t4b_json
import re as _t4b_re
import time as _t4b_time
import threading as _t4b_th
import uuid as _t4b_uuid
from typing import Any, Callable, Dict, List, Optional, Iterator
from dataclasses import dataclass, field

_T4B_CHAT_SLASH_CMDS = {
    "/help", "/clear", "/history", "/system", "/save", "/load",
    "/scan", "/findings", "/explain", "/replan", "/exit",
}

_T4B_DEFAULT_SYSTEM = (
    "You are CaseCrack security copilot. Provide concise, accurate, "
    "evidence-backed answers. Never fabricate findings or URLs."
)


@dataclass
class _T4BChatTurn:
    role: str
    content: str
    ts: float = field(default_factory=_t4b_time.time)
    tokens_in: int = 0
    tokens_out: int = 0
    duration_s: float = 0.0
    error: Optional[str] = None


def _t4b_chat_set_llm(self, bridge: Any) -> None:
    setattr(self, "_t4b_llm", bridge)


def _t4b_chat_set_system(self, prompt: str) -> None:
    setattr(self, "_t4b_system_prompt", str(prompt))


def _t4b_chat_get_system(self) -> str:
    return getattr(self, "_t4b_system_prompt", _T4B_DEFAULT_SYSTEM)


def _t4b_chat_history(self) -> List[Dict[str, Any]]:
    turns = getattr(self, "_t4b_turns", None) or []
    return [{"role": t.role, "content": t.content, "ts": t.ts,
              "tokens_in": t.tokens_in, "tokens_out": t.tokens_out,
              "duration_s": t.duration_s, "error": t.error} for t in turns]


def _t4b_chat_clear(self) -> int:
    turns = getattr(self, "_t4b_turns", []) or []
    n = len(turns)
    setattr(self, "_t4b_turns", [])
    return n


def _t4b_chat_save(self, path: str) -> Dict[str, Any]:
    h = _t4b_chat_history(self)
    try:
        with open(path, "w", encoding="utf-8") as f:
            _t4b_json.dump({"system": _t4b_chat_get_system(self), "turns": h}, f, indent=2)
        return {"ok": True, "path": path, "turns": len(h)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _t4b_chat_load(self, path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = _t4b_json.load(f)
        sys_p = data.get("system")
        if sys_p:
            _t4b_chat_set_system(self, sys_p)
        turns = []
        for t in data.get("turns", []):
            turns.append(_T4BChatTurn(role=t.get("role", "user"), content=t.get("content", ""),
                                          ts=t.get("ts", _t4b_time.time())))
        setattr(self, "_t4b_turns", turns)
        return {"ok": True, "loaded": len(turns)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _t4b_chat_send(self, content: str, max_tokens: int = 1024,
                       temperature: float = 0.2, timeout: float = 30.0) -> Dict[str, Any]:
    """Synchronous send; appends user + assistant turns."""
    turns = getattr(self, "_t4b_turns", None)
    if turns is None:
        turns = []
        setattr(self, "_t4b_turns", turns)
    user_turn = _T4BChatTurn(role="user", content=content, tokens_in=len(content) // 4)
    turns.append(user_turn)
    bridge = getattr(self, "_t4b_llm", None)
    if bridge is None:
        err_turn = _T4BChatTurn(role="assistant", content="", error="no_llm_bridge")
        turns.append(err_turn)
        return {"ok": False, "error": "no_llm_bridge", "turn": err_turn.__dict__}
    fn = getattr(bridge, "complete", None) or getattr(bridge, "generate", None) or getattr(bridge, "__call__", None)
    if fn is None:
        err_turn = _T4BChatTurn(role="assistant", content="", error="bridge_missing_complete")
        turns.append(err_turn)
        return {"ok": False, "error": "bridge_missing_complete"}
    sys_p = _t4b_chat_get_system(self)
    # Build context from last 6 turns
    ctx_turns = turns[-12:-1]  # exclude current user turn
    context_str = "\n\n".join(f"{t.role.upper()}: {t.content}" for t in ctx_turns)
    full_prompt = f"{context_str}\n\nUSER: {content}\nASSISTANT:" if context_str else content
    t0 = _t4b_time.time()
    try:
        if hasattr(fn, "__code__") and "system" in (fn.__code__.co_varnames or ()):
            out = fn(full_prompt, system=sys_p, max_tokens=max_tokens,
                     temperature=temperature, timeout=timeout)
        else:
            out = fn(full_prompt)
        text = out if isinstance(out, str) else (out.get("text") if isinstance(out, dict) else str(out))
        text = text or ""
        dur = round(_t4b_time.time() - t0, 3)
        a_turn = _T4BChatTurn(role="assistant", content=text,
                                  tokens_out=len(text) // 4, duration_s=dur)
        turns.append(a_turn)
        return {"ok": True, "text": text, "turn": a_turn.__dict__}
    except Exception as e:
        dur = round(_t4b_time.time() - t0, 3)
        a_turn = _T4BChatTurn(role="assistant", content="", duration_s=dur,
                                  error=f"{type(e).__name__}: {e}")
        turns.append(a_turn)
        return {"ok": False, "error": a_turn.error, "turn": a_turn.__dict__}


def _t4b_chat_stream(self, content: str, on_token: Callable[[str], None],
                         max_tokens: int = 1024, temperature: float = 0.2,
                         timeout: float = 60.0) -> Dict[str, Any]:
    """Stream tokens; returns final aggregate."""
    turns = getattr(self, "_t4b_turns", None)
    if turns is None:
        turns = []
        setattr(self, "_t4b_turns", turns)
    user_turn = _T4BChatTurn(role="user", content=content, tokens_in=len(content) // 4)
    turns.append(user_turn)
    bridge = getattr(self, "_t4b_llm", None)
    if bridge is None:
        return {"ok": False, "error": "no_llm_bridge", "text": ""}
    sfn = getattr(bridge, "stream", None) or getattr(bridge, "stream_complete", None)
    sys_p = _t4b_chat_get_system(self)
    ctx_turns = turns[-12:-1]
    context_str = "\n\n".join(f"{t.role.upper()}: {t.content}" for t in ctx_turns)
    full_prompt = f"{context_str}\n\nUSER: {content}\nASSISTANT:" if context_str else content
    t0 = _t4b_time.time()
    full = []
    try:
        if sfn is not None:
            it = sfn(full_prompt, system=sys_p, max_tokens=max_tokens,
                       temperature=temperature, timeout=timeout) \
                if hasattr(sfn, "__code__") and "system" in (sfn.__code__.co_varnames or ()) \
                else sfn(full_prompt)
            for chunk in it:
                text = chunk if isinstance(chunk, str) else (chunk.get("text") or chunk.get("delta") or "")
                if text:
                    full.append(text)
                    try: on_token(text)
                    except Exception: pass
        else:
            # Fallback: complete + chunk
            res = _t4b_chat_send(self, content, max_tokens=max_tokens,
                                     temperature=temperature, timeout=timeout)
            # remove the duplicate user/assistant pair we just appended above
            # by popping the assistant turn from inner call
            text = res.get("text", "")
            for i in range(0, len(text), 64):
                c = text[i:i+64]
                full.append(c)
                try: on_token(c)
                except Exception: pass
            # Remove the duplicate assistant turn from chat_send (we already added user above)
            if turns and turns[-1].role == "assistant":
                # the inner send appended both user (dup) and assistant; pop both
                if len(turns) >= 2 and turns[-2].role == "user" and turns[-2].content == content:
                    turns.pop()
                    turns.pop()
        text_full = "".join(full)
        dur = round(_t4b_time.time() - t0, 3)
        a_turn = _T4BChatTurn(role="assistant", content=text_full,
                                  tokens_out=len(text_full) // 4, duration_s=dur)
        turns.append(a_turn)
        return {"ok": True, "text": text_full, "duration_s": dur}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "text": "".join(full)}


def _t4b_parse_slash_command(self, line: str) -> Dict[str, Any]:
    line = (line or "").strip()
    if not line.startswith("/"):
        return {"is_command": False, "raw": line}
    parts = line.split(maxsplit=1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    return {"is_command": True, "command": cmd, "args": args,
              "known": cmd in _T4B_CHAT_SLASH_CMDS}


def _t4b_handle_command(self, line: str) -> Dict[str, Any]:
    parsed = _t4b_parse_slash_command(self, line)
    if not parsed["is_command"]:
        return {"handled": False, **parsed}
    cmd = parsed["command"]
    args = parsed["args"]
    if cmd == "/help":
        return {"handled": True, "text": "Commands: " + ", ".join(sorted(_T4B_CHAT_SLASH_CMDS))}
    if cmd == "/clear":
        n = _t4b_chat_clear(self)
        return {"handled": True, "text": f"Cleared {n} turns"}
    if cmd == "/history":
        return {"handled": True, "history": _t4b_chat_history(self)}
    if cmd == "/system":
        if args:
            _t4b_chat_set_system(self, args)
            return {"handled": True, "text": "System prompt updated"}
        return {"handled": True, "text": _t4b_chat_get_system(self)}
    if cmd == "/save":
        return {"handled": True, **_t4b_chat_save(self, args or "_chat_session.json")}
    if cmd == "/load":
        return {"handled": True, **_t4b_chat_load(self, args or "_chat_session.json")}
    if cmd == "/exit":
        return {"handled": True, "exit": True}
    return {"handled": False, "text": f"Unknown command: {cmd}"}


def _t4b_chat_token_count(self) -> Dict[str, int]:
    turns = getattr(self, "_t4b_turns", []) or []
    return {
        "tokens_in": sum(t.tokens_in for t in turns),
        "tokens_out": sum(t.tokens_out for t in turns),
        "turns": len(turns),
    }


def _t4b_chat_export_markdown(self) -> str:
    turns = getattr(self, "_t4b_turns", []) or []
    lines = ["# Chat Session", ""]
    for t in turns:
        lines.append(f"## {t.role.title()}")
        lines.append(t.content if not t.error else f"_Error: {t.error}_")
        lines.append("")
    return "\n".join(lines)


def _t4b_chat_summarize(self, max_tokens: int = 256) -> Dict[str, Any]:
    """Use LLM to summarize the chat history."""
    turns = getattr(self, "_t4b_turns", []) or []
    if not turns:
        return {"ok": False, "error": "empty_history"}
    bridge = getattr(self, "_t4b_llm", None)
    if bridge is None:
        # Fallback: heuristic
        snippet = " ".join(t.content[:100] for t in turns[-10:])
        return {"ok": True, "summary": snippet[:500], "fallback": True}
    transcript = "\n".join(f"{t.role}: {t.content[:300]}" for t in turns[-20:])
    prompt = f"Summarize this conversation in 3-5 bullet points:\n\n{transcript}"
    return _t4b_chat_send(self, prompt, max_tokens=max_tokens)


def _t4b_chat_validate_response(self, text: str) -> Dict[str, Any]:
    """Heuristic response sanity checks."""
    issues = []
    if not text or not text.strip():
        issues.append("empty")
    if len(text) < 10:
        issues.append("too_short")
    # Check for common hallucination markers
    if _t4b_re.search(r"\bAs an AI\b|\bI cannot\b.*\bbut here\b", text, _t4b_re.IGNORECASE):
        issues.append("refusal_with_bypass")
    # Detect URL fabrication
    fake_url_pattern = _t4b_re.compile(r"https?://example\.com/(secret|admin)/[a-f0-9]{16,}")
    if fake_url_pattern.search(text):
        issues.append("fabricated_url")
    return {"valid": len(issues) == 0, "issues": issues, "length": len(text)}


# --- Bind to ChatInterface ----------------------------------------------
try:
    ChatInterface.set_llm_bridge = _t4b_chat_set_llm  # type: ignore[name-defined]
    ChatInterface.set_system_prompt = _t4b_chat_set_system  # type: ignore[name-defined]
    ChatInterface.get_system_prompt = _t4b_chat_get_system  # type: ignore[name-defined]
    ChatInterface.history = _t4b_chat_history  # type: ignore[name-defined]
    ChatInterface.clear = _t4b_chat_clear  # type: ignore[name-defined]
    ChatInterface.save_session = _t4b_chat_save  # type: ignore[name-defined]
    ChatInterface.load_session = _t4b_chat_load  # type: ignore[name-defined]
    ChatInterface.send_message = _t4b_chat_send  # type: ignore[name-defined]
    ChatInterface.stream_message = _t4b_chat_stream  # type: ignore[name-defined]
    ChatInterface.parse_slash_command = _t4b_parse_slash_command  # type: ignore[name-defined]
    ChatInterface.handle_command = _t4b_handle_command  # type: ignore[name-defined]
    ChatInterface.token_count = _t4b_chat_token_count  # type: ignore[name-defined]
    ChatInterface.export_markdown = _t4b_chat_export_markdown  # type: ignore[name-defined]
    ChatInterface.summarize = _t4b_chat_summarize  # type: ignore[name-defined]
    ChatInterface.validate_response = _t4b_chat_validate_response  # type: ignore[name-defined]
except NameError:
    pass
