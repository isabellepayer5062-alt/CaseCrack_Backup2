    async def _handle_target_profile(self, _request: Any) -> Any:
        """Return the progressive target profile (GET /api/target-profile)."""
        return web.json_response(self._state.target_profile.to_dict())

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

    async def _handle_llm_chat_stream(self, request: Any) -> Any:
        """H-3: SSE streaming fallback for HTTP clients."""
        from . import routes_llm
        return await routes_llm.handle_llm_chat_stream(self, request)

    async def _handle_llm_feedback(self, request: Any) -> Any:
        """I-8: Store user quality feedback on LLM responses."""
        from . import routes_llm
        return await routes_llm.handle_llm_feedback(self, request)

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

