# Final MCP Tri-State Validation Report

Verdict: GO

OFFLINE:
  status: offline
  stream_ok: False

DEGRADED:
  status: degraded
  stream_ok: True
  outcomes: {"allowlist_deny": 1, "license_required": 1, "other_error": 0, "rate_limited": 0, "success": 1}

HEALTHY:
  status: healthy
  stream_ok: True
  outcomes: {"allowlist_deny": 1, "license_required": 0, "other_error": 0, "rate_limited": 1, "success": 1}

INTEGRITY:
  degraded_request_ids_unique: True
  healthy_sse_request_events: 3
  healthy_sse_result_events: 3
  snapshot_convergent: True

CONCURRENCY:
  honored: True
  observed_max_active: 3
  request_ids_unique: True
