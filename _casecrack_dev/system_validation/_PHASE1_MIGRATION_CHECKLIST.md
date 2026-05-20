# 🎯 Phase 1 Migration Checklist

**Objective**: Migrate Phase 1 commands (76% traffic) from passthrough to typed implementations  
**Timeline**: 4-6 weeks  
**Success**: All Phase 1 traffic flows through enforced types/policies with zero divergence

---

## Pre-Development (Week 0)

### Setup & Planning
- [ ] **Review existing passthrough implementations**
  - Locate current run_burp_scan, list_targets, get_report handlers
  - Document current behavior, error handling, timeouts
  - File: Document findings in `_PHASE1_IMPLEMENTATION_NOTES.md`

- [ ] **Baseline metrics snapshot**
  - Run: `python _analyze_passthrough_metrics.py` 
  - Save output: `_passthrough_baseline_week0.json`
  - Verify 76% concentration for Phase 1 commands

- [ ] **Staging environment ready**
  - Confirm staging has same config as production
  - Confirm test data available
  - Confirm logging/metrics collection working

- [ ] **Team alignment**
  - Share `_PHASE1_EXECUTION_PLAN.md` with team
  - Schedule weekly check-ins
  - Define on-call support for canary period

---

## Development Phase (Weeks 1-2)

### Week 1: Tool Definitions & Validation

#### Task 1.1: Create Tool Definitions
- [ ] **File created**: `_phase1_tool_definitions.py`
- [ ] **Schemas defined** for all 3 commands:
  - [ ] run_burp_scan (target, scan_profile, timeout_seconds, output_format)
  - [ ] list_targets (filter_tag, limit, offset)
  - [ ] get_report (report_id, format)
- [ ] **Verification**: `python _phase1_tool_definitions.py` runs without errors
- [ ] **Code review**: Schemas match actual command signatures

#### Task 1.2: Create Validators
- [ ] **File ready**: `_phase1_tool_definitions.py` (ToolValidator class)
- [ ] **Validators implemented**:
  - [ ] validate_run_burp_scan()
  - [ ] validate_list_targets()
  - [ ] validate_get_report()
- [ ] **Test coverage**:
  - [ ] Valid requests pass
  - [ ] Invalid requests fail with descriptive errors
  - [ ] Edge cases (empty strings, max values, type mismatches)
- [ ] **Verification**: 
  ```bash
  python -c "
  from _phase1_tool_definitions import ToolValidator
  v = ToolValidator()
  print(v.validate_run_burp_scan({'target': 'example.com', 'scan_profile': 'balanced'}))
  print(v.validate_run_burp_scan({'target': '!!!', 'scan_profile': 'invalid'}))
  "
  ```

#### Task 1.3: Create Policy Definitions
- [ ] **File ready**: `_phase1_tool_definitions.py` (PolicyEnforcer class)
- [ ] **Policies defined** for all 3 commands:
  - [ ] Role access (user, admin, viewer)
  - [ ] Plan limits (free, pro, enterprise)
  - [ ] Concurrency caps (3 for run_burp_scan, 10 for list_targets, 5 for get_report)
  - [ ] Quota windows (24 hours)
- [ ] **Policy enforcer** can check:
  - [ ] Role-based access
  - [ ] Plan-based access
  - [ ] Quota enforcement
  - [ ] Concurrency limits
- [ ] **Verification**:
  ```bash
  python -c "
  from _phase1_tool_definitions import PolicyEnforcer
  pe = PolicyEnforcer()
  # Test with mock principal
  "
  ```

### Week 2: Typed Implementations & Shadow Runner

#### Task 2.1: Create Shadow Runner Harness
- [ ] **File created**: `_phase1_shadow_runner.py`
- [ ] **ShadowRunner class** can execute:
  - [ ] run_burp_scan through both passthrough & typed
  - [ ] list_targets through both passthrough & typed
  - [ ] get_report through both passthrough & typed
- [ ] **Comparison logic** working:
  - [ ] Success/failure matching
  - [ ] Output hash comparison
  - [ ] Latency tracking
  - [ ] Divergence categorization
- [ ] **Logging** in place:
  - [ ] Shadow log (circular buffer, 10k max)
  - [ ] Divergence log (all mismatches)
  - [ ] Metrics collection
- [ ] **Verification**:
  ```bash
  python _phase1_shadow_runner.py  # Demo should run
  ```

#### Task 2.2: Implement Typed Commands (Minimal MVP)
- [ ] **run_burp_scan_typed()**
  - [ ] Validate params using ToolValidator
  - [ ] Check policy using PolicyEnforcer
  - [ ] Call actual Burp API
  - [ ] Return structured result
  - [ ] Log audit trail

- [ ] **list_targets_typed()**
  - [ ] Validate params using ToolValidator
  - [ ] Check policy using PolicyEnforcer
  - [ ] Query database
  - [ ] Return structured result
  - [ ] Log audit trail

- [ ] **get_report_typed()**
  - [ ] Validate params using ToolValidator
  - [ ] Check policy using PolicyEnforcer
  - [ ] Query database for report
  - [ ] Return structured result
  - [ ] Log audit trail

#### Task 2.3: Integration with MCP Server
- [ ] **Wire shadow runner into MCP server**:
  - [ ] Import ShadowRunner in mcp_server.py
  - [ ] Initialize with shadow_level="full"
  - [ ] Hook into request dispatch for Phase 1 commands

- [ ] **Route Phase 1 traffic** through shadow:
  ```python
  # In mcp_server._execute_tool()
  if command in ["run_burp_scan", "list_targets", "get_report"]:
    return await shadow_runner.{command}_shadow(...)
  ```

- [ ] **Verification**: Deploy to staging, confirm logs show both implementations

---

## Testing Phase (Week 3)

### Task 3.1: Staging Shadow Testing
- [ ] **Shadow runner active** in staging environment
- [ ] **Run for 7 days** collecting shadow data:
  - [ ] Manual test runs for each command
  - [ ] Automated test suite
  - [ ] Load testing (simulate production volume)
- [ ] **Monitor divergence**:
  - [ ] Check `divergence_log` daily
  - [ ] Investigate any mismatches
  - [ ] Fix typed implementations or validators

#### Data Collection (Daily)
- Day 1: [ ] run_burp_scan (50+ runs, check for patterns)
- Day 1: [ ] list_targets (100+ runs, pagination testing)
- Day 1: [ ] get_report (50+ runs, with real report IDs)
- Day 2-7: [ ] Repeat, increase volume, add edge cases

#### Sample Test Scenarios
```python
# run_burp_scan tests
validate_run_burp_scan({
  "target": "example.com",
  "scan_profile": "quick"
})
validate_run_burp_scan({
  "target": "192.168.1.1",
  "scan_profile": "thorough",
  "timeout_seconds": 1800
})

# list_targets tests
validate_list_targets({
  "limit": 100
})
validate_list_targets({
  "filter_tag": "prod",
  "limit": 1000,
  "offset": 0
})

# get_report tests
validate_get_report({
  "report_id": "550e8400-e29b-41d4-a716-446655440000"
})
validate_get_report({
  "report_id": "invalid-uuid"  # Should fail
})
```

### Task 3.2: Generate Readiness Report
- [ ] **After 7 days staging**: 
  ```bash
  report = shadow_runner.generate_readiness_report()
  # Check: all commands should have match_rate >= 99%
  # Check: total_runs per command >= 100
  ```

- [ ] **Criteria for moving to production**:
  - [ ] run_burp_scan: match_rate >= 99%, total_runs >= 100
  - [ ] list_targets: match_rate >= 99%, total_runs >= 100
  - [ ] get_report: match_rate >= 99%, total_runs >= 100
  - [ ] No unresolved divergences
  - [ ] Latency overhead < 20%

- [ ] **If criteria not met**:
  - [ ] Investigate divergences
  - [ ] Fix implementations
  - [ ] Return to testing (up to 2 more weeks)

---

## Production Canary (Week 4)

### Task 4.1: Canary 10% (Days 1-3)
- [ ] **Deploy shadow runner to production** with shadow_level="light"
- [ ] **Route 10% of Phase 1 traffic** through typed implementations
- [ ] **Shadow logging active** (logs divergence only)
- [ ] **Monitor**:
  - [ ] Error rates (typed vs passthrough)
  - [ ] Latencies (< 20% overhead)
  - [ ] Divergence log (should be empty)
  - [ ] User-reported issues

#### Checklist
- [ ] Deployment successful, no errors
- [ ] 10% traffic routing working (verify via metrics)
- [ ] Shadow logs being written
- [ ] Metrics being collected
- [ ] On-call team monitoring
- [ ] No user-reported issues

#### Success Criteria
- [ ] Zero divergence in 3 days
- [ ] Error rates stable vs baseline
- [ ] Latency overhead acceptable
- [ ] No user complaints

### Task 4.2: Canary 50% (Days 4-6)
- [ ] **Increase to 50% traffic** through typed implementations
- [ ] **Continue shadow logging**
- [ ] **Daily divergence reports**

#### Checklist
- [ ] 50% traffic routing confirmed
- [ ] Shadow logs being written
- [ ] Daily monitoring calls
- [ ] No regressions observed

#### Success Criteria
- [ ] Zero divergence in 3+ days
- [ ] Error rates stable
- [ ] Performance acceptable

### Task 4.3: Canary 100% (Days 7+)
- [ ] **Route 100% of Phase 1 traffic** through typed implementations
- [ ] **Keep passthrough available** as emergency rollback
- [ ] **Shadow logging** continues for 7 days

#### Checklist
- [ ] 100% traffic routing confirmed
- [ ] Shadow logs clean for 7 days
- [ ] Metrics show expected behavior
- [ ] Audit trails complete

#### Success Criteria
- [ ] 7+ days at 100% with zero divergence
- [ ] All audit logging working
- [ ] Policy enforcement active
- [ ] Quota tracking accurate

---

## Decommissioning (Week 5)

### Task 5.1: Kill Passthrough for Phase 1 Commands
- [ ] **Update policy** to reject passthrough requests for Phase 1:
  ```python
  PHASE1_COMMANDS = {"run_burp_scan", "list_targets", "get_report"}
  
  def check_passthrough_allowed(command):
    if command in PHASE1_COMMANDS:
      raise PolicyViolation(f"{command} is no longer available via passthrough")
    return True
  ```

- [ ] **Disable shadow runner** for Phase 1 commands
  ```python
  shadow_runner.shadow_level = "off"
  ```

- [ ] **Archive shadow logs**:
  - [ ] Export divergence_log to JSON for audit
  - [ ] Save readiness_report
  - [ ] File: `_PHASE1_SHADOW_LOGS_FINAL.json`

- [ ] **Update documentation**:
  - [ ] Mark passthrough deprecated for Phase 1
  - [ ] Document new typed API
  - [ ] Update runbooks, dashboards, alerts

### Task 5.2: Verify Decommissioning
- [ ] **Test passthrough rejection**:
  ```bash
  # Should fail with "no longer available via passthrough"
  curl -X POST http://localhost:8000/mcp/call \
    -d '{"command": "run_burp_scan", "use_passthrough": true, ...}'
  ```

- [ ] **Confirm typed-only routing**:
  - [ ] Metrics show 100% typed traffic
  - [ ] No passthrough calls recorded
  - [ ] Audit logs show policy enforcement

---

## Post-Deployment (Week 6+)

### Task 6.1: Monitor Production (1 week)
- [ ] **Daily checks**:
  - [ ] Error rates (target: <0.5% for Phase 1)
  - [ ] Performance (p99 latency within SLA)
  - [ ] Quota enforcement (users not exceeding limits)
  - [ ] Audit logs (complete trail for all requests)
  - [ ] User feedback (any issues reported)

### Task 6.2: Generate Phase 1 Completion Report
- [ ] **Document results**:
  - [ ] Baseline vs final metrics
  - [ ] Divergence stats (total, by type)
  - [ ] Performance impact
  - [ ] Policy enforcement effectiveness
  - [ ] User experience (smooth/problematic)

- [ ] **File**: `_PHASE1_COMPLETION_REPORT.md`
  ```markdown
  # Phase 1 Migration — Completion Report
  
  ## Summary
  - Status: COMPLETE
  - Commands migrated: run_burp_scan, list_targets, get_report
  - Traffic coverage: 100% (2,076/2,537 baseline calls)
  - Timeline: 4 weeks
  
  ## Key Metrics
  - Shadow divergence rate: 0%
  - Error rate improvement: X%
  - Performance overhead: <10%
  - Policy enforcement: 100%
  
  ## Lessons Learned
  - What worked well
  - What could be improved
  - Recommendations for Phase 2/3
  ```

- [ ] **Share findings** with team and stakeholders

### Task 6.3: Plan Phase 2
- [ ] **Analyze Phase 2 commands** (19% traffic):
  - export_findings
  - check_status
- [ ] **Create Phase 2 execution plan** using same approach
- [ ] **Timeline**: Start Phase 2 after Phase 1 stable (2+ weeks post-migration)

---

## Rollback Plan (Emergency)

If production issues detected:

### Immediate Actions
- [ ] **Panic button**: Revert 100% traffic to passthrough
  ```bash
  # In mcp_server.py, toggle shadow_level to "off" and routing to passthrough
  ```

- [ ] **Contact on-call**: Page engineer to investigate
- [ ] **Customer communication**: Notify users of temporary degradation

### Investigation (24 hours)
- [ ] **Review shadow logs** for error patterns
- [ ] **Check metrics** for anomalies
- [ ] **Gather user reports** for common issues
- [ ] **Identify root cause**

### Remediation (24-72 hours)
- [ ] **Fix** typed implementation or validator
- [ ] **Test in staging** until zero divergence
- [ ] **Restart canary** at 10%
- [ ] **Document** what failed and why

---

## Success Metrics Summary

| Phase | Timeline | Success Criteria |
|-------|----------|-----------------|
| **Development** | Weeks 1-2 | Tool defs + validators + shadow runner complete, tested |
| **Staging** | Week 3 | 7 days shadow test, 99%+ match rate, zero divergence |
| **Canary** | Week 4 | 10% → 50% → 100% with zero divergence, metrics stable |
| **Decommission** | Week 5 | Passthrough disabled, 7+ days at 100% typed, audit complete |
| **Monitor** | Week 6+ | Error rates low, performance good, users happy |

---

## Key Deliverables

- [ ] `_phase1_tool_definitions.py` — Schemas + validators + policy
- [ ] `_phase1_shadow_runner.py` — A/B comparison harness
- [ ] `_PHASE1_SHADOW_LOGS_FINAL.json` — Final audit archive
- [ ] `_PHASE1_COMPLETION_REPORT.md` — Post-launch retrospective
- [ ] Updated `mcp_server.py` — Typed implementations wired
- [ ] Updated documentation — API migration guide

---

## Contact & Support

- **Questions**: See `_PHASE1_EXECUTION_PLAN.md`
- **Technical issues**: Reference `_phase1_tool_definitions.py` docstrings
- **On-call**: [Team contact info]

**Status**: Ready to begin development
**Owner**: [Your name]
**Last updated**: [Today's date]
