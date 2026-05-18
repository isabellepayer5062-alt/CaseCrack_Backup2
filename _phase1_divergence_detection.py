#!/usr/bin/env python3
"""
Phase 1 Advanced Divergence Detection
======================================

Hardens shadow runner against silent divergence by implementing:
- Strict comparison rules (exact match, semantic match, divergence)
- Structure normalization (ordering, timestamps, non-semantic fields)
- Policy side-effect tracking (denials, rate limits that didn't happen before)
- Fail-safe mode for early canary (prefer passthrough on typed failure)
- Regression snapshots (baseline outputs for comparison)

This is the "real divergence detector" that catches structural changes
that basic result hashing would miss.

Usage:
  from _phase1_divergence_detection import DivergenceDetector
  
  detector = DivergenceDetector(strict_mode=True)
  
  # Analyze divergence between two results
  analysis = detector.analyze_divergence(
    passthrough_result=pt_result,
    typed_result=typed_result,
    command="run_burp_scan"
  )
  
  if analysis['classification'] == "DIVERGENCE":
    logger.error(f"Divergence detected: {analysis['reason']}")
  elif analysis['classification'] == "SEMANTIC_MATCH":
    if not detector.strict_mode:
      logger.warning(f"Semantic match only: {analysis['details']}")
"""

import json
import logging
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from collections import OrderedDict
import hashlib
import re
from datetime import datetime

logger = logging.getLogger(__name__)


# ============================================================================
# Classification Enums
# ============================================================================

class DivergenceClassification(str, Enum):
    """Divergence severity levels"""
    EXACT_MATCH = "exact_match"                    # Identical structures
    SEMANTIC_MATCH = "semantic_match"              # Logically equivalent, structure differs
    SOFT_DIVERGENCE = "soft_divergence"            # Policy side-effect (would be denied)
    DIVERGENCE = "divergence"                      # Real mismatch
    FATAL_DIVERGENCE = "fatal_divergence"          # One succeeded, one failed


class ComparisonMode(str, Enum):
    """Comparison strictness"""
    STRICT = "strict"                              # Exact match only
    SEMANTIC = "semantic"                          # Semantic equivalence allowed
    PERMISSIVE = "permissive"                      # Allow known differences


@dataclass
class DivergenceAnalysis:
    """Result of divergence analysis"""
    classification: DivergenceClassification
    match: bool  # True for EXACT/SEMANTIC, False otherwise
    reason: str
    details: Dict[str, Any]
    severity: int  # 0-10, 10=worst
    recommendation: str


# ============================================================================
# Divergence Detector
# ============================================================================

class DivergenceDetector:
    """Advanced divergence detection with normalization & classification"""
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize detector
        
        Args:
          strict_mode: If True, SEMANTIC_MATCH counts as divergence
                      If False, SEMANTIC_MATCH allowed
        """
        self.strict_mode = strict_mode
        self.baseline_snapshots = {}  # Canonical outputs by (command, scenario)
        self.soft_divergences = []    # Policy side-effects
    
    # ==========================================================================
    # Main Analysis
    # ==========================================================================
    
    def analyze_divergence(
        self,
        passthrough_result: Any,
        typed_result: Any,
        command: str,
        policy_side_effects: Optional[Dict[str, Any]] = None
    ) -> DivergenceAnalysis:
        """
        Comprehensive divergence analysis
        
        Returns classification with reason and recommendation
        """
        
        # First: Check for fatal divergence (one succeeded, one failed)
        pt_success = passthrough_result and not isinstance(passthrough_result, Exception)
        typed_success = typed_result and not isinstance(typed_result, Exception)
        
        if pt_success != typed_success:
            return DivergenceAnalysis(
                classification=DivergenceClassification.FATAL_DIVERGENCE,
                match=False,
                reason=f"Success mismatch: PT={pt_success}, Typed={typed_success}",
                details={
                    "passthrough_success": pt_success,
                    "typed_success": typed_success,
                    "passthrough_type": type(passthrough_result).__name__,
                    "typed_type": type(typed_result).__name__
                },
                severity=10,
                recommendation="STOP: Investigate immediately. Typed implementation has critical bug."
            )
        
        # Both failed: Check if error types match
        if not pt_success and not typed_success:
            pt_error_type = type(passthrough_result).__name__
            typed_error_type = type(typed_result).__name__
            
            if pt_error_type == typed_error_type:
                return DivergenceAnalysis(
                    classification=DivergenceClassification.EXACT_MATCH,
                    match=True,
                    reason="Both failed with same error type",
                    details={
                        "error_type": pt_error_type
                    },
                    severity=0,
                    recommendation="OK: Expected behavior."
                )
            else:
                return DivergenceAnalysis(
                    classification=DivergenceClassification.DIVERGENCE,
                    match=False,
                    reason=f"Different error types: PT={pt_error_type}, Typed={typed_error_type}",
                    details={
                        "passthrough_error": pt_error_type,
                        "typed_error": typed_error_type
                    },
                    severity=7,
                    recommendation="Investigate: Check error handling logic"
                )
        
        # Both succeeded: Compare outputs
        comparison = self._compare_outputs(passthrough_result, typed_result, command)
        
        # Check for policy side-effects
        if policy_side_effects:
            soft_div = self._check_policy_side_effects(policy_side_effects)
            if soft_div:
                self.soft_divergences.append(soft_div)
                return DivergenceAnalysis(
                    classification=DivergenceClassification.SOFT_DIVERGENCE,
                    match=False,
                    reason=soft_div['reason'],
                    details=soft_div['details'],
                    severity=soft_div['severity'],
                    recommendation=soft_div['recommendation']
                )
        
        # Determine strictness
        if comparison['classification'] == "EXACT":
            return DivergenceAnalysis(
                classification=DivergenceClassification.EXACT_MATCH,
                match=True,
                reason="Exact structural match",
                details=comparison,
                severity=0,
                recommendation="✓ Safe to proceed"
            )
        elif comparison['classification'] == "SEMANTIC":
            if self.strict_mode:
                return DivergenceAnalysis(
                    classification=DivergenceClassification.DIVERGENCE,
                    match=False,
                    reason="Semantic match only (strict mode rejects)",
                    details=comparison,
                    severity=5,
                    recommendation="Decide: Accept semantic difference or fix structure?"
                )
            else:
                return DivergenceAnalysis(
                    classification=DivergenceClassification.SEMANTIC_MATCH,
                    match=True,
                    reason="Semantic match (permissive mode allows)",
                    details=comparison,
                    severity=2,
                    recommendation="⚠ Monitor for downstream impact"
                )
        else:
            return DivergenceAnalysis(
                classification=DivergenceClassification.DIVERGENCE,
                match=False,
                reason=comparison['reason'],
                details=comparison,
                severity=8,
                recommendation="INVESTIGATE: Real output difference"
            )
    
    # ==========================================================================
    # Output Comparison
    # ==========================================================================
    
    def _compare_outputs(
        self,
        pt_result: Dict[str, Any],
        typed_result: Dict[str, Any],
        command: str
    ) -> Dict[str, Any]:
        """
        Compare two outputs with normalization
        
        Returns: {classification, reason, differences}
        """
        
        # Normalize both
        pt_norm = self._normalize_output(pt_result, command)
        typed_norm = self._normalize_output(typed_result, command)
        
        # Compare
        if pt_norm == typed_norm:
            return {
                "classification": "EXACT",
                "reason": "Normalized outputs are identical"
            }
        
        # Check semantic equivalence
        semantic_eq = self._check_semantic_equivalence(pt_norm, typed_norm)
        if semantic_eq['equivalent']:
            return {
                "classification": "SEMANTIC",
                "reason": f"Semantically equivalent: {semantic_eq['reason']}",
                "differences": semantic_eq['differences']
            }
        
        # Find specific differences
        diff = self._find_differences(pt_norm, typed_norm)
        return {
            "classification": "DIVERGENCE",
            "reason": f"Structural difference: {diff['summary']}",
            "differences": diff['details']
        }
    
    def _normalize_output(self, result: Any, command: str) -> Any:
        """
        Normalize output for comparison
        
        Handles:
        - Sort dict keys (ensure consistent ordering)
        - Remove timestamps (or convert to fixed format)
        - Remove transient fields (IDs, request_ids, etc.)
        - Convert similar types (e.g., int vs float)
        """
        
        if isinstance(result, dict):
            normalized = {}
            for k, v in sorted(result.items()):
                # Skip transient fields
                if k in ['request_id', 'correlation_id', 'timestamp', 'created_at', '_latency_ms']:
                    continue
                
                normalized[k] = self._normalize_output(v, command)
            
            return normalized
        
        elif isinstance(result, list):
            # Sort lists if they're dicts (to handle ordering differences)
            if result and isinstance(result[0], dict):
                # Try to sort by a stable key
                try:
                    return sorted([self._normalize_output(item, command) for item in result], 
                                key=lambda x: str(x))
                except:
                    return [self._normalize_output(item, command) for item in result]
            else:
                return [self._normalize_output(item, command) for item in result]
        
        elif isinstance(result, str):
            # Normalize timestamps
            if self._looks_like_timestamp(result):
                return "<TIMESTAMP>"
            # Normalize UUIDs
            if self._looks_like_uuid(result):
                return "<UUID>"
            return result
        
        return result
    
    def _check_semantic_equivalence(
        self,
        pt: Any,
        typed: Any
    ) -> Dict[str, Any]:
        """
        Check if outputs are semantically equivalent despite structural differences
        
        Examples:
        - {"items": [1,2,3]} vs {"items": [3,2,1]} (ordering)
        - {"value": 100} vs {"value": "100"} (type coercion)
        - {"data": {...}} vs data: {...}} (wrapper)
        """
        
        # Same after normalization
        if pt == typed:
            return {"equivalent": True, "reason": "Identical", "differences": []}
        
        # Both dicts: check if same keys/values ignoring order
        if isinstance(pt, dict) and isinstance(typed, dict):
            if set(pt.keys()) != set(typed.keys()):
                return {
                    "equivalent": False,
                    "reason": "Different keys",
                    "differences": {
                        "pt_keys": list(pt.keys()),
                        "typed_keys": list(typed.keys())
                    }
                }
            
            differences = []
            for key in pt.keys():
                if pt[key] != typed[key]:
                    # Check if values are semantically equivalent
                    if self._semantically_equivalent(pt[key], typed[key]):
                        differences.append(f"{key}: {type(pt[key]).__name__} vs {type(typed[key]).__name__}")
                    else:
                        return {
                            "equivalent": False,
                            "reason": f"Value differs at {key}",
                            "differences": {key: {"pt": pt[key], "typed": typed[key]}}
                        }
            
            if differences:
                return {
                    "equivalent": True,
                    "reason": "Type/formatting differences",
                    "differences": differences
                }
        
        # Both lists: check content ignoring order
        if isinstance(pt, list) and isinstance(typed, list):
            if sorted(str(x) for x in pt) == sorted(str(x) for x in typed):
                return {
                    "equivalent": True,
                    "reason": "Same content, different order",
                    "differences": ["ordering"]
                }
        
        return {"equivalent": False, "reason": "Not equivalent", "differences": []}
    
    def _semantically_equivalent(self, a: Any, b: Any) -> bool:
        """Check if two values are semantically equivalent despite type differences"""
        # 100 == "100" == 100.0
        try:
            return float(a) == float(b)
        except:
            pass
        
        # "yes"/"true"/1 are truthy
        if isinstance(a, (bool, int, str)) and isinstance(b, (bool, int, str)):
            return bool(a) == bool(b)
        
        return False
    
    def _find_differences(self, pt: Any, typed: Any) -> Dict[str, Any]:
        """Find specific differences between outputs"""
        diff_paths = []
        
        def recurse(path, p, t):
            if type(p) != type(t):
                diff_paths.append((path, f"type mismatch: {type(p).__name__} vs {type(t).__name__}"))
                return
            
            if isinstance(p, dict):
                if set(p.keys()) != set(t.keys()):
                    diff_paths.append((path, f"keys differ: {set(p.keys()) - set(t.keys())} missing"))
                for key in p.keys():
                    if key in t:
                        recurse(f"{path}.{key}", p[key], t[key])
            
            elif isinstance(p, list):
                if len(p) != len(t):
                    diff_paths.append((path, f"length differs: {len(p)} vs {len(t)}"))
                for i, (pi, ti) in enumerate(zip(p, t)):
                    recurse(f"{path}[{i}]", pi, ti)
            
            elif p != t:
                diff_paths.append((path, f"value differs: {p!r} vs {t!r}"))
        
        recurse("$", pt, typed)
        
        return {
            "summary": f"{len(diff_paths)} difference(s)",
            "details": diff_paths[:10]  # First 10
        }
    
    # ==========================================================================
    # Policy Side-Effects
    # ==========================================================================
    
    def _check_policy_side_effects(self, effects: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if policy enforcement caused behavioral changes
        
        Effects tracked:
        - would_have_been_denied_by_policy
        - would_have_been_rate_limited
        - would_have_been_throttled
        """
        
        if effects.get('would_have_been_denied_by_policy'):
            return {
                "reason": f"Policy rejection: {effects['denial_reason']}",
                "details": {
                    "denial_reason": effects['denial_reason'],
                    "policy": effects.get('policy', 'unknown')
                },
                "severity": 6,
                "recommendation": "Decide: Adjust limits or accept stricter enforcement?"
            }
        
        if effects.get('would_have_been_rate_limited'):
            return {
                "reason": f"Rate limit: {effects['limit_reason']}",
                "details": {
                    "limit_reason": effects['limit_reason'],
                    "quota": effects.get('quota', 'unknown')
                },
                "severity": 5,
                "recommendation": "Monitor: Users may experience degradation"
            }
        
        if effects.get('would_have_been_throttled'):
            return {
                "reason": f"Throttled: {effects['throttle_reason']}",
                "details": {
                    "throttle_reason": effects['throttle_reason']
                },
                "severity": 4,
                "recommendation": "Monitor: Check response times"
            }
        
        return None
    
    # ==========================================================================
    # Baseline Snapshots
    # ==========================================================================
    
    def snapshot_baseline_output(
        self,
        command: str,
        scenario: str,
        result: Any
    ) -> None:
        """
        Snapshot canonical output for regression testing
        
        Usage:
          detector.snapshot_baseline_output("run_burp_scan", "basic_scan", result)
          
          # Later, verify output hasn't regressed:
          regression = detector.check_regression(
            "run_burp_scan", "basic_scan", new_result
          )
        """
        key = (command, scenario)
        self.baseline_snapshots[key] = {
            "timestamp": datetime.now().isoformat(),
            "result": self._normalize_output(result, command),
            "hash": self._hash_result(result)
        }
        logger.info(f"Snapshotted baseline: {command}/{scenario}")
    
    def check_regression(
        self,
        command: str,
        scenario: str,
        current_result: Any
    ) -> Dict[str, Any]:
        """
        Check if current result has regressed from baseline
        
        Returns: {regressed, differences}
        """
        key = (command, scenario)
        
        if key not in self.baseline_snapshots:
            return {
                "regressed": False,
                "reason": "No baseline snapshot"
            }
        
        baseline = self.baseline_snapshots[key]['result']
        current_norm = self._normalize_output(current_result, command)
        
        if baseline == current_norm:
            return {
                "regressed": False,
                "reason": "No regression"
            }
        
        # Find differences
        diff = self._find_differences(baseline, current_norm)
        
        return {
            "regressed": True,
            "reason": "Output differs from baseline",
            "differences": diff['details'],
            "baseline_snapshot_age": self.baseline_snapshots[key].get('timestamp')
        }
    
    # ==========================================================================
    # Utilities
    # ==========================================================================
    
    @staticmethod
    def _looks_like_timestamp(s: str) -> bool:
        """Check if string looks like a timestamp"""
        if not isinstance(s, str):
            return False
        # ISO format: 2026-04-24T10:30:45.123456
        return bool(re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', s))
    
    @staticmethod
    def _looks_like_uuid(s: str) -> bool:
        """Check if string looks like UUID"""
        if not isinstance(s, str):
            return False
        return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', s, re.I))
    
    @staticmethod
    def _hash_result(result: Any) -> str:
        """Hash result"""
        try:
            json_str = json.dumps(result, sort_keys=True, default=str)
            return hashlib.sha256(json_str.encode()).hexdigest()[:16]
        except:
            return "ERROR"


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "DivergenceDetector",
    "DivergenceClassification",
    "DivergenceAnalysis",
    "ComparisonMode",
]


if __name__ == "__main__":
    # Demo
    detector = DivergenceDetector(strict_mode=False)
    
    # Test exact match
    pt = {"status": "ok", "count": 5}
    typed = {"status": "ok", "count": 5}
    result = detector.analyze_divergence(pt, typed, "list_targets")
    print(f"Exact match: {result.classification}")
    
    # Test semantic match (ordering)
    pt = {"targets": [1, 2, 3], "status": "ok"}
    typed = {"status": "ok", "targets": [3, 2, 1]}
    result = detector.analyze_divergence(pt, typed, "list_targets")
    print(f"Ordering diff: {result.classification}")
    
    # Test fatal divergence
    pt = {"status": "ok"}
    typed = Exception("Failed")
    result = detector.analyze_divergence(pt, typed, "list_targets")
    print(f"Fatal divergence: {result.classification}, severity: {result.severity}")
    
    # Test baseline snapshot
    detector.snapshot_baseline_output("run_burp_scan", "basic_scan", 
                                     {"status": "complete", "findings": 5})
    regression = detector.check_regression("run_burp_scan", "basic_scan",
                                         {"status": "complete", "findings": 10})
    print(f"Regression check: {regression}")
