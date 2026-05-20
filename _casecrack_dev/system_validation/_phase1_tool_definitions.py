#!/usr/bin/env python3
"""
Phase 1 Tool Definitions & Policy Enforcement
==============================================

Implements typed tool schemas, policies, and validators for Phase 1 commands:
- run_burp_scan (34% of traffic)
- list_targets (26% of traffic)
- get_report (17% of traffic)

Total Phase 1 coverage: 76% of all passthrough traffic

Usage:
  from _phase1_tool_definitions import ToolDefinitions, ToolValidator, PolicyEnforcer
  
  definitions = ToolDefinitions()
  validator = ToolValidator()
  enforcer = PolicyEnforcer(mcp_server.policy_resolver)
  
  # Validate incoming request
  result = validator.validate_run_burp_scan(params)
  if not result['valid']:
    raise ValidationError(result['errors'])
  
  # Check policy (role, quota, concurrency)
  check = enforcer.check_run_burp_scan(principal, params)
  if not check['allowed']:
    raise PolicyViolation(check['reason'])
  
  # Execute typed implementation
  output = await mcp_server.run_burp_scan_typed(principal, params)
"""

import re
import uuid
import ipaddress
import socket
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


# ============================================================================
# Tool Definitions (Schemas)
# ============================================================================

class ScanProfile(str, Enum):
    """Allowed scan profiles for run_burp_scan"""
    QUICK = "quick"           # 5-10 min, basic checks
    BALANCED = "balanced"      # 15-30 min, standard checks
    THOROUGH = "thorough"      # 60+ min, deep analysis


class OutputFormat(str, Enum):
    """Allowed output formats"""
    JSON = "json"
    XML = "xml"
    SARIF = "sarif"


class ReportFormat(str, Enum):
    """Allowed report formats"""
    JSON = "json"
    PDF = "pdf"
    HTML = "html"


@dataclass
class ToolDefinition:
    """Schema for a typed tool"""
    name: str
    version: str
    description: str
    params: Dict[str, Dict[str, Any]]
    policy: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization"""
        return asdict(self)


class ToolDefinitions:
    """Container for all Phase 1 tool definitions"""
    
    @staticmethod
    def get_run_burp_scan() -> Dict[str, Any]:
        """Schema for run_burp_scan"""
        return {
            "name": "run_burp_scan",
            "version": "1.0",
            "description": "Execute security scan with profile-based configuration",
            "params": {
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname, IP address, or CIDR range",
                    "pattern": r"^[a-zA-Z0-9:./\-\.]+$",
                    "validation": "dns_or_ip_or_cidr",
                    "examples": ["example.com", "192.168.1.1", "10.0.0.0/24"]
                },
                "scan_profile": {
                    "type": "enum",
                    "enum": ["quick", "balanced", "thorough"],
                    "required": True,
                    "default": "balanced",
                    "description": "Scan intensity and duration"
                },
                "timeout_seconds": {
                    "type": "integer",
                    "min": 30,
                    "max": 3600,
                    "required": False,
                    "default": 600,
                    "description": "Scan timeout in seconds (30-3600)"
                },
                "output_format": {
                    "type": "enum",
                    "enum": ["json", "xml", "sarif"],
                    "required": False,
                    "default": "json",
                    "description": "Output format for scan results"
                }
            },
            "policy": {
                "category": "security_scan",
                "roles_allowed": ["user", "admin"],
                "plans_allowed": ["pro", "enterprise"],
                "concurrency_limit": 3,
                "per_tenant_quota": 100,
                "quota_window_hours": 24,
                "requires_mfa": False,
                "audit_level": "full"
            }
        }
    
    @staticmethod
    def get_list_targets() -> Dict[str, Any]:
        """Schema for list_targets"""
        return {
            "name": "list_targets",
            "version": "1.0",
            "description": "List all configured scan targets with optional filtering",
            "params": {
                "filter_tag": {
                    "type": "string",
                    "required": False,
                    "description": "Filter targets by tag"
                },
                "limit": {
                    "type": "integer",
                    "min": 1,
                    "max": 10000,
                    "required": False,
                    "default": 100,
                    "description": "Max results to return"
                },
                "offset": {
                    "type": "integer",
                    "min": 0,
                    "required": False,
                    "default": 0,
                    "description": "Pagination offset"
                }
            },
            "policy": {
                "category": "read_only",
                "roles_allowed": ["user", "admin", "viewer"],
                "plans_allowed": ["free", "pro", "enterprise"],
                "concurrency_limit": 10,
                "per_tenant_quota": 10000,
                "quota_window_hours": 24,
                "requires_mfa": False,
                "audit_level": "light"
            }
        }
    
    @staticmethod
    def get_get_report() -> Dict[str, Any]:
        """Schema for get_report"""
        return {
            "name": "get_report",
            "version": "1.0",
            "description": "Retrieve completed scan report",
            "params": {
                "report_id": {
                    "type": "string",
                    "required": True,
                    "description": "Report UUID",
                    "validation": "uuid",
                    "examples": ["550e8400-e29b-41d4-a716-446655440000"]
                },
                "format": {
                    "type": "enum",
                    "enum": ["json", "pdf", "html"],
                    "required": False,
                    "default": "json",
                    "description": "Output format for report"
                }
            },
            "policy": {
                "category": "read_only",
                "roles_allowed": ["user", "admin", "viewer"],
                "plans_allowed": ["free", "pro", "enterprise"],
                "concurrency_limit": 5,
                "per_tenant_quota": 5000,
                "quota_window_hours": 24,
                "requires_mfa": False,
                "audit_level": "light"
            }
        }


# ============================================================================
# Validators
# ============================================================================

class ToolValidator:
    """Validate parameters against tool schemas"""
    
    def __init__(self):
        self.definitions = ToolDefinitions()
    
    def validate_run_burp_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate run_burp_scan parameters"""
        errors = []
        
        # Validate target (required)
        if not params.get("target"):
            errors.append("target is required")
        elif not self._is_valid_target(params["target"]):
            errors.append(
                f"target '{params['target']}' is invalid "
                "(must be FQDN, IPv4/IPv6, or CIDR)"
            )
        
        # Validate scan_profile (required, enum)
        if "scan_profile" not in params:
            errors.append("scan_profile is required")
        elif params["scan_profile"] not in ["quick", "balanced", "thorough"]:
            errors.append(
                f"scan_profile '{params['scan_profile']}' is invalid "
                "(must be: quick, balanced, thorough)"
            )
        
        # Validate timeout_seconds (optional, bounded int)
        if "timeout_seconds" in params:
            timeout = params["timeout_seconds"]
            if not isinstance(timeout, int):
                errors.append(f"timeout_seconds must be integer, got {type(timeout).__name__}")
            elif timeout < 30 or timeout > 3600:
                errors.append(f"timeout_seconds must be 30-3600, got {timeout}")
        
        # Validate output_format (optional, enum)
        if "output_format" in params:
            fmt = params["output_format"]
            if fmt not in ["json", "xml", "sarif"]:
                errors.append(
                    f"output_format '{fmt}' is invalid "
                    "(must be: json, xml, sarif)"
                )
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "tool": "run_burp_scan",
            "param_count": len(params)
        }
    
    def validate_list_targets(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate list_targets parameters"""
        errors = []
        
        # Validate filter_tag (optional, string)
        if "filter_tag" in params:
            tag = params["filter_tag"]
            if not isinstance(tag, str):
                errors.append(f"filter_tag must be string, got {type(tag).__name__}")
            elif len(tag) > 255:
                errors.append("filter_tag must be <= 255 characters")
        
        # Validate limit (optional, bounded int)
        if "limit" in params:
            limit = params["limit"]
            if not isinstance(limit, int):
                errors.append(f"limit must be integer, got {type(limit).__name__}")
            elif limit < 1 or limit > 10000:
                errors.append(f"limit must be 1-10000, got {limit}")
        
        # Validate offset (optional, non-negative int)
        if "offset" in params:
            offset = params["offset"]
            if not isinstance(offset, int):
                errors.append(f"offset must be integer, got {type(offset).__name__}")
            elif offset < 0:
                errors.append(f"offset must be non-negative, got {offset}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "tool": "list_targets",
            "param_count": len(params)
        }
    
    def validate_get_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate get_report parameters"""
        errors = []
        
        # Validate report_id (required, UUID)
        if not params.get("report_id"):
            errors.append("report_id is required")
        elif not self._is_valid_uuid(params["report_id"]):
            errors.append(
                f"report_id must be valid UUID, got '{params['report_id']}'"
            )
        
        # Validate format (optional, enum)
        if "format" in params:
            fmt = params["format"]
            if fmt not in ["json", "pdf", "html"]:
                errors.append(
                    f"format '{fmt}' is invalid "
                    "(must be: json, pdf, html)"
                )
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "tool": "get_report",
            "param_count": len(params)
        }
    
    # Helper validators
    @staticmethod
    def _is_valid_target(target: str) -> bool:
        """Check if target is valid FQDN, IP, or CIDR"""
        if not isinstance(target, str) or not target:
            return False
        
        # Try CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        
        # Try IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Try FQDN
        # Pattern: labels separated by dots, each 1-63 chars, alphanumeric + hyphen
        fqdn_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(fqdn_pattern, target):
            return True
        
        # Try hostname (single label)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if re.match(hostname_pattern, target):
            return True
        
        return False
    
    @staticmethod
    def _is_valid_uuid(value: str) -> bool:
        """Check if value is valid UUID"""
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            return False


# ============================================================================
# Policy Enforcement
# ============================================================================

class PolicyEnforcer:
    """Enforce policies (role access, quotas, concurrency)"""
    
    def __init__(self, policy_resolver=None, metrics=None):
        """
        Initialize policy enforcer
        
        Args:
          policy_resolver: PolicyResolver instance from mcp_server
          metrics: MCPMetrics instance for quota tracking
        """
        self.policy_resolver = policy_resolver
        self.metrics = metrics
        self.definitions = ToolDefinitions()
    
    def check_run_burp_scan(
        self,
        principal: 'MCPPrincipal',
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check if run_burp_scan is allowed for this principal"""
        errors = []
        reason = None
        
        # Get policy
        policy = self.definitions.get_run_burp_scan()["policy"]
        
        # Check role access
        role = principal.claims.get("role", "user")
        if role not in policy["roles_allowed"]:
            return {
                "allowed": False,
                "reason": f"Role '{role}' not allowed for run_burp_scan",
                "tool": "run_burp_scan",
                "errors": [f"Unauthorized role: {role}"]
            }
        
        # Check plan access
        plan = principal.claims.get("plan_id", "free")
        if plan not in policy["plans_allowed"]:
            return {
                "allowed": False,
                "reason": f"Plan '{plan}' not allowed for run_burp_scan",
                "tool": "run_burp_scan",
                "errors": [f"Unauthorized plan: {plan}"]
            }
        
        # Check quota (if metrics available)
        if self.metrics:
            quota_window = timedelta(hours=policy["quota_window_hours"])
            calls_in_window = self._get_quota_usage(
                principal.tenant_id,
                "run_burp_scan",
                quota_window
            )
            if calls_in_window >= policy["per_tenant_quota"]:
                return {
                    "allowed": False,
                    "reason": f"Quota exceeded: {calls_in_window}/{policy['per_tenant_quota']} calls",
                    "tool": "run_burp_scan",
                    "errors": ["Daily quota exhausted"]
                }
        
        # Check concurrency (if metrics available)
        if self.metrics:
            active_count = self._get_active_concurrency(
                principal.tenant_id,
                "run_burp_scan"
            )
            if active_count >= policy["concurrency_limit"]:
                return {
                    "allowed": False,
                    "reason": f"Concurrency limit exceeded: {active_count}/{policy['concurrency_limit']}",
                    "tool": "run_burp_scan",
                    "errors": ["Max concurrent scans reached"]
                }
        
        return {
            "allowed": True,
            "reason": "Policy check passed",
            "tool": "run_burp_scan",
            "errors": []
        }
    
    def check_list_targets(
        self,
        principal: 'MCPPrincipal',
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check if list_targets is allowed"""
        policy = self.definitions.get_list_targets()["policy"]
        
        # Check role
        role = principal.claims.get("role", "user")
        if role not in policy["roles_allowed"]:
            return {
                "allowed": False,
                "reason": f"Role '{role}' not allowed",
                "tool": "list_targets",
                "errors": [f"Unauthorized role: {role}"]
            }
        
        # Check plan
        plan = principal.claims.get("plan_id", "free")
        if plan not in policy["plans_allowed"]:
            return {
                "allowed": False,
                "reason": f"Plan '{plan}' not allowed",
                "tool": "list_targets",
                "errors": [f"Unauthorized plan: {plan}"]
            }
        
        return {
            "allowed": True,
            "reason": "Policy check passed",
            "tool": "list_targets",
            "errors": []
        }
    
    def check_get_report(
        self,
        principal: 'MCPPrincipal',
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check if get_report is allowed"""
        policy = self.definitions.get_get_report()["policy"]
        
        # Check role
        role = principal.claims.get("role", "user")
        if role not in policy["roles_allowed"]:
            return {
                "allowed": False,
                "reason": f"Role '{role}' not allowed",
                "tool": "get_report",
                "errors": [f"Unauthorized role: {role}"]
            }
        
        # Check plan
        plan = principal.claims.get("plan_id", "free")
        if plan not in policy["plans_allowed"]:
            return {
                "allowed": False,
                "reason": f"Plan '{plan}' not allowed",
                "tool": "get_report",
                "errors": [f"Unauthorized plan: {plan}"]
            }
        
        return {
            "allowed": True,
            "reason": "Policy check passed",
            "tool": "get_report",
            "errors": []
        }
    
    def _get_quota_usage(
        self,
        tenant_id: str,
        command: str,
        window: timedelta
    ) -> int:
        """Get call count for tenant/command in recent window"""
        if not self.metrics:
            return 0
        
        # Sum calls to this command for this tenant in window
        now = datetime.now()
        cutoff = now - window
        
        count = 0
        for (tid, cmd), metric in self.metrics._passthrough_calls_total.items():
            if tid == tenant_id and cmd == command:
                # Simple counter; real implementation would track timestamps
                return metric.get("value", 0)
        
        return count
    
    def _get_active_concurrency(self, tenant_id: str, command: str) -> int:
        """Get active concurrency for tenant/command"""
        if not self.metrics:
            return 0
        
        # Query active requests; real implementation would check ongoing states
        return 0


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "ToolDefinitions",
    "ToolValidator",
    "PolicyEnforcer",
    "ScanProfile",
    "OutputFormat",
    "ReportFormat",
]


if __name__ == "__main__":
    # Demo: validate tool definitions
    import json
    
    definitions = ToolDefinitions()
    validator = ToolValidator()
    
    print("=" * 80)
    print("PHASE 1 TOOL DEFINITIONS")
    print("=" * 80)
    
    # Print schemas
    for tool_name in ["run_burp_scan", "list_targets", "get_report"]:
        getter = getattr(definitions, f"get_{tool_name}")
        schema = getter()
        print(f"\n{tool_name}:")
        print(json.dumps(schema, indent=2))
    
    # Demo validation
    print("\n" + "=" * 80)
    print("VALIDATION EXAMPLES")
    print("=" * 80)
    
    # Valid request
    result = validator.validate_run_burp_scan({
        "target": "example.com",
        "scan_profile": "balanced"
    })
    print(f"\nValid run_burp_scan: {result}")
    
    # Invalid request
    result = validator.validate_run_burp_scan({
        "target": "!!!invalid!!!",
        "scan_profile": "unknown",
        "timeout_seconds": 99999
    })
    print(f"\nInvalid run_burp_scan: {result}")
    
    # Valid list_targets
    result = validator.validate_list_targets({
        "limit": 100,
        "offset": 0
    })
    print(f"\nValid list_targets: {result}")
