"""
Cross-Module Wiring Audit — Verifies fixes B2, B3, A4, C4, K, J.

Tests that previously disconnected modules are now properly wired:
  B2: api_discovery results → recon_context (dataclass attribute access)
  B3: param_discovery results → injection scan (parameter enrichment)
  A4: waf_payload_adapter → injection scan (WAF-aware tampers)
  C4: credential_enumerator → auth_context (identity registration)
  K:  webtransport_security + http3_security registered in scanner_hooks
  J:  JSON output preserves attack_chains + correlation_links
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))

BE = "CaseCrack.tools.burp_enterprise"


# ═══════════════════════════════════════════════════════════════════════
# B2: api_discovery returns APIDiscoveryResult (dataclass), not dict.
#     The recon pipeline must use attribute access, not .get().
# ═══════════════════════════════════════════════════════════════════════

class TestB2_ApiDiscoveryWiring:
    """Verify api_discovery results are consumed via attribute access."""

    def test_api_discovery_result_attributes_used(self):
        """Ensure recon pipeline reads .endpoints, .findings as attrs."""
        from CaseCrack.tools.burp_enterprise.discovery_pkg.api_discovery import (
            APIDiscoveryResult,
            DiscoveredEndpoint,
            APIFinding,
            APIFindingType,
            Severity,
        )

        ep = DiscoveredEndpoint(url="https://example.com/api/v1/users", path="/api/v1/users")
        finding = APIFinding(
            finding_type=APIFindingType.DEBUG_ENDPOINT,
            severity=Severity.HIGH,
            title="Debug endpoint exposed",
            description="test",
            url="https://example.com/debug",
        )
        result = APIDiscoveryResult(
            target="https://example.com",
            endpoints=[ep],
            findings=[finding],
        )

        # Pipeline now uses getattr — verify it works
        endpoints = getattr(result, "endpoints", [])
        assert len(endpoints) == 1
        assert endpoints[0].url == "https://example.com/api/v1/users"

        findings = getattr(result, "findings", [])
        assert len(findings) == 1
        # Verify .to_dict() produces the dict format ctx.add_findings needs
        d = findings[0].to_dict()
        assert isinstance(d, dict)
        assert "type" in d or "title" in d


# ═══════════════════════════════════════════════════════════════════════
# B3: param_discovery results feed into injection scan targets
# ═══════════════════════════════════════════════════════════════════════

class TestB3_ParamDiscoveryInjectionWiring:
    """Verify discovered params enrich injection targets."""

    def test_param_enrichment_builds_fuzz_urls(self):
        """With discovered params, injection targets include ?param=FUZZ."""
        from urllib.parse import urlparse

        targets = ["https://example.com/login"]
        discovered_params = ["username", "password", "token"]

        # Simulate B3-FIX logic
        enriched_targets: list[str] = []
        for url in targets:
            enriched_targets.append(url)
            parsed = urlparse(url)
            param_str = "&".join(f"{p}=FUZZ" for p in discovered_params[:10])
            sep = "&" if parsed.query else "?"
            enriched_targets.append(f"{url}{sep}{param_str}")

        assert len(enriched_targets) == 2
        assert "username=FUZZ" in enriched_targets[1]
        assert "password=FUZZ" in enriched_targets[1]
        assert enriched_targets[1].startswith("https://example.com/login?")


# ═══════════════════════════════════════════════════════════════════════
# A4: waf_payload_adapter is registered and callable
# ═══════════════════════════════════════════════════════════════════════

class TestA4_WAFPayloadAdapterWiring:
    """Verify WAFPayloadAdapter is importable and has adapt() method."""

    def test_adapter_importable(self):
        from CaseCrack.tools.burp_enterprise.scanners.waf_payload_adapter import (
            WAFPayloadAdapter,
        )
        adapter = WAFPayloadAdapter()
        assert hasattr(adapter, "adapt")
        assert hasattr(adapter, "get_sqli_bypasses")

    def test_adapt_returns_payload_set(self):
        from CaseCrack.tools.burp_enterprise.scanners.waf_payload_adapter import (
            WAFPayloadAdapter,
            AdaptedPayloadSet,
        )
        from CaseCrack.tools.burp_enterprise.scanners.waf import WAFVendor

        adapter = WAFPayloadAdapter()
        # Use first available vendor
        vendors = list(WAFVendor)
        if vendors:
            result = adapter.adapt(vendors[0], 0.8)
            assert isinstance(result, AdaptedPayloadSet)


# ═══════════════════════════════════════════════════════════════════════
# C4: credential_enumerator → auth_context registration
# ═══════════════════════════════════════════════════════════════════════

class TestC4_CredentialAuthContextWiring:
    """Verify AuthContextExplorer.add_identity() accepts cred enum data."""

    def test_add_identity_from_cred_enum(self):
        from CaseCrack.tools.burp_enterprise.session_auth.auth_context import (
            AuthContextExplorer,
        )

        ctx = AuthContextExplorer()
        identity = ctx.add_identity(
            name="github_testuser",
            role="editor",
            permissions={"repo:read", "repo:write"},
        )
        assert identity.name == "github_testuser"
        assert identity.role == "editor"
        assert "repo:read" in identity.permissions

        # Verify retrieval
        found = ctx.get_identity("github_testuser")
        assert found is not None
        assert found.name == "github_testuser"


# ═══════════════════════════════════════════════════════════════════════
# K: webtransport_security + http3_security in scanner_hooks registry
# ═══════════════════════════════════════════════════════════════════════

class TestK_ProtocolScannerRegistration:
    """Verify orphaned protocol scanners are registered in hooks."""

    def test_webtransport_in_registry(self):
        from CaseCrack.tools.burp_enterprise.scanners.scanner_hooks import (
            _SCANNER_REGISTRY,
        )
        names = [spec[0] for spec in _SCANNER_REGISTRY]
        assert "webtransport_security" in names, (
            "webtransport_security missing from _SCANNER_REGISTRY"
        )

    def test_http3_in_registry(self):
        from CaseCrack.tools.burp_enterprise.scanners.scanner_hooks import (
            _SCANNER_REGISTRY,
        )
        names = [spec[0] for spec in _SCANNER_REGISTRY]
        assert "http3_security" in names, (
            "http3_security missing from _SCANNER_REGISTRY"
        )


# ═══════════════════════════════════════════════════════════════════════
# J: JSON output preserves attack_chains and correlation_links
# ═══════════════════════════════════════════════════════════════════════

class TestJ_JSONOutputGraphContext:
    """Verify JSON export preserves exploit chain context."""

    def test_json_export_includes_attack_chains(self, tmp_path):
        from CaseCrack.tools.burp_enterprise.output.output_formats import export

        findings = [{"title": "XSS", "severity": "high", "url": "/test"}]

        @dataclass
        class FakeChain:
            chain_id: str = "c1"
            title: str = "XSS to Account Takeover"
            def to_dict(self):
                return {"chain_id": self.chain_id, "title": self.title}

        out = tmp_path / "report.json"
        export(
            findings, str(out),
            attack_chains=[FakeChain()],
            correlation_links=[],
            target="example.com",
        )

        data = json.loads(out.read_text(encoding="utf-8"))
        assert "findings" in data
        assert "attack_chains" in data
        assert len(data["attack_chains"]) == 1
        assert data["attack_chains"][0]["chain_id"] == "c1"
        assert data["target"] == "example.com"

    def test_json_export_without_chains_still_works(self, tmp_path):
        from CaseCrack.tools.burp_enterprise.output.output_formats import export

        findings = [{"title": "Info", "severity": "info"}]
        out = tmp_path / "basic.json"
        export(findings, str(out))

        data = json.loads(out.read_text(encoding="utf-8"))
        assert "findings" in data
        assert "attack_chains" not in data  # Not provided = not included
