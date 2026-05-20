#!/usr/bin/env python3
"""Verify Phase 15 lifecycle metadata persisted in manifests."""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent / "CaseCrack"))

from tools.burp_enterprise.recon_dashboard.runner import StandaloneReconRunner
from tools.burp_enterprise.recon_dashboard.phase_handlers.base import PhaseContext


def test_p15_lifecycle_metadata():
    """Test that lifecycle metadata is captured and persisted in manifest."""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        report_dir = Path(tmpdir)
        
        # Create minimal necessary input files
        (report_dir / "recon-crawl.json").write_text(
            json.dumps({"data": [{"url": "http://127.0.0.1:45250"}]})
        )
        (report_dir / "recon-discovery.json").write_text(
            json.dumps({"data": []})
        )
        (report_dir / "recon-jsluice-gau.json").write_text(
            json.dumps({"data": {"urls": []}})
        )
        
        runner = StandaloneReconRunner(
            target_url="http://127.0.0.1:45250",
            report_dir=str(report_dir),
        )
        
        # Create minimal context for Phase 15
        ctx = PhaseContext(
            phase_num=15,
            phase_name="Phase 15: Secrets",
            runner=runner,
            abort=False,
            phase_timeout=30,
            phase_deadline=0,
            phase_cmd_margin=2,
            phase_delay=0.1,
        )
        ctx.phase_deadline = __import__("time").monotonic() + 30
        
        # Import and run expand_commands
        from tools.burp_enterprise.recon_dashboard.phase_handlers.security_testing import expand_commands
        
        print("[*] Running Phase 15 expand_commands...")
        try:
            expand_commands(ctx)
        except Exception as e:
            print(f"[!] Exception during expand_commands (expected): {type(e).__name__}: {e}")
        
        # Check manifest
        manifest_path = report_dir / "_artifacts" / "p15_js_bundle" / "manifest.json"
        
        print(f"\n[*] Checking manifest at: {manifest_path}")
        print(f"    Manifest exists: {manifest_path.exists()}")
        
        if manifest_path.exists():
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            print(f"\n[+] Manifest loaded successfully")
            print(f"    Created at: {manifest.get('created_at')}")
            print(f"    JS files: {manifest.get('js_files', 0)}")
            print(f"    Total encountered: {manifest.get('total_encountered', 0)}")
            print(f"    Total persisted: {manifest.get('total_persisted', 0)}")
            print(f"    Total skipped: {manifest.get('total_skipped', 0)}")
            print(f"    Entries count: {len(manifest.get('entries', []))}")
            
            # Check first entry for lifecycle metadata
            if manifest.get("entries"):
                entry = manifest["entries"][0]
                print(f"\n[+] First entry lifecycle metadata:")
                print(f"    URL: {entry.get('source_url', '<missing>')}")
                print(f"    first_seen_stage: {entry.get('first_seen_stage', '<missing>')}")
                print(f"    persisted_stage: {entry.get('persisted_stage', '<missing>')}")
                print(f"    encountered_at: {entry.get('encountered_at', '<missing>')}")
                print(f"    persisted_at: {entry.get('persisted_at', '<missing>')}")
                print(f"    download_attempts: {entry.get('download_attempts', '<missing>')}")
                print(f"    persisted: {entry.get('persisted', '<missing>')}")
                print(f"    manifested: {entry.get('manifested', '<missing>')}")
                print(f"    skip_reason: {entry.get('skip_reason', '<missing>')}")
                
                # Verify all lifecycle fields are present
                required_fields = {
                    "source_url", "file", "sha1", "size", "source",
                    "first_seen_stage", "persisted_stage",
                    "encountered_at", "persisted_at", "download_attempts",
                    "persisted", "manifested", "skip_reason"
                }
                missing_fields = required_fields - set(entry.keys())
                if missing_fields:
                    print(f"\n[!] Missing fields: {missing_fields}")
                else:
                    print(f"\n[✓] All lifecycle metadata fields present")
                
                # Pretty-print first entry
                print(f"\n[+] Full entry (JSON):")
                print(json.dumps(entry, indent=2, default=str))
        else:
            print(f"[!] Manifest not found at {manifest_path}")
            print(f"    Artifact dir exists: {manifest_path.parent.parent.exists()}")
            if manifest_path.parent.parent.exists():
                print(f"    Contents: {list(manifest_path.parent.parent.iterdir())}")


if __name__ == "__main__":
    test_p15_lifecycle_metadata()
