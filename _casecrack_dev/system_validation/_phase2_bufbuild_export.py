#!/usr/bin/env python3
"""
PHASE 2A — buf.build lattice-sdk full proto export
Downloads every available .proto file from buf.build/anduril/lattice-sdk
and saves them locally for field-layout analysis.
"""
import requests, json, base64, os, sys

S = requests.Session()
S.headers.update({"User-Agent": "Mozilla/5.0 (compatible; buf-client/1.0)"})

OUT_DIR = "./anduril_protos"
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Method 1: Buf Connect HTTP API ─────────────────────────────────────────
print("=" * 70)
print("  buf.build Connect API — lattice-sdk download")
print("=" * 70)

BSR_BASE = "https://buf.build"

# Try the buf Connect (JSON) API for module download
endpoints = [
    # v1beta1 API (older BSR format)
    f"{BSR_BASE}/buf.alpha.registry.v1alpha1.DownloadService/Download",
    # v1 API
    f"{BSR_BASE}/buf.registry.module.v1.ModuleService/GetModuleFiles",
    # Direct ref download
    f"{BSR_BASE}/buf.alpha.registry.v1alpha1.DownloadService/Download",
]

# The correct BSR download body format
download_bodies = [
    {
        "owner": "anduril",
        "repository": "lattice-sdk",
        "reference": "main"
    },
    {
        "owner": "anduril",
        "repository": "lattice-sdk",
        "reference": "latest"
    },
    {
        "moduleRef": {
            "owner": "anduril",
            "module": "lattice-sdk",
            "ref": "main"
        }
    },
]

all_files = {}
for endpoint in endpoints[:1]:  # Start with v1alpha1
    for body in download_bodies[:1]:
        try:
            r = S.post(
                endpoint,
                json=body,
                headers={"Content-Type": "application/json",
                         "Connect-Protocol-Version": "1"},
                timeout=30
            )
            print(f"  POST {endpoint}")
            print(f"    → HTTP {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                files = data.get("module", {}).get("files", [])
                print(f"    → {len(files)} files in response")
                for f in files:
                    path = f.get("path", "")
                    content_b64 = f.get("content", "")
                    if content_b64:
                        try:
                            content = base64.b64decode(content_b64).decode("utf-8")
                        except Exception:
                            content = base64.b64decode(content_b64 + "==").decode("utf-8", "replace")
                        all_files[path] = content
                        # Save to disk
                        full_path = os.path.join(OUT_DIR, path.replace("/", os.sep))
                        os.makedirs(os.path.dirname(full_path), exist_ok=True)
                        with open(full_path, "w", encoding="utf-8") as fp:
                            fp.write(content)
            else:
                print(f"    Response: {r.text[:300]}")
        except Exception as e:
            print(f"    ERROR: {e}")

# ─── Method 2: BSR web API (REST-style) ─────────────────────────────────────
print()
print("  buf.build REST API — module tree exploration")

rest_endpoints = [
    "https://buf.build/api/modules/anduril/lattice-sdk",
    "https://buf.build/api/v1/modules/anduril/lattice-sdk",
    "https://buf.build/anduril/lattice-sdk/file/main",
    "https://buf.build/anduril/lattice-sdk/tree/main",
    "https://buf.build/api/modules/anduril/lattice-sdk/files?version=main",
]

for url in rest_endpoints:
    try:
        r = S.get(url, timeout=15, headers={"Accept": "application/json"})
        print(f"  GET {url}")
        print(f"    → HTTP {r.status_code} | {r.text[:200]}")
    except Exception as e:
        print(f"  GET {url} → ERROR: {e}")

# ─── Method 3: Known public proto paths (direct file fetch) ─────────────────
print()
print("  Direct proto file fetch — known Anduril paths")

# Anduril's public lattice-sdk has these namespaces confirmed in public docs:
known_paths = [
    "anduril/entitymanager/v1/entity.proto",
    "anduril/entitymanager/v1/entity_manager_api.proto",
    "anduril/tasks/v2/task.proto",
    "anduril/tasks/v2/task_api.proto",
    "anduril/type/v1/common.proto",
    "anduril/type/v1/coordinates.proto",
    "anduril/type/v1/dimensions.proto",
    # Try auth paths (may not be public)
    "anduril/auth/v2/tokens.proto",
    "anduril/auth/v2/service.proto",
    "anduril/auth/v2/common.proto",
    "anduril/auth/v2/login.proto",
    "anduril/auth/v2/idp.proto",
    "anduril/authx/v1/tokens.proto",
    "anduril/authx/v2/service.proto",
    "anduril/api/v1/annotations.proto",
]

# Try fetching from the raw BSR download endpoint
for proto_path in known_paths:
    try:
        r = S.post(
            "https://buf.build/buf.alpha.registry.v1alpha1.DownloadService/Download",
            json={"owner": "anduril", "repository": "lattice-sdk", "reference": "main",
                  "files": [{"path": proto_path}]},
            headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            files = data.get("module", {}).get("files", [])
            for f in files:
                path = f.get("path", "")
                content_b64 = f.get("content", "")
                if content_b64:
                    try:
                        content = base64.b64decode(content_b64).decode("utf-8")
                    except Exception:
                        content = base64.b64decode(content_b64 + "==").decode("utf-8", "replace")
                    all_files[path] = content
                    full_path = os.path.join(OUT_DIR, path.replace("/", os.sep))
                    os.makedirs(os.path.dirname(full_path), exist_ok=True)
                    with open(full_path, "w", encoding="utf-8") as fp:
                        fp.write(content)
                    print(f"  ★ SAVED: {path} ({len(content)} bytes)")
                    print(f"    Preview: {content[:200]}")
        elif r.status_code != 404:
            print(f"  {proto_path}: HTTP {r.status_code} | {r.text[:100]}")
    except Exception as e:
        print(f"  {proto_path}: ERROR {e}")

# ─── Summary ─────────────────────────────────────────────────────────────────
print()
print("=" * 70)
print(f"  Total proto files downloaded: {len(all_files)}")
if all_files:
    print("  Files:")
    for path in sorted(all_files.keys()):
        print(f"    {path}")
print()
print("  Saved to:", OUT_DIR)
print("=" * 70)
