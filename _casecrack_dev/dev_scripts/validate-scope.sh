#!/usr/bin/env bash
set -euo pipefail

SCOPE_FILE="${ROOT_SCOPE_FILE:-/bb/scope/roots.txt}"
RUN_DIR="${1:-}"

echo "[*] Validating scope before recon..."

if [[ ! -f "$SCOPE_FILE" ]]; then
  echo "[!] CRITICAL: Scope file missing: $SCOPE_FILE"
  exit 1
fi

# Quick check that we have at least one root
if [[ $(wc -l < "$SCOPE_FILE") -eq 0 ]]; then
  echo "[!] Scope file is empty. Aborting."
  exit 1
fi

# Optional: block common dangerous wildcards if you want extra safety
if grep -qE '^\*\..*' "$SCOPE_FILE"; then
  echo "[!] WARNING: Broad * wildcard detected. Confirm this is in-scope!"
fi

if [[ -n "$RUN_DIR" ]]; then
  mkdir -p "$RUN_DIR"
  cp "$SCOPE_FILE" "$RUN_DIR/scope_snapshot.txt"
fi

echo "[+] Scope validated: $(wc -l < "$SCOPE_FILE") roots loaded."
