#!/usr/bin/env bash
set -euo pipefail

# Daily in-scope wildcard recon pipeline:
# subfinder -> httpx -> nuclei -> BugBountyHunter skill trigger

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-load local environment file for cron/manual runs.
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${SCRIPT_DIR}/.env"
  set +a
fi

ROOT_SCOPE_FILE="${ROOT_SCOPE_FILE:-/bb/scope/roots.txt}"
BASE_INCOMING_DIR="${BASE_INCOMING_DIR:-/bb/incoming}"
OPENCLAW_CONFIG="${OPENCLAW_CONFIG:-./openclaw.json}"
OPENCLAW_WEBHOOK_URL="${OPENCLAW_WEBHOOK_URL:-http://127.0.0.1:8765/hooks/openclaw}"
OPENCLAW_WEBHOOK_TOKEN="${OPENCLAW_WEBHOOK_TOKEN:-}"
VALIDATOR_SCRIPT="${VALIDATOR_SCRIPT:-${SCRIPT_DIR}/validate-scope.sh}"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="${BASE_INCOMING_DIR}/${TIMESTAMP}"
LATEST_LINK="${BASE_INCOMING_DIR}/latest"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing required command: $1" >&2
    exit 1
  }
}

echo "[*] Validating dependencies..."
require_cmd subfinder
require_cmd httpx
require_cmd nuclei
require_cmd jq
require_cmd openclaw

if [[ -x "${VALIDATOR_SCRIPT}" ]]; then
  "${VALIDATOR_SCRIPT}" "${RUN_DIR}"
else
  echo "[!] Scope validator missing or not executable: ${VALIDATOR_SCRIPT}" >&2
  exit 1
fi

if [[ ! -f "${ROOT_SCOPE_FILE}" ]]; then
  echo "[!] Scope file not found: ${ROOT_SCOPE_FILE}" >&2
  exit 1
fi

mkdir -p "${RUN_DIR}"

echo "[*] Running subfinder against approved wildcard roots..."
subfinder \
  -dL "${ROOT_SCOPE_FILE}" \
  -silent \
  -all \
  -o "${RUN_DIR}/subs.txt"

if [[ ! -s "${RUN_DIR}/subs.txt" ]]; then
  echo "[!] No subdomains discovered. Exiting safely."
  exit 0
fi

echo "[*] Probing live hosts with httpx..."
httpx \
  -l "${RUN_DIR}/subs.txt" \
  -silent \
  -threads 100 \
  -timeout 10 \
  -retries 2 \
  -title \
  -status-code \
  -tech-detect \
  -json \
  -o "${RUN_DIR}/httpx.jsonl"

jq -r 'select(.url != null) | .url' "${RUN_DIR}/httpx.jsonl" | sort -u > "${RUN_DIR}/live.txt"

if [[ ! -s "${RUN_DIR}/live.txt" ]]; then
  echo "[!] No live URLs found. Exiting safely."
  exit 0
fi

echo "[*] Running nuclei in non-destructive signal mode..."
nuclei \
  -l "${RUN_DIR}/live.txt" \
  -severity low,medium,high,critical \
  -rate-limit 40 \
  -bulk-size 25 \
  -c 20 \
  -jsonl \
  -o "${RUN_DIR}/nuclei.jsonl" \
  -tags exposure,misconfig,tech,auth

cat > "${RUN_DIR}/manifest.json" <<EOF
{
  "generated_at": "${TIMESTAMP}",
  "scope_file": "${ROOT_SCOPE_FILE}",
  "run_dir": "${RUN_DIR}",
  "artifacts": {
    "subs": "${RUN_DIR}/subs.txt",
    "httpx": "${RUN_DIR}/httpx.jsonl",
    "live": "${RUN_DIR}/live.txt",
    "nuclei": "${RUN_DIR}/nuclei.jsonl"
  },
  "tags": ["recon", "triage"]
}
EOF

ln -sfn "${RUN_DIR}" "${LATEST_LINK}"

echo "[*] Triggering BugBountyHunter skill via CLI..."
# Skills are invoked through the agent in openclaw v2026.5+
# --local runs the embedded agent without requiring a running Gateway
openclaw agent --local \
  --message "Run BugBountyHunter on manifest: $(cat "${RUN_DIR}/manifest.json")" \
  --model "anthropic/claude-sonnet-4-6"

if [[ -n "${OPENCLAW_WEBHOOK_TOKEN}" ]]; then
  echo "[*] Triggering optional webhook fan-out..."
  curl -sS -X POST "${OPENCLAW_WEBHOOK_URL}" \
    -H "Authorization: Bearer ${OPENCLAW_WEBHOOK_TOKEN}" \
    -H "Content-Type: application/json" \
    --data-binary @"${RUN_DIR}/manifest.json" >/dev/null
fi

echo "[+] Recon pipeline complete: ${RUN_DIR}"
