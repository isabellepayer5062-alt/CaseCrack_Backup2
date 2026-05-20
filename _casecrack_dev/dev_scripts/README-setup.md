# OpenClaw 2026 Hybrid Setup (Claude Sonnet 4.6 + GPT-5.5)

This setup creates a secure, in-scope-only bug bounty automation rig where:

- `anthropic/claude-sonnet-4-6` is the default for recon, triage, and reporting.
- `openai/gpt-5.5` is used only for `complex_agentic`, `exploit_poc`, or `race_condition` tagged tasks.

## 1) Prerequisites (Kali/Linux VM)

```bash
sudo apt update
sudo apt install -y jq curl cron

# Install ProjectDiscovery tools (if missing)
# Use official install methods if your distro package is outdated.
subfinder -version || echo "Install subfinder from official ProjectDiscovery release"
httpx -version || echo "Install httpx from official ProjectDiscovery release"
nuclei -version || echo "Install nuclei from official ProjectDiscovery release"

# OpenClaw CLI check
openclaw --version
```

## 2) Place config in ~/.openclaw

```bash
mkdir -p ~/.openclaw
cp ./openclaw.json ~/.openclaw/openclaw.json
chmod 600 ~/.openclaw/openclaw.json
```

## 2.1) Create and load environment variables

```bash
cp .env.example .env
# edit .env with your real API keys/tokens
source .env
```

## 3) Prepare in-scope root list

```bash
sudo mkdir -p /bb/scope /bb/incoming
sudo chown -R "$USER":"$USER" /bb

cat > /bb/scope/roots.txt <<'EOF'
example.com
example.org
*.example.net
EOF
```

Only include assets explicitly authorized by the bounty program.

## 4) Apply OpenClaw config and create skills

```bash
# Apply base config
openclaw config apply --file ~/.openclaw/openclaw.json

# Register composite skill package
openclaw skill create --path ./skills/BugBountyHunter

# Validate routing and guards
openclaw config validate --file ~/.openclaw/openclaw.json
openclaw skill validate --path ./skills/BugBountyHunter
```

## 5) Make recon pipeline executable and run once

```bash
chmod +x ./recon-pipeline.sh ./validate-scope.sh
./validate-scope.sh
./recon-pipeline.sh
```

## 6) Register OpenClaw cron jobs

> **Note (openclaw v2026.5+):** `openclaw cron import --file` does not exist.
> Register jobs individually using `openclaw cron add`:

```bash
# Daily wildcard recon at 09:00 UTC
openclaw cron add \
  --cron "0 9 * * *" \
  --description "Daily in-scope wildcard recon" \
  --message "Run daily recon pipeline via bash recon-pipeline.sh" \
  --timeout-seconds 7200

# Nightly BugBountyHunter triage + report at 01:30 UTC
openclaw cron add \
  --cron "30 1 * * *" \
  --description "Nightly BugBountyHunter triage and report" \
  --message "Run BugBountyHunter triage and reporting on manifest: $(cat /bb/incoming/latest/manifest.json)" \
  --model "anthropic/claude-sonnet-4-6" \
  --timeout-seconds 5400

# Verify
openclaw cron list
```

Optional system cron fallback:

```bash
crontab -l > /tmp/current-cron 2>/dev/null || true
{
  cat /tmp/current-cron
  echo "0 9 * * * cd $(pwd) ; ./recon-pipeline.sh >> /bb/incoming/recon-cron.log 2>&1"
} | crontab -
```

## 7) Test hybrid model routing

> **Note (openclaw v2026.5+):** Skills are invoked through the agent, not as
> standalone commands. `openclaw run skill` no longer exists. Use
> `openclaw agent --local --message "..."` instead.

### Test A: Sonnet default path (recon tags → claude-sonnet-4-6)

```bash
openclaw agent --local \
  --message "Run BugBountyHunter on manifest: $(cat /bb/incoming/latest/manifest.json)" \
  --model "anthropic/claude-sonnet-4-6"
```

Expected: resolves to `anthropic/claude-sonnet-4-6`.

### Test B: GPT escalation path (exploit_poc + complex_agentic tags → gpt-5.5)

```bash
openclaw agent --local \
  --message "Run BugBountyHunter with exploit_poc and complex_agentic on manifest: $(cat /bb/incoming/latest/manifest.json)" \
  --model "openai/gpt-5.5"
```

Expected: escalates to `openai/gpt-5.5`.

### Inspect effective routing (dry-run)

```bash
openclaw agent --local --dry-run \
  --message "Run BugBountyHunter on manifest: $(cat /bb/incoming/latest/manifest.json)"
```

## Cost Optimization Checklist (80/20 Sonnet-heavy)

- Keep default tags to recon and triage unless GPT escalation is genuinely required.
- Route only hardest reasoning or PoC synthesis tasks to `openai/gpt-5.5`.
- Keep prompt caching enabled globally (already in config).
- Limit each run to max 150k tokens (already enforced).
- Use nightly triage batch jobs instead of ad-hoc repeated runs.
- Deduplicate incoming targets before running nuclei.

## Safety Reminders for Kali/VM

- Run only against in-scope targets in `/bb/scope/roots.txt`.
- Keep OpenClaw webhook bound to `127.0.0.1`.
- Do not expose OpenClaw ports publicly or through broad host networking.
- Use non-destructive templates and avoid DoS/state-changing tests.
- Store API keys in environment variables or secret managers, not in files.

## Updated Quick Start (WSL2/Kali)

```bash
# 1. Load secrets
source .env

# 2. Create directories
sudo mkdir -p /bb/scope /bb/incoming
sudo chown -R $USER:$USER /bb

# 3. Populate real scope (one program at a time)
cat > /bb/scope/roots.txt <<EOF
your-target-bounty-program.com
*.your-target-bounty-program.com
EOF

# 4. Validate + apply
./validate-scope.sh
openclaw config apply --file openclaw.json
openclaw skill create --path ./skills/BugBountyHunter
openclaw cron import --file ./cron-jobs.json

# 5. First test run
chmod +x recon-pipeline.sh validate-scope.sh
./recon-pipeline.sh
```

## Useful Ops Commands

```bash
openclaw cron run --id daily-wildcard-recon
openclaw cron run --id nightly-triage-report
openclaw logs tail --component scheduler
openclaw logs tail --component router
```
