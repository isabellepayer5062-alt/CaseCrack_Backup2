## Tool Execution Layer (MCP-Compatible)

The orchestrator delegates all external tool invocations through a sandboxed
MCP-compatible tool registry. No skill directly shells out.

```yaml
tool_registry:
  mode: mcp_sandbox
  sandbox_image: openclaw/tool-sandbox:2026.05
  network_policy: deny_egress_except_scope
  max_execution_time_seconds: 300
  max_memory_mb: 512
  max_disk_mb: 1024
  allowed_tools:
    - subfinder
    - httpx
    - nuclei
    - jq
    - awk
    - grep
    - sort
    - uniq
    - curl
    - nmap:
        args_allowlist: ["-sV","-sS","-p","--open","-Pn","-T4","--max-retries","2"]
        deny: ["-A","-O","-sC","--script","-T5","--max-parallelism"]
    - ffuf:
        args_allowlist: ["-u","-w","-H","-X","-mc","-fc","-t","-rate"]
        deny: ["-x","-r","-recursion","-od"]
    - sqlmap:
        args_allowlist: ["-u","--batch","--level=1","--risk=1","--tamper","--timeout"]
        deny: ["--os-shell","--os-pwn","--os-cmd","--file-read","--file-write"]
    - playwright:
        mode: headless
        deny_navigation: true
        max_pages: 1
    - burp_cli:
        args_allowlist: ["--scan","--scope","--report"]
        deny: ["--intruder","--repeater","--sequencer"]
    - metasploit_module:
        mode: auxiliary_only
        deny_exploit_modules: true
    - naabu:
        args_allowlist: ["-l","-p","-top-ports","-silent","-json","-o","-rate"]
        deny: ["-nmap-cli","-proxy"]
        condition: "explicit_port_scan_authorized == true"
    - gau:
        args_allowlist: ["--threads","--timeout","--providers","--blacklist","--o"]
        deny: ["--proxy"]
    - waybackurls:
        args_allowlist: ["--no-subs","--get-versions"]
        deny: []
    - jsluice:
        args_allowlist: ["urls","secrets","-r","--input"]
        deny: ["--write"]
    - linkfinder:
        args_allowlist: ["-i","-o","-d"]
        deny: ["--burp"]
    - interactsh_client:
        mode: oob_listener_only
        args_allowlist: ["--server","--token","--poll-interval","--output-json","--max-wait-seconds","--correlation-id","--since"]
        deny: ["--persistent"]
        condition: "interactsh_server_configured == true"
```

### execute_tool Contract

```python
def execute_tool(
    tool_name: str,
    args: List[str],
    safety_scope: SafetyScope,
    timeout_seconds: int = 300,
    token_quota: int = 5000,
    capture_stdout: bool = True,
    capture_stderr: bool = True,
    structured_output_schema: Optional[JsonSchema] = None
) -> ToolResult:
    """
    safety_scope enforces:
      - in_scope_hosts only
      - non_destructive_only
      - rate_limits per host
      - deny_state_changing_requests
    """
```

Every tool invocation is logged to `/bb/audit/{{run_id}}.jsonl` with:
- `tool_name`, `args`, `start_time`, `end_time`, `exit_code`
- `stdout_hash` (SHA-256), `stderr_hash`
- `safety_scope` snapshot
- `token_consumed` (for LLM-based parsing)

