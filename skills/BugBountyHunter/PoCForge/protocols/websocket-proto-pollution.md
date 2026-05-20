    timeout: 120
    headless: true
    max_pages: 1
    deny_navigation: false
    allow_hosts: []  # populated from scope at runtime
```

### execute_tool Contract

```python
def execute_tool(
    tool_name: str,
    args: List[str],
    safety_scope: SafetyScope,
    timeout_seconds: int = 60,
    token_quota: int = 3000,
    capture_stdout: bool = True,
    capture_stderr: bool = True
) -> ToolResult:
    """
    For PoCForge: replay HTTP requests and compare responses.
