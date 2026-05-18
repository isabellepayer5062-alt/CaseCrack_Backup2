"""
Patch recon_dashboard.py to load dashboard HTML from static files instead of
the inline RECON_DASHBOARD_HTML constant.  Safe, reversible (back-up created).
"""
import pathlib, shutil, sys

ROOT = pathlib.Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"
SRC  = ROOT / "recon_dashboard.py"

if not SRC.exists():
    print(f"ERROR: {SRC} not found"); sys.exit(1)

text  = SRC.read_text(encoding="utf-8")
lines = text.splitlines(keepends=True)
print(f"Original: {len(lines)} lines, {len(text)} bytes")

# ── Find start / end of the inline constant block ─────────────────────────
# Start: line that contains  RECON_DASHBOARD_HTML = r"""
# Anchor comment block: 3 lines before (# DASHBOARD HTML / CSS / JS etc.)
start_html = None   # first line of the comment anchor
start_const = None  # line with  RECON_DASHBOARD_HTML = r"""
end_const   = None  # last line, ends with  """

for i, raw in enumerate(lines):
    s = raw.strip()
    if start_const is None and 'RECON_DASHBOARD_HTML = r"""' in s:
        # Look back for the comment anchor (up to 4 lines)
        for j in range(max(0, i-4), i+1):
            if "# DASHBOARD HTML" in lines[j] or "# ════" in lines[j]:
                start_html = j
                break
        if start_html is None:
            start_html = i
        start_const = i
    if start_const is not None and i > start_const:
        # The closing line is either exactly  </html>"""  or  </html>\n  on the
        # penultimate line followed by  """  on the last.
        if s == '</html>"""' or (s == '"""' and '</html>' in (lines[i-1] if i > 0 else '')):
            end_const = i
            break

if start_const is None or end_const is None:
    print(f"ERROR: could not locate template block  start={start_const}  end={end_const}")
    sys.exit(1)

anchor = start_html if start_html is not None else start_const
print(f"Block to replace: lines {anchor+1}–{end_const+1}  ({end_const - anchor + 1} lines)")

# ── Create backup ──────────────────────────────────────────────────────────
backup = SRC.with_suffix(".py.bak_inline")
shutil.copy2(SRC, backup)
print(f"Backup: {backup}")

# ── Build the replacement block ────────────────────────────────────────────
REPLACEMENT = '''\
# DASHBOARD HTML / CSS / JS
# ═══════════════════════════════════════════════════════════════════
# Assembled at import time from the static source files so that edits
# to the CSS / JS / HTML body files are immediately reflected on
# server restart — no need to maintain a multi-thousand-line inline
# string constant.
#
# Source files (relative to this module):
#   static/css/recon-dashboard.css          — full dashboard CSS
#   static/js/recon-dashboard.js            — full dashboard JS
#   static/html/recon-dashboard-body.html   — HTML body markup
#   static/html/_head_fragment.txt          — <head> preamble
#   static/html/_tail_fragment.txt          — </script></body></html>
# ═══════════════════════════════════════════════════════════════════

def _build_dashboard_html() -> str:
    """Assemble dashboard HTML from static component files."""
    _s = Path(__file__).parent / "static"
    head = (_s / "html" / "_head_fragment.txt").read_text(encoding="utf-8")
    css  = (_s / "css"  / "recon-dashboard.css").read_text(encoding="utf-8")
    body = (_s / "html" / "recon-dashboard-body.html").read_text(encoding="utf-8")
    js   = (_s / "js"   / "recon-dashboard.js").read_text(encoding="utf-8")
    # Replace design-token placeholder; the CSS file already contains :root vars.
    head = head.replace("__DESIGN_TOKENS_CSS__", "")
    # Inject runtime config before the main script so window.__CC_CONFIG is
    # available to the JS.  WS_PORT_PLACEHOLDER is substituted at serve time.
    config_block = (
        "<script>\\n"
        "window.__CC_CONFIG = {\\n"
        '  wsPort: "WS_PORT_PLACEHOLDER",\\n'
        '  authToken: "",\\n'
        '  sessionId: ""\\n'
        "};\\n"
        "</script>\\n"
    )
    return (
        head + css
        + body
        + config_block
        + "<script>\\n"
        + js
        + "\\n</script>\\n</body>\\n</html>"
    )


RECON_DASHBOARD_HTML: str = _build_dashboard_html()
'''

# ── Splice the replacement in ──────────────────────────────────────────────
new_lines = lines[:anchor] + [REPLACEMENT] + lines[end_const + 1:]
new_text  = "".join(new_lines)

print(f"New:      {len(new_lines)} lines, {len(new_text)} bytes")

# ── Quick sanity check: the new file must still import cleanly ─────────────
import py_compile, tempfile, os
tmp = pathlib.Path(tempfile.mktemp(suffix=".py"))
tmp.write_text(new_text, encoding="utf-8")
try:
    py_compile.compile(str(tmp), doraise=True)
    print("Syntax check: OK")
except py_compile.PyCompileError as e:
    print(f"Syntax check FAILED: {e}")
    tmp.unlink(missing_ok=True)
    sys.exit(1)
finally:
    tmp.unlink(missing_ok=True)

# ── Write ──────────────────────────────────────────────────────────────────
SRC.write_text(new_text, encoding="utf-8")
print(f"Written:  {SRC}")
print("Done — restart the dashboard server to pick up static-file changes.")
