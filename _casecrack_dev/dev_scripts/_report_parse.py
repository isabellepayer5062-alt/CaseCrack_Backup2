import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

with open('_mandarin_report.md', encoding='utf-8') as f:
    raw = f.read()
lines = raw.split('\n')

print('=== TOOL ERRORS / TIMEOUTS IN REPORT ===')
keywords = ['FIX-TIMEOUT','Self-kill','timed out after','nuclei binary not','zap sidecar','mitmproxy','droopescan','docker run timed','Degraded','degraded','ssrf_map','traversal','sqli timeout','cmdi timeout']
for i, ln in enumerate(lines):
    if any(k in ln for k in keywords):
        print(ln[:200])

print()
print('=== REPORT SECTIONS ===')
for ln in lines:
    if ln.startswith('## ') or ln.startswith('### '):
        print(ln[:120])
