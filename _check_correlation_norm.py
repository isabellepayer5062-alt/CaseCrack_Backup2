"""Check what normalized_findings contains and if it's worth merging back."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("CaseCrack")))

src = pathlib.Path("CaseCrack/tools/burp_enterprise/output/correlation_engine.py").read_text('utf-8', 'replace')

# Find NormalizedFinding class
idx = src.find('class NormalizedFinding')
print('=== NormalizedFinding ===')
print(src[idx:idx+800])

# Find the section that produces normalized_findings
idx2 = src.find('normalized_findings')
print('\n=== normalized_findings first occurrence ===')
print(src[max(0,idx2-100):idx2+500])

# Check if correlate_findings returns CorrelationReport
idx3 = src.find('def correlate_findings')
print('\n=== correlate_findings signature ===')
print(src[idx3:idx3+400])
