import re

# Search all bundles for Sentry DSN - look more broadly
for fname in ["_catalog_bundle.js", "_proving_ground_bundle.js", "_sandboxes_bundle.js"]:
    try:
        with open(f"c:\\Users\\ya754\\CaseCrack v1.0\\{fname}", "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        
        # Sentry DSN is usually formatted as: https://<32hex>@o<digits>.ingest.sentry.io/<digits>
        sentry = re.findall(r'https://[a-f0-9]{32}@o\d+\.ingest\.sentry\.io/\d+', content)
        sentry2 = re.findall(r'ingest\.sentry\.io[^"\s]{0,50}', content)
        sentry3 = re.findall(r'sentry\.io[^"\s]{0,50}', content)
        
        # Datadog API key pattern
        datadog = re.findall(r'[a-f0-9]{32}', content[:500000])
        datadog_refs = [d for d in datadog if len(d) == 32]
        
        # Amplitude / Segment / etc
        segment = re.findall(r'analytics[_\-]?key["\x27]?\s*[=:]\s*["\x27]([a-zA-Z0-9]{10,50})', content, re.I)
        amplitude = re.findall(r'amplitude[^"\']{0,50}api[_\-]?key[^"\']{0,50}["\x27]([a-zA-Z0-9]{10,50})', content, re.I)
        
        # Look for DSN-like patterns more broadly
        dsn_like = re.findall(r'["\x27](https://[a-zA-Z0-9]+@[a-z]+\.sentry\.io[^"\']{0,50})["\x27]', content)
        
        print(f"\n{fname}:")
        print(f"  Sentry DSN exact: {sentry}")
        print(f"  ingest.sentry.io refs: {sentry2[:5]}")
        print(f"  sentry.io refs (other): {sentry3[:3]}")
        print(f"  DSN-like: {dsn_like[:3]}")
        print(f"  Segment keys: {segment[:3]}")
        print(f"  Amplitude keys: {amplitude[:3]}")
        # Look for the actual SENTRY_DSN env variable value
        dsn_env = re.findall(r'(?:SENTRY_DSN|sentryDsn|dsn)["\x27]?\s*[=:]\s*["\x27]([^"\']{20,100})["\x27]', content, re.I)
        if dsn_env:
            print(f"  SENTRY_DSN env values: {dsn_env[:3]}")
    except Exception as e:
        print(f"Error reading {fname}: {e}")
