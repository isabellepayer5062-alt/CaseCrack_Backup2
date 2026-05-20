import re, os
catalog_bundle = r"c:\Users\ya754\CaseCrack v1.0\_catalog_bundle.js"
if os.path.exists(catalog_bundle):
    with open(catalog_bundle, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    sentry_dsns = re.findall(r'https://[a-f0-9]{32}@[o\d]+\.ingest\.sentry\.io/\d+', content)
    sentry_dsns2 = re.findall(r'https://[a-f0-9]{32}@sentry\.io/\d+', content)
    sentry_keys = re.findall(r'[a-f0-9]{32}@[a-zA-Z0-9.]+/\d+', content)
    print("Sentry DSNs:", sentry_dsns + sentry_dsns2)
    print("Sentry keys:", sentry_keys[:5])
    monitoring_patterns = ["sentry", "datadog", "rollbar", "logrocket", "mixpanel", "segment", "amplitude", "bugsnag", "newrelic"]
    for mp in monitoring_patterns:
        matches = [m for m in re.findall(r'["\x27][^"\x27]{5,100}["\x27]', content) if mp in m.lower()]
        if matches:
            print(f"  {mp}: {matches[:3]}")
    # Any pattern like "Bearer ..." or "token: ..." 
    hardcoded = re.findall(r'(?:Bearer|token|secret|password|apiKey|api_key)\s*[=:]\s*["\x27]([a-zA-Z0-9._\-]{15,80})["\x27]', content[:100000], re.I)
    if hardcoded:
        print("Hardcoded tokens/keys:", hardcoded[:5])
    else:
        print("No hardcoded tokens found in first 100KB")
else:
    print("Bundle not found")
