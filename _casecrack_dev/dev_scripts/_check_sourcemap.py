import httpx

HDR = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}

with httpx.Client(http2=True, verify=True, timeout=10) as c:
    # Check source map
    r = c.get("https://catalog.anduril.com/login/assets/index-C7oRpF3Z.js.map", headers=HDR)
    ct = r.headers.get("content-type", "?")
    print(f"Source map: HTTP={r.status_code} Content-Type={ct} len={len(r.content)}")
    if r.status_code == 200:
        print(f"First 200: {r.text[:200]!r}")
        print("*** SOURCE MAP PUBLICLY ACCESSIBLE ***")
    else:
        print(f"Not accessible. Body: {r.text[:100]!r}")

    # Also check if there's a favicon or any other static assets exposed
    r2 = c.get("https://catalog.anduril.com/login/assets/", headers=HDR)
    print(f"\nDirectory listing attempt: HTTP={r2.status_code}")
