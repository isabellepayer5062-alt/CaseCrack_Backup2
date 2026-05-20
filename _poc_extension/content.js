/**
 * content.js — runs in MAIN world (same JS context as catalog.anduril.com page).
 *
 * The Anduril catalog SPA calls:
 *   globalThis.postMessage(p, "*")
 * where p = { type: "__GRPCWEB_DEVTOOLS__", method, request, response, status, traceparent }
 *
 * Because this content script runs in the MAIN world, window.addEventListener("message")
 * receives these broadcasts just like the grpc-web-devtools DevTools extension would.
 *
 * NOTE: "world": "MAIN" is required in manifest.json for this to work.
 * An ISOLATED world content script cannot see postMessage events dispatched by the page to itself.
 */

(function () {
  "use strict";

  const TYPES = new Set([
    "__GRPCWEB_DEVTOOLS__",
    "__GRPCWEB_DEVTOOLS_STREAMING__",
  ]);

  window.addEventListener(
    "message",
    function (event) {
      // Filter: only intercept gRPC-Web DevTools protocol messages
      if (!event.data || !TYPES.has(event.data.type)) return;

      const d = event.data;

      // Forward captured payload to background service worker
      chrome.runtime.sendMessage({
        source: "anduril-grpc-sniffer",
        url: window.location.href,
        timestamp: new Date().toISOString(),
        grpcData: {
          type: d.type,
          method: d.method,          // e.g. "anduril.auth.v2.Tokens/GenerateBearerToken"
          methodType: d.methodType,  // "unary" | "stream"
          request: d.request,        // deserialized request proto
          response: d.response,      // deserialized response proto  ← may include bearer token
          status: d.status,
          statusMessage: d.statusMessage,
          traceparent: d.traceparent,
        },
      });
    },
    false
  );
})();
