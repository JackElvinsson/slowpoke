# Slowpoke

A Chrome DevTools panel that shows which network requests are slow, which run more than once, and why.

## Install

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and pick this folder.
3. Open DevTools on any page and switch to the **Slowpoke** tab. Reload the page to capture every request.

After changing the code, click the reload icon on the extension card and reopen DevTools.

## Features

- **Slow requests**: a global threshold plus optional per-type overrides (XHR, document, script, CSS, image, font, other).
- **Repeated requests**: requests match on method, URL and a hash of the request body, so POSTs to one endpoint (GraphQL, `admin-ajax.php`) only match when the body is the same. GraphQL operation names are shown and searchable.
- **Ignore params**: query params left out when matching repeats, for cache-busters like `_` or `ver`. Use `*` to ignore the whole query string.
- **Bursts**: repeats that fire within 1 second of each other, such as a component fetching twice on mount.
- **Grouped view**: one row per request with call count, average, p95, max and total time.
- **Initiator**: the call stack that started the request, with links that open the source in the Sources panel. Repeated requests list their distinct callers.
- **Server timing and cache**: `Server-Timing` metrics and the CDN or proxy cache result (`cf-cache-status`, `x-cache`, `x-cache-status`, `x-proxy-cache`, `x-litespeed-cache`, `x-vercel-cache`, `age`).
- **Hints**: likely causes such as long server wait, queueing on HTTP/1.1, slow connection setup, redirects, missing compression, large payloads and static assets without cache headers.
- **Baseline**: save the current run, then compare later runs to see what got slower, faster, new or newly repeated.
- **Export**: copy the filtered list, a single request as a summary for an LLM, or a request as a cURL command.

Toolbar settings and the baseline are stored in the panel's `localStorage`.
