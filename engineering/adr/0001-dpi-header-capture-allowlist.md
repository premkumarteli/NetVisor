# 0001. Allow-List Constrained HTTP Header Capture and Sensitive Token Redaction

Status: Proposed

## Context
During deep packet inspection (DPI) via `mitmproxy` on managed endpoints, `agent/dpi/event_buffer.py` attempts to sanitize HTTP headers using `redact_headers()`. However, `agent/dpi/mitm_addon.py` currently omits HTTP request/response headers from the emitted `DpiObservation` payload, causing headers to be completely dropped. Indiscriminately capturing raw headers risks storing sensitive tokens (e.g., `Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Token`), violating user privacy and NIST SP 800-218 security requirements.

## Options Considered
- **Option A: Capture All Headers with Regex Blacklist.** Extract all incoming HTTP headers and apply regex replacement (`[REDACTED]`) to known sensitive headers (`Cookie`, `Authorization`).
  - *Pros:* Simple to write.
  - *Cons:* Fragile; new or proprietary auth headers (e.g., `X-Api-Key`, `X-Session-ID`, bearer tokens in custom headers) will leak into persisted logs whenever blacklist patterns miss them.
- **Option B: Strict Allow-List Header Ingestion (Recommended).** Intercept and persist ONLY explicitly approved, non-sensitive operational headers (`Host`, `User-Agent`, `Accept`, `Content-Type`, `Referer`), dropping all unlisted headers by default, while sanitizing query parameters and values on allowed headers.
  - *Pros:* Secure by default (defense-in-depth); zero risk of credential leakage from unexpected custom headers; conforms to OWASP ASVS Section 8.3.
  - *Cons:* Analysts cannot inspect non-whitelisted custom debugging headers.
- **Option C: Header Discard (Status Quo).** Continue omitting all HTTP headers from storage, retaining only URL, method, status code, and SNI.
  - *Pros:* Zero credential leak risk.
  - *Cons:* Deprives SOC analysts of critical diagnostic context (e.g., client User-Agent mismatch, content-type spoofing).

## Decision
Adopt **Option B: Strict Allow-List Header Ingestion**.
1. In `agent/dpi/mitm_addon.py`, extract only headers whose normalized lowercase names match `ALLOWED_DPI_HEADERS`:
   `{"host", "user-agent", "accept", "content-type", "referer"}`.
2. Ensure `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, and all other headers are rejected by default before payload serialization.
3. Pass allowed headers through `agent/dpi/redaction.py::redact_headers()` to strip any embedded tokens or secrets before writing to `event_buffer.py`.

## Consequences
- *What gets easier:* Consistent, privacy-safe header telemetry for user-agent analysis and spoofing detection without secret leakage.
- *What gets harder:* Adding visibility for custom operational headers requires updating the explicit whitelist.
- *What to monitor:* Ensure high-entropy tokens never appear in allowed header values; monitor memory usage of `DpiObservation` payload buffers.

## Revisit If
Enterprise customers require selective, opt-in inspection of specific internal API headers with organization-level cryptographic keys.
