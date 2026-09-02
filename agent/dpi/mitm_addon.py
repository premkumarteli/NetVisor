import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

# Add project root to sys.path
root = Path(__file__).resolve().parent.parent.parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from cryptography import x509
from intel import get_base_domain, get_service_info, is_sensitive_destination, normalize_host
from packet_engine import DpiObservation
from agent.dpi.aia_chaser import AiaChaser

logger = logging.getLogger("NetVisorMitmAddon")

EVENT_PREFIX = "__NETVISOR_WEB_EVENT__"
STATUS_PREFIX = "__NETVISOR_DPI_STATUS__"
ALERT_PREFIX = "__NETVISOR_DPI_ALERT__"

ALLOWED_DOMAINS = {
    item
    for item in json.loads(os.getenv("NETVISOR_ALLOWED_DOMAINS_JSON", "[]") or "[]")
    if str(item).strip()
}
SNIPPET_MAX_BYTES = min(max(int(os.getenv("NETVISOR_SNIPPET_MAX_BYTES", "256")), 0), 256)

# Backoff intervals in seconds: 5m, 15m, 30m, max 60m
BACKOFF_INTERVALS = [300, 900, 1800, 3600]
PERSISTENT_FAILURE_THRESHOLD = 3


def _find_header(headers, name: str) -> str:
    target = str(name or "").lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _browser_from_name(name: str) -> tuple[str, str]:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return "Unknown", "unknown"
    if "antigravity" in lowered:
        return "Antigravity", "antigravity.exe"
    if "whatsapp" in lowered:
        return "WhatsApp", "WhatsApp.exe"
    if "edge" in lowered or "edg" in lowered:
        return "Edge", "msedge.exe"
    if "chrome" in lowered or "chromium" in lowered:
        return "Chrome", "chrome.exe"
    if "brave" in lowered:
        return "Brave", "brave.exe"
    if "opera" in lowered or "opr" in lowered:
        return "Opera", "opera.exe"
    if "firefox" in lowered:
        return "Firefox", "firefox.exe"
    if "postman" in lowered:
        return "Postman", "postman.exe"
    if "slack" in lowered:
        return "Slack", "slack.exe"
    if "teams" in lowered:
        return "Microsoft Teams", "ms-teams.exe"
    if "outlook" in lowered:
        return "Outlook", "outlook.exe"
    if "code" in lowered or "vscode" in lowered:
        return "VS Code", "code.exe"
    if "electron" in lowered:
        return "Electron App", "electron.exe"
    if "python" in lowered:
        return "Python", "python.exe"
    if "curl" in lowered:
        return "cURL", "curl.exe"
    if "go" in lowered:
        return "Go Client", "go.exe"
    if "safari" in lowered and "chrome" not in lowered:
        return "Safari", "safari.exe"
    return "System App", f"{lowered}.exe"


def infer_browser_identity(headers) -> tuple[str, str]:
    sec_ch_ua = _find_header(headers, "sec-ch-ua").lower()
    user_agent = _find_header(headers, "user-agent").lower()
    combined = f"{sec_ch_ua} {user_agent}"

    if "antigravity" in combined:
        return "Antigravity", "antigravity.exe"
    if "whatsapp" in combined:
        return "WhatsApp", "WhatsApp.exe"
    if "edg/" in combined or "edge" in combined:
        return "Edge", "msedge.exe"
    if "brave" in combined:
        return "Brave", "brave.exe"
    if "opera" in combined or "opr/" in combined:
        return "Opera", "opera.exe"
    if "chrome/" in combined or "chromium" in combined:
        return "Chrome", "chrome.exe"
    if "firefox/" in combined:
        return "Firefox", "firefox.exe"
    if "postman" in combined or "postmanruntime" in combined:
        return "Postman", "postman.exe"
    if "slack" in combined:
        return "Slack", "slack.exe"
    if "teams" in combined:
        return "Microsoft Teams", "ms-teams.exe"
    if "outlook" in combined:
        return "Outlook", "outlook.exe"
    if "code/" in combined or "vscode" in combined:
        return "VS Code", "code.exe"
    if "electron" in combined:
        return "Electron App", "electron.exe"
    if "python" in combined:
        return "Python", "python.exe"
    if "curl" in combined:
        return "cURL", "curl.exe"
    if "go-http-client" in combined:
        return "Go Client", "go.exe"
    if "safari/" in combined and "chrome/" not in combined:
        return "Safari", "safari.exe"

    if user_agent:
        parts = user_agent.split()
        if parts:
            token = parts[0].split("/")[0].strip()
            if token and len(token) < 30 and token.replace("-", "").replace("_", "").isalnum():
                return token.title(), f"{token.lower()}.exe"

    return "System App", "system.exe"


def _preferred_domain_label(host: str | None) -> str | None:
    normalized_host = normalize_host(host)
    if not normalized_host:
        return None

    base_domain = get_base_domain(normalized_host) or normalized_host
    exact_name, exact_category = get_service_info(normalized_host)
    base_name, base_category = get_service_info(base_domain)
    if normalized_host != base_domain and (exact_name != base_name or exact_category != base_category):
        return normalized_host
    return base_domain


def extract_page_title(body: str | bytes | None) -> str | None:
    if body in (None, "", b""):
        return None
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = body

    patterns = (
        r"<title[^>]*>(.*?)</title>",
        r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']',
        r'<meta[^>]+name=["\']title["\'][^>]+content=["\'](.*?)["\']',
        r'"title"\s*:\s*"([^"]+)"',
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            title = unescape(match.group(1)).strip()
            if title:
                return re.sub(r"\s+", " ", title)[:255]
    return None


def extract_site_details(url: str, page_title: str | None) -> tuple[str, str | None, str | None, str]:
    """Returns (category, content_id, search_query, service_name)."""
    split = urlsplit(url or "")
    host = normalize_host(split.netloc)
    base_domain = get_base_domain(host) or host
    query = parse_qs(split.query)

    service_name, category = get_service_info(host or base_domain)

    if category == "search":
        q = (
            query.get("q")
            or query.get("query")
            or query.get("p")
            or query.get("text")
            or []
        )
        search_query = q[0] if q else None
        return "search", None, search_query, service_name

    if "youtube.com" in base_domain or "youtu.be" in base_domain:
        v = query.get("v", [])
        content_id = v[0] if v else None
        if not content_id and "/shorts/" in split.path:
            parts = split.path.strip("/").split("/")
            if len(parts) >= 2 and parts[0] == "shorts":
                content_id = parts[1]
        return "streaming_media", content_id, None, "YouTube"

    if "claude.ai" in base_domain:
        parts = split.path.strip("/").split("/")
        chat_id = parts[1] if len(parts) >= 2 and parts[0] == "chat" else None
        return "ai_assistant", chat_id, None, "Claude"

    if "chatgpt.com" in base_domain or "openai.com" in base_domain:
        parts = split.path.strip("/").split("/")
        chat_id = parts[1] if len(parts) >= 2 and parts[0] == "c" else None
        return "ai_assistant", chat_id, None, "ChatGPT"

    if "github.com" in base_domain:
        parts = [p for p in split.path.strip("/").split("/") if p]
        repo_id = "/".join(parts[:2]) if len(parts) >= 2 else None
        return "developer_tools", repo_id, None, "GitHub"

    return category, None, None, service_name


def sanitize_snippet(snippet: str) -> str:
    """Redacts obvious tokens/passwords in snippets before streaming."""
    if not snippet:
        return ""
    token_pattern = r"(bearer\s+[\w\-\.]+)|(password\s*[:=]\s*[\w\-\.@!#]+)|(api[_\-]?key\s*[:=]\s*[\w\-]+)"
    return re.sub(token_pattern, "[REDACTED_SECRET]", snippet, flags=re.IGNORECASE)[:SNIPPET_MAX_BYTES]


def redact_url_secrets(url: str) -> str:
    if not url:
        return ""
    return re.sub(r"(key|token|auth|password|secret|apikey)=[^&#]+", r"\1=[REDACTED]", url, flags=re.IGNORECASE)


def split_url_label(url: str) -> str:
    split = urlsplit(url or "")
    if split.path and split.path != "/":
        return split.path.strip("/").replace("-", " ")[:255] or split.netloc
    return split.netloc or "Untitled"


class NetVisorDpiAddon:
    """Mitmproxy Addon providing L7 DPI event extraction, dynamic AIA intermediate chain

    healing, domain-scoped certificate verification, and resilient TTL fail-open tracking.
    """

    def __init__(self):
        self.aia_chaser = AiaChaser()
        self._lock = threading.Lock()
        # Fail-open tracker structure:
        # { domain: { "error": str, "failed_at": float, "expires_at": float, "consecutive_failures": int, "status": str } }
        self._upstream_fail_open_tracker: dict[str, dict] = {}
        self._last_telemetry_emit = 0.0

    def _get_backoff_ttl(self, consecutive_failures: int) -> float:
        idx = min(max(consecutive_failures - 1, 0), len(BACKOFF_INTERVALS) - 1)
        return float(BACKOFF_INTERVALS[idx])

    def _emit_telemetry_snapshot(self):
        now = time.time()
        with self._lock:
            healed = self.aia_chaser.get_cached_domains()
            recovering = []
            persistently_failing = []

            # Clean expired entries and categorize
            expired_keys = []
            for domain, data in list(self._upstream_fail_open_tracker.items()):
                if now >= data["expires_at"]:
                    expired_keys.append(domain)
                    continue

                item = {
                    "domain": domain,
                    "error": data["error"],
                    "consecutive_failures": data["consecutive_failures"],
                    "expires_in_seconds": max(int(data["expires_at"] - now), 0),
                    "failed_at": datetime.fromtimestamp(data["failed_at"], timezone.utc).isoformat(),
                }
                if data["status"] == "persistently_failing":
                    persistently_failing.append(item)
                else:
                    recovering.append(item)

            for k in expired_keys:
                del self._upstream_fail_open_tracker[k]

        snapshot = {
            "type": "upstream_tls_status",
            "healed_domains": healed,
            "recovering_domains": recovering,
            "persistently_failing_domains": persistently_failing,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        print(f"{STATUS_PREFIX}{json.dumps(snapshot, ensure_ascii=False)}", flush=True)

    # --- MITMPROXY HOOKS ---

    def tls_clienthello(self, data):
        """Called when a client initiates TLS handshake.

        If the SNI host is currently in a non-expired fail-open state, ignore connection
        to stream raw TCP without hard-failing to a 502 Bad Gateway.
        """
        sni = str(getattr(getattr(data, "client_hello", None), "sni", None) or "").strip().lower()
        if not sni:
            return

        now = time.time()
        should_ignore = False
        with self._lock:
            tracker = self._upstream_fail_open_tracker.get(sni)
            if tracker:
                if now < tracker["expires_at"]:
                    should_ignore = True
                else:
                    # TTL expired: evict to re-attempt full upstream verification
                    del self._upstream_fail_open_tracker[sni]

        if should_ignore:
            logger.debug("[TLS Fail-Open] Bypassing interception for %s (active fail-open TTL)", sni)
            data.ignore_connection = True

    def tls_failed_server(self, tls_data):
        """Called when upstream TLS handshake with server fails."""
        conn = getattr(tls_data, "conn", None)
        if not conn:
            return

        sni = str(getattr(conn, "sni", None) or getattr(conn, "peername", [None])[0] or "").strip().lower()
        error_msg = str(getattr(conn, "error", None) or "Unknown TLS handshake failure")
        if not sni:
            return

        now = time.time()
        with self._lock:
            prev = self._upstream_fail_open_tracker.get(sni, {})
            consecutive = prev.get("consecutive_failures", 0) + 1
            status = "persistently_failing" if consecutive >= PERSISTENT_FAILURE_THRESHOLD else "recovering"
            ttl = self._get_backoff_ttl(consecutive)

            self._upstream_fail_open_tracker[sni] = {
                "error": error_msg,
                "failed_at": now,
                "expires_at": now + ttl,
                "consecutive_failures": consecutive,
                "status": status,
            }

        logger.warning(
            "[Upstream TLS Failure] %s failed verification (%s). Fail-open TTL: %ds, Consecutive: %d, Status: %s",
            sni,
            error_msg,
            int(ttl),
            consecutive,
            status,
        )

        # Emit telemetry event
        event = {
            "type": "upstream_tls_verify_failed",
            "domain": sni,
            "error": error_msg,
            "consecutive_failures": consecutive,
            "status": status,
            "ttl_seconds": int(ttl),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        print(f"{EVENT_PREFIX}{json.dumps(event, ensure_ascii=False)}", flush=True)

        if status == "persistently_failing":
            alert = {
                "type": "upstream_tls_persistent_blind_spot",
                "domain": sni,
                "error": error_msg,
                "consecutive_failures": consecutive,
                "severity": "WARNING",
                "message": f"Domain {sni} has failed TLS verification {consecutive} consecutive times. Traffic is passing uninspected.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            print(f"{ALERT_PREFIX}{json.dumps(alert, ensure_ascii=False)}", flush=True)

        # If failure was missing intermediate certificate, trigger background AIA chasing
        if "unable to get local issuer certificate" in error_msg.lower():
            threading.Thread(target=self._async_chase_aia, args=(sni,), daemon=True).start()

        self._emit_telemetry_snapshot()

    def server_connect_error(self, data):
        """Called on Layer 4 / TCP-level connection failures to upstream server."""
        server = getattr(data, "server", None)
        if not server:
            return
        address = getattr(server, "address", None)
        sni = str(address[0] if address else "").strip().lower()
        error_msg = str(getattr(server, "error", None) or "Upstream connection error")
        if not sni:
            return

        now = time.time()
        with self._lock:
            prev = self._upstream_fail_open_tracker.get(sni, {})
            consecutive = prev.get("consecutive_failures", 0) + 1
            status = "persistently_failing" if consecutive >= PERSISTENT_FAILURE_THRESHOLD else "recovering"
            ttl = self._get_backoff_ttl(consecutive)

            self._upstream_fail_open_tracker[sni] = {
                "error": error_msg,
                "failed_at": now,
                "expires_at": now + ttl,
                "consecutive_failures": consecutive,
                "status": status,
            }

        self._emit_telemetry_snapshot()

    def _async_chase_aia(self, domain: str):
        """Background thread worker that fetches leaf cert directly, validates AIA intermediate

        cryptographically, and caches it scoped to domain.
        """
        import socket
        import ssl

        logger.info("[AIA Chase Worker] Starting background AIA chase for %s", domain)
        try:
            # Connect directly with unverified SSL to fetch leaf certificate
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    leaf_der = ssock.getpeercert(binary_form=True)

            if not leaf_der:
                logger.warning("[AIA Chase Worker] No leaf certificate returned by %s", domain)
                return

            leaf_cert = x509.load_der_x509_certificate(leaf_der)
            result = self.aia_chaser.resolve_and_cache_for_domain(domain, leaf_cert)

            if result.success:
                with self._lock:
                    # Immediately evict from fail-open so next flow uses healed chain!
                    if domain in self._upstream_fail_open_tracker:
                        del self._upstream_fail_open_tracker[domain]
                logger.info("[AIA Chase Worker] Healed intermediate chain for %s! Evicted from fail-open.", domain)
                self._emit_telemetry_snapshot()
            else:
                logger.warning("[AIA Chase Worker] AIA chase could not heal chain for %s: %s", domain, result.error)
        except Exception as exc:
            logger.warning("[AIA Chase Worker] Background AIA chase error for %s: %s", domain, exc)

    def response(self, flow):
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)
        if not request or not response:
            return

        host = normalize_host(getattr(request, "pretty_host", None) or getattr(request, "host", None))
        base_domain = _preferred_domain_label(host)
        if not base_domain:
            return
        if is_sensitive_destination(base_domain):
            return
        if ALLOWED_DOMAINS and "*" not in ALLOWED_DOMAINS and not any(
            base_domain == allowed or host == allowed or host.endswith(f".{allowed}")
            for allowed in ALLOWED_DOMAINS
        ):
            return


        content_type = ""
        headers = getattr(response, "headers", {}) or {}
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                content_type = str(value)
                break

        raw_content = getattr(response, "content", None) or getattr(response, "raw_content", None) or b""
        is_textual = content_type.startswith("text/") or "json" in content_type or "javascript" in content_type
        snippet = None
        page_title = None
        if is_textual:
            body = raw_content[:SNIPPET_MAX_BYTES]
            decoded = body.decode("utf-8", errors="replace")
            snippet = sanitize_snippet(decoded)
            page_title = extract_page_title(raw_content[:32768])

        raw_url = getattr(request, "pretty_url", None) or getattr(request, "url", None) or ""
        url = redact_url_secrets(raw_url)
        content_category, content_id, search_query, service_name = extract_site_details(url, page_title)

        if not page_title:
            if content_id:
                page_title = f"{service_name}: {content_id}"
            elif search_query:
                page_title = f"Search: {search_query}"
            else:
                page_title = service_name if service_name != base_domain else split_url_label(url)

        request_headers = getattr(request, "headers", {}) or {}
        browser_name, process_name = infer_browser_identity(request_headers)

        event = DpiObservation(
            browser_name=browser_name,
            process_name=process_name,
            page_url=url,
            base_domain=base_domain,
            page_title=page_title or "Untitled",
            content_category=content_category,
            content_id=content_id,
            search_query=search_query,
            http_method=getattr(request, "method", "GET"),
            status_code=getattr(response, "status_code", None),
            content_type=content_type or None,
            request_bytes=len(getattr(request, "raw_content", None) or b""),
            response_bytes=len(raw_content),
            snippet_redacted=snippet,
            timestamp=datetime.now(timezone.utc).isoformat(),
            app=browser_name,
        ).to_payload()

        print(f"{EVENT_PREFIX}{json.dumps(event, ensure_ascii=False)}", flush=True)


addons = [NetVisorDpiAddon()]
