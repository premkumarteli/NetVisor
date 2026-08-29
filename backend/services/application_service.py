from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import logging
import threading
import time

from ..core.config import settings
from ..db.session import get_db_connection, require_runtime_schema
from ..utils.asn_lookup import asn_lookup_service
from ..engines.application.ja4_signatures import lookup_ja4_signature
from ..utils.domain_intelligence import get_service_info
from ..utils.domain_utils import get_base_domain, normalize_host
from ..utils.network import is_rfc1918_device_ip, normalize_ip
from .device_service import device_service
from .web_inspection_service import web_inspection_service

from intel.app_classifier import (
    GENERIC_CERT_ORGS,
    MULTI_TENANT_SUFFIXES,
    clean_cert_org_to_app_name,
    clean_domain_to_app_name,
    clean_process_to_app_name,
    clean_title_to_app_name,
    infer_app_category,
)

logger = logging.getLogger("netvisor.apps")

DEFAULT_APPLICATION_WINDOW_MINUTES = 24 * 60
DEFAULT_ACTIVE_APPLICATION_WINDOW_SECONDS = 5 * 60

# Specific canonical applications checked first
CANONICAL_APP_RULES: dict[str, list[str]] = {
    "Claude": ["anthropic.com", "claude.ai"],
    "ChatGPT": ["openai.com", "chatgpt.com"],
    "Gemini": ["gemini.google.com", "bard.google.com"],
    "YouTube": ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
    "Instagram": ["instagram.com"],
    "Facebook": ["facebook.com", "fbcdn.net", "messenger.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "web.whatsapp.com"],
    "Telegram": ["telegram.org", "t.me", "telegram.me"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com"],
    "GitHub": ["github.com", "githubassets.com", "githubusercontent.com"],
    "Perplexity": ["perplexity.ai", "perplexity.com"],
    "Zoom": ["zoom.us"],
    "Google Meet": ["meet.google.com"],
    "Google Play": ["play.google.com"],
    "Sentry": ["sentry.io"],
    "Spotify": ["spotify.com", "scdn.co"],
    "Slack": ["slack.com", "slack-edge.com"],
    "LinkedIn": ["linkedin.com", "licdn.com"],
    "Stack Overflow": ["stackoverflow.com", "stackexchange.com"],
    "Notion": ["notion.so", "notion.site"],
    "Antigravity": ["antigravity-unleash.goog"],
    "VTU": ["vtu.ac.in", "results.vtu.ac.in"],
    "Acharya Institutes": ["acharya.ac.in", "acharyaerp.in", "erp.acharya.ac.in"],
    "RailOne": ["railone.indianrailways.gov.in", "railone.in", "cris.org.in"],
    "IRCTC": ["irctc.co.in", "irctc.com"],
    "HDHub4u": ["hdhub4u.tv", "hdhub4u.ms", "hdhub4u.work", "hdhub4u.lat", "hdhub4u.top", "hdhub4u.guru"],
}

# Generic umbrella providers checked after curated domain intelligence
UMBRELLA_APP_RULES: dict[str, list[str]] = {
    "Google": [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "google.co.in",
        "googletagmanager.com",
        "google-analytics.com",
    ],
    "Microsoft": [
        "bing.com",
        "bingapis.com",
        "microsoft.com",
        "live.com",
        "msn.com",
        "msedge.net",
        "office.com",
        "office.net",
        "outlook.com",
        "sharepoint.com",
        "microsoftonline.com",
        "gamepass.com",
        "xbox.com",
        "azure.com",
        "azureedge.net",
        "windows.net",
        "edge.microsoft.com",
    ],
}

APP_RULES: dict[str, list[str]] = {**CANONICAL_APP_RULES, **UMBRELLA_APP_RULES}


CONTROL_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
TRANSPORT_PROTOCOL_LABELS = {
    "dns": "DNS",
    "dhcp": "DHCP",
    "http": "HTTP",
    "https": "HTTPS",
    "tls": "TLS",
    "quic": "QUIC",
    "ntp": "NTP",
    "ssdp": "SSDP",
    "mdns": "mDNS",
    "llmnr": "LLMNR",
    "nbns": "NBNS",
    "nbds": "NBDS",
}
CONTROL_TRANSPORT_LABELS = {"DNS", "DHCP", "NTP", "SSDP", "mDNS", "LLMNR", "NBNS", "NBDS"}
GENERIC_TRANSPORT_APPLICATIONS = {
    "ARP",
    "DHCP",
    "DNS",
    "HTTP",
    "HTTPS",
    "ICMP",
    "ICMPV6",
    "LLMNR",
    "mDNS",
    "NBDS",
    "NBNS",
    "NTP",
    "QUIC",
    "SSDP",
    "TCP",
    "TLS",
    "UDP",
}
SHARED_INFRA_BASE_DOMAINS = {
    "amazonaws.com",
    "awsstatic.com",
    "cloudflare.com",
    "cloudfront.net",
    "akamaized.net",
    "akamaihd.net",
    "fastly.net",
}
UNCLASSIFIED_SENTINELS = {"", "Other", "Unknown", None}


class ApplicationService:
    def __init__(self) -> None:
        self._schema_ready = False
        self._unknown_debug_cache: set[tuple[str, str | None]] = set()
        self._lock = threading.RLock()
        self._domain_app_cache: dict[str, dict] = {}
        self._overrides_loaded = False
        self._persist_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="netvisor-app-persist")
        self._summary_cache: dict[tuple[str, int, int], tuple[float, list[dict]]] = {}
        self._summary_cache_ttl = 2.0  # seconds

    def _load_overrides_if_needed(self, db_conn, organization_id: Optional[str] = None) -> None:
        if self._overrides_loaded or db_conn is None:
            return
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            query = "SELECT domain, application_name, category, source_layer, is_override FROM discovered_applications WHERE is_override = 1"
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            cursor.execute(query, tuple(params))
            with self._lock:
                for row in cursor.fetchall() or []:
                    domain = str(row.get("domain") or "").strip().lower()
                    if domain:
                        self._domain_app_cache[domain] = {
                            "name": row.get("application_name"),
                            "category": row.get("category") or "web",
                            "source": "override",
                            "is_override": True,
                            "confidence": 1.0,
                        }
                self._overrides_loaded = True
        except Exception as exc:
            logger.debug("Could not load app overrides: %s", exc)
        finally:
            cursor.close()

    def _async_persist_discovery(
        self,
        organization_id: str,
        domain: str,
        app_name: str,
        category: str = "web",
        source_layer: str = "sld_heuristics",
        confidence: float = 0.85,
    ) -> None:
        if not domain or not app_name or app_name in UNCLASSIFIED_SENTINELS:
            return

        def _persist_task():
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        """
                        INSERT INTO discovered_applications
                            (organization_id, domain, application_name, category, source_layer, confidence, is_override)
                        VALUES
                            (%s, %s, %s, %s, %s, %s, 0)
                        AS new_row
                        ON DUPLICATE KEY UPDATE
                            application_name = IF(discovered_applications.is_override = 1, discovered_applications.application_name, new_row.application_name),
                            category = IF(discovered_applications.is_override = 1, discovered_applications.category, new_row.category),
                            updated_at = NOW()
                        """,
                        (organization_id, domain.lower(), app_name, category, source_layer, confidence),
                    )
                    conn.commit()
                finally:
                    cursor.close()
                    conn.close()
            except Exception as e:
                logger.warning("Failed async discovery persistence for %s: %s", domain, e)

        self._persist_executor.submit(_persist_task)

    def _row_value(self, row: Any, key: str) -> Any:
        if isinstance(row, dict):
            return row.get(key)
        return getattr(row, key, None)


    def _normalize_domain(self, value: object) -> Optional[str]:
        return normalize_host(value)

    def get_base_domain(self, domain: object) -> Optional[str]:
        return get_base_domain(domain)

    def _fallback_application_label(self, base_domain: str | None) -> str:
        if not base_domain:
            return "Other"

        root_label = str(base_domain).split(".", 1)[0].replace("-", " ").replace("_", " ").strip()
        if not root_label:
            return "Other"

        tokens = root_label.split()
        if len(tokens) > 1 and len(tokens[0]) == 1 and tokens[0].isalpha():
            tokens = tokens[1:]
        normalized_root = " ".join(tokens) or root_label

        if "msedge" in normalized_root:
            return "Microsoft Edge"

        words = []
        for part in normalized_root.split():
            if len(part) <= 3 and part.isalpha():
                words.append(part.upper())
            else:
                words.append(part.capitalize())
        return " ".join(words) or "Other"

    def _preferred_host(self, row: Any) -> Optional[str]:
        return self._normalize_domain(
            self._row_value(row, "sni")
            or self._row_value(row, "domain")
            or self._row_value(row, "base_domain")
            or self._row_value(row, "host")
        )


    def _preferred_external_ip(self, row: Any) -> Optional[str]:
        for key in ("external_endpoint_ip", "external_ip", "dst_ip", "src_ip"):
            candidate = normalize_ip(self._row_value(row, key))
            if candidate and not is_rfc1918_device_ip(candidate):
                return candidate

        for key in ("external_endpoint_ip", "external_ip", "dst_ip", "src_ip"):
            candidate = normalize_ip(self._row_value(row, key))
            if candidate:
                return candidate
        return None

    def _service_label_from_host(self, host: object) -> Optional[str]:
        normalized = self._normalize_domain(host)
        if not normalized:
            return None

        service_name, _ = get_service_info(normalized)
        label = str(service_name or "").strip()
        if not label:
            return None

        base_domain = self.get_base_domain(normalized)
        lowered = label.lower()
        if lowered in {normalized, (base_domain or "").lower()}:
            return None
        return label

    def _transport_label(self, row: Any) -> Optional[str]:
        application_protocol = str(self._row_value(row, "application_protocol") or "").strip().lower()
        if application_protocol in TRANSPORT_PROTOCOL_LABELS:
            return TRANSPORT_PROTOCOL_LABELS[application_protocol]

        service_name = str(self._row_value(row, "service_name") or "").strip().lower()
        if service_name in TRANSPORT_PROTOCOL_LABELS:
            return TRANSPORT_PROTOCOL_LABELS[service_name]

        protocol = str(self._row_value(row, "protocol") or "").strip().upper()
        try:
            src_port = int(self._row_value(row, "src_port") or 0)
        except (ValueError, TypeError):
            src_port = 0
            
        try:
            dst_port = int(self._row_value(row, "dst_port") or 0)
        except (ValueError, TypeError):
            dst_port = 0
            
        port = dst_port or src_port

        if protocol == "UDP" and port == 443:
            return "QUIC"

        port_labels = {
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            80: "HTTP",
            123: "NTP",
            137: "NBNS",
            138: "NBDS",
            1900: "SSDP",
            5353: "mDNS",
            5355: "LLMNR",
            443: "HTTPS" if protocol != "UDP" else "QUIC",
            8443: "HTTPS" if protocol != "UDP" else "QUIC",
            8000: "HTTP",
            8008: "HTTP",
            8080: "HTTP",
            8888: "HTTP",
        }
        return port_labels.get(port)

    def is_generic_transport_application(self, application: object) -> bool:
        normalized = str(application or "").strip()
        if not normalized:
            return False
        return normalized.upper() in {label.upper() for label in GENERIC_TRANSPORT_APPLICATIONS}

    def classify_by_domain(self, domain: object, organization_id: str = "default-org-id") -> Optional[str]:
        """
        Classify domain using 5-layer pipeline:
        Layer 0: Admin Overrides (in-memory / DB)
        Layer 1: Seed Rules (APP_RULES) & curated domain intelligence
        Layer 2: Dynamic SLD & Multi-Tenant Subdomain Heuristics
        """
        normalized = self._normalize_domain(domain)
        if not normalized:
            return None

        # Layer 0: Check in-memory cache / admin overrides
        with self._lock:
            cached = self._domain_app_cache.get(normalized)
            if cached:
                return cached["name"]

        base_domain = self.get_base_domain(normalized) or normalized

        # Layer 1A: Check Canonical Specific Seed Rules (e.g. ChatGPT, YouTube, Claude, Discord)
        for application, allowed_domains in CANONICAL_APP_RULES.items():
            for allowed_domain in allowed_domains:
                if (
                    base_domain == allowed_domain
                    or normalized == allowed_domain
                    or normalized.endswith(f".{allowed_domain}")
                ):
                    with self._lock:
                        existing = self._domain_app_cache.get(normalized)
                        if not existing or not existing.get("is_override"):
                            self._domain_app_cache[normalized] = {
                                "name": application,
                                "category": infer_app_category(application, normalized),
                                "source": "seed_rule",
                                "is_override": False,
                                "confidence": 1.0,
                            }
                    return application

        # Layer 1B: Check curated domain intelligence (e.g. Azure CloudApp, Visual Studio Code, Grammarly)
        service_label = self._service_label_from_host(normalized)
        if service_label:
            with self._lock:
                existing = self._domain_app_cache.get(normalized)
                if not existing or not existing.get("is_override"):
                    self._domain_app_cache[normalized] = {
                        "name": service_label,
                        "category": infer_app_category(service_label, normalized),
                        "source": "domain_intelligence",
                        "is_override": False,
                        "confidence": 0.95,
                    }
            return service_label

        # Layer 1C: Check Umbrella Providers (Google, Microsoft)
        for application, allowed_domains in UMBRELLA_APP_RULES.items():
            for allowed_domain in allowed_domains:
                if (
                    base_domain == allowed_domain
                    or normalized == allowed_domain
                    or normalized.endswith(f".{allowed_domain}")
                ):
                    with self._lock:
                        existing = self._domain_app_cache.get(normalized)
                        if not existing or not existing.get("is_override"):
                            self._domain_app_cache[normalized] = {
                                "name": application,
                                "category": infer_app_category(application, normalized),
                                "source": "seed_rule",
                                "is_override": False,
                                "confidence": 1.0,
                            }
                    return application

        if base_domain in SHARED_INFRA_BASE_DOMAINS:
            return None

        # Layer 2: Dynamic SLD / Multi-Tenant Subdomain Decomposition
        dynamic_name, category = clean_domain_to_app_name(normalized)
        if dynamic_name and dynamic_name not in UNCLASSIFIED_SENTINELS and dynamic_name != "Unknown":
            with self._lock:
                existing = self._domain_app_cache.get(normalized)
                if not existing or not existing.get("is_override"):
                    self._domain_app_cache[normalized] = {
                        "name": dynamic_name,
                        "category": category,
                        "source": "sld_heuristics",
                        "is_override": False,
                        "confidence": 0.85,
                    }
            self._async_persist_discovery(
                organization_id,
                normalized,
                dynamic_name,
                category=category,
                source_layer="sld_heuristics",
                confidence=0.85,
            )
            return dynamic_name

        return "Other"

    def classify_by_asn(self, ip_value: str | None) -> Optional[str]:
        return asn_lookup_service.classify_ip(ip_value)

    def classify_by_tls_fingerprint(self, fingerprint: str | None) -> Optional[dict]:
        return lookup_ja4_signature(fingerprint)

    def classify_app(self, row: Any, organization_id: str = "default-org-id") -> str:
        """
        Classification hierarchy:
        1. Malicious JA4
        2. Local Process Name (Layer 3 - desktop non-browser apps)
        3. Domain / SNI with Admin Overrides & Seed Rules (Layer 0 & Layer 1 Seed)
        4. Web Page Title / Open Graph (Layer 1 Dynamic)
        5. Dynamic SLD & Multi-Tenant Subdomain Heuristics (Layer 2)
        6. TLS Cert Organization (Layer 4 - with CDN denylist)
        7. Standard JA4
        8. ASN Fallback
        9. Transport hint / Unknown
        """
        # 1. Malicious JA4
        fingerprint = (
            self._row_value(row, "ja4")
            or self._row_value(row, "ja4_fingerprint")
            or self._row_value(row, "tls_fingerprint")
        )
        fp_info = self.classify_by_tls_fingerprint(fingerprint)
        if fp_info and fp_info.get("is_malicious"):
            return fp_info["application_name"]

        # 2. Local Process Name (Layer 3)
        process_name = self._row_value(row, "process_name")
        if process_name:
            proc_app, _ = clean_process_to_app_name(process_name)
            if proc_app and proc_app not in {"Unknown", "Google Chrome", "Mozilla Firefox", "Microsoft Edge"}:
                return proc_app

        # 3. Domain / SNI (Admin Overrides & Seed Rules & Curated Intel)
        host = self._preferred_host(row)
        if host:
            domain_app = self.classify_by_domain(host, organization_id=organization_id)
            if domain_app and domain_app != "Other":
                return domain_app

        # 4. Web Page Title (Layer 1 Dynamic)
        page_title = self._row_value(row, "page_title") or self._row_value(row, "title")
        if page_title:
            title_app = clean_title_to_app_name(page_title)
            if title_app and title_app not in UNCLASSIFIED_SENTINELS and len(title_app) >= 2:
                if host:
                    self._async_persist_discovery(
                        organization_id,
                        host,
                        title_app,
                        category=infer_app_category(title_app, host),
                        source_layer="dpi_title",
                        confidence=0.9,
                    )
                return title_app

        # 5. Dynamic SLD / Multi-Tenant (handled in classify_by_domain fallback)

        # 6. TLS Cert Organization (Layer 4)
        cert_org = self._row_value(row, "cert_org") or self._row_value(row, "issuer_org")
        if cert_org:
            clean_org = clean_cert_org_to_app_name(cert_org)
            if clean_org:
                return clean_org

        # 7. Standard JA4
        if fp_info:
            return fp_info["application_name"]

        # 8. ASN Fallback
        transport_app = self._transport_label(row)
        asn_app = self.classify_by_asn(self._preferred_external_ip(row))

        if host:
            if asn_app:
                return asn_app
            if transport_app:
                return transport_app
            return "Other"

        if transport_app in CONTROL_TRANSPORT_LABELS:
            return transport_app

        if asn_app:
            return asn_app

        if transport_app:
            return transport_app

        return "Unknown"


    def resolve_application_label(self, row: Any, organization_id: str = "default-org-id") -> str:
        stored_application = str(self._row_value(row, "application") or "").strip()
        if (
            stored_application
            and stored_application not in UNCLASSIFIED_SENTINELS
            and not self.is_generic_transport_application(stored_application)
        ):
            return stored_application

        classified = self.classify_app(row, organization_id=organization_id)
        if classified in UNCLASSIFIED_SENTINELS:
            return stored_application or "Unknown"
        return classified


    def _is_trackable_device_ip(self, value: str | None) -> bool:
        return is_rfc1918_device_ip(value)

    def _is_noise_flow(self, row: dict) -> bool:
        try:
            src_port = int(row.get("src_port") or 0)
        except (ValueError, TypeError):
            src_port = 0
            
        try:
            dst_port = int(row.get("dst_port") or 0)
        except (ValueError, TypeError):
            dst_port = 0
        if src_port in CONTROL_PORTS or dst_port in CONTROL_PORTS:
            return True

        host = self._preferred_host(row)
        if not host:
            if row.get("network_scope") == "internal_lan":
                return True
            if not row.get("external_endpoint_ip"):
                return True
            return False

        return host.endswith(".in-addr.arpa") or host.endswith(".ip6.arpa") or host.endswith(".local")

    def _select_device_ip(self, row: dict) -> Optional[str]:
        internal_device_ip = normalize_ip(row.get("internal_device_ip"))
        if self._is_trackable_device_ip(internal_device_ip):
            return internal_device_ip

        src_ip = row.get("src_ip")
        dst_ip = row.get("dst_ip")
        src_trackable = self._is_trackable_device_ip(src_ip)
        dst_trackable = self._is_trackable_device_ip(dst_ip)

        if src_trackable and not dst_trackable:
            return src_ip
        if dst_trackable and not src_trackable:
            return dst_ip
        if src_trackable and dst_trackable:
            return src_ip
        return None

    def _session_domain_key(self, row: dict) -> str:
        host = self._preferred_host(row)
        if not host:
            return "-"
        return self.get_base_domain(host) or host

    def _fetch_recent_sessions(
        self,
        db_conn,
        organization_id: Optional[str],
        window_minutes: int,
    ) -> list[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [window_minutes]
            query = """
                SELECT
                    s.device_ip,
                    s.external_ip,
                    s.application,
                    s.domain,
                    s.protocol,
                    s.total_packets,
                    s.total_bytes,
                    s.first_seen,
                    s.last_seen,
                    0 AS src_port,
                    0 AS dst_port
                FROM sessions s
                WHERE s.last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
            """
            if organization_id:
                query += " AND s.organization_id = %s"
                params.append(organization_id)
            query += " ORDER BY s.last_seen DESC LIMIT 5000"
            cursor.execute(query, tuple(params))
            return cursor.fetchall() or []
        finally:
            cursor.close()

    def _fetch_recent_web_events(
        self,
        db_conn,
        organization_id: Optional[str],
        window_minutes: int,
    ) -> list[dict]:
        if db_conn is None:
            return []
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [window_minutes]
            query = """
                SELECT
                    device_ip,
                    process_name,
                    browser_name,
                    base_domain,
                    page_title,
                    content_category,
                    COALESCE(request_bytes, 0) AS request_bytes,
                    COALESCE(response_bytes, 0) AS response_bytes,
                    COALESCE(event_count, 1) AS event_count,
                    first_seen,
                    last_seen
                FROM web_events
                WHERE last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += " ORDER BY last_seen DESC LIMIT 5000"
            cursor.execute(query, tuple(params))
            return cursor.fetchall() or []
        finally:
            cursor.close()

    def _fetch_unassigned_flow_logs(
        self,
        db_conn,
        organization_id: Optional[str],
        window_minutes: int,
    ) -> list[dict]:
        if db_conn is None:
            return []
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = [window_minutes]
            query = """
                SELECT
                    src_ip,
                    dst_ip,
                    internal_device_ip,
                    external_endpoint_ip,
                    domain,
                    sni,
                    application,
                    protocol,
                    src_port,
                    dst_port,
                    COALESCE(byte_count, 0) AS byte_count,
                    start_time,
                    last_seen
                FROM flow_logs
                WHERE (session_id IS NULL OR session_id = '')
                  AND last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += " ORDER BY last_seen DESC LIMIT 3000"
            cursor.execute(query, tuple(params))
            return cursor.fetchall() or []
        finally:
            cursor.close()


    def _is_meaningful_session(self, row: dict) -> bool:
        device_ip = normalize_ip(row.get("device_ip"))
        if not self._is_trackable_device_ip(device_ip):
            return False

        host = self._preferred_host(row)
        external_ip = normalize_ip(row.get("external_ip"))
        protocol = str(row.get("protocol") or "").upper()
        transport_app = self._transport_label(row)

        if host and (host.endswith(".in-addr.arpa") or host.endswith(".ip6.arpa") or host.endswith(".local")):
            return False

        if not external_ip:
            if not host and not transport_app:
                return False
            if protocol == "UDP" and not transport_app:
                return False
            if (row.get("application") or "Unknown") in {"Unknown", "Other"} and not transport_app and not host:
                return False

        return True

    def _resolve_session_application(self, row: dict, organization_id: str = "default-org-id") -> str:
        return self.resolve_application_label(
            {
                "src_ip": row.get("device_ip"),
                "dst_ip": row.get("external_ip"),
                "domain": row.get("domain"),
                "sni": None,
                "protocol": row.get("protocol"),
                "src_port": row.get("src_port"),
                "dst_port": row.get("dst_port"),
                "external_endpoint_ip": row.get("external_ip"),
                "application": row.get("application"),
            },
            organization_id=organization_id,
        )

    def _matches_application_name(self, app_name: str, row: dict) -> bool:
        normalized = str(app_name or "").strip().lower()
        if not normalized:
            return False

        base_domain = str(row.get("base_domain") or row.get("domain") or "").strip()
        service_name, _ = get_service_info(base_domain)
        candidates = {
            str(service_name or "").strip().lower(),
            str(self.classify_by_domain(base_domain) or "").strip().lower(),
            str(row.get("content_category") or "").strip().lower(),
            str(row.get("page_title") or "").strip().lower(),
            str(row.get("content_id") or "").strip().lower(),
            str(row.get("search_query") or "").strip().lower(),
            str(row.get("application") or "").strip().lower(),
        }
        return normalized in candidates or any(normalized in c for c in candidates if c)

    def _build_sessions(self, db_conn, organization_id: Optional[str], window_minutes: int) -> list[dict]:
        rows = self._fetch_recent_sessions(db_conn, organization_id, window_minutes)
        sessions: list[dict] = []
        org_id = organization_id or "default-org-id"

        for row in rows:
            if not self._is_meaningful_session(row):
                continue

            host = self._preferred_host(row)
            sessions.append(
                {
                    "device_ip": normalize_ip(row.get("device_ip")),
                    "application": self._resolve_session_application(row, organization_id=org_id),
                    "domain": self.get_base_domain(host) if host else "-",
                    "src_port": int(row.get("src_port") or 0),
                    "dst_port": int(row.get("dst_port") or 0),
                    "bandwidth_bytes": int(row.get("total_bytes") or 0),
                    "first_seen": row.get("first_seen") or row.get("last_seen"),
                    "last_seen": row.get("last_seen"),
                }
            )

        return sessions

    def _column_exists(self, cursor, table_name: str, column_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s AND column_name = %s
            LIMIT 1
            """,
            (settings.DB_NAME, table_name, column_name),
        )
        return cursor.fetchone() is not None

    def _index_exists(self, cursor, table_name: str, index_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.statistics
            WHERE table_schema = %s AND table_name = %s AND index_name = %s
            LIMIT 1
            """,
            (settings.DB_NAME, table_name, index_name),
        )
        return cursor.fetchone() is not None

    def ensure_schema(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def _format_bytes(self, byte_count: float) -> str:
        if byte_count >= 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        if byte_count >= 1024:
            return f"{byte_count / 1024:.1f} KB"
        return f"{int(byte_count)} B"

    def _format_timestamp(self, value) -> str:
        if value and hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value or "")

    def _coerce_utc_datetime(self, value):
        if not value:
            return None
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                return None
        if getattr(value, "tzinfo", None) is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _runtime_seconds(self, first_seen, last_seen) -> int:
        first_seen = self._coerce_utc_datetime(first_seen)
        last_seen = self._coerce_utc_datetime(last_seen)
        if not last_seen or not first_seen:
            return 0
        try:
            delta = last_seen - first_seen
            return max(int(delta.total_seconds()), 0)
        except Exception:
            return 0

    def _format_runtime(self, seconds: int) -> str:
        seconds = max(int(seconds or 0), 0)
        hours, remainder = divmod(seconds, 3600)
        minutes, remaining_seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m"
        if minutes:
            return f"{minutes}m {remaining_seconds}s"
        return f"{remaining_seconds}s"

    def get_application_summary(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        window_minutes: int = DEFAULT_APPLICATION_WINDOW_MINUTES,
        active_window_seconds: int = DEFAULT_ACTIVE_APPLICATION_WINDOW_SECONDS,
        force_refresh: bool = False,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        self._load_overrides_if_needed(db_conn, organization_id)
        org_id = organization_id or "default-org-id"
        cache_key = (org_id, window_minutes, active_window_seconds)
        now_ts = time.time()

        if not force_refresh:
            with self._lock:
                cached_entry = self._summary_cache.get(cache_key)
                if cached_entry and (now_ts - cached_entry[0]) < self._summary_cache_ttl:
                    return [dict(item) for item in cached_entry[1]]

        active_cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_window_seconds)

        # Fast path: Query pre-aggregated application_summary table
        if db_conn is not None:
            cursor = db_conn.cursor(dictionary=True)
            try:
                params = []
                org_filter = ""
                if organization_id:
                    org_filter = "WHERE organization_id = %s"
                    params.append(organization_id)

                cursor.execute(
                    f"""
                    SELECT
                        application_name AS application,
                        category,
                        flow_count,
                        total_bytes AS bandwidth_bytes,
                        last_seen
                    FROM application_summary
                    {org_filter}
                    ORDER BY flow_count DESC
                    LIMIT 100
                    """,
                    tuple(params)
                )
                rows = cursor.fetchall() or []
                if rows:
                    res = []
                    for r in rows:
                        last_dt = self._coerce_utc_datetime(r.get("last_seen"))
                        is_active = bool(last_dt and last_dt >= active_cutoff)
                        b_bytes = float(r.get("bandwidth_bytes") or 0)
                        res.append({
                            "application": r["application"],
                            "device_count": 1,
                            "device_ips": [],
                            "active_devices": 1 if is_active else 0,
                            "is_active": is_active,
                            "bandwidth_bytes": b_bytes,
                            "bandwidth_formatted": self._format_bytes(b_bytes),
                            "session_count": int(r.get("flow_count") or 0),
                            "flow_count": int(r.get("flow_count") or 0),
                            "first_seen": self._format_timestamp(last_dt),
                            "last_seen": self._format_timestamp(last_dt),
                            "runtime_seconds": 60,
                            "runtime_formatted": "Active",
                            "category": r.get("category") or "web",
                        })
                    with self._lock:
                        self._summary_cache[cache_key] = (now_ts, res)
                    return res
            except Exception as exc:
                logger.debug("application_summary fast query fallback: %s", exc)
            finally:
                cursor.close()

        grouped: dict[str, dict] = {}

        # 1. Process L4 Sessions
        for session in self._build_sessions(db_conn, organization_id, window_minutes):
            application = session["application"]
            first_seen = self._coerce_utc_datetime(session.get("first_seen"))
            last_seen = self._coerce_utc_datetime(session.get("last_seen"))
            is_active = bool(last_seen and last_seen >= active_cutoff)
            entry = grouped.get(application)
            if entry is None:
                grouped[application] = {
                    "application": application,
                    "device_ips": {session["device_ip"]},
                    "active_device_ips": {session["device_ip"]} if is_active else set(),
                    "bandwidth_bytes": session["bandwidth_bytes"],
                    "runtime_seconds": self._runtime_seconds(first_seen, last_seen),
                    "last_seen": last_seen,
                }
            else:
                entry["device_ips"].add(session["device_ip"])
                if is_active:
                    entry["active_device_ips"].add(session["device_ip"])
                entry["bandwidth_bytes"] += session["bandwidth_bytes"]
                entry["runtime_seconds"] += self._runtime_seconds(first_seen, last_seen)
                if last_seen and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
                    entry["last_seen"] = last_seen

        # 2. Process DPI Web Events (Claude, ChatGPT, Gemini, Google Play, etc.)
        for event in self._fetch_recent_web_events(db_conn, organization_id, window_minutes):
            app = self.classify_app(
                {
                    "base_domain": event.get("base_domain"),
                    "page_title": event.get("page_title"),
                    "process_name": event.get("process_name"),
                },
                organization_id=org_id,
            )
            device_ip = normalize_ip(event.get("device_ip"))
            if not self._is_trackable_device_ip(device_ip):
                continue

            first_seen = self._coerce_utc_datetime(event.get("first_seen"))
            last_seen = self._coerce_utc_datetime(event.get("last_seen"))
            is_active = bool(last_seen and last_seen >= active_cutoff)
            bytes_total = int(event.get("request_bytes", 0) + event.get("response_bytes", 0))
            if bytes_total == 0:
                bytes_total = max(int(event.get("event_count", 1)) * 1024, 1024)

            entry = grouped.get(app)
            if entry is None:
                grouped[app] = {
                    "application": app,
                    "device_ips": {device_ip},
                    "active_device_ips": {device_ip} if is_active else set(),
                    "bandwidth_bytes": bytes_total,
                    "runtime_seconds": self._runtime_seconds(first_seen, last_seen),
                    "last_seen": last_seen,
                }
            else:
                entry["device_ips"].add(device_ip)
                if is_active:
                    entry["active_device_ips"].add(device_ip)
                entry["bandwidth_bytes"] += bytes_total
                entry["runtime_seconds"] += self._runtime_seconds(first_seen, last_seen)
                if last_seen and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
                    entry["last_seen"] = last_seen

        # 3. Process Unassigned Flow Logs (e.g. Sentry, Microsoft, App Insights)
        for flow in self._fetch_unassigned_flow_logs(db_conn, organization_id, window_minutes):
            app = self.resolve_application_label(flow, organization_id=org_id)
            device_ip = self._select_device_ip(flow)
            if not self._is_trackable_device_ip(device_ip):
                continue

            first_seen = self._coerce_utc_datetime(flow.get("start_time") or flow.get("last_seen"))
            last_seen = self._coerce_utc_datetime(flow.get("last_seen"))
            is_active = bool(last_seen and last_seen >= active_cutoff)
            byte_count = int(flow.get("byte_count") or 0)

            entry = grouped.get(app)
            if entry is None:
                grouped[app] = {
                    "application": app,
                    "device_ips": {device_ip},
                    "active_device_ips": {device_ip} if is_active else set(),
                    "bandwidth_bytes": byte_count,
                    "runtime_seconds": self._runtime_seconds(first_seen, last_seen),
                    "last_seen": last_seen,
                }
            else:
                entry["device_ips"].add(device_ip)
                if is_active:
                    entry["active_device_ips"].add(device_ip)
                entry["bandwidth_bytes"] += byte_count
                entry["runtime_seconds"] += self._runtime_seconds(first_seen, last_seen)
                if last_seen and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
                    entry["last_seen"] = last_seen

        results = []
        for entry in grouped.values():
            results.append(
                {
                    "application": entry["application"],
                    "device_count": len(entry["device_ips"]),
                    "active_device_count": len(entry["active_device_ips"]),
                    "bandwidth_bytes": int(entry["bandwidth_bytes"] or 0),
                    "bandwidth": self._format_bytes(float(entry["bandwidth_bytes"] or 0)),
                    "runtime_seconds": int(entry["runtime_seconds"] or 0),
                    "runtime": self._format_runtime(int(entry["runtime_seconds"] or 0)),
                    "last_seen": self._format_timestamp(entry["last_seen"]),
                }
            )

        results.sort(
            key=lambda item: (
                1
                if item["application"] in UNCLASSIFIED_SENTINELS
                or self.is_generic_transport_application(item["application"])
                else 0,
                -item["active_device_count"],
                -item["device_count"],
                -item["bandwidth_bytes"],
                item["application"],
            )
        )
        with self._lock:
            self._summary_cache[cache_key] = (now_ts, results)
        return results

    def get_application_devices(
        self,
        db_conn,
        app_name: str,
        organization_id: Optional[str] = None,
        window_minutes: int = DEFAULT_APPLICATION_WINDOW_MINUTES,
        active_window_seconds: int = DEFAULT_ACTIVE_APPLICATION_WINDOW_SECONDS,
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        self._load_overrides_if_needed(db_conn, organization_id)
        org_id = organization_id or "default-org-id"
        active_cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_window_seconds)
        device_lookup = {
            device.get("ip"): device
            for device in device_service.get_devices(db_conn, organization_id=organization_id)
        }

        grouped: dict[str, dict] = {}

        # 1. Search Sessions
        sessions = [
            session
            for session in self._build_sessions(db_conn, organization_id, window_minutes)
            if session["application"] == app_name
        ]
        for session in sessions:
            device_ip = session.get("device_ip")
            if not device_ip:
                continue

            device = device_lookup.get(device_ip, {})
            first_seen = self._coerce_utc_datetime(session.get("first_seen"))
            last_seen = self._coerce_utc_datetime(session.get("last_seen"))
            is_active = bool(last_seen and last_seen >= active_cutoff)
            entry = grouped.get(device_ip)

            if entry is None:
                grouped[device_ip] = {
                    "device_ip": device_ip,
                    "hostname": device.get("hostname") or "Unknown",
                    "status": "Active" if is_active else "Idle",
                    "bandwidth_bytes": int(session.get("bandwidth_bytes") or 0),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "session_count": 1,
                    "active_session_count": 1 if is_active else 0,
                    "management_mode": device.get("management_mode") or "byod",
                }
            else:
                entry["bandwidth_bytes"] += int(session.get("bandwidth_bytes") or 0)
                entry["session_count"] += 1
                if is_active:
                    entry["active_session_count"] += 1
                if first_seen and (entry["first_seen"] is None or first_seen < entry["first_seen"]):
                    entry["first_seen"] = first_seen
                if last_seen and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
                    entry["last_seen"] = last_seen
                entry["status"] = "Active" if entry["active_session_count"] > 0 else "Idle"

        # 2. Search Web Events
        web_events = self._fetch_recent_web_events(db_conn, organization_id, window_minutes)
        for event in web_events:
            classified_app = self.classify_app(
                {
                    "base_domain": event.get("base_domain"),
                    "page_title": event.get("page_title"),
                    "process_name": event.get("process_name"),
                },
                organization_id=org_id,
            )
            if classified_app != app_name:
                continue

            device_ip = normalize_ip(event.get("device_ip"))
            if not device_ip:
                continue

            device = device_lookup.get(device_ip, {})
            first_seen = self._coerce_utc_datetime(event.get("first_seen"))
            last_seen = self._coerce_utc_datetime(event.get("last_seen"))
            is_active = bool(last_seen and last_seen >= active_cutoff)
            bytes_total = int(event.get("request_bytes", 0) + event.get("response_bytes", 0))
            if bytes_total == 0:
                bytes_total = max(int(event.get("event_count", 1)) * 1024, 1024)

            entry = grouped.get(device_ip)
            if entry is None:
                grouped[device_ip] = {
                    "device_ip": device_ip,
                    "hostname": device.get("hostname") or "Unknown",
                    "status": "Active" if is_active else "Idle",
                    "bandwidth_bytes": bytes_total,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "session_count": 1,
                    "active_session_count": 1 if is_active else 0,
                    "management_mode": device.get("management_mode") or "byod",
                }
            else:
                entry["bandwidth_bytes"] += bytes_total
                entry["session_count"] += 1
                if is_active:
                    entry["active_session_count"] += 1
                if first_seen and (entry["first_seen"] is None or first_seen < entry["first_seen"]):
                    entry["first_seen"] = first_seen
                if last_seen and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
                    entry["last_seen"] = last_seen
                entry["status"] = "Active" if entry["active_session_count"] > 0 else "Idle"

        results = []
        for entry in grouped.values():
            first_seen = entry.get("first_seen")
            last_seen = entry.get("last_seen") or first_seen
            runtime_seconds = self._runtime_seconds(first_seen, last_seen)
            results.append(
                {
                    "device_ip": entry["device_ip"],
                    "hostname": entry["hostname"],
                    "status": entry["status"],
                    "bandwidth_bytes": int(entry["bandwidth_bytes"] or 0),
                    "bandwidth": self._format_bytes(float(entry["bandwidth_bytes"] or 0)),
                    "runtime_seconds": runtime_seconds,
                    "runtime": self._format_runtime(runtime_seconds),
                    "last_seen": self._format_timestamp(last_seen),
                    "management_mode": entry["management_mode"],
                    "session_count": int(entry.get("session_count") or 0),
                    "active_session_count": int(entry.get("active_session_count") or 0),
                }
            )

        results.sort(
            key=lambda item: (
                0 if item["status"] == "Active" else 1,
                -item["bandwidth_bytes"],
                item["device_ip"],
            )
        )
        return results

    def get_application_workspace(
        self,
        db_conn,
        app_name: str,
        organization_id: Optional[str] = None,
        window_minutes: int = DEFAULT_APPLICATION_WINDOW_MINUTES,
    ) -> dict:
        self.ensure_schema(db_conn)
        decoded_name = str(app_name or "").strip()
        devices = self.get_application_devices(
            db_conn,
            app_name=decoded_name,
            organization_id=organization_id,
            window_minutes=window_minutes,
        )

        raw_events = web_inspection_service.get_global_activity(
            db_conn,
            organization_id=organization_id,
            limit=min(max(window_minutes // 2, 100), 500),
        )
        filtered_events = [row for row in raw_events if self._matches_application_name(decoded_name, row)]

        grouped_events = web_inspection_service.get_global_evidence_groups(
            db_conn,
            organization_id=organization_id,
            limit=min(max(window_minutes // 4, 50), 200),
        )
        grouped_events = [row for row in grouped_events if self._matches_application_name(decoded_name, row)]

        total_bandwidth_bytes = sum(int(row.get("bandwidth_bytes") or 0) for row in devices)
        active_device_count = sum(1 for row in devices if row.get("status") == "Active")
        last_seen_candidates = [row.get("last_seen") for row in devices if row.get("last_seen")]
        last_seen_candidates += [row.get("last_seen") for row in grouped_events if row.get("last_seen")]
        last_seen = max(last_seen_candidates) if last_seen_candidates else None

        return {
            "application": decoded_name,
            "devices": devices,
            "web_activity": filtered_events,
            "web_evidence_groups": grouped_events,
            "summary": {
                "device_count": len(devices),
                "active_device_count": active_device_count,
                "bandwidth_bytes": total_bandwidth_bytes,
                "last_seen": last_seen,
                "event_count": len(filtered_events),
                "group_count": len(grouped_events),
            },
        }

    # =========================================================
    # ADMIN OVERRIDE MANAGEMENT (LAYER 0)
    # =========================================================

    def get_admin_overrides(self, db_conn, organization_id: Optional[str] = None) -> list[dict]:
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            params = []
            query = """
                SELECT id, domain, application_name, category, source_layer, confidence, is_override, updated_at
                FROM discovered_applications
                WHERE is_override = 1
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += " ORDER BY domain ASC"
            cursor.execute(query, tuple(params))
            return cursor.fetchall() or []
        finally:
            cursor.close()

    def set_admin_override(
        self,
        db_conn,
        domain: str,
        app_name: str,
        category: str = "web",
        organization_id: Optional[str] = None,
    ) -> dict:
        self.ensure_schema(db_conn)
        org_id = organization_id or "default-org-id"
        normalized_domain = self._normalize_domain(domain)
        if not normalized_domain:
            raise ValueError(f"Invalid domain: '{domain}'")
        clean_name = str(app_name).strip()
        if not clean_name:
            raise ValueError("Application name cannot be empty.")

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO discovered_applications
                    (organization_id, domain, application_name, category, source_layer, confidence, is_override)
                VALUES
                    (%s, %s, %s, %s, 'override', 1.0, 1)
                ON DUPLICATE KEY UPDATE
                    application_name = VALUES(application_name),
                    category = VALUES(category),
                    source_layer = 'override',
                    confidence = 1.0,
                    is_override = 1,
                    updated_at = NOW()
                """,
                (org_id, normalized_domain, clean_name, category),
            )
            db_conn.commit()

            with self._lock:
                self._domain_app_cache[normalized_domain] = {
                    "name": clean_name,
                    "category": category,
                    "source": "override",
                    "is_override": True,
                    "confidence": 1.0,
                }
                self._summary_cache.clear()

            return {
                "organization_id": org_id,
                "domain": normalized_domain,
                "application_name": clean_name,
                "category": category,
                "is_override": True,
            }
        finally:
            cursor.close()

    def delete_admin_override(self, db_conn, domain: str, organization_id: Optional[str] = None) -> bool:
        self.ensure_schema(db_conn)
        org_id = organization_id or "default-org-id"
        normalized_domain = self._normalize_domain(domain)
        if not normalized_domain:
            return False

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                DELETE FROM discovered_applications
                WHERE organization_id = %s AND domain = %s AND is_override = 1
                """,
                (org_id, normalized_domain),
            )
            db_conn.commit()
            deleted = cursor.rowcount > 0

            with self._lock:
                if normalized_domain in self._domain_app_cache:
                    del self._domain_app_cache[normalized_domain]
                self._summary_cache.clear()

            return deleted
        finally:
            cursor.close()


    def get_top_other_domains(
        self,
        db_conn,
        organization_id: Optional[str] = None,
        limit: int = 20,
    ) -> list[dict]:
        """
        Optional analytics helper for investigating uncategorized but known domains.
        """
        self.ensure_schema(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            query = """
                SELECT
                    COALESCE(NULLIF(sni, ''), NULLIF(domain, '')) AS host,
                    COUNT(*) AS flow_count,
                    COALESCE(SUM(byte_count), 0) AS bandwidth_bytes,
                    MAX(last_seen) AS last_seen
                FROM flow_logs
                WHERE application = 'Other'
                  AND COALESCE(NULLIF(sni, ''), NULLIF(domain, '')) IS NOT NULL
            """
            if organization_id:
                query += " AND organization_id = %s"
                params.append(organization_id)
            query += """
                GROUP BY host
                ORDER BY flow_count DESC, bandwidth_bytes DESC
                LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = []
            for row in cursor.fetchall():
                rows.append(
                    {
                        "host": row.get("host"),
                        "base_domain": self.get_base_domain(row.get("host")) or row.get("host"),
                        "flow_count": int(row.get("flow_count") or 0),
                        "bandwidth_bytes": int(row.get("bandwidth_bytes") or 0),
                        "last_seen": self._format_timestamp(row.get("last_seen")),
                    }
                )
            return rows
        finally:
            cursor.close()


application_service = ApplicationService()


def application_compatibility_wrapper(row: Any) -> "EngineResult":
    from engine import EngineResult, Finding, Severity
    raw_org_id = application_service._row_value(row, "organization_id")
    if not raw_org_id:
        logger.warning(
            "application_compatibility_wrapper called on row without 'organization_id' (host: %s); fallback to '%s'.",
            application_service._preferred_host(row),
            settings.DEFAULT_ORGANIZATION_ID,
        )
        org_id = settings.DEFAULT_ORGANIZATION_ID
    else:
        org_id = str(raw_org_id).strip()
    app_label = application_service.classify_app(row, organization_id=org_id)
    
    findings = []
    if app_label and app_label not in {"Unknown", "Other"}:
        host = application_service._preferred_host(row)
        
        # JA4 fingerprint lookup
        fingerprint = (
            application_service._row_value(row, "ja4")
            or application_service._row_value(row, "ja4_fingerprint")
            or application_service._row_value(row, "tls_fingerprint")
        )
        fp_info = application_service.classify_by_tls_fingerprint(fingerprint)
        
        # ASN details lookup
        external_ip = application_service._preferred_external_ip(row)
        asn_details = asn_lookup_service.lookup_asn_details(external_ip)
        asn_val = asn_details.get("asn") if asn_details else None
        asn_org_val = asn_details.get("organization") if asn_details else None
        
        # Default properties
        finding_type = "application_detected"
        severity = Severity.INFO
        mitre_attack_id = None
        
        if fp_info:
            if fp_info.get("is_malicious"):
                finding_type = "malicious_application_detected"
                severity = Severity.CRITICAL
                mitre_attack_id = fp_info.get("mitre_id")
                evidence = [f"Malicious application detected: {app_label} via TLS/JA4 fingerprinting"]
            elif fp_info.get("is_suspicious"):
                finding_type = "suspicious_application_detected"
                severity = Severity.HIGH
                mitre_attack_id = fp_info.get("mitre_id")
                evidence = [f"Suspicious application detected: {app_label} via TLS/JA4 fingerprinting"]
            else:
                evidence = [f"Classified application: {app_label} via TLS/JA4 fingerprinting"]
        else:
            evidence = [f"Classified application: {app_label}"]
            
        findings.append(
            Finding(
                engine="application",
                finding_type=finding_type,
                severity=severity,
                confidence=1.0 if host or fp_info else 0.8,
                evidence=evidence,
                target_ip=str(external_ip or "0.0.0.0"),
                mitre_attack_id=mitre_attack_id,
                details={
                    "application_name": app_label,
                    "asn": asn_val,
                    "asn_org": asn_org_val,
                    "ja4_fingerprint": fingerprint
                }
            )
        )
    return EngineResult(findings=findings, metadata={"application": app_label})

