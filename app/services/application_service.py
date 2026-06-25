from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import logging
import threading

from ..core.config import settings
from ..db.session import require_runtime_schema
from ..utils.asn_lookup import asn_lookup_service
from ..engines.application.ja4_signatures import lookup_ja4_signature
from ..utils.domain_intelligence import get_service_info
from ..utils.domain_utils import get_base_domain, normalize_host
from ..utils.network import is_rfc1918_device_ip, normalize_ip
from .device_service import device_service
from .web_inspection_service import web_inspection_service

logger = logging.getLogger("netvisor.apps")

DEFAULT_APPLICATION_WINDOW_MINUTES = 24 * 60
DEFAULT_ACTIVE_APPLICATION_WINDOW_SECONDS = 5 * 60

# Specific applications must be checked before generic umbrella providers.
APP_RULES: dict[str, list[str]] = {
    "YouTube": ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
    "Instagram": ["instagram.com"],
    "Facebook": ["facebook.com", "fbcdn.net", "messenger.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net"],
    "Telegram": ["telegram.org", "t.me", "telegram.me"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com"],
    "ChatGPT": ["openai.com", "chatgpt.com"],
    "Claude": ["anthropic.com", "claude.ai"],
    "GitHub": ["github.com", "githubassets.com", "githubusercontent.com"],
    "Perplexity": ["perplexity.ai", "perplexity.com"],
    "Zoom": ["zoom.us"],
    "Google Meet": ["meet.google.com"],
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
    ],
    "Google Play": ["play.google.com"],
    "Google": ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.co.in"],
}

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
        return self._normalize_domain(self._row_value(row, "sni") or self._row_value(row, "domain"))

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

    def resolve_application_label(self, row: Any) -> str:
        """
        Preserve a stored product label when we have one, but promote generic
        transport buckets like HTTPS/DNS/QUIC whenever the row carries better
        host or ASN context.
        """
        stored_application = str(self._row_value(row, "application") or "").strip()
        if stored_application and stored_application not in UNCLASSIFIED_SENTINELS and not self.is_generic_transport_application(stored_application):
            return stored_application

        classified = self.classify_app(row)
        if classified in UNCLASSIFIED_SENTINELS:
            return stored_application or "Unknown"
        return classified

    def classify_by_domain(self, domain: object) -> Optional[str]:
        """
        Classify using SNI/domain data.
        Returns a concrete app name when matched, "Other" for known-but-uncategorized
        hosts, and None when the host is missing/invalid or generic infrastructure
        should defer to ASN resolution.
        """
        normalized = self._normalize_domain(domain)
        if not normalized:
            return None

        base_domain = self.get_base_domain(normalized)
        if not base_domain:
            return None

        for application, allowed_domains in APP_RULES.items():
            for allowed_domain in allowed_domains:
                if (
                    base_domain == allowed_domain
                    or normalized == allowed_domain
                    or normalized.endswith(f".{allowed_domain}")
                ):
                    return application

        service_label = self._service_label_from_host(normalized)
        if service_label:
            return service_label

        if base_domain in SHARED_INFRA_BASE_DOMAINS:
            return None

        return "Other"

    def classify_by_asn(self, ip_value: str | None) -> Optional[str]:
        return asn_lookup_service.classify_ip(ip_value)

    def classify_by_tls_fingerprint(self, fingerprint: str | None) -> Optional[dict]:
        return lookup_ja4_signature(fingerprint)

    def classify_app(self, row: Any) -> str:
        """
        Classification priority:
        1. Malicious JA4
        2. Domain/SNI
        3. Standard/Suspicious JA4
        4. ASN Fallback
        5. Transport/protocol hints
        6. Unknown/Other separation
        """
        # Retrieve JA4/TLS client fingerprint if present
        fingerprint = (
            self._row_value(row, "ja4")
            or self._row_value(row, "ja4_fingerprint")
            or self._row_value(row, "tls_fingerprint")
        )
        fp_info = self.classify_by_tls_fingerprint(fingerprint)
        
        # 1. Malicious JA4
        if fp_info and fp_info.get("is_malicious"):
            return fp_info["application_name"]
            
        # 2. Domain / SNI
        host = self._preferred_host(row)
        if host:
            domain_app = self.classify_by_domain(host)
            if domain_app and domain_app != "Other":
                return domain_app
                
        # 3. Standard / Suspicious JA4
        if fp_info:
            return fp_info["application_name"]
            
        # 4. ASN Fallback
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
            
        debug_key = (
            str(self._row_value(row, "dst_ip") or self._row_value(row, "src_ip") or ""),
            self._row_value(row, "network_scope"),
        )
        with self._lock:
            in_cache = debug_key in self._unknown_debug_cache
            cache_len = len(self._unknown_debug_cache)
            if not in_cache and cache_len < 512:
                self._unknown_debug_cache.add(debug_key)
                should_log = True
            else:
                should_log = False

        if should_log:
            logger.debug(
                "Unknown traffic: src=%s dst=%s domain=%s sni=%s",
                self._row_value(row, "src_ip"),
                self._row_value(row, "dst_ip"),
                self._row_value(row, "domain"),
                self._row_value(row, "sni"),
            )
        return "Unknown"

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
                    COALESCE(flow_ports.src_port, 0) AS src_port,
                    COALESCE(flow_ports.dst_port, 0) AS dst_port
                FROM sessions s
                LEFT JOIN (
                    SELECT
                        session_id,
                        MAX(src_port) AS src_port,
                        MAX(dst_port) AS dst_port
                    FROM flow_logs
                    WHERE session_id IS NOT NULL AND session_id != ''
                    GROUP BY session_id
                ) AS flow_ports
                    ON flow_ports.session_id = s.session_id
                WHERE s.last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
            """
            if organization_id:
                query += " AND s.organization_id = %s"
                params.append(organization_id)
            query += " ORDER BY s.last_seen DESC"
            cursor.execute(query, tuple(params))
            return cursor.fetchall()
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

    def _resolve_session_application(self, row: dict) -> str:
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
            }
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
        }
        return normalized in candidates

    def _build_sessions(self, db_conn, organization_id: Optional[str], window_minutes: int) -> list[dict]:
        rows = self._fetch_recent_sessions(db_conn, organization_id, window_minutes)
        sessions: list[dict] = []

        for row in rows:
            if not self._is_meaningful_session(row):
                continue

            host = self._preferred_host(row)
            sessions.append(
                {
                    "device_ip": normalize_ip(row.get("device_ip")),
                    "application": self._resolve_session_application(row),
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

    def _backfill_applications(self, db_conn, batch_size: int = 1000) -> None:
        """
        Safe backfill:
        - does not overwrite specifically classified rows
        - updates missing/legacy Other/Unknown rows using the new classifier
        """
        select_cursor = db_conn.cursor(dictionary=True)
        update_cursor = db_conn.cursor()
        try:
            last_id = 0
            while True:
                select_cursor.execute(
                    """
                    SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, external_endpoint_ip, domain, sni, application
                    FROM flow_logs
                    WHERE id > %s
                      AND (application IS NULL OR application = '' OR application = 'Other' OR application = 'Unknown')
                    ORDER BY id
                    LIMIT %s
                    """,
                    (last_id, batch_size),
                )
                rows = select_cursor.fetchall()
                if not rows:
                    break

                updates = []
                for row in rows:
                    classified = self.classify_app(row)
                    if classified != (row.get("application") or ""):
                        updates.append((classified, row["id"]))

                if updates:
                    update_cursor.executemany(
                        "UPDATE flow_logs SET application = %s WHERE id = %s",
                        updates,
                    )
                    db_conn.commit()

                last_id = rows[-1]["id"]
        finally:
            select_cursor.close()
            update_cursor.close()

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
        if not last_seen and not first_seen:
            return 0
        if not first_seen:
            return 0
        if not last_seen:
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
    ) -> list[dict]:
        self.ensure_schema(db_conn)
        active_cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_window_seconds)
        grouped: dict[str, dict] = {}
        for session in self._build_sessions(db_conn, organization_id, window_minutes):
            application = session["application"]
            entry = grouped.get(application)
            first_seen = self._coerce_utc_datetime(session.get("first_seen"))
            last_seen = self._coerce_utc_datetime(session.get("last_seen"))
            is_active = bool(last_seen and last_seen >= active_cutoff)
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
                1 if item["application"] in UNCLASSIFIED_SENTINELS or self.is_generic_transport_application(item["application"]) else 0,
                -item["active_device_count"],
                -item["device_count"],
                -item["bandwidth_bytes"],
                item["application"],
            )
        )
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
        active_cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_window_seconds)
        device_lookup = {
            device.get("ip"): device
            for device in device_service.get_devices(db_conn, organization_id=organization_id)
        }
        sessions = [
            session
            for session in self._build_sessions(db_conn, organization_id, window_minutes)
            if session["application"] == app_name
        ]
        grouped: dict[str, dict] = {}

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
                continue

            entry["bandwidth_bytes"] += int(session.get("bandwidth_bytes") or 0)
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
    from shared.engine import EngineResult, Finding, Severity
    app_label = application_service.classify_app(row)
    
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

