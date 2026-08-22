from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    PROJECT_NAME: str = "NetVisor"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    CHAOS_ENABLED: bool = Field(default=False, validation_alias="NETVISOR_CHAOS_ENABLED")

    SECRET_KEY: str = Field(default="", validation_alias="NETVISOR_SECRET_KEY")
    JWT_ALGORITHM: str = Field(default="RS256", validation_alias="NETVISOR_JWT_ALGORITHM")
    JWT_PRIVATE_KEY: str = Field(default="", validation_alias="NETVISOR_JWT_PRIVATE_KEY")
    JWT_PUBLIC_KEY: str = Field(default="", validation_alias="NETVISOR_JWT_PUBLIC_KEY")
    JWT_PRIVATE_KEY_PATH: str = Field(default="", validation_alias="NETVISOR_JWT_PRIVATE_KEY_PATH")
    JWT_PUBLIC_KEY_PATH: str = Field(default="", validation_alias="NETVISOR_JWT_PUBLIC_KEY_PATH")
    ENVIRONMENT: str = Field(default="production", validation_alias="NETVISOR_ENVIRONMENT")
    TRUSTED_PROXIES: str = Field(default="127.0.0.1,::1", validation_alias="NETVISOR_TRUSTED_PROXIES")
    AGENT_API_KEY: str = Field(default="", validation_alias="AGENT_API_KEY")
    GATEWAY_API_KEY: str = Field(default="", validation_alias="GATEWAY_API_KEY")
    AGENT_MASTER_KEY: str = Field(default="", validation_alias="NETVISOR_AGENT_MASTER_KEY")
    GATEWAY_MASTER_KEY: str = Field(default="", validation_alias="NETVISOR_GATEWAY_MASTER_KEY")
    AGENT_NONCE_TTL_SECONDS: int = Field(default=300, validation_alias="NETVISOR_AGENT_NONCE_TTL_SECONDS")
    AGENT_MAX_CLOCK_SKEW_SECONDS: int = Field(default=60, validation_alias="NETVISOR_AGENT_MAX_CLOCK_SKEW_SECONDS")
    ACCESS_TOKEN_MINUTES: int = Field(default=30, validation_alias="NETVISOR_ACCESS_TOKEN_MINUTES")
    AUTH_COOKIE_NAME: str = Field(default="netvisor_session", validation_alias="NETVISOR_AUTH_COOKIE_NAME")
    AUTH_COOKIE_SAMESITE: str = Field(default="lax", validation_alias="NETVISOR_AUTH_COOKIE_SAMESITE")
    AUTH_COOKIE_SECURE: bool = Field(default=True, validation_alias="NETVISOR_AUTH_COOKIE_SECURE")
    AUTH_COOKIE_DOMAIN: Optional[str] = Field(default=None, validation_alias="NETVISOR_AUTH_COOKIE_DOMAIN")
    AUTH_COOKIE_PATH: str = Field(default="/", validation_alias="NETVISOR_AUTH_COOKIE_PATH")
    REFRESH_TOKEN_DAYS: int = Field(default=7, validation_alias="NETVISOR_REFRESH_TOKEN_DAYS")
    REFRESH_COOKIE_NAME: str = Field(default="netvisor_refresh_token", validation_alias="NETVISOR_REFRESH_COOKIE_NAME")
    CSRF_COOKIE_NAME: str = Field(default="XSRF-TOKEN", validation_alias="NETVISOR_CSRF_COOKIE_NAME")
    CSRF_HEADER_NAME: str = Field(default="X-XSRF-TOKEN", validation_alias="NETVISOR_CSRF_HEADER_NAME")
    RELEASE_VERSION: str = Field(default="", validation_alias="NETVISOR_RELEASE_VERSION")
    RELEASE_CHANNEL: str = Field(default="dev", validation_alias="NETVISOR_RELEASE_CHANNEL")
    GIT_COMMIT: str = Field(default="", validation_alias="NETVISOR_GIT_COMMIT")
    BUILD_TIMESTAMP: str = Field(default="", validation_alias="NETVISOR_BUILD_TIMESTAMP")
    LOGIN_LOCKOUT_THRESHOLD: int = Field(default=5, validation_alias="NETVISOR_LOGIN_LOCKOUT_THRESHOLD")
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, validation_alias="NETVISOR_LOGIN_LOCKOUT_MINUTES")
    BACKEND_TLS_PINS_JSON: str = Field(default="[]", validation_alias="NETVISOR_BACKEND_TLS_PINS_JSON")
    AUTH_LOGIN_RATE_LIMIT_PER_MINUTE: int = Field(default=20, validation_alias="NETVISOR_AUTH_LOGIN_RATE_LIMIT_PER_MINUTE")
    AUTH_REGISTER_RATE_LIMIT_PER_MINUTE: int = Field(default=5, validation_alias="NETVISOR_AUTH_REGISTER_RATE_LIMIT_PER_MINUTE")
    AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE: int = Field(default=30, validation_alias="NETVISOR_AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE")
    AGENT_CONTROL_RATE_LIMIT_PER_MINUTE: int = Field(default=240, validation_alias="NETVISOR_AGENT_CONTROL_RATE_LIMIT_PER_MINUTE")
    AGENT_FLOW_RATE_LIMIT_PER_MINUTE: int = Field(default=1200, validation_alias="NETVISOR_AGENT_FLOW_RATE_LIMIT_PER_MINUTE")
    AGENT_ENROLLMENT_PENDING_TTL_SECONDS: int = Field(
        default=86400,
        validation_alias="NETVISOR_AGENT_ENROLLMENT_PENDING_TTL_SECONDS",
    )
    AGENT_ENROLLMENT_RETRY_SECONDS: int = Field(
        default=15,
        validation_alias="NETVISOR_AGENT_ENROLLMENT_RETRY_SECONDS",
    )
    ADMIN_MUTATION_RATE_LIMIT_PER_MINUTE: int = Field(default=30, validation_alias="NETVISOR_ADMIN_MUTATION_RATE_LIMIT_PER_MINUTE")
    FLOW_WORKER_MODE: str = Field(default="embedded", validation_alias="NETVISOR_FLOW_WORKER_MODE")
    FLOW_WORKER_POLL_SECONDS: float = Field(default=1.0, validation_alias="NETVISOR_FLOW_WORKER_POLL_SECONDS")
    FLOW_WORKER_CLAIM_LIMIT: int = Field(default=10, validation_alias="NETVISOR_FLOW_WORKER_CLAIM_LIMIT")
    FLOW_WORKER_HEARTBEAT_SECONDS: float = Field(default=5.0, validation_alias="NETVISOR_FLOW_WORKER_HEARTBEAT_SECONDS")
    FLOW_WORKER_ALIVE_SECONDS: int = Field(default=15, validation_alias="NETVISOR_FLOW_WORKER_ALIVE_SECONDS")
    FLOW_QUEUE_STATUS_CACHE_SECONDS: float = Field(default=1.0, validation_alias="NETVISOR_FLOW_QUEUE_STATUS_CACHE_SECONDS")
    FLOW_INGEST_MAX_ATTEMPTS: int = Field(default=5, validation_alias="NETVISOR_FLOW_INGEST_MAX_ATTEMPTS")
    FLOW_INGEST_RETRY_SECONDS: int = Field(default=5, validation_alias="NETVISOR_FLOW_INGEST_RETRY_SECONDS")
    FLOW_INGEST_CLAIM_TTL_SECONDS: int = Field(default=120, validation_alias="NETVISOR_FLOW_INGEST_CLAIM_TTL_SECONDS")
    FLOW_INGEST_MAX_PENDING_FLOWS: int = Field(default=50000, validation_alias="NETVISOR_FLOW_INGEST_MAX_PENDING_FLOWS")
    FLOW_INGEST_MAX_LAG_SECONDS: int = Field(default=30, validation_alias="NETVISOR_FLOW_INGEST_MAX_LAG_SECONDS")
    FLOW_ALERT_DEDUPE_WINDOW_SECONDS: int = Field(
        default=300,
        validation_alias="NETVISOR_FLOW_ALERT_DEDUPE_WINDOW_SECONDS",
    )

    DB_HOST: str = Field(default="localhost", validation_alias="NETVISOR_DB_HOST")
    DB_USER: str = Field(default="root", validation_alias="NETVISOR_DB_USER")
    DB_PASSWORD: str = Field(default="", validation_alias="NETVISOR_DB_PASSWORD")
    DB_NAME: str = Field(default="network_security", validation_alias="NETVISOR_DB_NAME")
    DB_POOL_SIZE: int = Field(default=20, validation_alias="NETVISOR_DB_POOL_SIZE")
    
    # Redis Configurations
    REDIS_HOST: str = Field(default="localhost", validation_alias="NETVISOR_REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, validation_alias="NETVISOR_REDIS_PORT")
    
    # Correlation & Bounds Configurations
    NETVISOR_MAX_EDGES_PER_ORG: int = Field(default=100000, validation_alias="NETVISOR_MAX_EDGES_PER_ORG")
    NETVISOR_MAX_PREDECESSORS_PER_NODE: int = Field(default=1000, validation_alias="NETVISOR_MAX_PREDECESSORS_PER_NODE")
    NETVISOR_MAX_EVIDENCE_ENTRIES_PER_ORG: int = Field(default=50000, validation_alias="NETVISOR_MAX_EVIDENCE_ENTRIES_PER_ORG")
    NETVISOR_MAX_SUPPRESSION_ENTRIES_PER_ORG: int = Field(default=50000, validation_alias="NETVISOR_MAX_SUPPRESSION_ENTRIES_PER_ORG")
    NETVISOR_CORRELATION_WINDOW_SECONDS: int = Field(default=30, validation_alias="NETVISOR_CORRELATION_WINDOW_SECONDS")
    NETVISOR_EVIDENCE_TTL_SECONDS: int = Field(default=300, validation_alias="NETVISOR_EVIDENCE_TTL_SECONDS")
    
    # Organization Network Topology (JSON maps/lists)
    NETVISOR_ORGANIZATION_CIDRS: str = Field(
        default='{"default-org-id": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]}',
        validation_alias="NETVISOR_ORGANIZATION_CIDRS"
    )
    NETVISOR_INFRASTRUCTURE_ASSETS: str = Field(
        default='[{"org_id": "default-org-id", "cidr_or_ip": "10.147.172.96", "role": "server", "criticality": "high"}]',
        validation_alias="NETVISOR_INFRASTRUCTURE_ASSETS"
    )
    
    # ClickHouse Configurations
    CLICKHOUSE_HOST: str = Field(default="localhost", validation_alias="NETVISOR_CLICKHOUSE_HOST")
    CLICKHOUSE_PORT: int = Field(default=8123, validation_alias="NETVISOR_CLICKHOUSE_PORT")
    CLICKHOUSE_USER: str = Field(default="default", validation_alias="NETVISOR_CLICKHOUSE_USER")
    CLICKHOUSE_PASSWORD: str = Field(default="", validation_alias="NETVISOR_CLICKHOUSE_PASSWORD")
    CLICKHOUSE_DB: str = Field(default="default", validation_alias="NETVISOR_CLICKHOUSE_DB")
    
    SINGLE_ORG_MODE: bool = Field(default=True, validation_alias="NETVISOR_SINGLE_ORG_MODE")
    DEFAULT_ORGANIZATION_ID: Optional[str] = Field(default=None, validation_alias="NETVISOR_DEFAULT_ORGANIZATION_ID")

    BOOTSTRAP_ADMIN_USERNAME: str = Field(default="admin", validation_alias="NETVISOR_BOOTSTRAP_ADMIN_USERNAME")
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str] = Field(default=None, validation_alias="NETVISOR_BOOTSTRAP_ADMIN_PASSWORD")
    ALLOW_SELF_REGISTER: bool = Field(default=False, validation_alias="NETVISOR_ALLOW_SELF_REGISTER")
    ALLOW_LAN_HTTP: bool = Field(default=False, validation_alias="NETVISOR_ALLOW_LAN_HTTP")
    RESET_RUNTIME_ON_STARTUP: bool = Field(default=False, validation_alias="NETVISOR_RESET_RUNTIME_ON_STARTUP")
    BACKUP_AND_RESET_ON_SHUTDOWN: bool = Field(default=False, validation_alias="NETVISOR_BACKUP_AND_RESET_ON_SHUTDOWN")
    CORS_ORIGINS_RAW: str = Field(
        default="http://127.0.0.1:8000,http://localhost:8000",
        validation_alias="NETVISOR_CORS_ORIGINS",
    )
    LOG_LEVEL: str = Field(default="INFO", validation_alias="NETVISOR_LOG_LEVEL")
    DEBUG: bool = Field(default=False, validation_alias="NETVISOR_DEBUG")
    GEOIP_ASN_DB_PATH: str = Field(
        default=str(PROJECT_ROOT / "infra" / "database" / "GeoLite2-ASN.mmdb"),
        validation_alias="NETVISOR_GEOIP_ASN_DB_PATH",
    )
    BACKUP_DIR: str = Field(
        default=str(PROJECT_ROOT / "runtime" / "backups" / "server"),
        validation_alias="NETVISOR_BACKUP_DIR",
    )
    BACKUP_RETENTION_DAYS: int = Field(default=30, validation_alias="NETVISOR_BACKUP_RETENTION_DAYS")

    # mTLS settings
    MTLS_MODE: str = Field(default="disabled", validation_alias="NETVISOR_MTLS_MODE")
    MTLS_CERT_VALIDITY_DAYS: int = Field(default=90, validation_alias="NETVISOR_MTLS_CERT_VALIDITY_DAYS")
    MTLS_RENEWAL_WINDOW_DAYS: int = Field(default=30, validation_alias="NETVISOR_MTLS_RENEWAL_WINDOW_DAYS")
    MTLS_CA_DIR: str = Field(default="runtime/ca", validation_alias="NETVISOR_MTLS_CA_DIR")
    AUDIT_CHAIN_ENABLED: bool = Field(default=True, validation_alias="NETVISOR_AUDIT_CHAIN_ENABLED")
    AUDIT_CHAIN_GENESIS: str = Field(default="GENESIS", validation_alias="NETVISOR_AUDIT_CHAIN_GENESIS")

    # Modular Engine Settings
    NETVISOR_DEVICE_WEIGHT_DHCP: float = 0.40
    NETVISOR_DEVICE_WEIGHT_MDNS: float = 0.20
    NETVISOR_DEVICE_WEIGHT_SSDP: float = 0.15
    NETVISOR_DEVICE_WEIGHT_OUI: float = 0.15
    NETVISOR_DEVICE_WEIGHT_HOSTNAME: float = 0.10
    NETVISOR_DEVICE_WEIGHT_ACTIVE_PROBE: float = 0.15
    NETVISOR_ACTIVE_PROBER_PORTS: list[int] = [8008, 80, 443, 22, 8060, 9100, 502, 3000]
    NETVISOR_ACTIVE_PROBE_CONF_THRESHOLD: float = 0.50

    NETVISOR_PORT_SCAN_PORTS_THRESHOLD: int = 10
    NETVISOR_PORT_SCAN_WINDOW_SECONDS: int = 10

    NETVISOR_BRUTE_FORCE_ATTEMPTS_THRESHOLD: int = 15
    NETVISOR_BRUTE_FORCE_WINDOW_SECONDS: int = 60
    NETVISOR_BRUTE_FORCE_DURATION_THRESHOLD: float = 1.0
    NETVISOR_BRUTE_FORCE_BYTES_THRESHOLD: int = 500
    NETVISOR_BRUTE_FORCE_PORTS: list[int] = [22, 3389, 445, 80, 443]

    NETVISOR_BEACONING_MIN_EVENTS: int = 5
    NETVISOR_BEACONING_WINDOW_SECONDS: int = 1800
    NETVISOR_BEACONING_COV_THRESHOLD: float = 0.1

    NETVISOR_DNS_TUNNELING_ENTROPY_THRESHOLD: float = 3.8
    NETVISOR_DNS_TUNNELING_LABEL_LENGTH: int = 15
    NETVISOR_DNS_TUNNELING_BLOOM_THRESHOLD: int = 50
    NETVISOR_DNS_TUNNELING_TTL_SECONDS: int = 3600

    NETVISOR_LARGE_UPLOAD_THRESHOLD_BYTES: int = 5000000

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def validate_config(self) -> list[str]:
        """Validate critical configuration settings and return list of errors."""
        errors = []
        
        # Issue #11: Configuration Validation Gaps
        if self.SINGLE_ORG_MODE and not self.DEFAULT_ORGANIZATION_ID:
            errors.append("SINGLE_ORG_MODE=true requires NETVISOR_DEFAULT_ORGANIZATION_ID to be set")
        
        if self.BACKUP_RETENTION_DAYS < 1:
            errors.append("NETVISOR_BACKUP_RETENTION_DAYS must be >= 1")
        
        if self.FLOW_INGEST_MAX_PENDING_FLOWS < 100:
            errors.append("NETVISOR_FLOW_INGEST_MAX_PENDING_FLOWS must be >= 100 (got {})".format(self.FLOW_INGEST_MAX_PENDING_FLOWS))
        
        # JWT key validation for RS256
        if self.JWT_ALGORITHM.upper() == "RS256":
            has_private_key = bool(self.JWT_PRIVATE_KEY or self.JWT_PRIVATE_KEY_PATH)
            has_public_key = bool(self.JWT_PUBLIC_KEY or self.JWT_PUBLIC_KEY_PATH)
            if not has_private_key:
                errors.append("RS256 requires NETVISOR_JWT_PRIVATE_KEY or NETVISOR_JWT_PRIVATE_KEY_PATH")
            if not has_public_key:
                errors.append("RS256 requires NETVISOR_JWT_PUBLIC_KEY or NETVISOR_JWT_PUBLIC_KEY_PATH")
        
        # Magic number documentation (Issue #18)
        # 30 min session: Reasonable for security; configurable per deployment
        # 50K pending flows: Prevents unbounded queue growth; tune based on DB throughput
        # 1 day enrollment TTL: Prevents stale agent enrollments; security best practice
        
        return errors


# Global settings instance (can be overridden for testing)
_settings_instance: Settings | None = None


def get_settings() -> Settings:
    """Get the global settings instance, creating it if needed."""
    global _settings_instance, settings
    if _settings_instance is None:
        _settings_instance = Settings()
        settings = _settings_instance
    return _settings_instance


def set_settings(new_settings: Settings | None) -> None:
    """Override the global settings instance (for testing)."""
    global _settings_instance, settings
    _settings_instance = new_settings
    if new_settings is not None:
        settings = new_settings


# Backward compatibility - deprecated, use get_settings() instead
settings = get_settings()

