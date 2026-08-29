import logging
import os

try:
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration
    HAS_SENTRY = True
except ImportError:
    sentry_sdk = None
    FastApiIntegration = None
    StarletteIntegration = None
    LoggingIntegration = None
    HAS_SENTRY = False

logger = logging.getLogger("netvisor.sentry")


DEFAULT_SENTRY_DSN = "https://5d439a4ef329a54ccf53058c455a3e31@o4511967075893248.ingest.de.sentry.io/4511967117574224"


def init_sentry(dsn: str | None = None, environment: str = "production") -> bool:
    """Initialize Sentry Error Monitoring and Tracing SDK for NetVisor."""
    if not HAS_SENTRY:
        logger.info("sentry_sdk package not installed. Sentry monitoring disabled.")
        return False

    target_dsn = (
        dsn
        or os.getenv("NETVISOR_SENTRY_DSN")
        or os.getenv("SENTRY_DSN")
        or DEFAULT_SENTRY_DSN
    )

    if not target_dsn or str(target_dsn).strip().lower() in ("false", "0", "disabled", "none", ""):
        logger.info("Sentry DSN not configured or disabled.")
        return False

    try:
        env_name = os.getenv("NETVISOR_SENTRY_ENVIRONMENT") or os.getenv("NETVISOR_ENVIRONMENT") or environment
        traces_rate = float(os.getenv("NETVISOR_SENTRY_TRACES_SAMPLE_RATE", "1.0"))

        sentry_sdk.init(
            dsn=target_dsn,
            environment=env_name,
            send_default_pii=True,
            traces_sample_rate=traces_rate,
            profiles_sample_rate=1.0,
            integrations=[
                StarletteIntegration(transaction_style="endpoint"),
                FastApiIntegration(transaction_style="endpoint"),
                LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
            ],
        )
        logger.info("[*] Sentry Error Monitoring initialized (env: %s)", env_name)
        return True
    except Exception as exc:
        logger.warning("[!] Failed to initialize Sentry: %s", exc)
        return False


def capture_sample_event(message: str = "NetVisor Sentry Integration Test Event") -> str:
    """Trigger an explicit sample error event to verify Sentry dashboard connection."""
    if not HAS_SENTRY or sentry_sdk is None:
        return "sentry-sdk-not-installed"
    try:
        division_by_zero = 1 / 0
    except ZeroDivisionError as exc:
        event_id = sentry_sdk.capture_exception(exc)
        logger.info("Captured test exception in Sentry with Event ID: %s", event_id)
        return str(event_id)

