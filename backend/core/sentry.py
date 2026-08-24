import logging
import os
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.starlette import StarletteIntegration
from sentry_sdk.integrations.logging import LoggingIntegration

logger = logging.getLogger("netvisor.sentry")

DEFAULT_SENTRY_DSN = "https://1cd30c611f4340b25bc37b5991de2926@o4511967075893248.ingest.de.sentry.io/4511967097389136"


def init_sentry(dsn: str | None = None, environment: str = "production") -> bool:
    """Initialize Sentry Error Monitoring and Tracing SDK for NetVisor."""
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
    try:
        raise RuntimeError(f"Sentry Test Trigger: {message}")
    except RuntimeError as exc:
        event_id = sentry_sdk.capture_exception(exc)
        logger.info("Captured test exception in Sentry with Event ID: %s", event_id)
        return str(event_id)
