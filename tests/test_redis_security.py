"""
Tests for Redis Security (Task 2):
- Redis password configuration
- Connection pool authentication
"""

import pytest
from unittest.mock import patch, MagicMock
from backend.core.config import Settings, set_settings


def _test_settings(**overrides) -> Settings:
    """Create Settings bypassing .env file and env var resolution."""
    defaults = {
        "SECRET_KEY": "xK9#mP2$vL5@nQ8!rT3&wJ6*yH1!zA4",
        "AGENT_API_KEY": "aG3$kL9!xQ2@nR7#bM5",
        "GATEWAY_API_KEY": "gW8!pT3@yN6#cJ2$rF9",
        "AGENT_MASTER_KEY": "mA4#kL7!xQ1@nR9$bT5",
        "GATEWAY_MASTER_KEY": "gZ8!pW3@yN6#cJ2$rK9",
        "BOOTSTRAP_ADMIN_PASSWORD": "StrongP@ssw0rd!2024",
        "JWT_ALGORITHM": "HS256",
        "JWT_PRIVATE_KEY": "",
        "JWT_PUBLIC_KEY": "",
        "JWT_PRIVATE_KEY_PATH": "",
        "JWT_PUBLIC_KEY_PATH": "",
        "SINGLE_ORG_MODE": True,
        "DEFAULT_ORGANIZATION_ID": "test-org",
    }
    defaults.update(overrides)
    return Settings.model_construct(**defaults)


@pytest.fixture(autouse=True)
def reset_global_settings():
    yield
    set_settings(None)


class TestRedisPasswordConfig:
    def test_redis_password_default_empty(self):
        settings = _test_settings()
        assert settings.REDIS_PASSWORD == ""

    def test_redis_password_from_env(self):
        settings = _test_settings(REDIS_PASSWORD="my_secret_redis_pass")
        assert settings.REDIS_PASSWORD == "my_secret_redis_pass"

    def test_redis_db_default(self):
        settings = _test_settings()
        assert settings.REDIS_DB == 0

    def test_redis_db_from_env(self):
        settings = _test_settings(REDIS_DB=5)
        assert settings.REDIS_DB == 5


class TestRedisConnectionPool:
    def test_pool_includes_password_when_set(self):
        import redis
        from backend.db.redis_client import get_redis_pool
        import backend.db.redis_client as redis_module

        redis_module._redis_pool = None

        try:
            with patch.object(redis, "ConnectionPool") as mock_pool:
                mock_pool.return_value = MagicMock()
                settings = _test_settings(
                    REDIS_HOST="testhost",
                    REDIS_PORT=6380,
                    REDIS_PASSWORD="test_pass_123",
                    REDIS_DB=2,
                )
                with patch("backend.db.redis_client.settings", settings):
                    get_redis_pool()
                    mock_pool.assert_called_once()
                    call_kwargs = mock_pool.call_args[1]
                    assert call_kwargs["password"] == "test_pass_123"
                    assert call_kwargs["db"] == 2
                    assert call_kwargs["host"] == "testhost"
                    assert call_kwargs["port"] == 6380
        finally:
            redis_module._redis_pool = None

    def test_pool_omits_password_when_empty(self):
        import redis
        from backend.db.redis_client import get_redis_pool
        import backend.db.redis_client as redis_module

        redis_module._redis_pool = None

        try:
            with patch.object(redis, "ConnectionPool") as mock_pool:
                mock_pool.return_value = MagicMock()
                settings = _test_settings(REDIS_PASSWORD="", REDIS_DB=0)
                with patch("backend.db.redis_client.settings", settings):
                    get_redis_pool()
                    mock_pool.assert_called_once()
                    call_kwargs = mock_pool.call_args[1]
                    assert "password" not in call_kwargs
        finally:
            redis_module._redis_pool = None

    def test_pool_includes_db_number(self):
        import redis
        from backend.db.redis_client import get_redis_pool
        import backend.db.redis_client as redis_module

        redis_module._redis_pool = None

        try:
            with patch.object(redis, "ConnectionPool") as mock_pool:
                mock_pool.return_value = MagicMock()
                settings = _test_settings(REDIS_DB=3, REDIS_PASSWORD="x" * 16)
                with patch("backend.db.redis_client.settings", settings):
                    get_redis_pool()
                    call_kwargs = mock_pool.call_args[1]
                    assert call_kwargs["db"] == 3
        finally:
            redis_module._redis_pool = None
