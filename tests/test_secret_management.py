"""
Tests for Secret Management Hardening (Task 1):
- Entropy validation for critical secrets
- Rejection of well-known insecure values
- Minimum length enforcement
- Distinct key validation
- Bootstrap password validation
"""

import pytest
from backend.core.config import (
    Settings,
    _shannon_entropy_bits,
    _min_entropy_bits,
    validate_secret_strength,
    _INSECURE_SECRETS,
    set_settings,
)


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


# ============================================================
# Entropy utility tests
# ============================================================

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy_bits("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy_bits("a") == 0.0

    def test_two_distinct_chars(self):
        assert _shannon_entropy_bits("ab") == pytest.approx(2.0)

    def test_uniform_distribution(self):
        assert _shannon_entropy_bits("abcd") == pytest.approx(8.0)

    def test_all_same_chars(self):
        assert _shannon_entropy_bits("aaaa") == 0.0

    def test_high_entropy_string(self):
        assert _shannon_entropy_bits("aB3$kL9!xQ2@nR7") > 30.0

    def test_known_weak_secret(self):
        assert _shannon_entropy_bits("super_secure_secret_key_must_be_long_12345") < 200.0


class TestMinEntropy:
    def test_empty_string(self):
        assert _min_entropy_bits("") == 0.0

    def test_all_same_chars(self):
        assert _min_entropy_bits("aaaa") == 0.0

    def test_uniform_distribution(self):
        assert _min_entropy_bits("abcd") == pytest.approx(8.0)

    def test_repeated_pattern(self):
        assert _min_entropy_bits("ababab") > 0


# ============================================================
# Secret strength validation tests
# ============================================================

class TestValidateSecretStrength:
    def test_empty_secret(self):
        errors = validate_secret_strength("TEST_KEY", "", 64)
        assert len(errors) == 1
        assert "must not be empty" in errors[0]

    def test_well_known_insecure_value(self):
        errors = validate_secret_strength("TEST_KEY", "super_secure_secret_key_must_be_long_12345", 64)
        assert any("insecure value" in e.lower() for e in errors)

    def test_too_short(self):
        errors = validate_secret_strength("TEST_KEY", "short", 64)
        assert any("at least 16 characters" in e for e in errors)

    def test_low_entropy_rejected(self):
        errors = validate_secret_strength("TEST_KEY", "a" * 64, 64)
        assert any("entropy" in e.lower() for e in errors)

    def test_good_secret_accepted(self):
        errors = validate_secret_strength("TEST_KEY", "xK9#mP2$vL5@nQ8!rT3&wJ6*yH1", 64)
        entropy_errors = [e for e in errors if "entropy" in e.lower()]
        assert len(entropy_errors) == 0

    def test_medium_entropy_string(self):
        errors = validate_secret_strength("TEST_KEY", "abcdef123456", 64)
        assert any("entropy" in e.lower() for e in errors)

    def test_all_insecure_values_rejected(self):
        for insecure in list(_INSECURE_SECRETS)[:10]:
            if len(insecure) >= 16:
                errors = validate_secret_strength("TEST_KEY", insecure, 48)
                assert len(errors) > 0, f"Expected rejection for: {insecure!r}"


# ============================================================
# Settings validation integration tests
# ============================================================

class TestSettingsValidation:
    def test_valid_settings_pass(self):
        settings = _test_settings()
        errors = settings.validate_config()
        assert errors == []

    def test_empty_secret_key_rejected(self):
        settings = _test_settings(SECRET_KEY="")
        errors = settings.validate_config()
        assert any("SECRET_KEY" in e for e in errors)

    def test_weak_secret_key_rejected(self):
        settings = _test_settings(SECRET_KEY="super_secure_secret_key_must_be_long_12345")
        errors = settings.validate_config()
        assert any("SECRET_KEY" in e for e in errors)

    def test_empty_agent_api_key_rejected(self):
        settings = _test_settings(AGENT_API_KEY="")
        errors = settings.validate_config()
        assert any("AGENT_API_KEY" in e for e in errors)

    def test_empty_gateway_api_key_rejected(self):
        settings = _test_settings(GATEWAY_API_KEY="")
        errors = settings.validate_config()
        assert any("GATEWAY_API_KEY" in e for e in errors)

    def test_identical_api_keys_rejected(self):
        settings = _test_settings(
            AGENT_API_KEY="same_key_for_both_roles_12345678",
            GATEWAY_API_KEY="same_key_for_both_roles_12345678",
        )
        errors = settings.validate_config()
        assert any("distinct" in e.lower() for e in errors)

    def test_identical_master_keys_rejected(self):
        settings = _test_settings(
            AGENT_MASTER_KEY="same_master_key_for_both_12345678",
            GATEWAY_MASTER_KEY="same_master_key_for_both_12345678",
        )
        errors = settings.validate_config()
        assert any("distinct" in e.lower() and "MASTER_KEY" in e for e in errors)

    def test_short_bootstrap_password_rejected(self):
        settings = _test_settings(BOOTSTRAP_ADMIN_PASSWORD="short")
        errors = settings.validate_config()
        assert any("BOOTSTRAP_ADMIN_PASSWORD" in e for e in errors)

    def test_empty_bootstrap_password_rejected(self):
        settings = _test_settings(BOOTSTRAP_ADMIN_PASSWORD="")
        errors = settings.validate_config()
        assert any("BOOTSTRAP_ADMIN_PASSWORD" in e for e in errors)

    def test_weak_agent_master_key_rejected(self):
        settings = _test_settings(AGENT_MASTER_KEY="short")
        errors = settings.validate_config()
        assert any("AGENT_MASTER_KEY" in e for e in errors)
