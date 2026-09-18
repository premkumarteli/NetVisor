from backend.utils import domain_utils
import intel.domain_utils


def test_get_base_domain_returns_none_when_extractor_fails(monkeypatch):
    def explode(_host):
        raise RuntimeError("extractor failure")

    intel.domain_utils.get_base_domain.cache_clear()
    monkeypatch.setattr(intel.domain_utils, "_EXTRACTOR", explode)

    assert domain_utils.get_base_domain("mail.google.com") is None

    intel.domain_utils.get_base_domain.cache_clear()

