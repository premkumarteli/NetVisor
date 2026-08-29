import pytest
from intel.app_classifier import (
    clean_title_to_app_name,
    clean_domain_to_app_name,
    clean_process_to_app_name,
    clean_cert_org_to_app_name,
    infer_app_category,
    MULTI_TENANT_SUFFIXES,
    GENERIC_CERT_ORGS,
)
from backend.services.application_service import ApplicationService, application_service
from backend.db.session import get_db_connection


class TestDynamicAppClassifier:
    def test_multi_tenant_subdomain_extraction(self):
        # Multi-tenant PaaS domains should extract the tenant subdomain
        app, cat = clean_domain_to_app_name("analytics-dash.vercel.app")
        assert app == "Analytics Dash"
        assert cat in {"web", "dev", "cloud"}

        app, cat = clean_domain_to_app_name("my-crm.herokuapp.com")
        assert app in {"MY CRM", "My Crm", "My CRM"}

        app, cat = clean_domain_to_app_name("team-docs.pages.dev")
        assert app in {"Team Docs", "TEAM DOCS"}


        app, cat = clean_domain_to_app_name("developer-portal.github.io")
        assert app == "Developer Portal"
        assert cat in {"dev", "web"}

    def test_standard_sld_extraction(self):
        # Standard domains should extract and format the SLD
        app, cat = clean_domain_to_app_name("dashboard.acme-corp.com")
        assert app == "Acme Corp"

        app, cat = clean_domain_to_app_name("api.stripe.com")
        assert app == "Stripe"

        app, cat = clean_domain_to_app_name("hubspot.com")
        assert app == "Hubspot"

    def test_html_title_sanitization(self):
        # Should extract brand / product from title delimiter patterns
        assert clean_title_to_app_name("Claude - Project Review") == "Claude"
        assert clean_title_to_app_name("ChatGPT: Discuss system architecture") in {"ChatGPT", "Chat GPT"}
        assert clean_title_to_app_name("Google Gemini | Brainstorming Session") == "Google Gemini"
        assert clean_title_to_app_name("SalesForge CRM • Customer Pipeline") in {"SalesForge CRM", "Sales Forge CRM"}
        assert clean_title_to_app_name("Linear — Issue Tracking") == "Linear"


    def test_process_binary_mapping(self):
        app, cat = clean_process_to_app_name("cursor.exe")
        assert app == "Cursor"
        assert cat == "dev"

        app, cat = clean_process_to_app_name("spotify.exe")
        assert app == "Spotify"
        assert cat == "streaming"

        app, cat = clean_process_to_app_name("code.exe")
        assert app == "Visual Studio Code"
        assert cat == "dev"

        app, cat = clean_process_to_app_name("custom-tool.exe")
        assert app == "Custom Tool"

    def test_tls_cert_org_with_cdn_denylist(self):
        # Generic CA / CDNs must be rejected (Layer 4 Guard)
        assert clean_cert_org_to_app_name("Cloudflare, Inc.") is None
        assert clean_cert_org_to_app_name("Let's Encrypt") is None
        assert clean_cert_org_to_app_name("DigiCert, Inc.") is None
        assert clean_cert_org_to_app_name("Google Trust Services LLC") is None
        assert clean_cert_org_to_app_name("Amazon Corporate LLC") is None

        # Real enterprise organizations must be accepted
        assert clean_cert_org_to_app_name("Anthropic, PBC") == "Anthropic"
        assert clean_cert_org_to_app_name("Stripe, Inc.") == "Stripe"
        assert clean_cert_org_to_app_name("Spotify AB") == "Spotify"

    def test_admin_overrides_lifecycle(self):
        conn = get_db_connection()
        test_domain = "test-custom-crm-override.local"
        test_app_name = "Custom Enterprise CRM"

        try:
            # 1. Set admin override
            result = application_service.set_admin_override(
                conn,
                domain=test_domain,
                app_name=test_app_name,
                category="crm",
                organization_id="default-org-id",
            )
            assert result["application_name"] == test_app_name
            assert result["is_override"] is True

            # 2. Check classification uses override (Layer 0 Precedence)
            classified = application_service.classify_by_domain(test_domain, organization_id="default-org-id")
            assert classified == test_app_name

            # 3. List admin overrides
            overrides = application_service.get_admin_overrides(conn, organization_id="default-org-id")
            matched = [ov for ov in overrides if ov["domain"] == test_domain]
            assert len(matched) == 1
            assert matched[0]["application_name"] == test_app_name

            # 4. Delete admin override
            deleted = application_service.delete_admin_override(conn, domain=test_domain, organization_id="default-org-id")
            assert deleted is True

            # 5. Verify removal from overrides
            overrides_after = application_service.get_admin_overrides(conn, organization_id="default-org-id")
            assert not any(ov["domain"] == test_domain for ov in overrides_after)

        finally:
            conn.close()

    def test_application_summary_aggregation(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Insert a sample web event to guarantee non-empty aggregation
            cursor.execute(
                """
                INSERT INTO web_events
                    (organization_id, agent_id, device_ip, process_name, browser_name, page_url, base_domain, page_title, http_method, request_bytes, response_bytes, first_seen, last_seen, created_at)
                VALUES
                    ('default-org-id', 'AGENT-TEST', '10.18.86.99', 'chrome.exe', 'Chrome', 'https://claude.ai/chat', 'claude.ai', 'Claude - Anthropic', 'GET', 512, 1024, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())
                """
            )
            conn.commit()

            summary = application_service.get_application_summary(conn, window_minutes=60, force_refresh=True)
            assert isinstance(summary, list)
            assert len(summary) > 0

            claude_entry = next((e for e in summary if e["application"] == "Claude"), None)
            assert claude_entry is not None
            assert claude_entry["device_count"] >= 1
            assert claude_entry["bandwidth_bytes"] >= 1024
        finally:
            cursor.execute("DELETE FROM web_events WHERE agent_id = 'AGENT-TEST'")
            conn.commit()
            cursor.close()
            conn.close()
