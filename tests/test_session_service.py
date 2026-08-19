from backend.services.session_service import session_service


def test_session_id_prefers_domain_over_rotating_endpoint_ip():
    first = session_service.build_session_id(
        organization_id="org-1",
        device_ip="10.0.0.10",
        application="Google",
        domain="www.google.com",
        external_ip="142.250.1.1",
    )
    second = session_service.build_session_id(
        organization_id="org-1",
        device_ip="10.0.0.10",
        application="Google",
        domain="google.com",
        external_ip="142.250.1.2",
    )

    assert first == second


def test_session_id_falls_back_to_external_ip_without_domain():
    first = session_service.build_session_id(
        organization_id="org-1",
        device_ip="10.0.0.10",
        application="Unknown",
        domain=None,
        external_ip="8.8.8.8",
    )
    second = session_service.build_session_id(
        organization_id="org-1",
        device_ip="10.0.0.10",
        application="Unknown",
        domain=None,
        external_ip="1.1.1.1",
    )

    assert first != second
