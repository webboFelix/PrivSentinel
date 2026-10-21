import pytest

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.core.event_models import Detection, RiskAssessment, SecurityEvent


@pytest.fixture
def services(tmp_path):
    return ApplicationServices.create(AppPaths(tmp_path / "local"))


def _record_event(services, address: str, description: str = "Observed network host"):
    event = SecurityEvent(
        source="network",
        event_type="network_connection",
        severity="info",
        description=description,
        attributes={"remote_address": address},
    )
    services.security_repository.record_event(event, RiskAssessment(0, "low", ()))
    return event


def test_local_ip_indicator_matches_exact_ip_only(services):
    indicator_id = services.security_repository.add_threat_indicator(
        "8.8.8.8", "ip"
    )
    _record_event(services, "8.8.8.80")
    matching_event = _record_event(services, "8.8.8.8")

    matches = services.security_repository.list_threat_indicator_matches(indicator_id)

    assert [event["id"] for event in matches] == [matching_event.id]
    assert services.security_repository.threat_indicator_match_counts() == {
        indicator_id: 1
    }


def test_domain_indicator_requires_an_exact_domain_token(services):
    indicator_id = services.security_repository.add_threat_indicator(
        "EXAMPLE.COM.", "domain"
    )
    _record_event(services, "192.0.2.1", "notexample.com")
    matching_event = _record_event(
        services, "192.0.2.2", "Contacted example.com"
    )

    matches = services.security_repository.list_threat_indicator_matches(indicator_id)

    assert [event["id"] for event in matches] == [matching_event.id]
    assert services.security_repository.list_threat_indicators()[0]["value"] == (
        "example.com"
    )


def test_indicator_validation_and_duplicate_prevention(services):
    repo = services.security_repository

    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        repo.add_threat_indicator("not-an-ip", "ip")
    with pytest.raises(ValueError, match="64-character SHA-256"):
        repo.add_threat_indicator("abc", "sha256")

    repo.add_threat_indicator("2001:db8::1", "ip")
    with pytest.raises(ValueError, match="already in the local list"):
        repo.add_threat_indicator("2001:0db8:0:0:0:0:0:1", "ip")


def test_create_investigation_from_alert_links_event_and_updates_status(services):
    event = _record_event(services, "203.0.113.20")
    alert_id = services.security_repository.record_detection(
        event,
        Detection(
            "suspicious-network-rule",
            "Suspicious network connection",
            "high",
            "Local test detection rule",
            event.id,
        ),
    )

    investigation_id = (
        services.security_repository.create_investigation_for_alert(alert_id)
    )

    alert = services.security_repository.list_alerts()[0]
    investigation = services.security_repository.list_investigations()[0]
    assert alert["status"] == "investigating"
    assert investigation["id"] == investigation_id
    assert investigation["event_count"] == 1
