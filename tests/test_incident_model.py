from datetime import datetime, timezone

from backend.incident_model import SecurityIncident


def test_security_incident_creation():
    incident = SecurityIncident(
        incident_id="INC-0001",
        title="Possible Account Compromise",
        attack_type="Account Compromise",
        category="Authentication",
        severity="high",
        confidence=0.90,
        correlation_score=0.85,
        description=(
            "Multiple related security alerts indicate "
            "possible account compromise."
        ),
        host="test-host",
        username="testuser",
        source_ip="192.168.1.50",
        alert_ids=[
            "ALT-0001",
            "ALT-0002",
            "ALT-0003",
        ],
        alert_count=3,
    )

    assert incident.incident_id == "INC-0001"
    assert incident.title == "Possible Account Compromise"
    assert incident.attack_type == "Account Compromise"
    assert incident.category == "Authentication"
    assert incident.severity == "high"
    assert incident.confidence == 0.90
    assert incident.correlation_score == 0.85
    assert incident.status == "new"
    assert incident.host == "test-host"
    assert incident.username == "testuser"
    assert incident.source_ip == "192.168.1.50"
    assert incident.alert_ids == [
        "ALT-0001",
        "ALT-0002",
        "ALT-0003",
    ]
    assert incident.alert_count == 3


def test_incident_supports_optional_context():
    incident = SecurityIncident(
        incident_id="INC-0002",
        title="Suspicious Activity",
        attack_type="Unknown",
        category="Network",
        severity="medium",
        confidence=0.60,
        correlation_score=0.55,
        description="Related network alerts detected.",
    )

    assert incident.host is None
    assert incident.username is None
    assert incident.source_ip is None
    assert incident.alert_ids == []
    assert incident.alert_count is None
    assert incident.status == "new"


def test_incident_timestamp_is_created_automatically():
    incident = SecurityIncident(
        incident_id="INC-0003",
        title="Test Incident",
        attack_type="Test",
        category="Test",
        severity="low",
        confidence=0.50,
        correlation_score=0.50,
        description="Test incident.",
    )

    assert isinstance(
        incident.timestamp,
        datetime,
    )

    assert incident.timestamp.tzinfo is not None
    assert incident.timestamp.tzinfo == timezone.utc


def test_confidence_must_be_between_zero_and_one():
    from pydantic import ValidationError

    try:
        SecurityIncident(
            incident_id="INC-0004",
            title="Invalid Incident",
            attack_type="Test",
            category="Test",
            severity="low",
            confidence=1.5,
            correlation_score=0.5,
            description="Invalid confidence.",
        )

        assert False

    except ValidationError:
        assert True


def test_correlation_score_must_be_between_zero_and_one():
    from pydantic import ValidationError

    try:
        SecurityIncident(
            incident_id="INC-0005",
            title="Invalid Incident",
            attack_type="Test",
            category="Test",
            severity="low",
            confidence=0.5,
            correlation_score=-0.1,
            description="Invalid correlation score.",
        )

        assert False

    except ValidationError:
        assert True