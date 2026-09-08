from datetime import datetime, timedelta, timezone

from backend.alert_model import SecurityAlert
from backend.incident_model import SecurityIncident

from correlation.correlator import (
    calculate_correlation_score,
    correlate_alerts,
)


def create_alert(
    alert_id: str,
    attack_type: str,
    timestamp: datetime,
    host: str | None = "test-host",
    username: str | None = "testuser",
    source_ip: str | None = "192.168.1.50",
    severity: str = "medium",
    confidence: float = 0.80,
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        attack_type=attack_type,
        category="Test",
        severity=severity,
        confidence=confidence,
        detection_rule="TEST_RULE",
        description="Test security alert",
        host=host,
        username=username,
        source_ip=source_ip,
        source_event_ids=[f"event-{alert_id}"],
    )


def test_same_context_produces_strong_correlation():
    start_time = datetime.now(timezone.utc)

    first = create_alert(
        alert_id="ALT-001",
        attack_type="Brute Force",
        timestamp=start_time,
    )

    second = create_alert(
        alert_id="ALT-002",
        attack_type="Privilege Escalation",
        timestamp=start_time + timedelta(minutes=2),
    )

    score = calculate_correlation_score(
        first,
        second,
    )

    assert score == 1.00


def test_different_context_produces_low_correlation():
    start_time = datetime.now(timezone.utc)

    first = create_alert(
        alert_id="ALT-001",
        attack_type="Brute Force",
        timestamp=start_time,
        host="host-a",
        username="user-a",
        source_ip="10.0.0.1",
    )

    second = create_alert(
        alert_id="ALT-002",
        attack_type="Suspicious Process",
        timestamp=start_time + timedelta(hours=1),
        host="host-b",
        username="user-b",
        source_ip="10.0.0.2",
    )

    score = calculate_correlation_score(
        first,
        second,
    )

    assert score == 0.10


def test_related_alerts_become_one_incident():
    start_time = datetime.now(timezone.utc)

    alerts = [
        create_alert(
            alert_id="ALT-001",
            attack_type="Brute Force",
            timestamp=start_time,
        ),
        create_alert(
            alert_id="ALT-002",
            attack_type="Privilege Escalation",
            timestamp=start_time + timedelta(minutes=2),
        ),
        create_alert(
            alert_id="ALT-003",
            attack_type="Suspicious Process",
            timestamp=start_time + timedelta(minutes=4),
        ),
    ]

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert isinstance(
        incident,
        SecurityIncident,
    )

    assert incident.alert_count == 3

    assert incident.alert_ids == [
        "ALT-001",
        "ALT-002",
        "ALT-003",
    ]

    assert incident.attack_type == (
        "Multi-Stage Attack"
    )

    assert incident.host == "test-host"
    assert incident.username == "testuser"
    assert incident.source_ip == "192.168.1.50"


def test_single_alert_does_not_create_incident():
    start_time = datetime.now(timezone.utc)

    alerts = [
        create_alert(
            alert_id="ALT-001",
            attack_type="Brute Force",
            timestamp=start_time,
        )
    ]

    incidents = correlate_alerts(alerts)

    assert incidents == []


def test_unrelated_alerts_remain_separate():
    start_time = datetime.now(timezone.utc)

    alerts = [
        create_alert(
            alert_id="ALT-001",
            attack_type="Brute Force",
            timestamp=start_time,
            host="host-a",
            username="user-a",
            source_ip="10.0.0.1",
        ),
        create_alert(
            alert_id="ALT-002",
            attack_type="Suspicious Process",
            timestamp=start_time + timedelta(hours=1),
            host="host-b",
            username="user-b",
            source_ip="10.0.0.2",
        ),
    ]

    incidents = correlate_alerts(alerts)

    assert incidents == []


def test_highest_alert_severity_becomes_incident_severity():
    start_time = datetime.now(timezone.utc)

    alerts = [
        create_alert(
            alert_id="ALT-001",
            attack_type="Brute Force",
            timestamp=start_time,
            severity="medium",
        ),
        create_alert(
            alert_id="ALT-002",
            attack_type="Privilege Escalation",
            timestamp=start_time + timedelta(minutes=2),
            severity="high",
        ),
    ]

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0].severity == "high"