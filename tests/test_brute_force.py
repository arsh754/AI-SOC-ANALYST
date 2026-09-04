from datetime import datetime, timedelta, timezone

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert
from detections.brute_force import detect_brute_force


def create_login_event(
    event_id: str,
    timestamp: datetime,
    source_ip: str,
) -> SecurityEvent:

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        host="test-host",
        event_type="authentication",
        action="login_failed",
        source="test",
        severity="medium",
        username="testuser",
        source_ip=source_ip,
        description="Failed login attempt",
        subsystem="test",
        category="authentication",
        process_path=None,
        file_path=None,
        message_type="Default",
        raw_message="Failed login attempt",
    )


def test_brute_force_detected():

    start_time = datetime.now(timezone.utc)

    events = [
        create_login_event(
            event_id=f"login-{i}",
            timestamp=start_time + timedelta(seconds=i * 30),
            source_ip="192.168.1.50",
        )
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Brute Force"
    assert alert.category == "Authentication"
    assert alert.severity == "high"
    assert alert.confidence == 0.90
    assert alert.detection_rule == "BRUTE_FORCE_AUTH"

    assert alert.source_ip == "192.168.1.50"

    assert alert.event_count == 5
    assert len(alert.source_event_ids) == 5


def test_brute_force_not_detected_below_threshold():

    start_time = datetime.now(timezone.utc)

    events = [
        create_login_event(
            event_id=f"login-{i}",
            timestamp=start_time + timedelta(seconds=i * 30),
            source_ip="192.168.1.50",
        )
        for i in range(4)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_brute_force_not_detected_outside_time_window():

    start_time = datetime.now(timezone.utc)

    events = [
        create_login_event(
            event_id=f"login-{i}",
            timestamp=start_time + timedelta(minutes=i * 2),
            source_ip="192.168.1.50",
        )
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0