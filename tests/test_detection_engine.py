from datetime import datetime, timedelta, timezone

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert
from detections.detection_engine import run_detections


def create_failed_login(
    event_id: str,
    source_ip: str,
    timestamp: datetime,
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
        subsystem="authentication",
        category="authentication",
        process_path=None,
        file_path=None,
        message_type="Default",
        raw_message="Failed login attempt",
    )


def test_detect_brute_force():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            event_id=f"login-{number}",
            source_ip="192.168.1.50",
            timestamp=start_time + timedelta(
                seconds=number * 30
            ),
        )
        for number in range(5)
    ]

    alerts = run_detections(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Brute Force"
    assert alert.category == "Authentication"
    assert alert.severity == "high"
    assert alert.detection_rule == "BRUTE_FORCE_AUTH"

    assert alert.source_ip == "192.168.1.50"
    assert alert.event_count == 5


def test_no_brute_force_with_few_attempts():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            event_id=f"login-{number}",
            source_ip="192.168.1.50",
            timestamp=start_time + timedelta(
                seconds=number * 30
            ),
        )
        for number in range(4)
    ]

    alerts = run_detections(events)

    assert len(alerts) == 0