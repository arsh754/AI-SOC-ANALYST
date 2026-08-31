from datetime import datetime, timedelta, timezone

from backend.event_model import SecurityEvent
from detections.brute_force import detect_brute_force


def create_failed_login(
    event_id: str,
    source_ip: str,
    timestamp: datetime
) -> SecurityEvent:

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        host="test-host",
        event_type="authentication",
        action="login_failed",
        source="test",
        severity="medium",
        username="admin",
        source_ip=source_ip,
        description="Failed login attempt",
        subsystem="test",
        category="authentication",
        process_path="/test/process",
        message_type="Default",
        raw_message="authentication failure",
    )


def test_brute_force_detected():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            event_id=f"login-{i}",
            source_ip="192.168.1.50",
            timestamp=start_time + timedelta(seconds=i * 30)
        )
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["alert_type"] == "brute_force"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.50"
    assert alert["failed_attempts"] == 5


def test_brute_force_not_detected_with_few_attempts():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            event_id=f"login-{i}",
            source_ip="192.168.1.50",
            timestamp=start_time + timedelta(seconds=i * 30)
        )
        for i in range(3)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_different_ips_do_not_trigger_alert():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            event_id=f"login-{i}",
            source_ip=f"192.168.1.{i}",
            timestamp=start_time + timedelta(seconds=i * 30)
        )
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0