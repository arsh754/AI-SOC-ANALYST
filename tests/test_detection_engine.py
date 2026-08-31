from datetime import datetime, timedelta, timezone

from backend.event_model import SecurityEvent
from detections.detection_engine import detect_brute_force


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
        username="admin",
        source_ip=source_ip,
        description="Failed authentication attempt",
        subsystem="test",
        category="authentication",
        process_path="/test/process",
        message_type="Default",
        raw_message="authentication failure for user admin",
    )


def test_detect_brute_force():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            f"event-{number}",
            "192.168.1.50",
            start_time + timedelta(seconds=number * 30),
        )
        for number in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1

    assert alerts[0]["rule"] == "BRUTE_FORCE_AUTH"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["event_count"] == 5


def test_no_brute_force_with_few_attempts():

    start_time = datetime.now(timezone.utc)

    events = [
        create_failed_login(
            f"event-{number}",
            "192.168.1.50",
            start_time + timedelta(seconds=number * 30),
        )
        for number in range(3)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0