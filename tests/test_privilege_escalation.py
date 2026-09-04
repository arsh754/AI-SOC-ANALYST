from datetime import datetime, timezone

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert
from detections.privilege_escalation import detect_privilege_escalation


def create_process_event(
    event_id: str,
    process_path: str,
) -> SecurityEvent:

    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        host="test-host",
        event_type="process",
        action="process_started",
        source="test",
        severity="medium",
        username="testuser",
        description="Test process activity",
        subsystem="test",
        category="process",
        process_path=process_path,
        file_path=None,
        message_type="Default",
        raw_message=f"Process started: {process_path}",
    )


def test_sudo_detected():

    events = [
        create_process_event(
            "priv-1",
            "/usr/bin/sudo",
        )
    ]

    alerts = detect_privilege_escalation(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Privilege Escalation"
    assert alert.category == "Privilege"
    assert alert.severity == "high"
    assert alert.confidence == 0.85
    assert alert.detection_rule == "PRIVILEGE_ESCALATION"

    assert alert.process == "sudo"
    assert alert.host == "test-host"
    assert alert.username == "testuser"

    assert alert.source_event_ids == ["priv-1"]


def test_su_detected():

    events = [
        create_process_event(
            "priv-2",
            "/usr/bin/su",
        )
    ]

    alerts = detect_privilege_escalation(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Privilege Escalation"
    assert alert.process == "su"


def test_normal_process_not_detected():

    events = [
        create_process_event(
            "priv-3",
            "/usr/bin/python3",
        )
    ]

    alerts = detect_privilege_escalation(events)

    assert len(alerts) == 0