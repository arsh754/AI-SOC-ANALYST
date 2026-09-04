from datetime import datetime, timezone

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert
from detections.suspicious_process import detect_suspicious_process


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


def test_suspicious_process_detected():

    events = [
        create_process_event(
            "process-1",
            "/usr/bin/curl",
        )
    ]

    alerts = detect_suspicious_process(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Suspicious Process"
    assert alert.category == "Process"
    assert alert.severity == "medium"
    assert alert.confidence == 0.80
    assert alert.detection_rule == "SUSPICIOUS_PROCESS"

    assert alert.process == "curl"
    assert alert.host == "test-host"
    assert alert.username == "testuser"

    assert alert.source_event_ids == ["process-1"]


def test_suspicious_shell_detected():

    events = [
        create_process_event(
            "process-2",
            "/bin/bash",
        )
    ]

    alerts = detect_suspicious_process(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)
    assert alert.attack_type == "Suspicious Process"
    assert alert.process == "bash"


def test_normal_process_not_detected():

    events = [
        create_process_event(
            "process-3",
            "/usr/bin/python3",
        )
    ]

    alerts = detect_suspicious_process(events)

    assert len(alerts) == 0