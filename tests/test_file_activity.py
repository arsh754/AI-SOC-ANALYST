from datetime import datetime, timezone

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert
from detections.file_activity import detect_suspicious_file_activity


def create_file_event(
    event_id: str,
    file_path: str,
    action: str = "file_created",
) -> SecurityEvent:

    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        host="test-host",
        event_type="file",
        action=action,
        source="test",
        severity="medium",
        username="testuser",
        description="Test file activity",
        subsystem="test",
        category="file",
        process_path="/usr/bin/test",
        file_path=file_path,
        message_type="Default",
        raw_message=f"File {action}: {file_path}",
    )


def test_suspicious_temp_file_detected():

    events = [
        create_file_event(
            "file-1",
            "/tmp/payload.sh",
        )
    ]

    alerts = detect_suspicious_file_activity(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Suspicious File Activity"
    assert alert.category == "File"
    assert alert.severity == "medium"
    assert alert.confidence == 0.80
    assert alert.detection_rule == "SUSPICIOUS_FILE_ACTIVITY"

    assert alert.file_path == "/tmp/payload.sh"
    assert alert.host == "test-host"
    assert alert.username == "testuser"

    assert alert.source_event_ids == ["file-1"]


def test_suspicious_extension_detected():

    events = [
        create_file_event(
            "file-2",
            "/Users/test/install.command",
        )
    ]

    alerts = detect_suspicious_file_activity(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Suspicious File Activity"
    assert alert.category == "File"
    assert alert.detection_rule == "SUSPICIOUS_FILE_ACTIVITY"


def test_normal_file_not_detected():

    events = [
        create_file_event(
            "file-3",
            "/Users/test/document.txt",
        )
    ]

    alerts = detect_suspicious_file_activity(events)

    assert len(alerts) == 0