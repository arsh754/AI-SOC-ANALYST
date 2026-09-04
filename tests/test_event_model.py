from datetime import datetime, timezone

from backend.event_model import SecurityEvent


def test_security_event_creation():

    event = SecurityEvent(
        event_id="evt-0001",
        timestamp=datetime.now(timezone.utc),
        host="test-host",
        event_type="authentication",
        action="login_failed",
        source="test",
        severity="medium",
        username="testuser",
        source_ip="192.168.1.50",
        description="Failed login attempt",
        subsystem="authentication",
        category="authentication",
        process_path=None,
        file_path=None,
        message_type="Default",
        raw_message="Failed login attempt",
    )

    assert event.event_id == "evt-0001"
    assert event.host == "test-host"
    assert event.event_type == "authentication"
    assert event.action == "login_failed"
    assert event.source == "test"
    assert event.severity == "medium"

    assert event.username == "testuser"
    assert event.source_ip == "192.168.1.50"

    assert event.description == "Failed login attempt"
    assert event.subsystem == "authentication"
    assert event.category == "authentication"

    assert event.process_path is None
    assert event.file_path is None

    assert event.message_type == "Default"
    assert event.raw_message == "Failed login attempt"


def test_security_event_supports_file_information():

    event = SecurityEvent(
        event_id="evt-0002",
        timestamp=datetime.now(timezone.utc),
        host="test-host",
        event_type="file",
        action="file_created",
        source="test",
        severity="medium",
        username="testuser",
        description="File created",
        subsystem="filesystem",
        category="file",
        process_path="/usr/bin/test",
        file_path="/tmp/test.sh",
        message_type="Default",
        raw_message="File created: /tmp/test.sh",
    )

    assert event.event_type == "file"
    assert event.file_path == "/tmp/test.sh"
    assert event.process_path == "/usr/bin/test"
    assert event.raw_message == "File created: /tmp/test.sh"