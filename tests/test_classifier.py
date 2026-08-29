from datetime import datetime, timezone

from backend.event_model import SecurityEvent
from detections.classifier import classify_event


def create_test_event(message: str) -> SecurityEvent:
    return SecurityEvent(
        event_id="test-001",
        timestamp=datetime.now(timezone.utc),
        host="test-host",
        event_type="system",
        action="log_event",
        source="test",
        severity="low",
        description=message,
        subsystem="test.subsystem",
        category="test",
        process_path="/test/process",
        message_type="Default",
        raw_message=message,
    )


def test_authentication_classification():

    event = create_test_event(
        "authentication failure for user admin"
    )

    classified = classify_event(event)

    assert classified.event_type == "authentication"


def test_network_classification():

    event = create_test_event(
        "TCP connection established"
    )

    classified = classify_event(event)

    assert classified.event_type == "network"


def test_process_classification():

    event = create_test_event(
        "process launch detected"
    )

    classified = classify_event(event)

    assert classified.event_type == "process"


def test_file_classification():

    event = create_test_event(
        "file created"
    )

    classified = classify_event(event)

    assert classified.event_type == "file"


def test_privilege_classification():

    event = create_test_event(
        "permission denied"
    )

    classified = classify_event(event)

    assert classified.event_type == "privilege"