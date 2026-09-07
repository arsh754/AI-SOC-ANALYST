from datetime import datetime, timedelta, timezone

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert

from detections.network_activity import (
    detect_suspicious_network_activity,
)


def create_network_event(
    event_id: str,
    timestamp: datetime,
    message: str,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        host="test-host",
        event_type="network",
        action="network_connection",
        source="test",
        severity="low",
        description=message,
        subsystem="network",
        category="connection",
        process_path="/usr/bin/networkd",
        message_type="Default",
        raw_message=message,
    )


def test_suspicious_port_detected():
    start_time = datetime.now(timezone.utc)

    events = [
        create_network_event(
            "network-1",
            start_time,
            "Connection established to 192.168.1.10:4444",
        )
    ]

    alerts = detect_suspicious_network_activity(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)
    assert alert.attack_type == (
        "Suspicious Network Activity"
    )
    assert alert.category == "Network"
    assert alert.severity == "medium"
    assert alert.detection_rule == (
        "SUSPICIOUS_NETWORK_PORT"
    )


def test_repeated_connections_detected():
    start_time = datetime.now(timezone.utc)

    events = []

    for i in range(5):
        events.append(
            create_network_event(
                f"network-{i}",
                start_time + timedelta(seconds=i * 30),
                "Connection established to 192.168.1.20:443",
            )
        )

    alerts = detect_suspicious_network_activity(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert isinstance(alert, SecurityAlert)
    assert alert.attack_type == (
        "Suspicious Network Activity"
    )
    assert alert.category == "Network"
    assert alert.detection_rule == (
        "REPEATED_NETWORK_CONNECTIONS"
    )
    assert alert.event_count == 5


def test_normal_network_activity_not_detected():
    start_time = datetime.now(timezone.utc)

    events = [
        create_network_event(
            "network-normal",
            start_time,
            "Connection established to 192.168.1.20:443",
        )
    ]

    alerts = detect_suspicious_network_activity(events)

    assert len(alerts) == 0