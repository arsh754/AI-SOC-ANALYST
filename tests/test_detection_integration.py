from datetime import datetime, timedelta, timezone

from backend.event_model import SecurityEvent
from detections.detection_engine import run_detections


def create_event(
    event_id: str,
    timestamp: datetime,
    event_type: str,
    action: str,
    process_path: str | None = None,
    file_path: str | None = None,
    source_ip: str | None = None,
) -> SecurityEvent:

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        host="test-host",
        event_type=event_type,
        action=action,
        source="test",
        severity="medium",
        username="testuser",
        source_ip=source_ip,
        description="Integration test event",
        subsystem="test",
        category=event_type,
        process_path=process_path,
        file_path=file_path,
        message_type="Default",
        raw_message=f"Test {event_type} event",
    )


def test_detection_engine_runs_all_detection_rules():

    start_time = datetime.now(timezone.utc)

    events = []

    # ---------------------------------------------------------
    # 1. Create five failed login attempts.
    #
    # These should trigger the brute-force detector.
    # ---------------------------------------------------------

    for i in range(5):

        events.append(
            create_event(
                event_id=f"login-{i}",
                timestamp=start_time + timedelta(seconds=i * 20),
                event_type="authentication",
                action="login_failed",
                source_ip="192.168.1.50",
            )
        )

    # ---------------------------------------------------------
    # 2. Create a suspicious process event.
    #
    # This should trigger the suspicious-process detector.
    # ---------------------------------------------------------

    events.append(
        create_event(
            event_id="process-1",
            timestamp=start_time + timedelta(seconds=120),
            event_type="process",
            action="process_started",
            process_path="/usr/bin/curl",
        )
    )

    # ---------------------------------------------------------
    # 3. Create suspicious file activity.
    #
    # This should trigger the file-activity detector.
    # ---------------------------------------------------------

    events.append(
        create_event(
            event_id="file-1",
            timestamp=start_time + timedelta(seconds=140),
            event_type="file",
            action="file_created",
            file_path="/tmp/payload.sh",
        )
    )

    # ---------------------------------------------------------
    # 4. Create privilege-related process activity.
    #
    # This should trigger the privilege-escalation detector.
    # ---------------------------------------------------------

    events.append(
        create_event(
            event_id="privilege-1",
            timestamp=start_time + timedelta(seconds=160),
            event_type="process",
            action="process_started",
            process_path="/usr/bin/sudo",
        )
    )

    # ---------------------------------------------------------
    # Run the complete Detection Engine.
    # ---------------------------------------------------------

    alerts = run_detections(events)

    # ---------------------------------------------------------
    # Verify that alerts were generated.
    # ---------------------------------------------------------

    alert_types = {
        alert["alert_type"]
        for alert in alerts
    }

    # All four detection capabilities should have
    # generated an alert.
    assert "brute_force" in alert_types
    assert "suspicious_process" in alert_types
    assert "suspicious_file_activity" in alert_types
    assert "privilege_escalation" in alert_types

    # We expect exactly four alerts in this controlled
    # test scenario.
    assert len(alerts) == 4