import json
import socket
import subprocess
from datetime import datetime

from backend.event_model import SecurityEvent


def collect_macos_logs(minutes: int = 1):
    """
    Collect macOS Unified Log events from the last few minutes.
    """

    command = [
        "log",
        "show",
        "--last",
        f"{minutes}m",
        "--style",
        "json"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error collecting macOS logs:")
        print(result.stderr)
        return []

    try:
        logs = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Could not parse macOS log output as JSON.")
        return []

    return logs


def parse_log(raw_log: dict) -> SecurityEvent:
    """
    Convert one raw macOS log event into our standard SecurityEvent.
    """

    # Get timestamp from the raw macOS event
    timestamp = raw_log.get("timestamp")

    if timestamp:
        event_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    else:
        event_time = datetime.now()

    # Extract useful information from the raw log
    message = raw_log.get("eventMessage", "")
    subsystem = raw_log.get("subsystem")
    category = raw_log.get("category")
    process_path = raw_log.get("processImagePath")
    message_type = raw_log.get("messageType")

    # Create a readable description
    description = (
        message.strip()
        if message
        else "macOS system event"
    )

    # Convert the raw log into our standard SecurityEvent
    return SecurityEvent(
        event_id=f"macos-{timestamp}",
        timestamp=event_time,
        host=socket.gethostname(),

        # Classification
        event_type="system",
        action="log_event",
        source="macos_unified_log",
        severity="low",

        # Description
        description=description,

        # Original telemetry
        subsystem=subsystem,
        category=category,
        process_path=process_path,
        message_type=message_type,
        raw_message=message
    )


if __name__ == "__main__":

    print("AI SOC Analyst - macOS Log Collector")
    print("--------------------------------------")

    # Collect logs from the last minute
    raw_logs = collect_macos_logs(minutes=1)

    print(f"Collected {len(raw_logs)} raw log events.")

    # Parse and display the first event
    if raw_logs:

        print("\nFirst parsed SecurityEvent:")

        event = parse_log(raw_logs[0])

        print(event)