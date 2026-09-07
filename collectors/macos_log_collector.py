import json
import socket
import subprocess
from datetime import datetime, timezone

from backend.event_model import SecurityEvent


def collect_macos_logs(minutes: int = 1) -> list[dict]:
    """
    Collect macOS Unified Log events from the last few minutes.
    """

    command = [
        "log",
        "show",
        "--last",
        f"{minutes}m",
        "--style",
        "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
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

    if not isinstance(logs, list):
        print("Unexpected macOS log format.")
        return []

    return logs


def parse_timestamp(timestamp: str | None) -> datetime:
    """
    Convert a macOS timestamp into a timezone-aware datetime.
    """

    if not timestamp:
        return datetime.now(timezone.utc)

    try:
        event_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        if event_time.tzinfo is None:
            event_time = event_time.replace(
                tzinfo=timezone.utc
            )

        return event_time

    except ValueError:
        return datetime.now(timezone.utc)


def classify_macos_event(
    raw_log: dict,
) -> tuple[str, str]:
    """
    Determine the broad event type and specific action.

    This function identifies what happened.
    It does NOT decide whether the activity is malicious.
    """

    message = (
        raw_log.get("eventMessage") or ""
    ).strip().lower()

    subsystem = (
        raw_log.get("subsystem") or ""
    ).strip().lower()

    category = (
        raw_log.get("category") or ""
    ).strip().lower()

    process_path = (
        raw_log.get("processImagePath") or ""
    ).strip().lower()

    combined = " ".join(
        [
            message,
            subsystem,
            category,
            process_path,
        ]
    )

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    authentication_indicators = [
        "loginwindow",
        "authentication",
        "authd",
        "opendirectory",
        "securityagent",
        "login failed",
        "login succeeded",
        "password incorrect",
    ]

    if any(
        indicator in combined
        for indicator in authentication_indicators
    ):

        if any(
            indicator in combined
            for indicator in [
                "login failed",
                "failed login",
                "authentication failed",
                "auth failed",
                "password incorrect",
                "invalid password",
            ]
        ):
            return "authentication", "login_failed"

        if any(
            indicator in combined
            for indicator in [
                "login succeeded",
                "login successful",
                "authentication succeeded",
                "authentication successful",
            ]
        ):
            return "authentication", "login_success"

        return "authentication", "authentication_event"

    # ---------------------------------------------------------
    # Privilege / authorization
    # ---------------------------------------------------------

    if "/sudo" in combined or " sudo " in f" {combined} ":

        return "privilege", "sudo"

    if any(
        indicator in combined
        for indicator in [
            "authorization",
            "authorizationexecute",
            "privilege",
            "securityagent",
        ]
    ):

        return "privilege", "authorization_event"

    # ---------------------------------------------------------
    # File activity
    # ---------------------------------------------------------

    if any(
        indicator in combined
        for indicator in [
            "file created",
            "file modified",
            "file deleted",
            "file renamed",
            "createfile",
            "removefile",
        ]
    ):

        if "file created" in combined or "createfile" in combined:
            return "file", "file_created"

        if "file modified" in combined:
            return "file", "file_modified"

        if "file deleted" in combined or "removefile" in combined:
            return "file", "file_deleted"

        if "file renamed" in combined:
            return "file", "file_renamed"

        return "file", "file_event"

    # ---------------------------------------------------------
    # Process activity
    # ---------------------------------------------------------

    if any(
        indicator in combined
        for indicator in [
            "process started",
            "process launched",
            "process exited",
            "process terminated",
        ]
    ):

        if (
            "process started" in combined
            or "process launched" in combined
        ):
            return "process", "process_started"

        if (
            "process exited" in combined
            or "process terminated" in combined
        ):
            return "process", "process_exited"

        return "process", "process_event"

    # ---------------------------------------------------------
    # Network activity
    # ---------------------------------------------------------

    if any(
        indicator in combined
        for indicator in [
            "dns",
            "socket",
            "tcp",
            "udp",
            "connection",
            "cfnetwork",
            "mdns",
            "wifimanager",
            "network",
        ]
    ):

        if "dns" in combined:
            return "network", "dns_activity"

        if "connection" in combined:
            return "network", "connection"

        return "network", "network_event"

    # ---------------------------------------------------------
    # General system activity
    # ---------------------------------------------------------

    return "system", "log_event"


def parse_log(raw_log: dict) -> SecurityEvent:
    """
    Convert one raw macOS log event into SecurityEvent.
    """

    timestamp = raw_log.get("timestamp")

    event_time = parse_timestamp(timestamp)

    message = (
        raw_log.get("eventMessage") or ""
    ).strip()

    subsystem = raw_log.get("subsystem") or None
    category = raw_log.get("category") or None
    process_path = raw_log.get("processImagePath") or None
    message_type = raw_log.get("messageType") or None

    event_type, action = classify_macos_event(
        raw_log
    )

    description = (
        message
        if message
        else "macOS system event"
    )

    raw_event_id = (
        raw_log.get("activityIdentifier")
        or raw_log.get("processID")
        or "unknown"
    )

    event_id = (
        f"macos-{timestamp}-{raw_event_id}"
    )

    return SecurityEvent(
        event_id=event_id,
        timestamp=event_time,
        host=socket.gethostname(),
        event_type=event_type,
        action=action,
        source="macos_unified_log",
        severity="low",
        description=description,
        subsystem=subsystem,
        category=category,
        process_path=process_path,
        file_path=None,
        message_type=message_type,
        raw_message=message,
    )


if __name__ == "__main__":

    print("AI SOC Analyst - macOS Log Collector")
    print("--------------------------------------")

    raw_logs = collect_macos_logs(minutes=1)

    print(
        f"Collected {len(raw_logs)} raw log events."
    )

    if raw_logs:

        print("\nFirst parsed SecurityEvent:")

        event = parse_log(raw_logs[0])

        print(event)

        print("\nEvent classification:")
        print(f"  Type:   {event.event_type}")
        print(f"  Action: {event.action}")
        print(f"  Source: {event.source}")