from pathlib import Path

from backend.event_model import SecurityEvent


SUSPICIOUS_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/dev/shm/",
]


SUSPICIOUS_EXTENSIONS = [
    ".sh",
    ".command",
    ".dmg",
    ".pkg",
]


def detect_suspicious_file_activity(
    events: list[SecurityEvent],
) -> list[dict]:
    """
    Detect potentially suspicious file activity.

    An alert is generated when a file event involves
    a suspicious location or potentially interesting
    executable/script file type.
    """

    alerts = []

    for event in events:

        if event.event_type != "file":
            continue

        file_path = (event.file_path or "").strip()

        if not file_path:
            continue

        normalized_path = file_path.lower()

        filename = Path(file_path).name.lower()

        suspicious_reason = None

        # Check suspicious locations
        for path in SUSPICIOUS_PATHS:

            if normalized_path.startswith(path):
                suspicious_reason = (
                    f"File activity in suspicious location: {path}"
                )
                break

        # Check suspicious extensions
        if suspicious_reason is None:

            for extension in SUSPICIOUS_EXTENSIONS:

                if filename.endswith(extension):
                    suspicious_reason = (
                        f"Potentially interesting file type: {extension}"
                    )
                    break

        if suspicious_reason is None:
            continue

        alerts.append({
            "alert_type": "suspicious_file_activity",
            "severity": "medium",
            "file_path": file_path,
            "action": event.action,
            "host": event.host,
            "description": suspicious_reason,
        })

    return alerts