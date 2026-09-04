from pathlib import Path
from uuid import uuid4

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert


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
) -> list[SecurityAlert]:
    """
    Detect potentially suspicious file activity.

    An alert is generated when a file event involves
    a suspicious location or potentially interesting
    executable/script file type.

    Detection of these characteristics does not automatically
    mean malicious activity occurred. The alert represents
    potentially suspicious behavior that should be investigated.
    """

    alerts = []

    for event in events:

        # Only analyze file events.
        if event.event_type != "file":
            continue

        file_path = (event.file_path or "").strip()

        if not file_path:
            continue

        normalized_path = file_path.lower()

        filename = Path(file_path).name.lower()

        suspicious_reason = None

        # -----------------------------------------------------
        # Check suspicious locations.
        # -----------------------------------------------------

        for path in SUSPICIOUS_PATHS:

            if normalized_path.startswith(path):

                suspicious_reason = (
                    f"File activity in suspicious location: {path}"
                )

                break

        # -----------------------------------------------------
        # Check suspicious extensions.
        # -----------------------------------------------------

        if suspicious_reason is None:

            for extension in SUSPICIOUS_EXTENSIONS:

                if filename.endswith(extension):

                    suspicious_reason = (
                        f"Potentially interesting file type: {extension}"
                    )

                    break

        # -----------------------------------------------------
        # Ignore normal file activity.
        # -----------------------------------------------------

        if suspicious_reason is None:
            continue

        # -----------------------------------------------------
        # Create standardized SecurityAlert.
        # -----------------------------------------------------

        alert = SecurityAlert(
            alert_id=f"ALT-{uuid4().hex[:8].upper()}",
            attack_type="Suspicious File Activity",
            category="File",
            severity="medium",
            confidence=0.80,
            detection_rule="SUSPICIOUS_FILE_ACTIVITY",
            description=suspicious_reason,
            host=event.host,
            username=event.username,
            file_path=file_path,
            source_event_ids=[
                event.event_id
            ],
        )

        alerts.append(alert)

    return alerts