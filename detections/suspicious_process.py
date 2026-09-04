from pathlib import Path
from uuid import uuid4

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert


SUSPICIOUS_PROCESSES = [
    "nc",
    "netcat",
    "ncat",
    "bash",
    "sh",
    "zsh",
    "curl",
    "wget",
]


def detect_suspicious_process(
    events: list[SecurityEvent],
) -> list[SecurityAlert]:
    """
    Detect potentially suspicious process executions.

    An alert is generated when the executable name matches
    a process in the suspicious-process list.

    Detection of a process does not automatically mean that
    malicious activity occurred. The alert represents
    potentially suspicious behavior that should be investigated.
    """

    alerts = []

    for event in events:

        # We only care about process execution events.
        if event.event_type != "process":
            continue

        process_path = (event.process_path or "").strip()

        if not process_path:
            continue

        # Extract the executable name from the complete path.
        #
        # Example:
        # /usr/bin/curl
        #
        # becomes:
        # curl
        process_name = Path(process_path).name.lower()

        # Ignore processes that are not in our suspicious list.
        if process_name not in SUSPICIOUS_PROCESSES:
            continue

        # Create a standardized SecurityAlert.
        alert = SecurityAlert(
            alert_id=f"ALT-{uuid4().hex[:8].upper()}",
            attack_type="Suspicious Process",
            category="Process",
            severity="medium",
            confidence=0.80,
            detection_rule="SUSPICIOUS_PROCESS",
            description=(
                f"Potentially suspicious process detected: "
                f"{process_name}"
            ),
            host=event.host,
            username=event.username,
            process=process_name,
            source_event_ids=[
                event.event_id
            ],
        )

        alerts.append(alert)

    return alerts