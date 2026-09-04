from pathlib import Path
from uuid import uuid4

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert


PRIVILEGE_PROCESSES = [
    "sudo",
    "su",
    "doas",
]


def detect_privilege_escalation(
    events: list[SecurityEvent],
) -> list[SecurityAlert]:
    """
    Detect potentially suspicious privilege escalation activity.

    The detector looks for execution of common privilege-related
    programs such as sudo, su, and doas.

    Detection of these programs does not automatically mean
    an attack occurred. They may also be used legitimately.
    Therefore, the generated alert represents potentially
    suspicious privilege activity that should be investigated.
    """

    alerts = []

    for event in events:

        # Only analyze process execution events.
        if event.event_type != "process":
            continue

        process_path = (event.process_path or "").strip()

        if not process_path:
            continue

        # Extract the executable name.
        #
        # Example:
        # /usr/bin/sudo
        #
        # becomes:
        # sudo
        process_name = Path(process_path).name.lower()

        if process_name not in PRIVILEGE_PROCESSES:
            continue

        # Create the standardized SOC alert.
        alert = SecurityAlert(
            alert_id=f"ALT-{uuid4().hex[:8].upper()}",
            attack_type="Privilege Escalation",
            category="Privilege",
            severity="high",
            confidence=0.85,
            detection_rule="PRIVILEGE_ESCALATION",
            description=(
                f"Potential privilege escalation activity "
                f"detected through {process_name}."
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