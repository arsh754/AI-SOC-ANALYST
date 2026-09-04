from pathlib import Path

from backend.event_model import SecurityEvent


PRIVILEGE_PROCESSES = [
    "sudo",
    "su",
    "doas",
]


def detect_privilege_escalation(
    events: list[SecurityEvent],
) -> list[dict]:
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

        # We are interested in process execution events.
        if event.event_type != "process":
            continue

        process_path = (event.process_path or "").strip()

        if not process_path:
            continue

        # Extract only the executable name.
        #
        # Example:
        # /usr/bin/sudo
        #
        # becomes:
        # sudo
        process_name = Path(process_path).name.lower()

        if process_name not in PRIVILEGE_PROCESSES:
            continue

        alerts.append({
            "alert_type": "privilege_escalation",
            "severity": "high",
            "process": process_name,
            "host": event.host,
            "username": event.username,
            "description": (
                f"Potential privilege escalation activity detected "
                f"through {process_name}."
            ),
        })

    return alerts