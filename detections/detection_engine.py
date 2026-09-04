from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert

from detections.brute_force import detect_brute_force
from detections.suspicious_process import detect_suspicious_process
from detections.file_activity import detect_suspicious_file_activity
from detections.privilege_escalation import detect_privilege_escalation


def run_detections(
    events: list[SecurityEvent],
) -> list[SecurityAlert]:
    """
    Run all security detection rules against a collection
    of SecurityEvent objects.

    Each detection rule analyzes the events and returns
    standardized SecurityAlert objects.

    The Detection Engine combines all alerts into one list.
    """

    alerts: list[SecurityAlert] = []

    # ---------------------------------------------------------
    # 1. Brute-force authentication detection
    # ---------------------------------------------------------

    brute_force_alerts = detect_brute_force(events)

    alerts.extend(brute_force_alerts)

    # ---------------------------------------------------------
    # 2. Suspicious process detection
    # ---------------------------------------------------------

    suspicious_process_alerts = detect_suspicious_process(events)

    alerts.extend(suspicious_process_alerts)

    # ---------------------------------------------------------
    # 3. Suspicious file activity detection
    # ---------------------------------------------------------

    file_activity_alerts = detect_suspicious_file_activity(events)

    alerts.extend(file_activity_alerts)

    # ---------------------------------------------------------
    # 4. Privilege escalation detection
    # ---------------------------------------------------------

    privilege_escalation_alerts = detect_privilege_escalation(events)

    alerts.extend(privilege_escalation_alerts)

    return alerts


if __name__ == "__main__":

    print("AI SOC Analyst — Detection Engine")
    print("=================================")
    print("Detection engine loaded successfully.")