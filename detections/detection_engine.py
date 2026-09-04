from backend.event_model import SecurityEvent

from detections.brute_force import detect_brute_force
from detections.suspicious_process import detect_suspicious_process
from detections.file_activity import detect_suspicious_file_activity
from detections.privilege_escalation import detect_privilege_escalation


def run_detections(events: list[SecurityEvent]) -> list[dict]:
    """
    Run all security detection rules against a collection of events.

    The Detection Engine acts as the central coordinator.
    Each specialized detection rule analyzes the same
    collection of SecurityEvent objects.

    All generated alerts are combined into one list.
    """

    alerts = []

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

    suspicious_file_alerts = detect_suspicious_file_activity(events)
    alerts.extend(suspicious_file_alerts)

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