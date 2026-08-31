from backend.event_model import SecurityEvent
from detections.brute_force import detect_brute_force


def run_detections(events: list[SecurityEvent]) -> list[dict]:
    """
    Run all security detection rules against a collection of events.
    """

    alerts = []

    # Run brute-force detection
    brute_force_alerts = detect_brute_force(events)

    alerts.extend(brute_force_alerts)

    return alerts


if __name__ == "__main__":
    print("AI SOC Analyst — Detection Engine")
    print("---------------------------------")
    print("Detection engine loaded successfully.")