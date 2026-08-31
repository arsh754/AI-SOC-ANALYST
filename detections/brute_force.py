from datetime import timedelta
from collections import defaultdict

from backend.event_model import SecurityEvent


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 5
) -> list[dict]:
    """
    Detect possible brute-force login attacks.

    A brute-force alert is generated when the same source IP
    produces multiple failed login attempts within a short
    time window.
    """

    # Group failed login events by source IP
    failed_logins = defaultdict(list)

    for event in events:

        if (
            event.action == "login_failed"
            and event.source_ip is not None
        ):
            failed_logins[event.source_ip].append(event)

    alerts = []

    # Analyze each source IP
    for source_ip, login_events in failed_logins.items():

        # Sort events chronologically
        login_events.sort(key=lambda event: event.timestamp)

        for i in range(len(login_events)):

            start_time = login_events[i].timestamp

            window_end = start_time + timedelta(
                minutes=window_minutes
            )

            attempts = [
                event
                for event in login_events[i:]
                if event.timestamp <= window_end
            ]

            if len(attempts) >= threshold:

                alerts.append({
                    "rule": "BRUTE_FORCE_AUTH",
                    "alert_type": "brute_force",
                    "severity": "high",
                    "source_ip": source_ip,
                    "event_count": len(attempts),
                    "failed_attempts": len(attempts),
                    "window_minutes": window_minutes,
                    "description": (
                        f"Possible brute-force attack detected from "
                        f"{source_ip}: {len(attempts)} failed login "
                        f"attempts within {window_minutes} minutes."
                    )
                })

                break

    return alerts