from datetime import timedelta
from collections import defaultdict
from uuid import uuid4

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[SecurityAlert]:
    """
    Detect possible brute-force authentication activity.

    A brute-force alert is generated when the same source IP
    produces multiple failed login attempts within a short
    period of time.
    """

    failed_logins = defaultdict(list)

    # ---------------------------------------------------------
    # Collect failed login events by source IP.
    # ---------------------------------------------------------

    for event in events:

        if (
            event.action == "login_failed"
            and event.source_ip is not None
        ):
            failed_logins[event.source_ip].append(event)

    alerts = []

    # ---------------------------------------------------------
    # Analyze the failed logins from each source IP.
    # ---------------------------------------------------------

    for source_ip, login_events in failed_logins.items():

        login_events.sort(
            key=lambda event: event.timestamp
        )

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

            if len(attempts) < threshold:
                continue

            # -------------------------------------------------
            # Create a standardized SecurityAlert.
            # -------------------------------------------------

            alert = SecurityAlert(
                alert_id=f"ALT-{uuid4().hex[:8].upper()}",
                attack_type="Brute Force",
                category="Authentication",
                severity="high",
                confidence=0.90,
                detection_rule="BRUTE_FORCE_AUTH",
                description=(
                    f"Possible brute-force authentication activity "
                    f"detected from {source_ip}: "
                    f"{len(attempts)} failed login attempts within "
                    f"{window_minutes} minutes."
                ),
                host=attempts[0].host,
                username=attempts[0].username,
                source_ip=source_ip,
                event_count=len(attempts),
                source_event_ids=[
                    event.event_id
                    for event in attempts
                ],
            )

            alerts.append(alert)

            # Generate only one alert for this source IP
            # during this detection run.
            break

    return alerts