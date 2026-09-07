from collections import defaultdict
from datetime import timedelta
from uuid import uuid4

from backend.event_model import SecurityEvent
from backend.alert_model import SecurityAlert


SUSPICIOUS_PORTS = [
    23,
    445,
    3389,
    4444,
]


def detect_suspicious_network_activity(
    events: list[SecurityEvent],
    connection_threshold: int = 5,
    window_minutes: int = 5,
) -> list[SecurityAlert]:
    """
    Detect potentially suspicious network activity.

    Looks for:
    1. Connections involving suspicious ports.
    2. Repeated identical network connections
       within a short time window.
    """

    alerts: list[SecurityAlert] = []

    # ---------------------------------------------------------
    # 1. Detect suspicious ports
    # ---------------------------------------------------------

    for event in events:
        if event.event_type != "network":
            continue

        message = (event.raw_message or "").lower()

        for port in SUSPICIOUS_PORTS:
            if f":{port}" in message or f"port {port}" in message:

                alerts.append(
                    SecurityAlert(
                        alert_id=f"ALT-{uuid4().hex[:8].upper()}",
                        attack_type="Suspicious Network Activity",
                        category="Network",
                        severity="medium",
                        confidence=0.80,
                        detection_rule="SUSPICIOUS_NETWORK_PORT",
                        description=(
                            f"Network activity involving suspicious "
                            f"port {port} was detected."
                        ),
                        host=event.host,
                        username=event.username,
                        source_ip=event.source_ip,
                        source_event_ids=[event.event_id],
                    )
                )

                break

    # ---------------------------------------------------------
    # 2. Detect repeated network connections
    # ---------------------------------------------------------

    destination_events = defaultdict(list)

    for event in events:
        if event.event_type != "network":
            continue

        message = (event.raw_message or "").strip()

        if not message:
            continue

        destination_events[message].append(event)

    for destination, network_events in destination_events.items():

        network_events.sort(
            key=lambda event: event.timestamp
        )

        for i in range(len(network_events)):

            start_time = network_events[i].timestamp

            window_end = (
                start_time
                + timedelta(minutes=window_minutes)
            )

            attempts = [
                event
                for event in network_events[i:]
                if event.timestamp <= window_end
            ]

            if len(attempts) >= connection_threshold:

                alerts.append(
                    SecurityAlert(
                        alert_id=f"ALT-{uuid4().hex[:8].upper()}",
                        attack_type="Suspicious Network Activity",
                        category="Network",
                        severity="medium",
                        confidence=0.75,
                        detection_rule="REPEATED_NETWORK_CONNECTIONS",
                        description=(
                            f"Repeated network activity detected: "
                            f"{len(attempts)} connections within "
                            f"{window_minutes} minutes."
                        ),
                        host=attempts[0].host,
                        username=attempts[0].username,
                        source_ip=attempts[0].source_ip,
                        event_count=len(attempts),
                        source_event_ids=[
                            event.event_id
                            for event in attempts
                        ],
                    )
                )

                break

    return alerts