from collections import Counter

from collectors.macos_log_collector import (
    collect_macos_logs,
    parse_log,
)
from detections.detection_engine import run_detections


def run_soc_pipeline(minutes: int = 1):
    """
    Run the complete AI SOC Analyst telemetry pipeline.

    Flow:

        macOS logs
            ↓
        Parser
            ↓
        SecurityEvent
            ↓
        Detection Engine
            ↓
        Security Alerts
    """

    print()
    print("=" * 60)
    print("             AI SOC ANALYST")
    print("             LIVE PIPELINE")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. Collect raw macOS telemetry
    # ---------------------------------------------------------

    print("\n[1] Collecting macOS telemetry...")

    raw_logs = collect_macos_logs(minutes=minutes)

    print(
        f"    Raw events collected: {len(raw_logs)}"
    )

    if not raw_logs:
        print("    No logs collected.")
        return

    # ---------------------------------------------------------
    # 2. Parse raw logs into SecurityEvents
    # ---------------------------------------------------------

    print("\n[2] Parsing telemetry...")

    security_events = []

    for raw_log in raw_logs:

        try:
            event = parse_log(raw_log)
            security_events.append(event)

        except Exception as error:
            print(
                f"    Warning: Could not parse event: {error}"
            )

    print(
        f"    SecurityEvents created: "
        f"{len(security_events)}"
    )

    # ---------------------------------------------------------
    # 3. Summarize event classifications
    # ---------------------------------------------------------

    print("\n[3] Event classification summary...")

    event_types = Counter(
        event.event_type
        for event in security_events
    )

    if event_types:

        for event_type, count in event_types.most_common():

            print(
                f"    {event_type:<20} {count}"
            )

    # ---------------------------------------------------------
    # 4. Run Detection Engine
    # ---------------------------------------------------------

    print("\n[4] Running detection engine...")

    alerts = run_detections(security_events)

    print(
        f"    Alerts generated: {len(alerts)}"
    )

    # ---------------------------------------------------------
    # 5. Display alerts
    # ---------------------------------------------------------

    print("\n[5] Security alerts")

    print("-" * 60)

    if not alerts:

        print("    No security alerts detected.")

    else:

        for number, alert in enumerate(
            alerts,
            start=1
        ):

            print()
            print(
                f"    ALERT #{number}"
            )
            print(
                f"    Type:     {alert.alert_type}"
            )
            print(
                f"    Severity: {alert.severity}"
            )

            if alert.description:
                print(
                    f"    Details:  "
                    f"{alert.description}"
                )

            # Display additional alert context
            # without assuming every alert has the
            # same fields.
            context = alert.model_dump(
                exclude_none=True
            )

            context.pop("alert_type", None)
            context.pop("severity", None)
            context.pop("description", None)

            for key, value in context.items():

                print(
                    f"    {key}: {value}"
                )

            print("-" * 60)

    # ---------------------------------------------------------
    # 6. Final SOC summary
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("                 SOC SUMMARY")
    print("=" * 60)

    print(
        f"Raw telemetry:       {len(raw_logs)}"
    )

    print(
        f"Parsed events:       {len(security_events)}"
    )

    print(
        f"Security alerts:     {len(alerts)}"
    )

    print("=" * 60)
    print()


if __name__ == "__main__":

    run_soc_pipeline(minutes=1)