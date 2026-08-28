import platform
import socket
from datetime import datetime

from backend.event_model import SecurityEvent


def create_system_event(
    event_type: str,
    action: str,
    severity: str,
    description: str,
    username: str | None = None,
    source_ip: str | None = None
) -> SecurityEvent:

    event = SecurityEvent(
        event_id=f"evt-{datetime.now().timestamp()}",
        timestamp=datetime.now(),
        host=socket.gethostname(),
        event_type=event_type,
        action=action,
        source="system_collector",
        severity=severity,
        username=username,
        source_ip=source_ip,
        description=description
    )

    return event


if __name__ == "__main__":

    print("AI SOC Analyst - System Collector")
    print("----------------------------------")

    print(f"Operating System: {platform.system()}")
    print(f"OS Version: {platform.version()}")
    print(f"Hostname: {socket.gethostname()}")

    event = create_system_event(
        event_type="system",
        action="collector_started",
        severity="low",
        description="System collector started successfully"
    )

    print("\nGenerated Security Event:")
    print(event)