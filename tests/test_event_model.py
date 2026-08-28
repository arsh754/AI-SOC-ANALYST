from backend.event_model import SecurityEvent


event = SecurityEvent(
    event_id="evt-0001",
    timestamp="2026-08-27T23:50:00",
    host="LAB-MACHINE-01",
    event_type="authentication",
    action="login_failed",
    source="system_log",
    severity="medium",
    username="admin",
    source_ip="192.168.1.50",
    description="Failed login attempt"
)

print(event)