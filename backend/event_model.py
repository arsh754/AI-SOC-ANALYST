from datetime import datetime
from pydantic import BaseModel


class SecurityEvent(BaseModel):
    # Basic event information
    event_id: str
    timestamp: datetime
    host: str

    # Security classification
    event_type: str
    action: str
    source: str
    severity: str

    # Identity and network information
    username: str | None = None
    source_ip: str | None = None

    # Human-readable information
    description: str | None = None

    # Original macOS telemetry
    subsystem: str | None = None
    category: str | None = None
    process_path: str | None = None
    message_type: str | None = None
    raw_message: str | None = None