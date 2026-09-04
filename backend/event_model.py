from datetime import datetime

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    """
    Standard security event used throughout the AI SOC Analyst.

    Every collector, parser, classifier, detection rule,
    correlation engine, and future AI component will work
    with this common event structure.
    """

    event_id: str
    timestamp: datetime

    host: str

    event_type: str
    action: str
    source: str
    severity: str

    username: str | None = None
    source_ip: str | None = None

    description: str

    subsystem: str | None = None
    category: str | None = None

    process_path: str | None = None
    file_path: str | None = None

    message_type: str | None = None
    raw_message: str