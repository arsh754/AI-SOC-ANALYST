from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SecurityAlert(BaseModel):
    """
    Standardized security alert used by the AI SOC Analyst.

    Detection rules generate findings, and those findings
    are converted into this common alert structure.

    The alert model is designed to provide enough context
    for future correlation, AI investigation, evidence
    collection, response, and SOC dashboard components.
    """

    # ---------------------------------------------------------
    # Alert identity
    # ---------------------------------------------------------

    alert_id: str

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    attack_type: str
    category: str

    # ---------------------------------------------------------
    # Risk assessment
    # ---------------------------------------------------------

    severity: str
    confidence: float = Field(
        ge=0.0,
        le=1.0
    )

    # ---------------------------------------------------------
    # Detection information
    # ---------------------------------------------------------

    detection_rule: str
    description: str

    # ---------------------------------------------------------
    # Host / user context
    # ---------------------------------------------------------

    host: str | None = None
    username: str | None = None

    # ---------------------------------------------------------
    # Network context
    # ---------------------------------------------------------

    source_ip: str | None = None

    # ---------------------------------------------------------
    # Process context
    # ---------------------------------------------------------

    process: str | None = None

    # ---------------------------------------------------------
    # File context
    # ---------------------------------------------------------

    file_path: str | None = None

    # ---------------------------------------------------------
    # Evidence / correlation context
    # ---------------------------------------------------------

    event_count: int | None = None

    source_event_ids: list[str] = Field(
        default_factory=list
    )