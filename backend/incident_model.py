from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SecurityIncident(BaseModel):
    """
    Represents a higher-level security incident.

    An incident groups multiple related SecurityAlert objects
    that may belong to the same attack or security situation.

    This model will later be used by:
    - Alert Correlation
    - AI Investigation
    - Evidence Collection
    - Response / Containment
    - SOC Dashboard
    """

    # ---------------------------------------------------------
    # Incident identity
    # ---------------------------------------------------------

    incident_id: str

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ---------------------------------------------------------
    # Incident classification
    # ---------------------------------------------------------

    title: str
    attack_type: str
    category: str

    # ---------------------------------------------------------
    # Risk assessment
    # ---------------------------------------------------------

    severity: str

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    correlation_score: float = Field(
        ge=0.0,
        le=1.0,
    )

    # ---------------------------------------------------------
    # Investigation status
    # ---------------------------------------------------------

    status: str = "new"

    # ---------------------------------------------------------
    # Incident description
    # ---------------------------------------------------------

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
    # Correlated alerts
    # ---------------------------------------------------------

    alert_ids: list[str] = Field(
        default_factory=list
    )

    alert_count: int | None = None