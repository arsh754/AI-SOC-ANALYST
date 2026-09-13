from datetime import datetime, timezone

from pydantic import BaseModel, Field


class InvestigationFinding(BaseModel):
    """
    Represents a finding discovered during an investigation.
    """

    finding_id: str

    title: str

    description: str

    severity: str = "medium"

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    source_alert_ids: list[str] = Field(
        default_factory=list
    )


class SecurityInvestigation(BaseModel):
    """
    Represents the investigation workspace for a
    SecurityIncident.

    This model will later be used by:
    - Evidence collection
    - Timeline reconstruction
    - Threat intelligence
    - MITRE ATT&CK mapping
    - RAG
    - AI investigation agent
    - Incident reporting
    """

    # ---------------------------------------------------------
    # Investigation identity
    # ---------------------------------------------------------

    investigation_id: str

    incident_id: str

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ---------------------------------------------------------
    # Investigation state
    # ---------------------------------------------------------

    status: str = "not_started"

    # ---------------------------------------------------------
    # Investigation summary
    # ---------------------------------------------------------

    objective: str

    summary: str | None = None

    conclusion: str | None = None

    # ---------------------------------------------------------
    # Investigation findings
    # ---------------------------------------------------------

    findings: list[InvestigationFinding] = Field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # Investigation references
    # ---------------------------------------------------------

    alert_ids: list[str] = Field(
        default_factory=list
    )

    evidence_ids: list[str] = Field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # AI investigation metadata
    # ---------------------------------------------------------

    ai_assisted: bool = False

    ai_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )