from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SecurityEvidence(BaseModel):
    """
    Represents a piece of evidence associated with a
    security investigation.

    Evidence may originate from:
    - Raw telemetry
    - Security alerts
    - Process activity
    - File activity
    - Network activity
    - Authentication events
    - Threat intelligence
    - Other forensic sources
    """

    # ---------------------------------------------------------
    # Evidence identity
    # ---------------------------------------------------------

    evidence_id: str

    investigation_id: str

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ---------------------------------------------------------
    # Evidence classification
    # ---------------------------------------------------------

    evidence_type: str

    source: str

    description: str

    # ---------------------------------------------------------
    # Original source reference
    # ---------------------------------------------------------

    source_event_ids: list[str] = Field(
        default_factory=list
    )

    source_alert_ids: list[str] = Field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # Technical context
    # ---------------------------------------------------------

    host: str | None = None

    username: str | None = None

    source_ip: str | None = None

    process: str | None = None

    file_path: str | None = None

    # ---------------------------------------------------------
    # Raw evidence
    # ---------------------------------------------------------

    raw_data: dict | None = None

    # ---------------------------------------------------------
    # Integrity
    # ---------------------------------------------------------

    integrity_hash: str | None = None

    # ---------------------------------------------------------
    # Evidence provenance
    # ---------------------------------------------------------

    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    collector: str | None = None