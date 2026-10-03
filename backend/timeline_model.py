from datetime import datetime, timezone

from pydantic import BaseModel, Field


class TimelineEntry(BaseModel):
    """
    Represents one chronological event in a security
    investigation timeline.
    """

    entry_id: str

    timestamp: datetime

    evidence_id: str

    evidence_type: str

    title: str

    description: str

    source: str

    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    process: str | None = None
    file_path: str | None = None


class SecurityTimeline(BaseModel):
    """
    Represents the chronological timeline of a
    security investigation.
    """

    timeline_id: str

    investigation_id: str

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    entries: list[TimelineEntry] = Field(
        default_factory=list
    )

    entry_count: int = 0