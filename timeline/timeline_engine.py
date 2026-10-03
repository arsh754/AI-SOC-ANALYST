from uuid import uuid4

from backend.evidence_model import SecurityEvidence
from backend.investigation_model import SecurityInvestigation
from backend.timeline_model import (
    SecurityTimeline,
    TimelineEntry,
)


def build_timeline(
    investigation: SecurityInvestigation,
    evidence: list[SecurityEvidence],
) -> SecurityTimeline:
    """
    Build a chronological security timeline from
    investigation evidence.
    """

    sorted_evidence = sorted(
        evidence,
        key=lambda item: item.timestamp,
    )

    entries: list[TimelineEntry] = []

    for item in sorted_evidence:
        entry = TimelineEntry(
            entry_id=(
                f"TLE-{uuid4().hex[:8].upper()}"
            ),
            timestamp=item.timestamp,
            evidence_id=item.evidence_id,
            evidence_type=item.evidence_type,
            title=(
                f"{item.evidence_type.title()} Activity"
            ),
            description=item.description,
            source=item.source,
            host=item.host,
            username=item.username,
            source_ip=item.source_ip,
            process=item.process,
            file_path=item.file_path,
        )

        entries.append(entry)

    return SecurityTimeline(
        timeline_id=(
            f"TL-{uuid4().hex[:8].upper()}"
        ),
        investigation_id=(
            investigation.investigation_id
        ),
        entries=entries,
        entry_count=len(entries),
    )