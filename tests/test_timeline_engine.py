from datetime import datetime, timedelta, timezone

from backend.evidence_model import SecurityEvidence
from backend.investigation_model import SecurityInvestigation
from backend.timeline_model import (
    SecurityTimeline,
)

from timeline.timeline_engine import build_timeline


def create_investigation() -> SecurityInvestigation:
    return SecurityInvestigation(
        investigation_id="INV-001",
        incident_id="INC-001",
        objective="Investigate suspicious activity.",
    )


def create_evidence() -> list[SecurityEvidence]:
    start_time = datetime.now(timezone.utc)

    return [
        SecurityEvidence(
            evidence_id="EVD-003",
            investigation_id="INV-001",
            timestamp=start_time
            + timedelta(minutes=5),
            evidence_type="privilege",
            source="test_source",
            description="sudo executed.",
            source_event_ids=["EVENT-003"],
            source_alert_ids=["ALT-002"],
            host="test-host",
            username="testuser",
            process="/usr/bin/sudo",
        ),
        SecurityEvidence(
            evidence_id="EVD-001",
            investigation_id="INV-001",
            timestamp=start_time,
            evidence_type="authentication",
            source="test_source",
            description="Login failed.",
            source_event_ids=["EVENT-001"],
            source_alert_ids=["ALT-001"],
            host="test-host",
            username="testuser",
            source_ip="10.0.0.5",
        ),
        SecurityEvidence(
            evidence_id="EVD-002",
            investigation_id="INV-001",
            timestamp=start_time
            + timedelta(minutes=2),
            evidence_type="authentication",
            source="test_source",
            description="Login failed.",
            source_event_ids=["EVENT-002"],
            source_alert_ids=["ALT-001"],
            host="test-host",
            username="testuser",
            source_ip="10.0.0.5",
        ),
    ]


def test_build_timeline_returns_security_timeline():
    investigation = create_investigation()
    evidence = create_evidence()

    timeline = build_timeline(
        investigation=investigation,
        evidence=evidence,
    )

    assert isinstance(
        timeline,
        SecurityTimeline,
    )


def test_timeline_is_sorted_chronologically():
    investigation = create_investigation()
    evidence = create_evidence()

    timeline = build_timeline(
        investigation=investigation,
        evidence=evidence,
    )

    timestamps = [
        entry.timestamp
        for entry in timeline.entries
    ]

    assert timestamps == sorted(timestamps)


def test_timeline_preserves_evidence_order():
    investigation = create_investigation()
    evidence = create_evidence()

    timeline = build_timeline(
        investigation=investigation,
        evidence=evidence,
    )

    assert [
        entry.evidence_id
        for entry in timeline.entries
    ] == [
        "EVD-001",
        "EVD-002",
        "EVD-003",
    ]


def test_timeline_preserves_context():
    investigation = create_investigation()
    evidence = create_evidence()

    timeline = build_timeline(
        investigation=investigation,
        evidence=evidence,
    )

    first_entry = timeline.entries[0]

    assert first_entry.evidence_type == "authentication"
    assert first_entry.host == "test-host"
    assert first_entry.username == "testuser"
    assert first_entry.source_ip == "10.0.0.5"


def test_entry_count_is_correct():
    investigation = create_investigation()
    evidence = create_evidence()

    timeline = build_timeline(
        investigation=investigation,
        evidence=evidence,
    )

    assert timeline.entry_count == 3
    assert len(timeline.entries) == 3


def test_timeline_uses_investigation_id():
    investigation = create_investigation()
    evidence = create_evidence()

    timeline = build_timeline(
        investigation=investigation,
        evidence=evidence,
    )

    assert timeline.investigation_id == "INV-001"


def test_empty_evidence_creates_empty_timeline():
    investigation = create_investigation()

    timeline = build_timeline(
        investigation=investigation,
        evidence=[],
    )

    assert isinstance(
        timeline,
        SecurityTimeline,
    )

    assert timeline.entries == []
    assert timeline.entry_count == 0