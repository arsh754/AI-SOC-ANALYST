from datetime import datetime, timezone

from backend.alert_model import SecurityAlert
from backend.event_model import SecurityEvent
from backend.evidence_model import SecurityEvidence
from backend.incident_model import SecurityIncident
from backend.investigation_model import SecurityInvestigation

from collectors.evidence_collector import (
    collect_evidence,
)


def create_investigation() -> SecurityInvestigation:
    return SecurityInvestigation(
        investigation_id="INV-001",
        incident_id="INC-001",
        objective="Investigate suspicious authentication activity.",
    )


def create_incident() -> SecurityIncident:
    return SecurityIncident(
        incident_id="INC-001",
        title="Potential Multi-Stage Attack",
        attack_type="Multi-Stage Attack",
        category="Multiple",
        severity="high",
        confidence=0.90,
        correlation_score=0.85,
        description="Test incident.",
        alert_ids=[
            "ALT-001",
            "ALT-002",
        ],
        alert_count=2,
    )


def create_alerts() -> list[SecurityAlert]:
    return [
        SecurityAlert(
            alert_id="ALT-001",
            attack_type="Brute Force",
            category="Authentication",
            severity="high",
            confidence=0.90,
            detection_rule="BRUTE_FORCE_AUTH",
            description="Multiple failed logins detected.",
            host="test-host",
            username="testuser",
            source_ip="10.0.0.5",
            source_event_ids=[
                "EVENT-001",
                "EVENT-002",
            ],
        ),
        SecurityAlert(
            alert_id="ALT-002",
            attack_type="Privilege Escalation",
            category="Privilege",
            severity="high",
            confidence=0.85,
            detection_rule="PRIVILEGE_ESCALATION",
            description="Potential sudo activity detected.",
            host="test-host",
            username="testuser",
            source_event_ids=[
                "EVENT-003",
            ],
        ),
    ]


def create_events() -> list[SecurityEvent]:
    timestamp = datetime.now(timezone.utc)

    return [
        SecurityEvent(
            event_id="EVENT-001",
            timestamp=timestamp,
            host="test-host",
            event_type="authentication",
            action="login_failed",
            source="test_source",
            severity="low",
            username="testuser",
            source_ip="10.0.0.5",
            description="Failed login attempt.",
            raw_message="Login failed.",
        ),
        SecurityEvent(
            event_id="EVENT-002",
            timestamp=timestamp,
            host="test-host",
            event_type="authentication",
            action="login_failed",
            source="test_source",
            severity="low",
            username="testuser",
            source_ip="10.0.0.5",
            description="Failed login attempt.",
            raw_message="Login failed.",
        ),
        SecurityEvent(
            event_id="EVENT-003",
            timestamp=timestamp,
            host="test-host",
            event_type="privilege",
            action="sudo",
            source="test_source",
            severity="medium",
            username="testuser",
            description="sudo command executed.",
            process_path="/usr/bin/sudo",
            raw_message="sudo executed.",
        ),
        SecurityEvent(
            event_id="EVENT-999",
            timestamp=timestamp,
            host="other-host",
            event_type="network",
            action="connection",
            source="test_source",
            severity="low",
            description="Unrelated network event.",
            raw_message="Network connection.",
        ),
    ]


def test_collects_evidence_from_incident_alerts():
    investigation = create_investigation()
    incident = create_incident()
    alerts = create_alerts()
    events = create_events()

    evidence = collect_evidence(
        investigation=investigation,
        incident=incident,
        alerts=alerts,
        events=events,
    )

    assert len(evidence) == 3

    assert all(
        isinstance(
            item,
            SecurityEvidence,
        )
        for item in evidence
    )


def test_evidence_preserves_traceability():
    investigation = create_investigation()
    incident = create_incident()
    alerts = create_alerts()
    events = create_events()

    evidence = collect_evidence(
        investigation=investigation,
        incident=incident,
        alerts=alerts,
        events=events,
    )

    event_ids = {
        item.source_event_ids[0]
        for item in evidence
    }

    assert event_ids == {
        "EVENT-001",
        "EVENT-002",
        "EVENT-003",
    }

    evidence_by_event = {
        item.source_event_ids[0]: item
        for item in evidence
    }

    assert evidence_by_event[
        "EVENT-001"
    ].source_alert_ids == ["ALT-001"]

    assert evidence_by_event[
        "EVENT-003"
    ].source_alert_ids == ["ALT-002"]


def test_evidence_preserves_event_context():
    investigation = create_investigation()
    incident = create_incident()
    alerts = create_alerts()
    events = create_events()

    evidence = collect_evidence(
        investigation=investigation,
        incident=incident,
        alerts=alerts,
        events=events,
    )

    process_evidence = next(
        item
        for item in evidence
        if item.source_event_ids == ["EVENT-003"]
    )

    assert process_evidence.evidence_type == "privilege"
    assert process_evidence.host == "test-host"
    assert process_evidence.username == "testuser"
    assert process_evidence.process == "/usr/bin/sudo"


def test_unrelated_events_are_not_collected():
    investigation = create_investigation()
    incident = create_incident()
    alerts = create_alerts()
    events = create_events()

    evidence = collect_evidence(
        investigation=investigation,
        incident=incident,
        alerts=alerts,
        events=events,
    )

    event_ids = {
        item.source_event_ids[0]
        for item in evidence
    }

    assert "EVENT-999" not in event_ids


def test_integrity_hash_is_generated():
    investigation = create_investigation()
    incident = create_incident()
    alerts = create_alerts()
    events = create_events()

    evidence = collect_evidence(
        investigation=investigation,
        incident=incident,
        alerts=alerts,
        events=events,
    )

    assert all(
        item.integrity_hash is not None
        for item in evidence
    )

    assert all(
        len(item.integrity_hash) == 64
        for item in evidence
    )


def test_no_matching_alerts_returns_empty_list():
    investigation = create_investigation()

    incident = SecurityIncident(
        incident_id="INC-002",
        title="Unrelated Incident",
        attack_type="Test",
        category="Test",
        severity="low",
        confidence=0.50,
        correlation_score=0.50,
        description="No matching alerts.",
        alert_ids=["ALT-999"],
    )

    evidence = collect_evidence(
        investigation=investigation,
        incident=incident,
        alerts=create_alerts(),
        events=create_events(),
    )

    assert evidence == []