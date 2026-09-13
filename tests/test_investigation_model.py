from datetime import datetime, timezone

from backend.investigation_model import (
    InvestigationFinding,
    SecurityInvestigation,
)


def test_investigation_creation():
    finding = InvestigationFinding(
        finding_id="FND-0001",
        title="Suspicious Shell Execution",
        description=(
            "A suspicious shell process was executed "
            "after privilege escalation."
        ),
        severity="high",
        confidence=0.91,
        source_alert_ids=[
            "ALT-0001",
            "ALT-0002",
        ],
    )

    investigation = SecurityInvestigation(
        investigation_id="INV-0001",
        incident_id="INC-0001",
        objective=(
            "Determine whether the correlated alerts "
            "represent an account compromise."
        ),
        summary=(
            "Investigation of a possible account compromise."
        ),
        findings=[finding],
        alert_ids=[
            "ALT-0001",
            "ALT-0002",
        ],
        evidence_ids=[
            "EV-0001",
        ],
        ai_assisted=True,
        ai_confidence=0.88,
    )

    assert investigation.investigation_id == "INV-0001"
    assert investigation.incident_id == "INC-0001"
    assert investigation.status == "not_started"

    assert investigation.objective == (
        "Determine whether the correlated alerts "
        "represent an account compromise."
    )

    assert len(investigation.findings) == 1

    assert (
        investigation.findings[0].finding_id
        == "FND-0001"
    )

    assert investigation.alert_ids == [
        "ALT-0001",
        "ALT-0002",
    ]

    assert investigation.evidence_ids == [
        "EV-0001",
    ]

    assert investigation.ai_assisted is True
    assert investigation.ai_confidence == 0.88


def test_investigation_defaults():
    investigation = SecurityInvestigation(
        investigation_id="INV-0002",
        incident_id="INC-0002",
        objective="Investigate suspicious activity.",
    )

    assert investigation.status == "not_started"
    assert investigation.summary is None
    assert investigation.conclusion is None
    assert investigation.findings == []
    assert investigation.alert_ids == []
    assert investigation.evidence_ids == []
    assert investigation.ai_assisted is False
    assert investigation.ai_confidence is None


def test_investigation_timestamp_is_utc():
    investigation = SecurityInvestigation(
        investigation_id="INV-0003",
        incident_id="INC-0003",
        objective="Test investigation.",
    )

    assert isinstance(
        investigation.timestamp,
        datetime,
    )

    assert investigation.timestamp.tzinfo is not None
    assert investigation.timestamp.tzinfo == timezone.utc


def test_finding_confidence_must_be_valid():
    from pydantic import ValidationError

    try:
        InvestigationFinding(
            finding_id="FND-0001",
            title="Invalid Finding",
            description="Invalid confidence.",
            confidence=1.5,
        )

        assert False

    except ValidationError:
        assert True


def test_ai_confidence_must_be_valid():
    from pydantic import ValidationError

    try:
        SecurityInvestigation(
            investigation_id="INV-0004",
            incident_id="INC-0004",
            objective="Invalid investigation.",
            ai_confidence=-0.1,
        )

        assert False

    except ValidationError:
        assert True