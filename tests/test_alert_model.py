from datetime import datetime, timezone

import pytest

from backend.alert_model import SecurityAlert


def test_security_alert_creation():

    alert = SecurityAlert(
        alert_id="ALT-000001",
        timestamp=datetime.now(timezone.utc),
        attack_type="Brute Force",
        category="Authentication",
        severity="high",
        confidence=0.94,
        detection_rule="BRUTE_FORCE_AUTH",
        description=(
            "Multiple failed login attempts detected "
            "from the same source IP."
        ),
        host="test-host",
        username="testuser",
        source_ip="192.168.1.50",
        event_count=5,
        source_event_ids=[
            "login-1",
            "login-2",
            "login-3",
            "login-4",
            "login-5",
        ],
    )

    assert alert.alert_id == "ALT-000001"
    assert alert.attack_type == "Brute Force"
    assert alert.category == "Authentication"
    assert alert.severity == "high"
    assert alert.confidence == 0.94
    assert alert.detection_rule == "BRUTE_FORCE_AUTH"
    assert alert.source_ip == "192.168.1.50"
    assert alert.event_count == 5
    assert len(alert.source_event_ids) == 5


def test_optional_context_fields_can_be_empty():

    alert = SecurityAlert(
        alert_id="ALT-000002",
        attack_type="Suspicious Process",
        category="Process",
        severity="medium",
        confidence=0.80,
        detection_rule="SUSPICIOUS_PROCESS",
        description="Potentially suspicious process detected.",
    )

    assert alert.host is None
    assert alert.username is None
    assert alert.source_ip is None
    assert alert.process is None
    assert alert.file_path is None
    assert alert.event_count is None
    assert alert.source_event_ids == []


def test_confidence_must_be_between_zero_and_one():

    with pytest.raises(ValueError):

        SecurityAlert(
            alert_id="ALT-000003",
            attack_type="Test",
            category="Test",
            severity="low",
            confidence=1.5,
            detection_rule="TEST_RULE",
            description="Invalid confidence value.",
        )