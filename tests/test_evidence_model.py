from datetime import datetime, timezone

from backend.evidence_model import SecurityEvidence


def test_security_evidence_creation():
    evidence = SecurityEvidence(
        evidence_id="EV-0001",
        investigation_id="INV-0001",
        evidence_type="process",
        source="macos_unified_log",
        description=(
            "Suspicious curl process execution detected."
        ),
        source_event_ids=[
            "macos-event-001",
        ],
        source_alert_ids=[
            "ALT-0001",
        ],
        host="test-host",
        username="testuser",
        process="/usr/bin/curl",
        raw_data={
            "eventMessage": (
                "Process started: /usr/bin/curl"
            ),
            "processID": 1234,
        },
        integrity_hash="abc123",
        collector="macos_log_collector",
    )

    assert evidence.evidence_id == "EV-0001"
    assert evidence.investigation_id == "INV-0001"
    assert evidence.evidence_type == "process"
    assert evidence.source == "macos_unified_log"

    assert evidence.source_event_ids == [
        "macos-event-001",
    ]

    assert evidence.source_alert_ids == [
        "ALT-0001",
    ]

    assert evidence.host == "test-host"
    assert evidence.username == "testuser"
    assert evidence.process == "/usr/bin/curl"

    assert evidence.raw_data["processID"] == 1234

    assert evidence.integrity_hash == "abc123"
    assert evidence.collector == "macos_log_collector"


def test_evidence_supports_optional_context():
    evidence = SecurityEvidence(
        evidence_id="EV-0002",
        investigation_id="INV-0002",
        evidence_type="network",
        source="test",
        description="Network evidence.",
    )

    assert evidence.host is None
    assert evidence.username is None
    assert evidence.source_ip is None
    assert evidence.process is None
    assert evidence.file_path is None
    assert evidence.raw_data is None
    assert evidence.integrity_hash is None
    assert evidence.collector is None

    assert evidence.source_event_ids == []
    assert evidence.source_alert_ids == []


def test_evidence_timestamps_are_utc():
    evidence = SecurityEvidence(
        evidence_id="EV-0003",
        investigation_id="INV-0003",
        evidence_type="log",
        source="test",
        description="Test evidence.",
    )

    assert isinstance(
        evidence.timestamp,
        datetime,
    )

    assert isinstance(
        evidence.collected_at,
        datetime,
    )

    assert evidence.timestamp.tzinfo == timezone.utc
    assert evidence.collected_at.tzinfo == timezone.utc


def test_network_evidence():
    evidence = SecurityEvidence(
        evidence_id="EV-0004",
        investigation_id="INV-0004",
        evidence_type="network",
        source="suricata",
        description="Suspicious outbound connection.",
        source_ip="192.168.1.50",
        raw_data={
            "destination_ip": "10.0.0.50",
            "destination_port": 4444,
        },
    )

    assert evidence.evidence_type == "network"
    assert evidence.source == "suricata"
    assert evidence.source_ip == "192.168.1.50"
    assert evidence.raw_data["destination_port"] == 4444


def test_file_evidence():
    evidence = SecurityEvidence(
        evidence_id="EV-0005",
        investigation_id="INV-0005",
        evidence_type="file",
        source="filesystem",
        description="Suspicious script created.",
        host="test-host",
        username="testuser",
        file_path="/tmp/payload.sh",
    )

    assert evidence.evidence_type == "file"
    assert evidence.file_path == "/tmp/payload.sh"