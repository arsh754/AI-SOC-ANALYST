import hashlib
import json
from uuid import uuid4

from backend.alert_model import SecurityAlert
from backend.event_model import SecurityEvent
from backend.evidence_model import SecurityEvidence
from backend.incident_model import SecurityIncident
from backend.investigation_model import SecurityInvestigation


EVENT_TYPE_TO_EVIDENCE_TYPE = {
    "authentication": "authentication",
    "network": "network",
    "process": "process",
    "file": "file",
    "privilege": "privilege",
    "system": "system",
}


def _get_evidence_type(event: SecurityEvent) -> str:
    """
    Convert a SecurityEvent type into an evidence type.
    """

    return EVENT_TYPE_TO_EVIDENCE_TYPE.get(
        event.event_type,
        "security_event",
    )


def _calculate_integrity_hash(
    event: SecurityEvent,
) -> str:
    """
    Calculate a SHA-256 hash of the original event data.

    This allows the evidence record to retain an
    integrity reference to the event that was collected.
    """

    event_data = event.model_dump(
        mode="json",
    )

    serialized_event = json.dumps(
        event_data,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        serialized_event.encode("utf-8")
    ).hexdigest()


def collect_evidence(
    investigation: SecurityInvestigation,
    incident: SecurityIncident,
    alerts: list[SecurityAlert],
    events: list[SecurityEvent],
) -> list[SecurityEvidence]:
    """
    Collect investigation evidence from the events
    associated with an incident's alerts.

    Evidence is collected through this relationship:

        Investigation
              ↓
           Incident
              ↓
            Alerts
              ↓
         Source Events
              ↓
           Evidence
    """

    incident_alert_ids = set(
        incident.alert_ids
    )

    relevant_alerts = [
        alert
        for alert in alerts
        if alert.alert_id in incident_alert_ids
    ]

    if not relevant_alerts:
        return []

    event_to_alerts: dict[str, list[str]] = {}

    for alert in relevant_alerts:
        for event_id in alert.source_event_ids:
            event_to_alerts.setdefault(
                event_id,
                [],
            ).append(alert.alert_id)

    if not event_to_alerts:
        return []

    relevant_events = [
        event
        for event in events
        if event.event_id in event_to_alerts
    ]

    evidence: list[SecurityEvidence] = []

    for event in relevant_events:
        source_alert_ids = sorted(
            set(
                event_to_alerts[
                    event.event_id
                ]
            )
        )

        raw_data = event.model_dump(
            mode="json",
        )

        evidence_item = SecurityEvidence(
            evidence_id=(
                f"EVD-{uuid4().hex[:8].upper()}"
            ),
            investigation_id=(
                investigation.investigation_id
            ),
            timestamp=event.timestamp,
            evidence_type=_get_evidence_type(
                event
            ),
            source=event.source,
            description=event.description,
            source_event_ids=[
                event.event_id
            ],
            source_alert_ids=source_alert_ids,
            host=event.host,
            username=event.username,
            source_ip=event.source_ip,
            process=event.process_path,
            file_path=event.file_path,
            raw_data=raw_data,
            integrity_hash=_calculate_integrity_hash(
                event
            ),
            collector="security_event_collector",
        )

        evidence.append(evidence_item)

    return evidence