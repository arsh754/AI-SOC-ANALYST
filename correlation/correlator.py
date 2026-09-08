from datetime import timedelta
from uuid import uuid4

from backend.alert_model import SecurityAlert
from backend.incident_model import SecurityIncident


CORRELATION_THRESHOLD = 0.50
CORRELATION_WINDOW_MINUTES = 10


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


RELATED_ATTACK_TYPES = {
    frozenset({"Brute Force", "Privilege Escalation"}),
    frozenset({"Brute Force", "Suspicious Process"}),
    frozenset({"Brute Force", "Suspicious File Activity"}),
    frozenset({"Brute Force", "Suspicious Network Activity"}),
    frozenset({"Privilege Escalation", "Suspicious Process"}),
    frozenset({"Privilege Escalation", "Suspicious File Activity"}),
    frozenset({"Privilege Escalation", "Suspicious Network Activity"}),
    frozenset({"Suspicious Process", "Suspicious File Activity"}),
    frozenset({"Suspicious Process", "Suspicious Network Activity"}),
    frozenset({"Suspicious File Activity", "Suspicious Network Activity"}),
}


def calculate_correlation_score(
    first: SecurityAlert,
    second: SecurityAlert,
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> float:
    """
    Calculate how strongly two security alerts appear
    to be related.

    The score is based on shared context:

    - same host
    - same username
    - same source IP
    - close timestamps
    - related attack types
    """

    score = 0.0

    # ---------------------------------------------------------
    # Same host
    # ---------------------------------------------------------

    if (
        first.host is not None
        and second.host is not None
        and first.host == second.host
    ):
        score += 0.30

    # ---------------------------------------------------------
    # Same username
    # ---------------------------------------------------------

    if (
        first.username is not None
        and second.username is not None
        and first.username == second.username
    ):
        score += 0.20

    # ---------------------------------------------------------
    # Same source IP
    # ---------------------------------------------------------

    if (
        first.source_ip is not None
        and second.source_ip is not None
        and first.source_ip == second.source_ip
    ):
        score += 0.25

    # ---------------------------------------------------------
    # Time proximity
    # ---------------------------------------------------------

    time_difference = abs(
        first.timestamp - second.timestamp
    )

    if time_difference <= timedelta(minutes=window_minutes):
        score += 0.15

    # ---------------------------------------------------------
    # Related attack types
    # ---------------------------------------------------------

    attack_pair = frozenset(
        {
            first.attack_type,
            second.attack_type,
        }
    )

    if (
        first.attack_type != second.attack_type
        and attack_pair in RELATED_ATTACK_TYPES
    ):
        score += 0.10

    return round(score, 2)


def _alerts_are_related(
    first: SecurityAlert,
    second: SecurityAlert,
    threshold: float = CORRELATION_THRESHOLD,
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> bool:
    """
    Determine whether two alerts are related enough
    to belong to the same correlation group.
    """

    score = calculate_correlation_score(
        first,
        second,
        window_minutes=window_minutes,
    )

    return score >= threshold


def _build_incident(
    alerts: list[SecurityAlert],
) -> SecurityIncident:
    """
    Convert a group of related alerts into a SecurityIncident.
    """

    sorted_alerts = sorted(
        alerts,
        key=lambda alert: alert.timestamp,
    )

    attack_types = {
        alert.attack_type
        for alert in sorted_alerts
    }

    categories = {
        alert.category
        for alert in sorted_alerts
    }

    # ---------------------------------------------------------
    # Determine overall incident type
    # ---------------------------------------------------------

    if len(attack_types) == 1:
        attack_type = next(iter(attack_types))
    else:
        attack_type = "Multi-Stage Attack"

    # ---------------------------------------------------------
    # Determine overall category
    # ---------------------------------------------------------

    if len(categories) == 1:
        category = next(iter(categories))
    else:
        category = "Multiple"

    # ---------------------------------------------------------
    # Determine highest severity
    # ---------------------------------------------------------

    highest_severity = max(
        sorted_alerts,
        key=lambda alert: SEVERITY_RANK.get(
            alert.severity.lower(),
            0,
        ),
    ).severity

    # ---------------------------------------------------------
    # Average alert confidence
    # ---------------------------------------------------------

    confidence = round(
        sum(
            alert.confidence
            for alert in sorted_alerts
        )
        / len(sorted_alerts),
        2,
    )

    # ---------------------------------------------------------
    # Calculate overall correlation score
    # ---------------------------------------------------------

    pair_scores = []

    for i in range(len(sorted_alerts)):
        for j in range(i + 1, len(sorted_alerts)):
            pair_scores.append(
                calculate_correlation_score(
                    sorted_alerts[i],
                    sorted_alerts[j],
                )
            )

    if pair_scores:
        correlation_score = round(
            sum(pair_scores) / len(pair_scores),
            2,
        )
    else:
        correlation_score = 1.0

    # ---------------------------------------------------------
    # Determine shared context
    # ---------------------------------------------------------

    hosts = {
        alert.host
        for alert in sorted_alerts
        if alert.host is not None
    }

    usernames = {
        alert.username
        for alert in sorted_alerts
        if alert.username is not None
    }

    source_ips = {
        alert.source_ip
        for alert in sorted_alerts
        if alert.source_ip is not None
    }

    host = (
        next(iter(hosts))
        if len(hosts) == 1
        else None
    )

    username = (
        next(iter(usernames))
        if len(usernames) == 1
        else None
    )

    source_ip = (
        next(iter(source_ips))
        if len(source_ips) == 1
        else None
    )

    alert_ids = [
        alert.alert_id
        for alert in sorted_alerts
    ]

    description = (
        f"Incident correlated from "
        f"{len(sorted_alerts)} related security alerts."
    )

    return SecurityIncident(
        incident_id=f"INC-{uuid4().hex[:8].upper()}",
        timestamp=sorted_alerts[0].timestamp,
        title=(
            f"Potential {attack_type}"
        ),
        attack_type=attack_type,
        category=category,
        severity=highest_severity,
        confidence=confidence,
        correlation_score=correlation_score,
        description=description,
        host=host,
        username=username,
        source_ip=source_ip,
        alert_ids=alert_ids,
        alert_count=len(sorted_alerts),
    )


def correlate_alerts(
    alerts: list[SecurityAlert],
    threshold: float = CORRELATION_THRESHOLD,
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> list[SecurityIncident]:
    """
    Correlate security alerts into higher-level incidents.

    Alerts are grouped when they are sufficiently related
    according to the correlation score.
    """

    if not alerts:
        return []

    groups: list[list[SecurityAlert]] = []

    # ---------------------------------------------------------
    # Build correlation groups
    # ---------------------------------------------------------

    for alert in sorted(
        alerts,
        key=lambda item: item.timestamp,
    ):

        matching_groups = []

        for group_index, group in enumerate(groups):

            if any(
                _alerts_are_related(
                    alert,
                    existing_alert,
                    threshold=threshold,
                    window_minutes=window_minutes,
                )
                for existing_alert in group
            ):
                matching_groups.append(group_index)

        if not matching_groups:
            groups.append([alert])
            continue

        # Add the alert to the first matching group.
        groups[matching_groups[0]].append(alert)

        # If it connects multiple groups, merge them.
        if len(matching_groups) > 1:

            primary_group = groups[matching_groups[0]]

            for group_index in reversed(
                matching_groups[1:]
            ):
                primary_group.extend(
                    groups[group_index]
                )
                del groups[group_index]

    # ---------------------------------------------------------
    # Only create incidents for actual groups
    # ---------------------------------------------------------

    incidents = []

    for group in groups:

        if len(group) < 2:
            continue

        incidents.append(
            _build_incident(group)
        )

    return incidents