from backend.event_model import SecurityEvent


def classify_event(event: SecurityEvent) -> SecurityEvent:
    """
    Classify a normalized SecurityEvent using deterministic rules.

    The classifier does not decide whether an event is malicious.
    It only determines what kind of activity the event represents.
    """

    message = (event.raw_message or "").lower()
    subsystem = (event.subsystem or "").lower()
    category = (event.category or "").lower()
    process_path = (event.process_path or "").lower()

    # ---------------------------------------------------------
    # 1. AUTHENTICATION
    # ---------------------------------------------------------

    authentication_indicators = [
        "authentication",
        "auth failure",
        "authentication failure",
        "failed authentication",
        "login failed",
        "login attempt",
        "password",
        "credential",
    ]

    if any(indicator in message for indicator in authentication_indicators):

        return event.model_copy(
            update={
                "event_type": "authentication",
                "action": "authentication_event",
            }
        )

    # ---------------------------------------------------------
    # 2. NETWORK
    # ---------------------------------------------------------

    network_indicators = [
        "connection",
        "network",
        "socket",
        "tcp",
        "udp",
        "dns",
        "http",
        "https",
    ]

    if (
        any(indicator in message for indicator in network_indicators)
        or "network" in category
    ):

        return event.model_copy(
            update={
                "event_type": "network",
                "action": "network_event",
            }
        )

    # ---------------------------------------------------------
    # 3. PROCESS
    # ---------------------------------------------------------

    process_indicators = [
        "process",
        "launch",
        "spawn",
        "exec",
        "terminated",
        "termination",
    ]

    if any(indicator in message for indicator in process_indicators):

        return event.model_copy(
            update={
                "event_type": "process",
                "action": "process_event",
            }
        )

    # ---------------------------------------------------------
    # 4. FILE ACTIVITY
    # ---------------------------------------------------------

    file_indicators = [
        "file",
        "directory",
        "created",
        "deleted",
        "modified",
        "renamed",
    ]

    if any(indicator in message for indicator in file_indicators):

        return event.model_copy(
            update={
                "event_type": "file",
                "action": "file_event",
            }
        )

    # ---------------------------------------------------------
    # 5. PRIVILEGE / SECURITY
    # ---------------------------------------------------------

    privilege_indicators = [
        "privilege",
        "authorization",
        "authorization denied",
        "permission denied",
        "sudo",
        "root",
    ]

    if any(indicator in message for indicator in privilege_indicators):

        return event.model_copy(
            update={
                "event_type": "privilege",
                "action": "privilege_event",
            }
        )

    # ---------------------------------------------------------
    # 6. SYSTEM
    # ---------------------------------------------------------

    if subsystem or category or process_path:

        return event.model_copy(
            update={
                "event_type": "system",
                "action": "system_event",
            }
        )

    # ---------------------------------------------------------
    # 7. UNKNOWN
    # ---------------------------------------------------------

    return event.model_copy(
        update={
            "event_type": "unknown",
            "action": "unknown_event",
        }
    )