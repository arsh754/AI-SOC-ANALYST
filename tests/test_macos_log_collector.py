from collectors.macos_log_collector import parse_log


def test_authentication_event():

    raw_log = {
        "timestamp": "2026-09-07T12:00:00+05:30",
        "eventMessage": "Login failed: password incorrect",
        "subsystem": "com.apple.loginwindow",
        "category": "authentication",
        "processImagePath": (
            "/System/Library/CoreServices/loginwindow"
        ),
        "messageType": "Error",
    }

    event = parse_log(raw_log)

    assert event.event_type == "authentication"
    assert event.action == "login_failed"


def test_privilege_event():

    raw_log = {
        "timestamp": "2026-09-07T12:00:00+05:30",
        "eventMessage": "Authorization request",
        "subsystem": "com.apple.security",
        "category": "authorization",
        "processImagePath": "/usr/bin/sudo",
        "messageType": "Default",
    }

    event = parse_log(raw_log)

    assert event.event_type == "privilege"
    assert event.action == "sudo"


def test_network_event():

    raw_log = {
        "timestamp": "2026-09-07T12:00:00+05:30",
        "eventMessage": "Network connection established",
        "subsystem": "com.apple.network",
        "category": "connection",
        "processImagePath": "/usr/bin/networkd",
        "messageType": "Default",
    }

    event = parse_log(raw_log)

    assert event.event_type == "network"
    assert event.action == "connection"


def test_file_event():

    raw_log = {
        "timestamp": "2026-09-07T12:00:00+05:30",
        "eventMessage": "File created: /tmp/test.sh",
        "subsystem": "filesystem",
        "category": "file",
        "processImagePath": "/usr/bin/test",
        "messageType": "Default",
    }

    event = parse_log(raw_log)

    assert event.event_type == "file"
    assert event.action == "file_created"


def test_unknown_event_becomes_system():

    raw_log = {
        "timestamp": "2026-09-07T12:00:00+05:30",
        "eventMessage": "PMRD: trace point 0x23",
        "subsystem": "",
        "category": "",
        "processImagePath": "/kernel",
        "messageType": "Default",
    }

    event = parse_log(raw_log)

    assert event.event_type == "system"
    assert event.action == "log_event"


def test_parser_preserves_original_message():

    raw_log = {
        "timestamp": "2026-09-07T12:00:00+05:30",
        "eventMessage": "Network connection established",
        "subsystem": "com.apple.network",
        "category": "connection",
        "processImagePath": "/usr/bin/networkd",
        "messageType": "Default",
    }

    event = parse_log(raw_log)

    assert event.raw_message == "Network connection established"
    assert event.subsystem == "com.apple.network"
    assert event.category == "connection"
    assert event.process_path == "/usr/bin/networkd"