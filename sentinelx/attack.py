"""Deterministic MITRE ATT&CK for Mobile technique mapping.

Every mapping carries the exact signal that triggered it, so an analyst can trace
any element of the attack chain back to a concrete artefact in the APK.
"""
from __future__ import annotations
from typing import Any

# (technique id, name, tactic, required short permissions (all), human evidence label)
RULES: list[tuple[str, str, str, set[str], str]] = [
    ("T1412", "Capture SMS Messages", "Collection",
     {"READ_SMS", "RECEIVE_SMS"}, "READ_SMS + RECEIVE_SMS declared"),
    ("T1417", "Input Capture", "Collection",
     {"BIND_ACCESSIBILITY_SERVICE"}, "Accessibility service binding declared"),
    ("T1418", "Software Discovery", "Discovery",
     {"QUERY_ALL_PACKAGES"}, "Enumerates installed packages"),
    ("T1416", "Input Injection", "Impact",
     {"SYSTEM_ALERT_WINDOW"}, "Draw-over-other-apps (overlay) permission"),
    ("T1401", "Device Administrator Permissions", "Persistence",
     {"BIND_DEVICE_ADMIN"}, "Device admin binding declared"),
    ("T1474", "Supply Chain Compromise", "Initial Access",
     {"REQUEST_INSTALL_PACKAGES"}, "Can install further packages (dropper)"),
    ("T1437", "Application Layer Protocol", "Command and Control",
     {"INTERNET"}, "Network access declared"),
    ("T1429", "Audio Capture", "Collection",
     {"RECORD_AUDIO"}, "Microphone access declared"),
    ("T1512", "Video Capture", "Collection",
     {"CAMERA"}, "Camera access declared"),
    ("T1433", "Access Call Log", "Collection",
     {"READ_CALL_LOG"}, "Call log access declared"),
    ("T1430", "Location Tracking", "Discovery",
     {"ACCESS_FINE_LOCATION"}, "Fine location access declared"),
    ("T1636", "Protected User Data: Contacts", "Collection",
     {"READ_CONTACTS"}, "Contact list access declared"),
    ("T1409", "Stored Application Data", "Collection",
     {"READ_EXTERNAL_STORAGE"}, "External storage read access"),
    ("T1624", "Event Triggered Execution", "Persistence",
     {"RECEIVE_BOOT_COMPLETED"}, "Auto-start on device boot"),
    ("T1541", "Foreground Persistence", "Persistence",
     {"FOREGROUND_SERVICE"}, "Persistent foreground service"),
]


def analyse(signals: dict[str, Any], fraud: dict[str, Any]) -> dict[str, Any]:
    short = set(signals.get("short_permissions", []))
    matched: list[dict[str, str]] = []

    for tid, name, tactic, required, label in RULES:
        if required and required <= short:
            matched.append({"id": tid, "name": name, "tactic": tactic,
                            "evidence": label})

    # Composite technique: overlay + bank targeting => credential phishing.
    if fraud.get("targeted_banks") and "SYSTEM_ALERT_WINDOW" in short:
        matched.append({
            "id": "T1417.002", "name": "GUI Input Capture", "tactic": "Collection",
            "evidence": "Overlay permission combined with Indian banking app targeting",
        })

    tactics: dict[str, list[str]] = {}
    for m in matched:
        tactics.setdefault(m["tactic"], []).append(m["id"])

    return {"techniques": matched, "technique_count": len(matched),
            "tactics": tactics}
