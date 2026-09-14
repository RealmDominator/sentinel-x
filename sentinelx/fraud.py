"""Banking-fraud signal detection: OTP interception, trojan capability kit, bank targeting.

Two separate questions, deliberately not blended:

1. *OTP-interception capability* - can the app read one-time passwords? SMS read/receive
   plus a second channel (notification listener or accessibility) rates HIGH. This is a
   capability, not a verdict: KDE Connect legitimately mirrors SMS and notifications.

2. *Banking-trojan kit* - does the app combine the three capabilities that define the
   overlay/OTP-theft trojans (Cerberus, Anubis, Hydra, SOVA, Octo, Ermac...)?
       BIND_ACCESSIBILITY_SERVICE  - read the screen, auto-click, inject overlays
       BIND_DEVICE_ADMIN           - resist uninstallation
       READ_SMS or RECEIVE_SMS     - capture OTPs
   Measured on real samples (scripts/real_world_eval.py): present in 21/27 MalwareBazaar
   banking trojans and 0/19 benign F-Droid apps, including hard negatives that hold two of
   the three (KDE Connect: accessibility+SMS; Key Mapper: accessibility+device admin).

Only (2) or concrete bank targeting drive the ML/rule reconciliation in risk.py.
"""
from __future__ import annotations
import re
from typing import Any

from .config import BANK_BRAND_TOKENS, BANK_PACKAGES

OTP_TRIPLET = {"READ_SMS", "RECEIVE_SMS", "BIND_NOTIFICATION_LISTENER_SERVICE"}
SMS_CAPTURE = {"READ_SMS", "RECEIVE_SMS"}

# capability -> permissions, any of which grants it
KIT_CAPABILITIES: dict[str, set[str]] = {
    "accessibility_abuse": {"BIND_ACCESSIBILITY_SERVICE"},
    "device_admin": {"BIND_DEVICE_ADMIN"},
    "sms_interception": SMS_CAPTURE,
    "notification_interception": {"BIND_NOTIFICATION_LISTENER_SERVICE"},
    "overlay": {"SYSTEM_ALERT_WINDOW"},
    "app_enumeration": {"QUERY_ALL_PACKAGES", "GET_TASKS", "PACKAGE_USAGE_STATS"},
    "lock_screen_control": {"DISABLE_KEYGUARD"},
    "fraud_actions": {"SEND_SMS", "CALL_PHONE"},
}
CORE_KIT = ("accessibility_abuse", "device_admin", "sms_interception")
# Newer SOVA/Anubis builds drop device admin. This profile alone also matches KDE
# Connect, so risk.py only acts on it together with obfuscation or anti-analysis.
OVERLAY_KIT = ("accessibility_abuse", "notification_interception", "sms_interception",
               "overlay")

CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxz]{5,}")

SPY_PERMS = {"RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "READ_CONTACTS",
             "ACCESS_FINE_LOCATION"}

SOURCE_LABEL = {"manifest": "manifest component", "dex_strings": "DEX string constant",
                "name_impersonation": "package-name impersonation"}


def _targets(signals: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    """Bank apps this sample references or impersonates, plus honesty notes."""
    own = signals.get("package") or ""
    notes: list[str] = []
    targeted: dict[str, dict[str, str]] = {}

    # The sample's own package is not a "reference" to itself: a genuine SBI YONO
    # upload must not be reported as targeting SBI YONO.
    sources = (("manifest", signals.get("referenced_packages", [])),
               ("dex_strings", signals.get("string_referenced_packages", [])))
    for source, pkgs in sources:
        for pkg in pkgs:
            if pkg in BANK_PACKAGES and pkg != own and pkg not in targeted:
                targeted[pkg] = {"package": pkg, "bank": BANK_PACKAGES[pkg],
                                 "source": source}

    if own in BANK_PACKAGES:
        notes.append(f"Package name is that of the legitimate {BANK_PACKAGES[own]} app. "
                     "The signing certificate was not verified against the official "
                     "publisher, so a repackaged clone cannot be ruled out statically.")
    else:
        segments = re.split(r"[._]", own.lower())
        claimed = {t["bank"] for t in targeted.values()}
        for token, bank in BANK_BRAND_TOKENS.items():
            # A brand must START a package segment: catches "iciciofficial" and
            # "sbisecure" without firing inside "maxis" or "taxis".
            if (any(seg.startswith(token) for seg in segments)
                    and not any(bank in c or c in bank for c in claimed)):
                targeted[f"{own}#{token}"] = {"package": own,
                                              "bank": f"{bank} (name impersonation)",
                                              "source": "name_impersonation"}
                claimed.add(bank)
    return list(targeted.values()), notes


def otp_risk(short: set[str]) -> str:
    sms = SMS_CAPTURE & short
    second_channel = {"BIND_NOTIFICATION_LISTENER_SERVICE",
                      "BIND_ACCESSIBILITY_SERVICE"} & short
    if sms and second_channel:
        return "HIGH"
    if sms == SMS_CAPTURE or "BIND_NOTIFICATION_LISTENER_SERVICE" in short:
        return "MEDIUM"
    return "LOW" if sms else "NONE"


def analyse(signals: dict[str, Any]) -> dict[str, Any]:
    short = set(signals.get("short_permissions", []))
    evidence: list[str] = []

    kit = {cap: sorted(perms & short) for cap, perms in KIT_CAPABILITIES.items()
           if perms & short}
    kit_complete = all(cap in kit for cap in CORE_KIT)
    overlay_kit = not kit_complete and all(cap in kit for cap in OVERLAY_KIT)
    if kit_complete:
        evidence.append("Banking-trojan capability kit: accessibility service + device "
                        "admin + SMS interception declared together")
    elif overlay_kit:
        evidence.append("Overlay/OTP kit without device admin: accessibility + "
                        "notification listener + SMS interception + overlay")

    package = (signals.get("package") or "").lower()
    obfuscated_name = bool(CONSONANT_RUN.search(package))
    if obfuscated_name:
        evidence.append(f"Package name looks machine-generated: {signals.get('package')}")
    for cap, perms in kit.items():
        evidence.append(f"{cap.replace('_', ' ').capitalize()}: {', '.join(perms)}")

    risk = otp_risk(short)
    if OTP_TRIPLET <= short:
        evidence.append("Full OTP-interception triplet declared: "
                        "READ_SMS + RECEIVE_SMS + BIND_NOTIFICATION_LISTENER_SERVICE")

    spy_hits = SPY_PERMS & short
    for p in sorted(spy_hits):
        evidence.append(f"Surveillance capability: {p}")

    targeted, notes = _targets(signals)
    for t in targeted:
        evidence.append(f"Targets Indian bank app: {t['bank']} ({t['package']}) "
                        f"via {SOURCE_LABEL[t['source']]}")

    # Fraud sub-score for the composite (0..10)
    score = 0
    score += 3 if kit_complete else 2 if overlay_kit else 0
    score += {"HIGH": 2, "MEDIUM": 1}.get(risk, 0)
    score += 2 if targeted else 0
    score += 1 if "overlay" in kit else 0
    score += 1 if {"device_admin", "lock_screen_control"} & kit.keys() else 0
    score += 1 if obfuscated_name else 0

    return {
        "otp_interception_risk": risk,
        "otp_triplet_complete": OTP_TRIPLET <= short,
        "trojan_kit_complete": kit_complete,
        "overlay_kit_without_admin": overlay_kit,
        "package_name_obfuscated": obfuscated_name,
        "capabilities": kit,
        "signals": evidence,
        "targeted_banks": targeted,
        "notes": notes,
        "fraud_signal_score": score,
        "fraud_signal_max": 10,
    }
