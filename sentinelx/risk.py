"""Composite risk score: 5 weighted signals, fully decomposed.

No black box: every sub-score, its weight, and its weighted contribution are
returned so the dashboard and the PDF can show exactly how the number was built.
"""
from __future__ import annotations
from typing import Any

WEIGHTS = {
    "ml_confidence": 0.35,
    "fraud_signals": 0.25,
    "attribution": 0.20,
    "evasion": 0.10,
    "targeting": 0.10,
}

ATTRIBUTION_VALUE = {"HIGH": 1.0, "MEDIUM": 0.65, "LOW": 0.35, "NONE": 0.1}
EVASION_VALUE = {"HIGH": 1.0, "MEDIUM": 0.65, "LOW": 0.3, "NONE": 0.0}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Behaviours that only a malicious app performs, phrased for the reconciliation note.
# Network contact is deliberately absent: every app talks to the internet, so C2
# traffic escalates a confirmed finding but never creates one on its own.
CONFIRMING_BEHAVIOURS = {
    "sms_interception": "intercepted incoming SMS",
    "sms_sending": "sent SMS without user interaction",
    "overlay_draw": "drew a window on top of other apps",
    "accessibility_abuse": "drove the device through the accessibility service",
    "runtime_dex_load": "loaded code that is not present in the APK",
    "command_execution": "executed a shell command",
}


def _at_least(severity: str, floor: str) -> str:
    return max(severity, floor, key=SEVERITY_ORDER.index)


def dynamic_reasons(dynamic: dict[str, Any] | None) -> list[str]:
    """Runtime behaviours strong enough to confirm a verdict on their own.

    Static rules infer intent from declared capability; these are observations of
    the sample actually doing it, so they outrank both the ML score and the
    static rules. An empty list is NOT evidence of innocence - a trojan that
    detects the emulator simply sits still - so nothing here ever lowers a score.
    """
    if not dynamic or dynamic.get("status") not in ("COMPLETED", "TIMEOUT"):
        return []
    observed = {b.get("id") for b in dynamic.get("behaviours", [])}
    return [label for key, label in CONFIRMING_BEHAVIOURS.items() if key in observed]


def override_reasons(fraud: dict[str, Any], evasion: dict[str, Any]) -> list[str]:
    """Rule findings strong enough to overrule a BENIGN ML verdict.

    Each condition was checked against 32 benign F-Droid apps chosen as hard
    negatives (see Final_md.md §9b). Capabilities that legitimate apps hold on
    their own - OTP capability, the overlay kit, a bank-like name - only count
    together with a second, independent signal.
    """
    reasons: list[str] = []
    caps = fraud.get("capabilities", {})
    otp_capable = fraud.get("otp_interception_risk") in ("HIGH", "MEDIUM")
    strong_evasion = (evasion.get("strong_indicators", 0) or 0) >= 1

    if fraud.get("trojan_kit_complete"):
        reasons.append("the banking-trojan capability kit (accessibility service + "
                       "device admin + SMS interception)")
    if fraud.get("overlay_kit_without_admin") and (
            fraud.get("package_name_obfuscated") or strong_evasion):
        second = ("a machine-generated package name" if fraud.get("package_name_obfuscated")
                  else "anti-analysis checks")
        reasons.append("the overlay/OTP kit (accessibility + notification listener + SMS "
                       f"+ overlay) combined with {second}")

    targets = fraud.get("targeted_banks", [])
    if any(t.get("source") != "name_impersonation" for t in targets):
        reasons.append("Indian bank apps referenced in the code or manifest")
    elif targets and (otp_capable or "accessibility_abuse" in caps):
        reasons.append("an Indian bank name in the package combined with "
                       "OTP-interception or accessibility capability")
    return reasons


def compute(classification: dict[str, Any], fraud: dict[str, Any],
            cert: dict[str, Any], evasion: dict[str, Any],
            completeness: float = 1.0,
            dynamic: dict[str, Any] | None = None) -> dict[str, Any]:
    ml = classification.get("malicious_probability", 0.0) * completeness
    fraud_norm = min(fraud.get("fraud_signal_score", 0)
                     / max(fraud.get("fraud_signal_max", 9), 1), 1.0)
    attr = ATTRIBUTION_VALUE.get(cert.get("confidence", "NONE"), 0.1)
    eva = EVASION_VALUE.get(evasion.get("sophistication", "NONE"), 0.0)
    n_banks = len(fraud.get("targeted_banks", []))
    targeting = min(n_banks / 3.0, 1.0)

    raw = {
        "ml_confidence": ml,
        "fraud_signals": fraud_norm,
        "attribution": attr,
        "evasion": eva,
        "targeting": targeting,
    }

    decomposition = []
    composite = 0.0
    for key, weight in WEIGHTS.items():
        contribution = raw[key] * weight * 100
        composite += contribution
        decomposition.append({
            "signal": key,
            "sub_score": round(raw[key], 4),
            "weight": weight,
            "contribution": round(contribution, 2),
        })

    composite = round(composite, 2)
    severity = ("CRITICAL" if composite >= 80 else
                "HIGH" if composite >= 60 else
                "MEDIUM" if composite >= 40 else "LOW")

    # --- ML / rule reconciliation -----------------------------------------
    # The permission model can be blind to banking-trojan signals that are not
    # in its training vocabulary (BIND_ACCESSIBILITY_SERVICE,
    # BIND_NOTIFICATION_LISTENER_SERVICE, BIND_DEVICE_ADMIN, ...) and carries a
    # temporal bias from its corpus. When the deterministic fraud rules find
    # strong evidence the model missed, we say so explicitly rather than
    # letting a single model's verdict stand unchallenged.
    # OTP-interception capability alone is NOT enough: legitimate apps such as KDE
    # Connect hold it. Only the full trojan kit or concrete bank targeting overrides.
    reasons = override_reasons(fraud, evasion)
    ml_says_benign = classification.get("verdict") == "BENIGN"
    disagreement = bool(ml_says_benign and reasons)

    severity_floor_applied = False
    if disagreement:
        headline = "SUSPICIOUS (rule-driven)"
        note = ("The ML classifier scored this sample BENIGN, but the deterministic "
                f"banking-fraud rules found {' and '.join(reasons)}. "
                "BIND_ACCESSIBILITY_SERVICE, BIND_NOTIFICATION_LISTENER_SERVICE and "
                "BIND_DEVICE_ADMIN are outside the model's training vocabulary, so the "
                "rule engine is the more reliable signal here. Severity is raised to at "
                "least MEDIUM so a known-blind model cannot bury the finding.")
        if severity == "LOW":
            severity, severity_floor_applied = "MEDIUM", True
    else:
        headline = classification.get("verdict", "UNKNOWN")
        note = ""

    # --- Dynamic confirmation ---------------------------------------------
    # Observed execution outranks both the model and the static rules: this is
    # the sample doing the thing, not the manifest saying it could. The composite
    # weights are deliberately left alone so static scores stay comparable across
    # the evaluation sets - confirmation raises the floor instead of the sum.
    dyn_reasons = dynamic_reasons(dynamic)
    dyn = dynamic or {}
    dynamic_ran = dyn.get("status") in ("COMPLETED", "TIMEOUT")
    if dyn_reasons:
        headline = "MALICIOUS (dynamically confirmed)"
        exfil = any(b.get("id") == "c2_contact" for b in dyn.get("behaviours", []))
        floor = "CRITICAL" if exfil else "HIGH"
        if severity != (raised := _at_least(severity, floor)):
            severity, severity_floor_applied = raised, True
        note = (f"Executed in the sandbox, the sample {', '.join(dyn_reasons)}"
                + (" and contacted its command-and-control endpoint" if exfil else "")
                + ". Observed behaviour outranks the permission model and the static "
                  f"rules, so severity is floored at {floor}.")
    elif dynamic_ran and not note:
        note = ("The sample was executed in the sandbox and no malicious behaviour "
                "was observed. This is not a clean bill of health: banking trojans "
                "commonly stay dormant when they detect an emulator, and the static "
                "verdict above stands on its own evidence.")

    return {
        "headline_verdict": headline,
        "ml_rule_disagreement": disagreement,
        "override_reasons": reasons if disagreement else [],
        "dynamic_confirmed": bool(dyn_reasons),
        "dynamic_reasons": dyn_reasons,
        "reconciliation_note": note,
        "composite_score": composite,
        "severity": severity,
        "severity_floor_applied": severity_floor_applied,
        "decomposition": decomposition,
        "completeness_factor": completeness,
        "recommended_response": {
            "CRITICAL": "Immediate containment and CERT-In notification recommended",
            "HIGH": "Expedited investigation and stakeholder notification",
            "MEDIUM": "Detailed manual review and IOC distribution",
            "LOW": "Monitoring and benign verification",
        }[severity],
    }
