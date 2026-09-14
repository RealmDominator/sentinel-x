"""Turn raw sandbox observations into normalized behaviour signatures.

Backend-agnostic on purpose: the emulator backend reports Frida hook hits and
the Triage backend reports its own signature names, but both arrive here as the
same block fields, so one rule set produces one vocabulary of behaviours.

The distinction that matters downstream: `attack.py` maps ATT&CK techniques from
*declared permissions* (what the app could do); these map them from *observed
execution* (what it actually did). Same technique IDs, far stronger evidence —
which is why `risk.dynamic_reasons()` lets them override the ML verdict.
"""
from __future__ import annotations
from typing import Any

# Static analysis admits these blind spots (evasion.BLIND_SPOTS). Running the
# sample is precisely how they get closed, so we record which ones this run shut.
_BLIND_SPOT_CLOSERS = {
    "dynamic_loading": ("dynamic_code_loading",
                        "the runtime-loaded payload was observed being loaded"),
    "crypto": ("_has_network",
               "C2 endpoints were recovered at runtime, after decryption"),
    "reflection": ("api_calls",
                   "API calls were hooked at the framework level, so reflection "
                   "did not conceal them"),
    "packer": ("api_calls",
               "the unpacked payload executed under instrumentation"),
    "native_libs": ("_has_network",
                    "network behaviour reaching the sinkhole includes any native "
                    "payload activity"),
}


def _has_api(block: dict[str, Any], klass: str, method: str = "") -> str:
    """Evidence string for a hooked API call, or '' when it was never seen."""
    for call in block.get("api_calls", []):
        if klass.lower() in str(call.get("class", "")).lower() and (
                not method or method.lower() in str(call.get("method", "")).lower()):
            name = f"{call.get('class', '')}.{call.get('method', '')}".strip(".")
            count = call.get("count", 1)
            return f"{name} called {count}x at runtime"
    return ""


def _has_network(block: dict[str, Any]) -> bool:
    net = block.get("network", {})
    return bool(net.get("http_requests") or net.get("dns_queries")
                or net.get("contacted_ips"))


def _network_evidence(block: dict[str, Any]) -> str:
    net = block.get("network", {})
    if reqs := net.get("http_requests"):
        first = reqs[0]
        host = first.get("host", "?") if isinstance(first, dict) else str(first)
        return f"{len(reqs)} HTTP request(s) at runtime, first to {host}"
    if hosts := net.get("dns_queries"):
        return f"resolved {len(hosts)} host(s) at runtime, including {hosts[0]}"
    if ips := net.get("contacted_ips"):
        return f"contacted {ips[0]} at runtime"
    return ""


def derive(block: dict[str, Any]) -> list[dict[str, str]]:
    """Normalized behaviours observed during execution, strongest first."""
    out: list[dict[str, str]] = []

    def add(bid: str, label: str, mitre: str, evidence: str) -> None:
        if evidence:
            out.append({"id": bid, "label": label, "mitre_id": mitre,
                        "evidence": evidence})

    # --- OTP / SMS interception: the core banking-fraud behaviour ------------
    if block.get("sms_intercepted"):
        add("sms_interception", "Intercepted incoming SMS", "T1412",
            _has_api(block, "SmsMessage") or _has_api(block, "ContentResolver")
            or "incoming SMS was read or its broadcast aborted at runtime")
    if sent := block.get("sms_sent"):
        add("sms_sending", "Sent SMS without user action", "T1582",
            f"{len(sent)} SMS send(s) observed, first to "
            f"{sent[0].get('to', 'unknown') if isinstance(sent[0], dict) else sent[0]}")

    # --- Overlay + accessibility: credential theft --------------------------
    if block.get("overlay_observed"):
        add("overlay_draw", "Drew a window over other apps", "T1417.002",
            _has_api(block, "WindowManager", "addView")
            or "an overlay window was added at runtime")
    if block.get("accessibility_used"):
        add("accessibility_abuse", "Used the accessibility service at runtime",
            "T1417", _has_api(block, "AccessibilityService")
            or "accessibility events were consumed at runtime")

    # --- The big static blind spot, closed ----------------------------------
    if loads := block.get("dynamic_code_loading"):
        first = loads[0] if isinstance(loads[0], dict) else {}
        add("runtime_dex_load", "Loaded additional code at runtime", "T1407",
            f"{len(loads)} runtime class-loader call(s); "
            f"{first.get('loader', 'class loader')} loaded "
            f"{first.get('path_or_hash', 'a payload not present in the APK')}")

    # --- C2 ------------------------------------------------------------------
    add("c2_contact", "Contacted a command-and-control endpoint", "T1437",
        _network_evidence(block))

    # --- Collection / discovery ---------------------------------------------
    add("device_fingerprinting", "Read device identifiers", "T1426",
        _has_api(block, "TelephonyManager"))
    add("contact_access", "Read the contact list", "T1636.003",
        _has_api(block, "ContactsContract"))
    add("package_enumeration", "Enumerated installed applications", "T1418",
        _has_api(block, "PackageManager", "getInstalledPackages"))
    add("command_execution", "Executed a shell command", "T1623",
        _has_api(block, "Runtime", "exec"))

    return out


def blind_spots_resolved(block: dict[str, Any],
                         flagged: set[str] | None = None) -> list[dict[str, str]]:
    """Which documented static blind spots this run actually closed.

    `flagged` is the set of evasion keys static analysis reported for THIS sample.
    Without it every closer would fire, which would claim to have resolved blind
    spots the sample never had - so an unknown set resolves nothing.
    """
    resolved = []
    for key, (field, note) in _BLIND_SPOT_CLOSERS.items():
        if flagged is not None and key not in flagged:
            continue
        observed = _has_network(block) if field == "_has_network" else block.get(field)
        if observed:
            resolved.append({"key": key, "observed": note})
    return resolved


def enrich(block: dict[str, Any], flagged: set[str] | None = None) -> dict[str, Any]:
    """Fill the derived fields of a block in place and return it."""
    block["behaviours"] = derive(block)
    block["blind_spots_resolved"] = blind_spots_resolved(block, flagged)
    return block
