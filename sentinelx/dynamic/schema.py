"""The normalized dynamic-analysis block — one shape, whatever the backend.

Every backend (local emulator, Hatching Triage, the test double) returns this
exact dict, so `risk.py`, `report.py`, `iocs.py`, `genai.py` and the dashboard
never branch on which sandbox produced the data. Keys are always present, even
when a run was skipped or failed, so consumers can read them without `.get()`
chains and a partial run degrades instead of crashing.

The block deliberately carries **no malware bytes**: dropped payloads are
recorded as hashes and paths, artefacts as counts. Nothing here can re-create
the sample.
"""
from __future__ import annotations
from typing import Any

BACKENDS = ("none", "emulator", "triage", "mock")
# COMPLETED - the sample ran to the end of its window.
# TIMEOUT   - it ran, the window expired first; partial observations are still valid.
# ERROR     - the sandbox itself failed (no AVD, no frida, API down). Nothing observed.
# SKIPPED   - dynamic analysis was never requested. The default for every upload.
STATUSES = ("COMPLETED", "TIMEOUT", "ERROR", "SKIPPED")

# Caps: a chatty sample can emit thousands of events. The case JSON stays readable
# and bounded; counts survive truncation so nothing is silently lost.
MAX_LIST = 50


def empty(backend: str = "none", status: str = "SKIPPED",
          detail: str = "") -> dict[str, Any]:
    """A fully-populated block describing a run that produced no observations."""
    return {
        "backend": backend,
        "status": status,
        "detail": detail,
        "duration_seconds": 0.0,
        "runtime_permissions_requested": [],
        "api_calls": [],
        "network": {"dns_queries": [], "http_requests": [], "contacted_ips": []},
        "dynamic_code_loading": [],
        "overlay_observed": False,
        "accessibility_used": False,
        "sms_intercepted": False,
        "sms_sent": [],
        "behaviours": [],
        "blind_spots_resolved": [],
        "observation_counts": {},
        "artifacts": {"logcat_lines": 0, "pcap_captured": False},
    }


def skipped(detail: str = "Dynamic analysis was not requested for this sample."
            ) -> dict[str, Any]:
    return empty("none", "SKIPPED", detail)


def error(backend: str, detail: str) -> dict[str, Any]:
    """A sandbox failure. Static results are unaffected — that is the whole point."""
    return empty(backend, "ERROR", detail)


def _dedupe(items: list[Any], limit: int = MAX_LIST) -> list[Any]:
    """Order-preserving dedupe that also works for unhashable dict entries."""
    out: list[Any] = []
    seen: set[str] = set()
    for item in items:
        key = repr(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
        if len(out) >= limit:
            break
    return out


def build(backend: str, status: str, *, detail: str = "",
          duration_seconds: float = 0.0, **observed: Any) -> dict[str, Any]:
    """Merge a backend's raw observations into the canonical block.

    Unknown keys are dropped rather than passed through, so a backend cannot
    quietly widen the contract that four consumers depend on.
    """
    block = empty(backend, status, detail)
    block["duration_seconds"] = round(float(duration_seconds), 2)

    for key in ("runtime_permissions_requested", "api_calls",
                "dynamic_code_loading", "sms_sent"):
        if value := observed.get(key):
            block[key] = _dedupe(list(value))

    for key in ("overlay_observed", "accessibility_used", "sms_intercepted"):
        block[key] = bool(observed.get(key, False))

    net = observed.get("network") or {}
    for key in ("dns_queries", "http_requests", "contacted_ips"):
        if value := net.get(key):
            block["network"][key] = _dedupe(list(value))

    artifacts = observed.get("artifacts") or {}
    block["artifacts"]["logcat_lines"] = int(artifacts.get("logcat_lines", 0))
    block["artifacts"]["pcap_captured"] = bool(artifacts.get("pcap_captured", False))

    # Pre-truncation totals, so a capped list still reports how much really happened.
    block["observation_counts"] = {
        "api_calls": len(observed.get("api_calls") or []),
        "http_requests": len(net.get("http_requests") or []),
        "dns_queries": len(net.get("dns_queries") or []),
        "dynamic_code_loading": len(observed.get("dynamic_code_loading") or []),
        "sms_sent": len(observed.get("sms_sent") or []),
    }
    return block


def ran(block: dict[str, Any]) -> bool:
    """True when the sandbox actually executed the sample (partial runs count)."""
    return block.get("status") in ("COMPLETED", "TIMEOUT")
