"""Hatching Triage backend — behavioural data without detonating anything locally.

Used by the evaluation path for MalwareBazaar samples, which are already public.
`dynamic.analyse()` refuses this backend unless the caller passes
`allow_upload=True`, because submitting a file publishes it to a third party.

Lookup by hash comes first: if Triage has already run the sample, no upload
happens at all. Only a sample Triage has never seen is submitted.

urllib on purpose — the project deliberately carries no HTTP client dependency
(see the GenAI providers in genai.py).
"""
from __future__ import annotations
import json
import time
import urllib.error
import urllib.request
from typing import Any

from . import schema
from ..config import TRIAGE_API_KEY, TRIAGE_BASE_URL

POLL_SECONDS = 10

# Triage signature/behaviour names -> the fields of our normalized block. Their
# taxonomy is prose, so matching is substring-based and deliberately narrow.
_SIGNATURE_MAP = {
    "sms_intercepted": ("intercept", "sms receiver", "reads sms", "sms message"),
    "overlay_observed": ("overlay", "draws over", "system_alert_window"),
    "accessibility_used": ("accessibility",),
}


def _request(path: str, data: bytes | None = None,
             content_type: str = "application/json") -> dict[str, Any]:
    req = urllib.request.Request(f"{TRIAGE_BASE_URL}{path}", data=data)
    req.add_header("Authorization", f"Bearer {TRIAGE_API_KEY}")
    if data is not None:
        req.add_header("Content-Type", content_type)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8", "replace") or "{}")


def _existing_report(sha256: str) -> str:
    """Sample id of an existing public analysis for this hash, or ''."""
    if not sha256:
        return ""
    try:
        found = _request(f"/v0/search?query=sha256:{sha256}").get("data") or []
    except Exception:
        return ""
    return found[0].get("id", "") if found else ""


def _submit(apk_bytes: bytes, sha256: str) -> str:
    boundary = "----sentinelx" + (sha256[:16] or "sample")
    body = b"".join([
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"_json\"\r\n\r\n".encode(),
        json.dumps({"kind": "file", "interactive": False}).encode(), b"\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"{sha256[:16] or 'sample'}.apk\"\r\n"
        f"Content-Type: application/vnd.android.package-archive\r\n\r\n".encode(),
        apk_bytes, b"\r\n", f"--{boundary}--\r\n".encode(),
    ])
    out = _request("/v0/samples", body, f"multipart/form-data; boundary={boundary}")
    return out.get("id", "")


def _wait(sample_id: str, timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = _request(f"/v0/samples/{sample_id}").get("status", "")
        if status == "reported":
            return _request(f"/v0/samples/{sample_id}/overview.json")
        if status == "failed":
            raise RuntimeError("Triage reported the analysis as failed")
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"Triage did not finish within {timeout}s")


def _normalise(overview: dict[str, Any], elapsed: float) -> dict[str, Any]:
    sigs = overview.get("signatures") or []
    names = [str(s.get("name", "")).lower() for s in sigs]

    observed: dict[str, Any] = {"api_calls": [], "sms_sent": [],
                                "dynamic_code_loading": []}
    for field, needles in _SIGNATURE_MAP.items():
        observed[field] = any(n in name for name in names for n in needles)

    targets = overview.get("targets") or []
    perms: list[str] = []
    for t in targets:
        perms.extend((t.get("metadata") or {}).get("permissions") or [])
    observed["runtime_permissions_requested"] = perms

    net = (overview.get("extracted") or []) + (overview.get("iocs") or [])
    domains, urls, ips = [], [], []
    for item in net if isinstance(net, list) else []:
        if isinstance(item, dict):
            domains.extend(item.get("domains") or [])
            urls.extend(item.get("urls") or [])
            ips.extend(item.get("ips") or [])
    top_iocs = (overview.get("targets") or [{}])[0].get("iocs") or {}
    domains.extend(top_iocs.get("domains") or [])
    urls.extend(top_iocs.get("urls") or [])
    ips.extend(top_iocs.get("ips") or [])

    observed["network"] = {
        "dns_queries": domains,
        "http_requests": [{"method": "GET", "host": u.split("/")[2], "path": ""}
                          for u in urls if "//" in u and len(u.split("/")) > 2],
        "contacted_ips": ips,
    }
    # Triage names its signatures; keep them as evidence-bearing API rows so the
    # behaviour rules and the report have something concrete to cite.
    observed["api_calls"] = [{"class": "triage.signature",
                              "method": str(s.get("name", ""))[:80],
                              "args_summary": str(s.get("desc", ""))[:120],
                              "count": 1} for s in sigs[:20]]
    score = overview.get("analysis", {}).get("score")
    detail = f"Hatching Triage report (score {score}/10)" if score else "Hatching Triage report"
    return schema.build("triage", "COMPLETED", detail=detail,
                        duration_seconds=elapsed, **observed)


def run(apk_bytes: bytes, package: str = "", *, timeout: int = 180,
        sha256: str = "") -> dict[str, Any]:
    if not TRIAGE_API_KEY:
        return schema.error("triage", "TRIAGE_API_KEY is not set in .env "
                                      "(free research keys: https://tria.ge).")
    started = time.monotonic()
    try:
        sample_id = _existing_report(sha256) or _submit(apk_bytes, sha256)
        if not sample_id:
            return schema.error("triage", "Triage accepted no sample id")
        overview = _wait(sample_id, timeout)
    except TimeoutError as exc:
        return schema.build("triage", "TIMEOUT", detail=str(exc),
                            duration_seconds=time.monotonic() - started)
    except urllib.error.HTTPError as exc:
        return schema.error("triage", f"HTTP {exc.code} from Triage: "
                                      f"{exc.read()[:160].decode('utf-8', 'replace')}")
    except Exception as exc:                      # noqa: BLE001
        return schema.error("triage", f"{type(exc).__name__}: {exc}")
    return _normalise(overview, time.monotonic() - started)
