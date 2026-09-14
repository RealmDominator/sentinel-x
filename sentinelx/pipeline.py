"""Ingestion guards + the end-to-end analysis pipeline.

The sample is handled entirely in memory: it is never written to disk, never
executed, and androguard parses it from bytes.
"""
from __future__ import annotations
import datetime as _dt
import hashlib
import io
import json
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

from . import attack, certgraph, classify, evasion, fraud, genai, risk
from .config import (CASES, LLM_PROVIDER, MAX_APK_BYTES, MAX_COMPRESSION_RATIO,
                     RETENTION_DAYS)
from .features import signal_bundle


SCHEMA_VERSION = 5   # bump whenever the case JSON shape changes


class IngestError(Exception):
    """Raised when a file is rejected before any parsing happens."""


class ParseError(Exception):
    """Raised when the file passes the guards but androguard cannot parse it."""


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def validate(data: bytes, path: Path | None = None) -> None:
    """Size, ZIP structure and ZIP-bomb guards — before androguard touches it.

    `path` is accepted for backwards compatibility and ignored; checks run on bytes.
    """
    if len(data) > MAX_APK_BYTES:
        raise IngestError(
            f"FILE_TOO_LARGE: {len(data)} bytes exceeds the "
            f"{MAX_APK_BYTES // (1024*1024)}MB limit")
    buf = io.BytesIO(data)
    if not zipfile.is_zipfile(buf):
        raise IngestError("INVALID_APK: file is not a valid ZIP/APK container")
    try:
        with zipfile.ZipFile(buf) as z:
            infos = z.infolist()
    except zipfile.BadZipFile as exc:
        raise IngestError(f"INVALID_APK: corrupt ZIP container ({exc})")
    if "AndroidManifest.xml" not in {i.filename for i in infos}:
        raise IngestError("INVALID_APK: no AndroidManifest.xml in archive")
    compressed = sum(i.compress_size for i in infos) or 1
    uncompressed = sum(i.file_size for i in infos)
    if uncompressed / compressed > MAX_COMPRESSION_RATIO:
        raise IngestError(
            f"ZIPBOMB_SUSPECTED: compression ratio "
            f"{uncompressed / compressed:.0f}:1 exceeds "
            f"{MAX_COMPRESSION_RATIO}:1")


def cached(sha256: str) -> dict[str, Any] | None:
    """Return a cached result, ignoring (and removing) stale-schema entries."""
    p = CASES / f"{sha256}.json"
    if not p.exists():
        return None
    try:
        case = json.loads(p.read_text())
    except Exception:
        p.unlink(missing_ok=True)
        return None
    if case.get("schema_version") != SCHEMA_VERSION:
        p.unlink(missing_ok=True)          # stale shape -> re-analyse
        return None
    # A case cached while no LLM was available (tests, batch evaluation) keeps a
    # template narrative. Once a key is configured, upgrade it instead of serving
    # "no LLM API key set" forever. Analysis results are untouched.
    meta = case.get("narrative", {}).get("generation_metadata", {})
    if meta.get("mode") == "TEMPLATE" and LLM_PROVIDER != "none":
        case["narrative"] = genai.generate(case)
        if case["narrative"]["generation_metadata"]["mode"] == "AI_GENERATED":
            p.write_text(json.dumps(case, indent=2))
    case["cache_hit"] = True
    return case


def purge_expired(days: int = RETENTION_DAYS) -> int:
    """Delete cached cases older than the retention window. Returns count removed."""
    if days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    removed = 0
    for p in CASES.glob("*.json"):
        if p.stat().st_mtime < cutoff:
            p.unlink(missing_ok=True)
            removed += 1
    return removed


def analyse(data: bytes, path: Path | None = None, filename: str = "sample.apk",
            use_cache: bool = True) -> dict[str, Any]:
    """Run the full pipeline on an already-validated APK held in memory."""
    hashes = _hashes(data)
    if use_cache and (hit := cached(hashes["sha256"])) is not None:
        return hit

    from androguard.core.apk import APK
    try:
        apk = APK(data, raw=True)
    except Exception as exc:
        raise ParseError(f"PARSE_FAILED: androguard could not parse the APK ({exc})")

    completeness, notes = 1.0, []
    signals = signal_bundle(apk)
    if not signals["permissions"]:
        completeness, _ = 0.85, notes.append(
            "No permissions parsed — analysis completeness reduced to PARTIAL.")

    classification = classify.classify(apk)
    cert = certgraph.extract_certificate(apk)
    if not cert:
        notes.append("No signing certificate could be extracted — attribution skipped.")
    attribution = certgraph.analyse(cert, hashes["sha256"])
    fraud_result = fraud.analyse(signals)
    evasion_result = evasion.analyse(apk)
    attack_result = attack.analyse(signals, fraud_result)
    risk_result = risk.compute(classification, fraud_result, attribution,
                               evasion_result, completeness)

    case: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": str(uuid.uuid4()),
        "filename": filename,
        "analysed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "hashes": hashes,
        "file_size_bytes": len(data),
        "package": signals.get("package", ""),
        "analysis_completeness": "FULL" if completeness == 1.0 else "PARTIAL",
        "notes": notes,
        "signals": signals,
        "classification": classification,
        "attribution": attribution,
        "fraud": fraud_result,
        "evasion": evasion_result,
        "attack": attack_result,
        "risk": risk_result,
        "cache_hit": False,
    }
    case["narrative"] = genai.generate(case)

    (CASES / f"{hashes['sha256']}.json").write_text(json.dumps(case, indent=2))
    return case
