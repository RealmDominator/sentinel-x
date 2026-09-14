"""Minimal MalwareBazaar client shared by fetch_cert_corpus.py and real_world_eval.py.

Safety model: samples are downloaded, decrypted and parsed **in memory only**.
Nothing is written to disk and nothing is executed — androguard reads the bytes.
This also keeps Windows Defender from quarantining files mid-run.

Needs a free Auth-Key from https://auth.abuse.ch/ in MALWAREBAZAAR_API_KEY.
"""
from __future__ import annotations
import io
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Iterator

API = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
DEFAULT_FAMILIES = ["Cerberus", "Anubis", "SpyNote", "Hydra", "Ermac", "SOVA",
                    "Octo", "Alien", "Hookbot", "BankBot"]


def api_key() -> str:
    import sentinelx.config  # noqa: F401  (loads the project .env into os.environ)
    key = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()
    if not key:
        raise SystemExit("Add MALWAREBAZAAR_API_KEY=... to the project .env file "
                         "(free key at https://auth.abuse.ch/).")
    return key


def _post(payload: dict[str, str], timeout: int = 60) -> bytes:
    req = urllib.request.Request(
        API, data=urllib.parse.urlencode(payload).encode(),
        headers={"Auth-Key": api_key(), "User-Agent": "sentinelx-research"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def apk_hashes(family: str, limit: int, skip: int = 0) -> list[str]:
    """SHA256s of APK samples MalwareBazaar labels with this family signature.

    `skip` drops the newest N APKs, so a second run can draw samples that an
    earlier run (and any rule tuned on it) has never seen.
    """
    res = json.loads(_post({"query": "get_siginfo", "signature": family,
                            "limit": str(min(max((limit + skip) * 4, 50), 1000))}))
    if res.get("query_status") != "ok":
        print(f"  {family}: {res.get('query_status')}")
        return []
    apks = [item["sha256_hash"] for item in res.get("data", [])
            if (item.get("file_type") or "").lower() == "apk"]
    return apks[skip:skip + limit]


def download_apk(sha256: str) -> bytes | None:
    """Fetch one sample and decrypt its AES zip in memory. None on any failure."""
    import pyzipper   # optional dependency; only needed for real-data scripts
    try:
        blob = _post({"query": "get_file", "sha256_hash": sha256}, timeout=120)
        if blob[:2] != b"PK":            # API returns JSON on errors / daily limit
            print(f"    {sha256[:12]}: {blob[:120]!r}")
            return None
        with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
            z.setpassword(ZIP_PASSWORD)
            return z.read(z.namelist()[0])
    except Exception as exc:
        print(f"    {sha256[:12]}: download failed ({exc})")
        return None


def iter_family_samples(families: list[str], per_family: int, skip: int = 0
                        ) -> Iterator[tuple[str, str, bytes]]:
    """Yield (family, sha256, apk_bytes) for each downloadable APK."""
    for fam in families:
        try:
            hashes = apk_hashes(fam, per_family, skip)
        except Exception as exc:
            print(f"  {fam}: query failed ({exc})")
            continue
        print(f"  {fam}: {len(hashes)} APK sample(s) listed")
        for sha in hashes:
            data = download_apk(sha)
            if data is not None:
                yield fam, sha, data


def certificate_of(data: bytes) -> dict[str, Any]:
    """Signer certificate of an in-memory APK via the production extractor."""
    from androguard.core.apk import APK
    from sentinelx import certgraph
    try:
        return certgraph.extract_certificate(APK(data, raw=True))
    except Exception:
        return {}
