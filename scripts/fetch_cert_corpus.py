"""Replace the synthetic seed corpus with REAL Android-malware signing certificates.

MalwareBazaar's `code_sign` field is Windows Authenticode data and is empty for
APKs, so certificates are extracted here by downloading each APK sample (in
memory only — see scripts/bazaar.py) and parsing its signer with androguard.

    set MALWAREBAZAAR_API_KEY=...
    python scripts/fetch_cert_corpus.py                 # 10 samples per family
    python scripts/fetch_cert_corpus.py --per-family 25 --families Cerberus SOVA

MalwareBazaar enforces a daily download limit, so start small.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from loguru import logger  # noqa: E402
logger.remove()

import bazaar  # noqa: E402

OUT = ROOT / "data" / "cert_corpus.json"


def build_entry(family: str, sha: str, data: bytes) -> dict | None:
    cert = bazaar.certificate_of(data)
    if not cert:
        return None
    return {"sha256": cert["sha256"], "subject_cn": cert.get("subject_cn") or "unknown",
            "family": family, "source": "MalwareBazaar", "sample_sha256": sha}


def write_corpus(entries: list[dict], note: str) -> None:
    seen, unique = set(), []
    for e in entries:
        if (e["sha256"], e["family"]) not in seen:
            seen.add((e["sha256"], e["family"]))
            unique.append(e)
    OUT.write_text(json.dumps({"_note": note, "certificates": unique}, indent=2))
    print(f"[done] wrote {len(unique)} real certificate entries -> {OUT}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--families", nargs="+", default=bazaar.DEFAULT_FAMILIES)
    ap.add_argument("--per-family", type=int, default=10)
    args = ap.parse_args()
    bazaar.api_key()

    entries = []
    for fam, sha, data in bazaar.iter_family_samples(args.families, args.per_family):
        if (entry := build_entry(fam, sha, data)) is not None:
            entries.append(entry)
            print(f"    {fam:10s} {sha[:12]} signer={entry['subject_cn']!s:.40}")
    if not entries:
        raise SystemExit("No certificates retrieved; seed corpus left unchanged.")
    write_corpus(entries, "Real signing certificates extracted from MalwareBazaar APK "
                          "samples (parsed in memory, never executed).")


if __name__ == "__main__":
    main()
