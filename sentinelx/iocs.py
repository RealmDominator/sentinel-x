"""IOC extraction and export (JSON / CSV)."""
from __future__ import annotations
import csv
import io
from typing import Any


def build(case: dict[str, Any]) -> dict[str, Any]:
    sig = case.get("signals", {})
    cert = case.get("attribution", {}).get("certificate", {}) or {}
    fraud = case.get("fraud", {})

    return {
        "case_id": case.get("case_id"),
        "generated_at": case.get("analysed_at"),
        "sample": {**case.get("hashes", {}),
                   "file_size_bytes": case.get("file_size_bytes"),
                   "package": sig.get("package", "")},
        "verdict": {
            "label": case["classification"]["verdict"],
            "confidence": case["classification"]["confidence"],
            "severity": case["risk"]["severity"],
        },
        "indicators": {
            "certificate_fingerprints": (
                [{"sha256": cert.get("sha256"),
                  "subject": cert.get("subject_cn"),
                  "self_signed": cert.get("self_signed"),
                  "family_association": ", ".join(
                      case["attribution"]["related_families"]) or "unknown"}]
                if cert else []),
            "c2_candidates": [{"value": u, "type": "url",
                               "extraction_method": "static_string"}
                              for u in sig.get("urls", [])[:25]]
            + [{"value": i, "type": "ip", "extraction_method": "static_string"}
               for i in sig.get("ips", [])[:25]],
            "package_names": [{"package": sig.get("package", ""),
                               "impersonation_target":
                                   ", ".join(b["bank"] for b in
                                             fraud.get("targeted_banks", []))
                                   or "none detected"}],
            "file_hashes": case.get("hashes", {}),
        },
        "attack_techniques": case["attack"]["techniques"],
    }


def to_csv(bundle: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["case_id", "ioc_type", "ioc_value", "context", "source_module"])
    cid = bundle.get("case_id", "")
    h = bundle["indicators"]["file_hashes"]
    for k, v in h.items():
        w.writerow([cid, f"hash_{k}", v, "sample file hash", "ingest"])
    for c in bundle["indicators"]["certificate_fingerprints"]:
        w.writerow([cid, "cert_sha256", c.get("sha256", ""),
                    f"subject={c.get('subject')}; family={c.get('family_association')}",
                    "certgraph"])
    for c in bundle["indicators"]["c2_candidates"]:
        w.writerow([cid, c["type"], c["value"], c["extraction_method"], "features"])
    for p in bundle["indicators"]["package_names"]:
        if p.get("package"):
            w.writerow([cid, "package", p["package"],
                        f"impersonates={p['impersonation_target']}", "fraud"])
    for t in bundle["attack_techniques"]:
        w.writerow([cid, "attack_technique", t["id"],
                    f"{t['name']} — {t['evidence']}", "attack"])
    return buf.getvalue()
