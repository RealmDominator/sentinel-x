"""Generate demo cases for the dashboard.

Real malware APKs are (rightly) not shipped with this repo, so the HIGH-severity
demo case is built by running the REAL analysis modules over a crafted signal
bundle that mirrors a documented Indian banking-trojan permission profile.

Every module below (classifier, fraud rules, ATT&CK mapping, risk scoring, GenAI)
is the production code path — only the APK-parsing step is substituted. Demo
cases are written to data/demo/ and clearly flagged `is_demo: true`.

Run:  python scripts/make_demo.py
"""
from __future__ import annotations
import datetime as _dt
import hashlib
import json
import sys
import uuid
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import os  # noqa: E402
# Demo cases must work offline and be reproducible: template narrative unless --live.
if "--live" not in sys.argv:
    os.environ["SENTINELX_LLM_PROVIDER"] = "none"

from sentinelx import attack, certgraph, evasion, fraud, genai, risk  # noqa: E402
from sentinelx.pipeline import SCHEMA_VERSION  # noqa: E402
from sentinelx.config import DEMO, MODELS  # noqa: E402
from sentinelx.features import feature_vocab  # noqa: E402

TROJAN_PERMS = [
    "android.permission.INTERNET",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.RECEIVE_USER_PRESENT",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.WAKE_LOCK",
    "android.permission.GET_TASKS",
    "android.permission.DISABLE_KEYGUARD",
]

CASES = [
    {
        "filename": "DEMO_banking_overlay_trojan.apk",
        "package": "com.sbi.secure.update",
        "cert_cn": "Cerberus",
        "permissions": TROJAN_PERMS,
        "referenced": ["com.sbi.lotusintouch", "com.snapwork.hdfc",
                       "com.csam.icici.bank.imobile", "net.one97.paytm"],
        "urls": ["http://c2-panel.example-demo.invalid/gate.php",
                 "http://api.example-demo.invalid/bot/register"],
        "ips": ["185.199.110.153"],
        "evasion": ["anti_emulator", "anti_debugger", "reflection",
                    "dynamic_loading", "crypto"],
    },
    {
        "filename": "DEMO_sms_stealer.apk",
        "package": "com.fastloan.instant",
        "cert_cn": "unknown-signer",
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        "referenced": [],
        "urls": ["http://loan-collect.example-demo.invalid/upload"],
        "ips": [],
        "evasion": ["crypto"],
    },
]


def classify_from_perms(permissions: list[str]) -> dict:
    """Run the REAL model over a permission set (no APK object needed)."""
    clf = joblib.load(MODELS / "xgb.joblib")
    cal = joblib.load(MODELS / "calibrator.joblib")
    import shap

    vocab = feature_vocab()
    perms = set(permissions)
    vec = np.array([[1.0 if p in perms else 0.0 for p in vocab]], dtype=np.float32)
    proba = float(cal.predict_proba(vec)[:, 1][0])
    verdict = "MALICIOUS" if proba >= 0.5 else "BENIGN"

    row = np.asarray(shap.TreeExplainer(clf).shap_values(vec))
    row = row[0] if row.ndim == 2 else row
    feats = sorted(
        ({"feature": vocab[i].rsplit(".", 1)[-1], "full_name": vocab[i],
          "contribution": round(float(row[i]), 4), "present": bool(vec[0][i])}
         for i in range(len(vocab)) if abs(row[i]) > 1e-6),
        key=lambda d: abs(d["contribution"]), reverse=True)[:15]

    return {"verdict": verdict,
            "confidence": round(proba if verdict == "MALICIOUS" else 1 - proba, 4),
            "malicious_probability": round(proba, 4),
            "shap_top_features": feats}


def build(spec: dict) -> dict:
    seed = spec["filename"].encode()
    hashes = {"md5": hashlib.md5(seed).hexdigest(),
              "sha1": hashlib.sha1(seed).hexdigest(),
              "sha256": hashlib.sha256(seed).hexdigest()}

    # Overlay trojans keep their target list as DEX string constants, so the
    # crafted bank references go where the real extractor would find them.
    signals = {
        "package": spec["package"],
        "permissions": spec["permissions"],
        "short_permissions": sorted({p.rsplit(".", 1)[-1] for p in spec["permissions"]}),
        "activities": [], "services": [], "receivers": [],
        "referenced_packages": [spec["package"]],
        "string_referenced_packages": sorted(spec["referenced"]),
        "urls": spec["urls"], "ips": spec["ips"], "n_strings": 0,
    }

    # Certificate: reuse a corpus fingerprint that genuinely attributes to one family
    # (shared/test keys are rejected by certgraph.attribute), preferring the spec's family.
    corpus = certgraph.corpus()
    usable = [c for c in corpus
              if certgraph.attribute({"sha256": c["sha256"],
                                      "subject_cn": c["subject_cn"]})[1] == "HIGH"]
    match = (next((c for c in usable if c["family"] == spec["cert_cn"]), None)
             or (usable[0] if spec["cert_cn"] != "unknown-signer" and usable else None))
    cert = ({"sha256": match["sha256"], "subject_cn": match["subject_cn"],
             "issuer_cn": match["subject_cn"], "self_signed": True, "serial": "1"}
            if match else
            {"sha256": hashlib.sha256(spec["cert_cn"].encode()).hexdigest(),
             "subject_cn": spec["cert_cn"], "issuer_cn": spec["cert_cn"],
             "self_signed": True, "serial": "1"})

    classification = classify_from_perms(spec["permissions"])
    attribution = certgraph.analyse(cert, hashes["sha256"])
    fraud_result = fraud.analyse(signals)
    evasion_result = evasion.summarise({k: evasion.LABELS[k] for k in spec["evasion"]})
    attack_result = attack.analyse(signals, fraud_result)
    risk_result = risk.compute(classification, fraud_result, attribution,
                               evasion_result, 1.0)

    case = {
        "schema_version": SCHEMA_VERSION,
        "case_id": str(uuid.uuid5(uuid.NAMESPACE_URL, spec["filename"])),
        "filename": spec["filename"],
        "analysed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "hashes": hashes, "file_size_bytes": 3_145_728,
        "package": spec["package"], "analysis_completeness": "FULL",
        "notes": ["DEMO CASE — analysis modules are real; APK parsing was "
                  "substituted with a crafted permission profile."],
        "is_demo": True,
        "signals": signals, "classification": classification,
        "attribution": attribution, "fraud": fraud_result,
        "evasion": evasion_result, "attack": attack_result, "risk": risk_result,
        "cache_hit": False,
    }
    case["narrative"] = genai.generate(case)
    meta = case["narrative"]["generation_metadata"]
    if meta["mode"] == "TEMPLATE" and "--live" not in sys.argv:
        meta["reason"] = ("demo cases use the deterministic template so they work offline; "
                          "uploads use the live LLM when a key is configured")
    return case


def main() -> None:
    DEMO.mkdir(parents=True, exist_ok=True)
    for spec in CASES:
        case = build(spec)
        out = DEMO / f"{case['case_id']}.json"
        out.write_text(json.dumps(case, indent=2))
        print(f"[demo] {spec['filename']:38s} {case['classification']['verdict']:9s} "
              f"score={case['risk']['composite_score']:>6} "
              f"{case['risk']['severity']:8s} -> {out.name}")


if __name__ == "__main__":
    main()
