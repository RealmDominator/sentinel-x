"""Unit tests for the SENTINEL-X analysis modules."""
from __future__ import annotations
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx import attack, fraud, iocs, pipeline, risk  # noqa: E402

TROJAN = {
    "package": "com.sbi.secure.update",
    "short_permissions": [
        "READ_SMS", "RECEIVE_SMS", "BIND_NOTIFICATION_LISTENER_SERVICE",
        "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
        "BIND_DEVICE_ADMIN", "INTERNET", "RECORD_AUDIO", "CAMERA",
    ],
    "referenced_packages": ["com.sbi.lotusintouch", "net.one97.paytm"],
}
BENIGN = {
    "package": "com.example.notepad",
    "short_permissions": ["INTERNET", "READ_EXTERNAL_STORAGE"],
    "referenced_packages": ["com.example.notepad"],
}


# --------------------------------------------------------------------- fraud
def test_otp_triplet_detected():
    r = fraud.analyse(TROJAN)
    assert r["otp_triplet_complete"] is True
    assert r["otp_interception_risk"] == "HIGH"


def test_benign_app_has_no_otp_risk():
    r = fraud.analyse(BENIGN)
    assert r["otp_triplet_complete"] is False
    assert r["otp_interception_risk"] in ("NONE", "LOW")


def test_trojan_kit_detected():
    r = fraud.analyse(TROJAN)
    assert r["trojan_kit_complete"] is True
    assert fraud.analyse(BENIGN)["trojan_kit_complete"] is False


def test_bank_targeting_detected():
    banks = {b["bank"] for b in fraud.analyse(TROJAN)["targeted_banks"]}
    assert any("SBI" in b for b in banks)
    assert any("Paytm" in b for b in banks)


def test_benign_app_targets_no_bank():
    assert fraud.analyse(BENIGN)["targeted_banks"] == []


# -------------------------------------------------------------------- attack
def test_attack_mapping_includes_sms_capture():
    f = fraud.analyse(TROJAN)
    ids = {t["id"] for t in attack.analyse(TROJAN, f)["techniques"]}
    assert "T1412" in ids          # Capture SMS Messages
    assert "T1417" in ids          # Input Capture (accessibility)
    assert "T1401" in ids          # Device Administrator


def test_every_technique_carries_evidence():
    f = fraud.analyse(TROJAN)
    for t in attack.analyse(TROJAN, f)["techniques"]:
        assert t["evidence"], f"{t['id']} has no evidence string"


# ---------------------------------------------------------------------- risk
def _risk_for(signals, ml_prob, otp_conf="NONE", evasion="NONE"):
    f = fraud.analyse(signals)
    cls = {"verdict": "MALICIOUS" if ml_prob >= .5 else "BENIGN",
           "malicious_probability": ml_prob, "confidence": ml_prob}
    return risk.compute(cls, f, {"confidence": otp_conf},
                        {"sophistication": evasion})


def test_trojan_scores_higher_than_benign():
    hi = _risk_for(TROJAN, 0.9, "HIGH", "HIGH")["composite_score"]
    lo = _risk_for(BENIGN, 0.1)["composite_score"]
    assert hi > lo
    assert hi >= 60


def test_decomposition_sums_to_composite():
    r = _risk_for(TROJAN, 0.9, "HIGH", "HIGH")
    total = sum(d["contribution"] for d in r["decomposition"])
    assert abs(total - r["composite_score"]) < 0.05


def test_ml_rule_disagreement_flagged():
    """ML says benign but the rules see a banking trojan -> must be flagged."""
    r = _risk_for(TROJAN, 0.02)
    assert r["ml_rule_disagreement"] is True
    assert "rule-driven" in r["headline_verdict"]


def test_no_false_disagreement_on_benign():
    r = _risk_for(BENIGN, 0.02)
    assert r["ml_rule_disagreement"] is False
    assert r["headline_verdict"] == "BENIGN"


def test_severity_bands():
    assert risk.compute({"verdict": "BENIGN", "malicious_probability": 0.0},
                        {"fraud_signal_score": 0, "fraud_signal_max": 9,
                         "targeted_banks": [], "otp_interception_risk": "NONE"},
                        {"confidence": "NONE"}, {"sophistication": "NONE"}
                        )["severity"] == "LOW"


# ------------------------------------------------------------------ ingestion
def test_rejects_non_zip(tmp_path):
    p = tmp_path / "x.apk"
    p.write_bytes(b"not a zip file at all")
    with pytest.raises(pipeline.IngestError, match="INVALID_APK"):
        pipeline.validate(p.read_bytes(), p)


def test_rejects_zip_without_manifest(tmp_path):
    p = tmp_path / "x.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("hello.txt", "hi")
    with pytest.raises(pipeline.IngestError, match="AndroidManifest"):
        pipeline.validate(p.read_bytes(), p)


def test_rejects_zip_bomb(tmp_path):
    p = tmp_path / "bomb.apk"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x00" * 16)
        z.writestr("bomb", b"\x00" * 8_000_000)     # compresses enormously
    with pytest.raises(pipeline.IngestError, match="ZIPBOMB"):
        pipeline.validate(p.read_bytes(), p)


def test_rejects_oversized(tmp_path):
    p = tmp_path / "big.apk"
    p.write_bytes(b"x" * 16)
    big = b"x" * (pipeline.MAX_APK_BYTES + 1)
    with pytest.raises(pipeline.IngestError, match="FILE_TOO_LARGE"):
        pipeline.validate(big, p)


# ----------------------------------------------------------------------- IOC
def _fake_case():
    f = fraud.analyse(TROJAN)
    cls = {"verdict": "MALICIOUS", "malicious_probability": .9, "confidence": .9,
           "shap_top_features": []}
    return {
        "case_id": "test-case", "analysed_at": "2026-01-01T00:00:00Z",
        "hashes": {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64},
        "file_size_bytes": 1024,
        "signals": {**TROJAN, "urls": ["http://evil.invalid/gate"], "ips": ["1.2.3.4"]},
        "classification": cls, "fraud": f,
        "attribution": {"certificate": {"sha256": "d" * 64, "subject_cn": "X",
                                        "self_signed": True},
                        "related_families": ["Cerberus"], "confidence": "HIGH"},
        "attack": attack.analyse(TROJAN, f),
        "risk": risk.compute(cls, f, {"confidence": "HIGH"},
                             {"sophistication": "HIGH"}),
    }


def test_ioc_bundle_contains_indicators():
    b = iocs.build(_fake_case())
    assert b["indicators"]["file_hashes"]["sha256"] == "c" * 64
    assert any(c["value"] == "http://evil.invalid/gate"
               for c in b["indicators"]["c2_candidates"])
    assert b["indicators"]["certificate_fingerprints"][0]["sha256"] == "d" * 64


def test_ioc_csv_has_header_and_rows():
    csv = iocs.to_csv(iocs.build(_fake_case()))
    lines = csv.splitlines()
    assert lines[0].startswith("case_id,ioc_type")
    assert len(lines) > 5


# ------------------------------------------------------------ bank targeting
def test_legitimate_bank_app_does_not_target_itself():
    genuine = {"package": "com.sbi.lotusintouch",
               "short_permissions": ["INTERNET"],
               "referenced_packages": ["com.sbi.lotusintouch"]}
    r = fraud.analyse(genuine)
    assert r["targeted_banks"] == []
    assert r["notes"], "genuine-package caveat should be stated"


def test_bank_targets_found_in_dex_strings():
    s = {**BENIGN, "string_referenced_packages": ["com.phonepe.app"]}
    targets = fraud.analyse(s)["targeted_banks"]
    assert [t["source"] for t in targets] == ["dex_strings"]


def test_impersonation_matches_segment_prefix_only():
    assert fraud.analyse({**BENIGN, "package": "com.maxis.taxis"})["targeted_banks"] == []
    for pkg in ("com.axis.bonus.reward", "com.example.iciciofficial"):
        hits = fraud.analyse({**BENIGN, "package": pkg})["targeted_banks"]
        assert hits and hits[0]["source"] == "name_impersonation", pkg


def test_bank_name_alone_does_not_override_ml():
    """A bank-affiliated app with no fraud capability must not be called suspicious."""
    r = _risk_for({**BENIGN, "package": "com.icicibank.rewards"}, 0.02)
    assert r["ml_rule_disagreement"] is False
    sms = {**BENIGN, "package": "com.example.iciciofficial",
           "short_permissions": ["READ_SMS", "RECEIVE_SMS"]}
    assert _risk_for(sms, 0.02)["ml_rule_disagreement"] is True


def test_overlay_kit_needs_a_second_signal():
    perms = ["BIND_ACCESSIBILITY_SERVICE", "BIND_NOTIFICATION_LISTENER_SERVICE",
             "READ_SMS", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW"]
    kde_like = {**BENIGN, "package": "org.kde.kdeconnect_tp", "short_permissions": perms}
    sova_like = {**kde_like, "package": "com.kghlbqvf.kcanlzw.ksy"}
    assert _risk_for(kde_like, 0.02)["ml_rule_disagreement"] is False
    assert _risk_for(sova_like, 0.02)["ml_rule_disagreement"] is True
    f = fraud.analyse(kde_like)
    cls = {"verdict": "BENIGN", "malicious_probability": 0.02, "confidence": 0.98}
    assert risk.compute(cls, f, {"confidence": "NONE"},
                        {"sophistication": "MEDIUM", "strong_indicators": 1}
                        )["ml_rule_disagreement"] is True


# ------------------------------------------------------------------- evasion
def test_weak_evasion_indicators_alone_rate_low():
    from sentinelx import evasion
    r = evasion.summarise({"reflection": "r", "crypto": "c", "anti_debugger": "d"})
    assert r["sophistication"] == "LOW"
    assert len(r["blind_spots"]) == 2       # still honest about what was unseen


def test_strong_evasion_indicators_rate_high():
    from sentinelx import evasion
    assert evasion.summarise({"anti_emulator": "e", "dynamic_loading": "d"}
                             )["sophistication"] == "HIGH"
    assert evasion.summarise({"packer": "p"})["sophistication"] == "HIGH"


# ---------------------------------------------------------------- GenAI
def _bundle(confidence="NONE", families=()):
    return {"sample_hashes": {"sha256": "c" * 64},
            "attribution": {"certificate_confidence": confidence,
                            "related_families": list(families)},
            "otp_interception": {"target_banks": ["SBI YONO"]},
            "attack_techniques": [{"id": "T1412"}]}


def _llm_out(**draft):
    base = {"sample_hash_sha256": "c" * 64, "malware_family": "not determined",
            "targeted_institutions": ["SBI YONO"], "attack_vectors": []}
    return {"executive_summary": "", "attack_chain_narrative": "T1412 used",
            "key_findings": [], "cert_in_draft": {**base, **draft}}


def test_grounded_llm_output_accepted():
    from sentinelx import genai
    assert genai.grounding_errors(_llm_out(), _bundle()) == []


def test_llm_hallucinations_rejected():
    from sentinelx import genai
    assert genai.grounding_errors(_llm_out(malware_family="Cerberus"), _bundle("MEDIUM",
                                  ["Cerberus"]))
    assert genai.grounding_errors(_llm_out(sample_hash_sha256="0" * 64), _bundle())
    assert genai.grounding_errors(_llm_out(targeted_institutions=["HDFC"]), _bundle())
    bad = _llm_out(); bad["attack_chain_narrative"] = "T1412 then T1999"
    assert genai.grounding_errors(bad, _bundle())


# ------------------------------------------------------------- real APKs
SAMPLES = sorted((ROOT / "samples").glob("*.apk"))


@pytest.mark.skipif(not SAMPLES, reason="no sample APKs in samples/")
@pytest.mark.parametrize("apk", SAMPLES, ids=lambda p: p.stem)
def test_benign_fdroid_apps_do_not_trip_the_rules(apk):
    """End-to-end regression on real benign apps (samples/ holds F-Droid APKs only).

    The ML model has known false positives on SMS apps; that is reported, not hidden.
    What must never happen is the RULE layer overriding a benign app.
    Evasion is not asserted: security-conscious benign apps (Aegis ships emulator
    checks; bank apps ship root detection) legitimately rate MEDIUM.
    """
    case = pipeline.analyse(apk.read_bytes(), None, apk.name, use_cache=False)
    assert case["fraud"]["trojan_kit_complete"] is False, apk.name
    assert case["risk"]["ml_rule_disagreement"] is False, apk.name
    assert case["evasion"]["sophistication"] != "HIGH", apk.name


# -------------------------------------------------- component permissions
class _FakeManifestApk:
    def __init__(self, xml: str):
        from lxml import etree
        self._root = etree.fromstring(xml.encode())

    def get_android_manifest_xml(self):
        return self._root


def test_component_bind_permissions_are_extracted():
    from sentinelx.features import component_permissions
    ns = 'xmlns:android="http://schemas.android.com/apk/res/android"'
    apk = _FakeManifestApk(f"""<manifest {ns}><application>
      <service android:name=".A" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
      <receiver android:name=".B"><intent-filter>
        <action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/></intent-filter></receiver>
    </application></manifest>""")
    assert component_permissions(apk) == ["android.permission.BIND_ACCESSIBILITY_SERVICE",
                                          "android.permission.BIND_DEVICE_ADMIN"]


# ------------------------------------------------------------ trojan kit
def test_two_of_three_kit_capabilities_do_not_trigger_override():
    """KDE Connect-like (accessibility + SMS) and Key Mapper-like (accessibility + admin)."""
    for perms in (["BIND_ACCESSIBILITY_SERVICE", "READ_SMS", "RECEIVE_SMS",
                   "BIND_NOTIFICATION_LISTENER_SERVICE"],
                  ["BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
                   "BIND_NOTIFICATION_LISTENER_SERVICE"]):
        r = _risk_for({**BENIGN, "short_permissions": perms}, 0.02)
        assert r["ml_rule_disagreement"] is False, perms


def test_rule_override_raises_severity_floor():
    r = _risk_for(TROJAN, 0.0)
    assert r["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


# ------------------------------------------------------------ attribution
def test_shared_test_key_is_not_attribution(monkeypatch):
    from sentinelx import certgraph
    fake = [{"sha256": "k" * 64, "subject_cn": "Android", "family": "Cerberus"},
            {"sha256": "k" * 64, "subject_cn": "Android", "family": "Hydra"},
            {"sha256": "u" * 64, "subject_cn": "zalelukufeho", "family": "Ermac"}]
    monkeypatch.setattr(certgraph, "corpus", lambda: fake)
    certgraph._families_by_fingerprint.cache_clear()
    try:
        fams, conf, flags = certgraph.attribute({"sha256": "k" * 64, "subject_cn": "Android"})
        assert (fams, conf, flags) == ([], "NONE", ["shared_or_test_key"])
        assert certgraph.attribute({"sha256": "u" * 64, "subject_cn": "zalelukufeho"}
                                   )[:2] == (["Ermac"], "HIGH")
        assert certgraph.attribute({"sha256": "x" * 64, "subject_cn": "Android"}
                                   )[1] == "NONE"
    finally:
        certgraph._families_by_fingerprint.cache_clear()


# --------------------------------------------------------------- dynamic
# The suite never executes a sample: every test here uses the `mock` backend,
# which returns scripted events, or builds a block by hand.
def test_dynamic_is_opt_in_by_default():
    from sentinelx import dynamic
    block = dynamic.analyse(b"anything", "com.example.app")
    assert block["status"] == "SKIPPED"
    assert block["behaviours"] == []


def test_unrequested_dynamic_block_has_every_key():
    """Consumers read the block directly, so a skipped run must not be sparse."""
    from sentinelx import dynamic
    ran = dynamic.analyse(b"x", "com.example.app", backend="mock")
    assert sorted(dynamic.schema.skipped()) == sorted(ran)


def test_triage_refuses_to_upload_without_permission():
    """Submitting to Triage publishes the sample; it must never be implicit."""
    from sentinelx import dynamic
    block = dynamic.analyse(b"x", "com.example.app", backend="triage")
    assert block["status"] == "ERROR"
    assert "public" in block["detail"].lower()


def test_unknown_backend_errors_instead_of_raising():
    from sentinelx import dynamic
    assert dynamic.analyse(b"x", "p", backend="nope")["status"] == "ERROR"


def test_behaviours_derived_from_observations():
    from sentinelx import dynamic
    ids = {b["id"] for b in
           dynamic.analyse(b"x", "p", backend="mock")["behaviours"]}
    assert {"sms_interception", "overlay_draw", "runtime_dex_load"} <= ids
    for b in dynamic.analyse(b"x", "p", backend="mock")["behaviours"]:
        assert b["evidence"] and b["mitre_id"]


def test_network_alone_is_not_a_confirmation():
    """Every app talks to the internet - C2 traffic escalates, never convicts."""
    from sentinelx.dynamic import behaviours, schema
    block = behaviours.enrich(schema.build(
        "mock", "COMPLETED",
        network={"http_requests": [{"method": "GET", "host": "a.example",
                                    "path": "/"}]}))
    assert [b["id"] for b in block["behaviours"]] == ["c2_contact"]
    assert risk.dynamic_reasons(block) == []


def test_dynamic_confirmation_overrides_benign_ml_verdict():
    from sentinelx import dynamic
    block = dynamic.analyse(b"x", "p", backend="mock")
    r = risk.compute({"verdict": "BENIGN", "malicious_probability": 0.01,
                      "confidence": 0.99}, fraud.analyse(BENIGN),
                     {"confidence": "NONE"}, {"sophistication": "NONE"}, 1.0, block)
    assert r["dynamic_confirmed"] is True
    assert r["headline_verdict"] == "MALICIOUS (dynamically confirmed)"
    assert r["severity"] == "CRITICAL"      # confirmed behaviour + C2 contact


def test_dynamic_does_not_change_the_composite_score():
    """Confirmation raises the floor; the 5 static weights stay comparable."""
    from sentinelx import dynamic
    cls = {"verdict": "BENIGN", "malicious_probability": 0.01, "confidence": 0.99}
    f = fraud.analyse(BENIGN)
    static = risk.compute(cls, f, {"confidence": "NONE"}, {"sophistication": "NONE"})
    dyn = risk.compute(cls, f, {"confidence": "NONE"}, {"sophistication": "NONE"},
                       1.0, dynamic.analyse(b"x", "p", backend="mock"))
    assert static["composite_score"] == dyn["composite_score"]


def test_quiet_run_never_lowers_the_static_verdict():
    """A dormant trojan is the expected case, not an acquittal."""
    from sentinelx.dynamic import behaviours, schema
    quiet = behaviours.enrich(schema.build("mock", "COMPLETED"))
    r = risk.compute({"verdict": "BENIGN", "malicious_probability": 0.02},
                     fraud.analyse(TROJAN), {"confidence": "NONE"},
                     {"sophistication": "NONE"}, 1.0, quiet)
    assert r["dynamic_confirmed"] is False
    assert r["ml_rule_disagreement"] is True     # the static override still stands
    assert r["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_blind_spots_only_resolved_when_static_flagged_them():
    from sentinelx.dynamic import behaviours, schema
    observed = {"dynamic_code_loading": [{"loader": "DexClassLoader",
                                          "path_or_hash": "/x/p.jar"}]}
    both = behaviours.enrich(schema.build("mock", "COMPLETED", **observed),
                             {"dynamic_loading"})
    assert [r["key"] for r in both["blind_spots_resolved"]] == ["dynamic_loading"]
    none = behaviours.enrich(schema.build("mock", "COMPLETED", **observed), set())
    assert none["blind_spots_resolved"] == []


def test_runtime_iocs_are_labelled_as_dynamic():
    from sentinelx import dynamic
    case = {"signals": {"package": "p", "urls": [], "ips": []},
            "hashes": {"sha256": "a" * 64}, "attribution": {"certificate": {},
            "related_families": []}, "fraud": {"targeted_banks": []},
            "classification": {"verdict": "BENIGN", "confidence": 0.9},
            "risk": {"severity": "LOW"}, "attack": {"techniques": []},
            "dynamic": dynamic.analyse(b"x", "p", backend="mock")}
    bundle = iocs.build(case)
    runtime = [c for c in bundle["indicators"]["c2_candidates"]
               if c["extraction_method"].startswith("dynamic")]
    assert runtime, "runtime-observed C2 endpoints must reach the IOC export"
    assert bundle["indicators"]["dropped_payloads"]
    assert ",dynamic" in iocs.to_csv(bundle)


def test_genai_never_implies_a_run_that_did_not_happen():
    from sentinelx import genai
    facts = genai._dynamic_facts({"dynamic": {"status": "SKIPPED"}})
    assert facts["executed"] is False
    assert "NOT executed" in facts["note"]


def test_grounding_accepts_attack_ids_seen_only_at_runtime():
    from sentinelx import genai
    bundle = {"sample_hashes": {"sha256": "a" * 64},
              "attribution": {"related_families": [], "certificate_confidence": "NONE"},
              "otp_interception": {"target_banks": []},
              "attack_techniques": [],
              "dynamic_analysis": {"behaviours": [{"mitre_id": "T1407",
                                                   "label": "x", "evidence": "y"}]}}
    out = {"cert_in_draft": {"sample_hash_sha256": "a" * 64,
                             "malware_family": "not determined",
                             "targeted_institutions": [], "attack_vectors": []},
           "attack_chain_narrative": "Loaded code at runtime (T1407).",
           "executive_summary": "", "key_findings": []}
    assert genai.grounding_errors(out, bundle) == []
    out["attack_chain_narrative"] = "Invented T1999."
    assert genai.grounding_errors(out, bundle)
