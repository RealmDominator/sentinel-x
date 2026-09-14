"""PDF intelligence report (fpdf2 — pure pip, no GTK/Windows pain)."""
from __future__ import annotations
from typing import Any

from fpdf import FPDF

SEV_RGB = {"CRITICAL": (176, 0, 32), "HIGH": (200, 80, 0),
           "MEDIUM": (170, 140, 0), "LOW": (0, 120, 70)}


def _clean(text: Any) -> str:
    """fpdf2 core fonts are latin-1; drop anything they can't encode."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class Report(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, "SENTINEL-X  |  Android Banking Malware Intelligence Report",
                  new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, 18, 200, 18)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"Page {self.page_no()}  -  Static analysis only; "
                         f"no sample was executed.", align="C")

    def h1(self, text: str) -> None:
        self.ln(2)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(20, 30, 60)
        self.cell(0, 8, _clean(text), new_x="LMARGIN", new_y="NEXT")

    def h2(self, text: str) -> None:
        self.ln(1)
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(40, 40, 40)
        self.cell(0, 6, _clean(text), new_x="LMARGIN", new_y="NEXT")

    def body(self, text: str) -> None:
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5, _clean(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def kv(self, key: str, value: str) -> None:
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 9.5)
        self.set_text_color(70, 70, 70)
        self.cell(52, 5.5, _clean(key))
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(20, 20, 20)
        width = self.w - self.r_margin - self.get_x()
        self.multi_cell(width, 5.5, _clean(value),
                        new_x="LMARGIN", new_y="NEXT")

    def bullets(self, items: list[str]) -> None:
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(30, 30, 30)
        for it in items:
            self.set_x(self.l_margin + 4)
            width = self.w - self.r_margin - self.get_x()
            self.multi_cell(width, 5, _clean(f"- {it}"),
                            new_x="LMARGIN", new_y="NEXT")
        self.ln(1)


def build_pdf(case: dict[str, Any]) -> bytes:
    p = Report()
    p.set_auto_page_break(auto=True, margin=18)
    p.add_page()

    risk = case["risk"]
    cls = case["classification"]
    sev = risk["severity"]

    # --- Title / verdict banner ---
    p.set_font("Helvetica", "B", 18)
    p.set_text_color(*SEV_RGB.get(sev, (0, 0, 0)))
    p.cell(0, 10, _clean(f"{risk.get('headline_verdict', cls['verdict'])}  -  {sev}"),
           new_x="LMARGIN", new_y="NEXT")
    p.set_font("Helvetica", "", 10)
    p.set_text_color(60, 60, 60)
    p.cell(0, 6, _clean(f"Composite risk score {risk['composite_score']}/100  |  "
                        f"calibrated confidence {cls['confidence']:.1%}"),
           new_x="LMARGIN", new_y="NEXT")
    p.ln(3)

    # --- 1. Case summary ---
    p.h1("1. Case Summary")
    p.kv("Case ID", case["case_id"])
    p.kv("File", case.get("filename", ""))
    p.kv("Package", case.get("package") or "not determined")
    p.kv("SHA256", case["hashes"]["sha256"])
    p.kv("MD5", case["hashes"]["md5"])
    p.kv("Analysed at (UTC)", case["analysed_at"])
    p.kv("Completeness", case.get("analysis_completeness", "FULL"))
    p.kv("Recommended response", risk["recommended_response"])
    if risk.get("ml_rule_disagreement"):
        p.h2("ML / rule disagreement")
        p.body(risk["reconciliation_note"])

    # --- 2. Executive summary (AI/template) ---
    nar = case.get("narrative", {})
    meta = nar.get("generation_metadata", {})
    p.h1("2. Executive Summary")
    p.set_font("Helvetica", "I", 8.5)
    p.set_text_color(120, 120, 120)
    p.multi_cell(0, 4.5, _clean(meta.get("label", "")))
    p.ln(1)
    p.body(nar.get("executive_summary", "not generated"))
    if nar.get("key_findings"):
        p.h2("Key findings")
        p.bullets(nar["key_findings"])

    # --- 3. Verdict + SHAP ---
    p.h1("3. Technical Verdict and Explainability")
    p.body(f"XGBoost classifier with isotonic-calibrated probability. "
           f"Verdict {cls['verdict']} at {cls['confidence']:.1%} confidence "
           f"(P(malicious) = {cls['malicious_probability']:.4f}).")
    p.h2("Top SHAP feature contributions")
    feats = cls.get("shap_top_features", [])
    if feats:
        p.set_font("Helvetica", "", 9)
        for f in feats[:12]:
            direction = "toward MALICIOUS" if f["contribution"] > 0 else "toward BENIGN"
            state = "declared" if f["present"] else "absent"
            p.set_x(p.l_margin + 4)
            p.multi_cell(p.w - p.r_margin - p.get_x(), 5, _clean(
                f"- {f['feature']} ({state}): {f['contribution']:+.4f} {direction}"),
                new_x="LMARGIN", new_y="NEXT")
    else:
        p.body("SHAP contributions unavailable for this sample.")

    # --- 4. Attribution ---
    p.add_page()
    p.h1("4. Attribution Analysis")
    attr = case["attribution"]
    cert = attr.get("certificate") or {}
    if cert:
        p.kv("Certificate SHA256", cert.get("sha256", ""))
        p.kv("Subject CN", cert.get("subject_cn", ""))
        p.kv("Issuer CN", cert.get("issuer_cn", ""))
        p.kv("Self-signed", str(cert.get("self_signed")))
    else:
        p.body("No signing certificate could be extracted from this sample.")
    p.kv("Attribution confidence", attr.get("confidence", "NONE"))
    p.kv("Related families", ", ".join(attr.get("related_families", [])) or "none")
    p.kv("Corpus size", f"{attr.get('corpus_size', 0)} known certificates")
    for f in attr.get("signer_flags", []):
        p.body(f"Note: {f['text']}")
    shared = attr.get("shared_signer_samples", [])
    if shared:
        p.h2("Previously analysed samples with the same signer")
        p.bullets([f"{s.get('package') or s['sha256'][:16]} - {s.get('severity')} "
                   f"({s['sha256'][:16]}...)" for s in shared])

    # --- 5. Attack chain ---
    p.h1("5. Attack Chain (MITRE ATT&CK for Mobile)")
    techs = case["attack"]["techniques"]
    if techs:
        p.set_font("Helvetica", "", 9)
        for t in techs:
            p.set_x(p.l_margin + 4)
            p.multi_cell(p.w - p.r_margin - p.get_x(), 5, _clean(
                f"- [{t['id']}] {t['name']} ({t['tactic']}) - evidence: {t['evidence']}"),
                new_x="LMARGIN", new_y="NEXT")
        p.ln(1)
    else:
        p.body("No techniques mapped from available static evidence.")
    p.h2("Narrative")
    p.body(nar.get("attack_chain_narrative", "not generated"))

    # --- 6. Fraud mechanism ---
    p.h1("6. Fraud Mechanism Analysis")
    fr = case["fraud"]
    p.kv("Banking-trojan kit", "COMPLETE (accessibility + device admin + SMS)"
         if fr.get("trojan_kit_complete") else
         "OVERLAY KIT (accessibility + notifications + SMS + overlay)"
         if fr.get("overlay_kit_without_admin") else "not complete")
    p.kv("Package name", "machine-generated" if fr.get("package_name_obfuscated")
         else "normal")
    p.kv("OTP interception capability", fr["otp_interception_risk"])
    p.kv("Full OTP triplet", "YES" if fr["otp_triplet_complete"] else "no")
    banks = ", ".join(f"{b['bank']} ({b['package']})" for b in fr["targeted_banks"])
    p.kv("Targeted banks", banks or "none detected")
    if fr["signals"]:
        p.h2("Triggering signals")
        p.bullets(fr["signals"])
    if fr.get("notes"):
        p.h2("Caveats")
        p.bullets(fr["notes"])

    # --- 7. Risk decomposition ---
    p.h1("7. Composite Risk Score Decomposition")
    p.set_font("Helvetica", "B", 9)
    p.cell(60, 6, "Signal"); p.cell(28, 6, "Sub-score")
    p.cell(24, 6, "Weight"); p.cell(30, 6, "Contribution", new_x="LMARGIN", new_y="NEXT")
    p.set_font("Helvetica", "", 9)
    for d in risk["decomposition"]:
        p.cell(60, 5.5, _clean(d["signal"]))
        p.cell(28, 5.5, f"{d['sub_score']:.3f}")
        p.cell(24, 5.5, f"{d['weight']:.0%}")
        p.cell(30, 5.5, f"{d['contribution']:.2f}", new_x="LMARGIN", new_y="NEXT")
    p.set_font("Helvetica", "B", 9.5)
    p.cell(112, 6, "COMPOSITE")
    p.cell(30, 6, f"{risk['composite_score']:.2f} / 100", new_x="LMARGIN", new_y="NEXT")

    # --- 8. IOCs ---
    p.add_page()
    p.h1("8. Indicators of Compromise")
    sig = case.get("signals", {})
    p.kv("Package name", sig.get("package") or "not determined")
    p.kv("SHA256", case["hashes"]["sha256"])
    if cert:
        p.kv("Cert fingerprint", cert.get("sha256", ""))
    urls, ips = sig.get("urls", [])[:12], sig.get("ips", [])[:12]
    if urls:
        p.h2("Candidate URLs (static strings)")
        p.bullets(urls)
    if ips:
        p.h2("Candidate IPs (static strings)")
        p.bullets(ips)
    if not urls and not ips:
        p.body("No plaintext network indicators recovered statically.")

    # --- 9. Evasion + blind spots ---
    p.h1("9. Evasion Profile and Analysis Blind Spots")
    ev = case["evasion"]
    p.kv("Evasion sophistication", ev["sophistication"])
    if ev["techniques_detected"]:
        p.bullets([t["label"] + (" (weak - common in benign apps)"
                                 if t.get("strength") == "weak" else "")
                   for t in ev["techniques_detected"]])
    p.h2("What this static analysis could NOT see")
    p.bullets(ev["blind_spots"])

    # --- 10. Recommended actions + CERT-In ---
    p.h1("10. Recommended Actions")
    p.bullets(nar.get("recommended_actions", []))

    p.h1("11. CERT-In Incident Report (Draft)")
    p.set_font("Helvetica", "I", 8.5)
    p.set_text_color(120, 120, 120)
    p.multi_cell(0, 4.5, _clean(meta.get("label", "")))
    draft = nar.get("cert_in_draft", {})
    for k, v in draft.items():
        p.kv(k.replace("_", " ").title(),
             ", ".join(v) if isinstance(v, list) else str(v))

    out = p.output()
    return bytes(out)
