"""Generative-AI narrative layer.

Design commitments (carried over from the audit's anti-AI-washing requirements):
  * Structured input only  — the model never sees raw APK bytes.
  * Deterministic fallback — a template engine produces every section when no
    API key is set or the call fails, so the demo never depends on the network.
  * Labeled output         — every section is tagged [AI GENERATED] or [TEMPLATE].

Three products: executive summary, attack-chain narrative, CERT-In incident draft.
"""
from __future__ import annotations
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

from .config import (GENAI_MODEL, LLM_API_KEY, LLM_BASE_URL, LLM_FALLBACK_MODELS,
                     LLM_PROVIDER)

SYSTEM_PROMPT = """You are a senior Android malware analyst writing for an Indian \
bank's SOC and for CERT-In.

CONSTRAINTS:
- Describe ONLY facts present in INPUT_JSON. Never invent IOCs, domains, malware \
family names, or attribution.
- If a field is null, empty or UNKNOWN, write "not determined" instead of guessing.
- Do not name a malware family unless attribution.confidence is HIGH.
- verdict.headline is the platform's verdict. If verdict.ml_rule_disagreement is true, say the \
ML model was overruled by the rules and why (verdict.rule_override_reasons); never present the \
ML label as the final verdict.
- dynamic_analysis.executed distinguishes what the sample DID from what it COULD do. When it \
is false, never write that anything was observed, seen, or confirmed at runtime. When it is \
true, attribute those findings to sandbox execution, and if dynamic_analysis.simulated is true \
say the run was simulated.
- Respond with valid JSON matching the requested schema, nothing else."""

OUTPUT_SCHEMA = {
    "executive_summary": "string, max 150 words, plain language for management",
    "attack_chain_narrative": "string, technical, references the MITRE technique IDs given",
    "key_findings": ["string, 3-5 items"],
    "recommended_actions": ["string, evidence-backed"],
    "cert_in_draft": {
        "incident_title": "string",
        "incident_category": "Malware",
        "affected_sector": "BFSI",
        "severity": "string",
        "sample_hash_sha256": "string",
        "malware_family": "string or 'not determined'",
        "targeted_institutions": ["string"],
        "attack_vectors": ["string"],
        "recommended_mitigations": ["string"],
        "reporting_urgency": "IMMEDIATE | EXPEDITED | STANDARD",
    },
}


def _dynamic_facts(case: dict[str, Any]) -> dict[str, Any]:
    """Runtime observations, or an explicit 'not executed' so the model cannot imply one."""
    dyn = case.get("dynamic") or {}
    if dyn.get("status") not in ("COMPLETED", "TIMEOUT"):
        return {"executed": False,
                "note": "This sample was NOT executed. Describe static evidence only "
                        "and never imply runtime observation."}
    net = dyn.get("network", {})
    return {
        "executed": True,
        "sandbox": dyn.get("backend", ""),
        "simulated": dyn.get("backend") == "mock",
        "behaviours": [{"label": b.get("label"), "mitre_id": b.get("mitre_id"),
                        "evidence": b.get("evidence")}
                       for b in dyn.get("behaviours", [])],
        "hosts_contacted": [r.get("host") for r in net.get("http_requests", [])
                            if r.get("host")] or net.get("dns_queries", []),
        "runtime_code_loading": bool(dyn.get("dynamic_code_loading")),
        "blind_spots_closed": [r.get("key") for r in dyn.get("blind_spots_resolved", [])],
    }


def build_bundle(case: dict[str, Any]) -> dict[str, Any]:
    """The structured, verified input the model is allowed to see."""
    return {
        "sample_hashes": case.get("hashes", {}),
        "package": case.get("package", ""),
        "verdict": {
            # The headline is the platform's verdict; the ML label is one input to it.
            "headline": case["risk"].get("headline_verdict", case["classification"]["verdict"]),
            "ml_label": case["classification"]["verdict"],
            "ml_confidence": case["classification"]["confidence"],
            "ml_rule_disagreement": case["risk"].get("ml_rule_disagreement", False),
            "rule_override_reasons": case["risk"].get("override_reasons", []),
            "dynamic_confirmed": case["risk"].get("dynamic_confirmed", False),
            "dynamic_reasons": case["risk"].get("dynamic_reasons", []),
        },
        "dynamic_analysis": _dynamic_facts(case),
        "banking_trojan_kit": {
            "complete": case["fraud"].get("trojan_kit_complete", False),
            "overlay_kit_without_admin": case["fraud"].get("overlay_kit_without_admin", False),
        },
        "shap_top_features": case["classification"]["shap_top_features"][:8],
        "otp_interception": {
            "risk": case["fraud"]["otp_interception_risk"],
            "signals": case["fraud"]["signals"],
            "target_banks": [b["bank"] for b in case["fraud"]["targeted_banks"]],
        },
        "attribution": {
            "certificate_confidence": case["attribution"]["confidence"],
            "related_families": case["attribution"]["related_families"],
        },
        "attack_techniques": case["attack"]["techniques"],
        "evasion": {
            "sophistication": case["evasion"]["sophistication"],
            "techniques": [t["label"] for t in case["evasion"]["techniques_detected"]],
        },
        "risk_score": {
            "composite": case["risk"]["composite_score"],
            "severity": case["risk"]["severity"],
        },
    }


# --------------------------------------------------------------------------- #
# Template engine (always available, deterministic)
# --------------------------------------------------------------------------- #
def _template(bundle: dict[str, Any]) -> dict[str, Any]:
    v = bundle["verdict"]
    otp = bundle["otp_interception"]
    banks = otp["target_banks"]
    techs = bundle["attack_techniques"]
    fam = bundle["attribution"]["related_families"]
    risk = bundle["risk_score"]
    sha = bundle["sample_hashes"].get("sha256", "not determined")

    bank_txt = ", ".join(banks) if banks else "no specific Indian bank"
    # Same rule the LLM is held to: name a family only on HIGH attribution.
    high = bundle["attribution"]["certificate_confidence"] == "HIGH"
    fam_txt = ", ".join(fam) if (fam and high) else "not determined"
    tech_ids = ", ".join(t["id"] for t in techs) if techs else "none mapped"

    dyn = bundle.get("dynamic_analysis", {})
    ml_txt = (f"The ML classifier alone said {v['ml_label']} at {v['ml_confidence']:.0%}; "
              "the banking-fraud rules overruled it. "
              if v["ml_rule_disagreement"] else "")
    dyn_txt = ""
    if v.get("dynamic_confirmed"):
        dyn_txt = ("Executed in the sandbox, the sample "
                   + ", ".join(v.get("dynamic_reasons", [])) + ", which confirms the "
                   "static findings by observation rather than inference. ")
    elif dyn.get("executed"):
        dyn_txt = ("The sample was executed in the sandbox and performed no flagged "
                   "action; dormancy under emulation is itself common trojan behaviour. ")
    summary = (
        f"Verdict: {v['headline']}. {ml_txt}{dyn_txt}"
        f"The sample carries a composite risk score of {risk['composite']} "
        f"({risk['severity']}). OTP-interception risk is rated {otp['risk']}. "
        f"Targeting analysis identifies {bank_txt}. Certificate attribution: {fam_txt}. "
        f"{len(techs)} MITRE ATT&CK for Mobile techniques were mapped from static "
        f"evidence. Recommended response: {risk['severity']} handling."
    )

    chain_bits = [f"[{t['id']}] {t['name']} — evidence: {t['evidence']}" for t in techs]
    narrative = (
        "Reconstructed attack chain from static evidence:\n  - "
        + "\n  - ".join(chain_bits) if chain_bits
        else "No ATT&CK techniques were mapped from the available static evidence."
    )
    if dyn.get("behaviours"):
        narrative += ("\n\nObserved during sandbox execution:\n  - " + "\n  - ".join(
            f"[{b['mitre_id']}] {b['label']} — {b['evidence']}"
            for b in dyn["behaviours"]))

    findings = [f"Verdict {v['headline']} (ML label {v['ml_label']} at "
                f"{v['ml_confidence']:.0%} calibrated confidence)"]
    if dyn.get("behaviours"):
        findings.append("Observed at runtime: "
                        + "; ".join(b["label"] for b in dyn["behaviours"][:3]))
    if otp["risk"] in ("HIGH", "MEDIUM"):
        findings.append(f"OTP interception risk {otp['risk']}: "
                        + "; ".join(otp["signals"][:3]))
    if banks:
        findings.append(f"Indian banking apps targeted: {bank_txt}")
    if bundle["evasion"]["techniques"]:
        findings.append("Evasion: " + ", ".join(bundle["evasion"]["techniques"][:3]))
    findings.append(f"ATT&CK techniques mapped: {tech_ids}")

    urgency = ("IMMEDIATE" if risk["severity"] == "CRITICAL"
               else "EXPEDITED" if risk["severity"] == "HIGH" else "STANDARD")

    return {
        "executive_summary": summary,
        "attack_chain_narrative": narrative,
        "key_findings": findings[:5],
        "recommended_actions": [
            "Block the listed IOCs (package name, certificate fingerprint, any C2 hosts) "
            "at the mobile-threat and network perimeter.",
            f"Issue a customer advisory for {bank_txt} covering fake-overlay login screens.",
            "Search fraud logs for transactions from devices matching these indicators.",
            "File the CERT-In notification below if the sample is novel or widespread.",
        ],
        "cert_in_draft": {
            "incident_title": f"Android banking trojan sample — {risk['severity']} severity",
            "incident_category": "Malware",
            "affected_sector": "BFSI",
            "severity": risk["severity"],
            "sample_hash_sha256": sha,
            "malware_family": fam_txt,
            "targeted_institutions": banks or ["not determined"],
            "attack_vectors": [t["name"] for t in techs] or ["not determined"],
            "recommended_mitigations": [
                "Block listed IOCs at perimeter and MTD platform",
                "Customer advisory on overlay phishing and OTP disclosure",
                "Monitor for transactions correlated with these indicators",
            ],
            "reporting_urgency": urgency,
            "reporting_institution": "[ANALYST TO COMPLETE]",
            "analyst_review_note": "DRAFT — verify all fields and IOCs before submission.",
        },
    }


# --------------------------------------------------------------------------- #
# Live LLM path (optional)
# --------------------------------------------------------------------------- #
_STR = {"type": "string"}
_STR_LIST = {"type": "array", "items": _STR}


def _obj(props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": props,
            "required": list(props), "additionalProperties": False}


# JSON Schema enforced server-side via output_config.format — the response is
# guaranteed to parse, so validation below only has to check *grounding*.
JSON_SCHEMA = _obj({
    "executive_summary": _STR,
    "attack_chain_narrative": _STR,
    "key_findings": _STR_LIST,
    "recommended_actions": _STR_LIST,
    "cert_in_draft": _obj({
        "incident_title": _STR,
        "incident_category": _STR,
        "affected_sector": _STR,
        "severity": _STR,
        "sample_hash_sha256": _STR,
        "malware_family": _STR,
        "targeted_institutions": _STR_LIST,
        "attack_vectors": _STR_LIST,
        "recommended_mitigations": _STR_LIST,
        "reporting_urgency": {"type": "string",
                              "enum": ["IMMEDIATE", "EXPEDITED", "STANDARD"]},
    }),
})

TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def grounding_errors(out: dict[str, Any], bundle: dict[str, Any]) -> list[str]:
    """Facts in the LLM output that are not in the verified input bundle.

    Any hit rejects the whole response: a CERT-In draft with an invented family,
    hash, bank or technique is worse than a plain template.
    """
    errors: list[str] = []
    draft = out.get("cert_in_draft", {})
    sha = bundle["sample_hashes"].get("sha256", "")
    if draft.get("sample_hash_sha256", "").lower() != sha.lower():
        errors.append("sample hash does not match the analysed sample")

    families = set(bundle["attribution"]["related_families"])
    fam = (draft.get("malware_family") or "").strip()
    if fam.lower() != "not determined":
        if bundle["attribution"]["certificate_confidence"] != "HIGH":
            errors.append(f"family '{fam}' named without HIGH attribution confidence")
        elif not any(f.lower() in fam.lower() for f in families):
            errors.append(f"family '{fam}' is not in the attributed families")

    banks = [b.lower() for b in bundle["otp_interception"]["target_banks"]]
    for inst in draft.get("targeted_institutions", []):
        low = inst.lower()
        if low != "not determined" and not any(b in low or low in b for b in banks):
            errors.append(f"targeted institution '{inst}' was not detected")

    # Techniques mapped from declared permissions, plus any observed during
    # execution — behaviours legitimately cite IDs the static mapping never had.
    allowed = {t["id"] for t in bundle["attack_techniques"]}
    allowed |= {b.get("mitre_id") for b
                in bundle.get("dynamic_analysis", {}).get("behaviours", [])}
    allowed.discard(None)
    text = " ".join([out.get("attack_chain_narrative", ""),
                     out.get("executive_summary", ""),
                     *out.get("key_findings", []), *draft.get("attack_vectors", [])])
    invented = sorted(set(TECH_ID_RE.findall(text)) - allowed)
    if invented:
        errors.append(f"ATT&CK IDs not in the mapping: {', '.join(invented)}")
    return errors


def _user_prompt(bundle: dict[str, Any]) -> str:
    return ("INPUT_JSON:\n" + json.dumps(bundle, indent=2, sort_keys=True)
            + "\n\nField guidance:\n" + json.dumps(OUTPUT_SCHEMA, indent=2)
            + "\n\nRespond with a single JSON object and nothing else.")


def _call_anthropic(bundle: dict[str, Any]) -> tuple[str | None, str]:
    """(response_text, model_or_reason) via the Anthropic SDK."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=LLM_API_KEY, timeout=120.0)
        msg = client.beta.messages.create(
            model=GENAI_MODEL,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _user_prompt(bundle)}],
            output_config={"effort": "medium",
                           "format": {"type": "json_schema", "schema": JSON_SCHEMA}},
            # Malware analysis can trip safety classifiers; re-route instead of failing.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except Exception as exc:
        return None, f"LLM call failed: {type(exc).__name__}: {exc}"[:300]
    if msg.stop_reason == "refusal":
        return None, "LLM declined the request (refusal)"
    if msg.stop_reason == "max_tokens":
        return None, "LLM output truncated at max_tokens"
    return next((b.text for b in msg.content if b.type == "text"), ""), msg.model


def _post_chat(payload: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{LLM_BASE_URL}/chat/completions", data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {LLM_API_KEY}",
                 "Content-Type": "application/json", "User-Agent": "sentinelx"})
    return json.loads(urllib.request.urlopen(req, timeout=120).read())


RETRYABLE = {429, 500, 502, 503, 504}


def _call_one_model(bundle: dict[str, Any], model: str) -> tuple[str | None, str, bool]:
    """(text, model_or_reason, retryable) for a single model, with one short retry."""
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": _user_prompt(bundle)}],
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "sentinelx_narrative", "strict": True, "schema": JSON_SCHEMA}},
    }
    last = ""
    for attempt in range(2):
        try:
            try:
                res = _post_chat(payload)
            except urllib.error.HTTPError as exc:
                if exc.code != 400 or payload["response_format"]["type"] == "json_object":
                    raise
                # Model without schema-constrained decoding: fall back to plain JSON
                # mode. The grounding check still validates every fact.
                payload["response_format"] = {"type": "json_object"}
                res = _post_chat(payload)
        except urllib.error.HTTPError as exc:
            detail = " ".join(exc.read()[:300].decode("utf-8", "replace").split())
            last = f"HTTP {exc.code} from {model}: {detail}"
            if exc.code in RETRYABLE:
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None, last, True
            return None, last, False
        except Exception as exc:
            return None, f"{type(exc).__name__} from {model}: {exc}"[:300], True
        choice = (res.get("choices") or [{}])[0]
        if choice.get("finish_reason") == "length":
            return None, f"output truncated by {model}", False
        return (choice.get("message") or {}).get("content") or "", res.get("model", model), False
    return None, last, True


def _call_openai_compatible(bundle: dict[str, Any]) -> tuple[str | None, str]:
    """(response_text, model_or_reason) via an OpenAI-compatible endpoint
    (Gemini, Groq, OpenRouter). Standard library only — no extra SDK.

    Free tiers regularly return 429/503 under load, so an overloaded model is
    retried once and then the provider's fallback models are tried in order.
    """
    failures = []
    for model in [GENAI_MODEL, *(m for m in LLM_FALLBACK_MODELS if m != GENAI_MODEL)]:
        text, info, retryable = _call_one_model(bundle, model)
        if text is not None:
            return text, info
        failures.append(info)
        if not retryable:
            break
    return None, "LLM call failed: " + " | ".join(failures)


def _live(bundle: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Returns (output, model). output is None whenever the template must be used,
    and the second element is then the reason."""
    if LLM_PROVIDER == "none":
        return None, ("no LLM API key set (GEMINI_API_KEY, GROQ_API_KEY, "
                      "OPENROUTER_API_KEY or ANTHROPIC_API_KEY)")
    call = _call_anthropic if LLM_PROVIDER == "anthropic" else _call_openai_compatible
    text, info = call(bundle)
    if text is None:
        return None, info
    text = text.strip()
    if text.startswith("```"):                      # JSON-mode models sometimes fence
        text = text.strip("`").removeprefix("json").strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None, "LLM output was not valid JSON"
    if missing := [k for k in JSON_SCHEMA["required"] if k not in parsed]:
        return None, f"LLM output missing fields: {', '.join(missing)}"
    if errors := grounding_errors(parsed, bundle):
        return None, "LLM output failed grounding check: " + "; ".join(errors)
    parsed["cert_in_draft"]["reporting_institution"] = "[ANALYST TO COMPLETE]"
    parsed["cert_in_draft"]["analyst_review_note"] = (
        "DRAFT — verify all fields and IOCs before submission.")
    return parsed, f"{LLM_PROVIDER}:{info}"


def generate(case: dict[str, Any]) -> dict[str, Any]:
    bundle = build_bundle(case)
    live, info = _live(bundle)
    if live is not None:
        live["generation_metadata"] = {
            "mode": "AI_GENERATED", "model": info,
            "label": "[AI GENERATED — VERIFY AGAINST SOURCE DATA]",
            "fallback_used": False,
            "grounding_check": "passed",
        }
        live["source_bundle"] = bundle
        return live

    out = _template(bundle)
    out["generation_metadata"] = {
        "mode": "TEMPLATE", "model": None,
        "label": "[TEMPLATE — deterministic, no LLM call]",
        "fallback_used": True,
        "reason": info,
    }
    out["source_bundle"] = bundle
    return out
