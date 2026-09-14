# SENTINEL-X

---

# One-Line Pitch

An automated intelligence platform that transforms a suspicious Android APK into a complete, explainable, attributed, and regulator-ready threat report in under sixty seconds — built specifically for Indian BFSI security teams and CERT-In analysts.

---

# Executive Summary

Every day, banking security teams in India receive suspicious Android applications. Some are reported by customers who narrowly avoided fraud. Others are intercepted by threat feeds or discovered during incident response. The universal problem is the same: the tools available to analyze these files answer only one question — *is this malicious?* — and stop there.

The question that actually matters to a BFSI security team is not whether a file is malicious. It is *why it was flagged, who built it, which Indian banks it targets, how the attack chain works from the victim's perspective, whether it belongs to a known campaign, and what needs to be reported to CERT-In by end of business today.* Answering these questions with existing tools requires an experienced analyst, five separate platforms, and four to eight hours of manual work. Most banking institutions do not have four hours. Many do not have the analyst.

SENTINEL-X is an Android Banking Malware Attribution Intelligence Platform that compresses that entire workflow into a single automated pipeline. A suspicious APK is submitted through a web interface or REST API. Within sixty seconds, the platform returns a complete intelligence product: an explainable ML verdict with per-feature SHAP attribution, a certificate relationship graph revealing shared infrastructure with known malware families, a builder kit identification identifying which dark-web malware construction kit produced the sample, a MITRE ATT&CK for Mobile technique matrix, a visual reconstruction of the phishing overlay the fraud victim encounters, an OTP interception risk assessment, a composite risk score decomposed across five auditable dimensions, and — critically — two outputs that no existing tool produces: AI-generated analysis of obfuscated bytecode intent, and a pre-drafted CERT-In incident notification ready for analyst review and submission.

The platform is built around a deliberate design principle: Generative AI performs analysis, not formatting. The most common failure mode in AI-augmented security tools is using a language model to reformat information that was already clear. SENTINEL-X uses GenAI for tasks that genuinely require language model reasoning: inferring the operational intent of obfuscated Android bytecode that traditional pattern matching cannot decode, generating a structured fraud playbook describing the attack lifecycle from installation to credential exfiltration in terms usable by fraud investigators and law enforcement, and drafting the mandatory incident report fields that CERT-In requires but that current tools leave entirely to human analysts. These are not prose generation tasks. They are reasoning tasks that produce investigative outputs unavailable by any other method.

The Indian banking context is not incidental to the platform — it is its calibration axis. Target detection covers SBI YONO, HDFC MobileBanking, ICICI iMobile Pay, Axis Bank Mobile Banking, and Paytm. The OTP interception module is weighted for India's SMS-based two-factor authentication model, which remains the primary authentication bypass vector in Indian banking fraud. Attribution coverage includes Drinik — the malware family that specifically targeted customers of 18 Indian banks — alongside Cerberus, Anubis, and SpyNote. Intelligence report outputs reference CERT-In reporting obligations and RBI cybersecurity incident notification requirements by name. The platform does not speak generic security language; it speaks the operational language of Indian banking infrastructure protection.

For a solo developer building under time constraints, the architecture is designed for incremental completeness: each module produces independent value, the core pipeline is demonstrable before all modules are finished, and the three most impactful visual outputs — the SHAP waterfall chart, the D3 certificate relationship graph, and the fraud overlay reconstruction — are achievable with well-established open-source libraries and AI-assisted development. The Generative AI components require thirty to fifty lines of API code per function. There is no training infrastructure, no MLOps pipeline, and no dependency on live external feeds in the critical analysis path.

This is not a research concept or a product roadmap. It is a buildable, demonstrable, judge-ready platform that solves a real problem in Indian banking security, with three capabilities that no publicly available tool currently provides.

---

# Problem Statement Mapping

**Problem Statement 1 — Full Text:**
*Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic Analysis, and Risk Scoring of Fraudulent Mobile Applications (APKs) and Malwares.*

| Requirement | Module | How It Is Satisfied |
|---|---|---|
| **Generative AI** | Obfuscated Code Intent Reconstructor; Fraud Playbook Generator; CERT-In Report Drafter; Executive Narrative Engine | GenAI is used for four distinct analytical functions. The primary function — bytecode semantic inference — requires LLM reasoning, not template formatting. The model infers the operational intent of obfuscated code blocks that static pattern matching cannot classify. This is analysis-layer GenAI, not presentation-layer GenAI. |
| **Automated Reverse Engineering** | APK Ingestion and Disassembly Pipeline | apktool decompiles the APK structure; jadx decompiles Dalvik bytecode to Java; Smali output is preserved for feature extraction and GenAI input. The pipeline is fully automated — no analyst interaction required from submission to disassembly completion. |
| **Static Analysis** | Static Feature Analysis Engine; OTP Interception Detection Module; Anti-Analysis Indicator Detection Module | Four-category static feature extraction (permission vector, API call families, opcode n-gram frequencies, string entropy) feeds XGBoost classification with SHAP explainability. OTP interception signals, accessibility service abuse patterns, and anti-analysis heuristics are extracted from manifests and disassembled bytecode without code execution. |
| **Dynamic Analysis** | Behavioral Static Analysis (integrated into Static Feature Analysis Engine) | Dynamic execution of malicious APKs presents legal risk, operational risk, and throughput constraints that make it unsuitable for banking institution deployment. Behavioral intent is inferred from opcode n-gram frequency distributions extracted from disassembled Smali bytecode — a technique that captures execution intent signatures without execution. Banking trojans' operationally significant behaviors (overlay rendering, OTP interception, accessibility abuse) all produce complete static signatures. This is framed as behavioral static analysis rather than a gap, because the behavioral signals are present and extractable. |
| **Risk Scoring** | Composite Risk Scoring and Reporting Engine | A five-signal weighted composite score aggregates ML confidence (35%), attribution evidence strength (25%), fraud signal density (20%), evasion sophistication (10%), and targeting specificity (10%) into a single 0–100 score with four-tier severity label. All five component scores and weighted contributions are displayed alongside the composite, enabling full audit transparency. XGBoost confidence scores are calibrated using isotonic regression on a held-out validation set to produce true probability estimates rather than raw classifier outputs. |
| **Fraudulent Mobile Applications / APKs** | All modules | The platform is scoped entirely to Android APK analysis. All feature extraction, attribution logic, and detection rules are calibrated for Android malware targeting banking applications. |
| **Malwares** | Static Feature Analysis Engine; Malware Provenance Analysis Module; Certificate Relationship Intelligence Module | The XGBoost classifier is trained on Android malware datasets. Attribution covers known malware families through both certificate fingerprint matching and builder kit structural fingerprinting. |

---

# Core Modules

## Module 1 — APK Ingestion and Disassembly Pipeline

**Purpose:** Accept a submitted APK file, validate its integrity, and produce all raw artifacts required by downstream analysis modules.

**Inputs:** APK file (uploaded via web interface or REST API endpoint).

**Outputs:** Decompiled Smali bytecode, jadx-decompiled Java source (where available), AndroidManifest.xml (parsed), resource directory tree, META-INF certificate files, strings.xml and raw string tables.

**Buildability:** High. apktool and jadx are mature, well-documented open-source tools. Python subprocess invocation is straightforward. File size limits (default 100MB), MIME type validation (application/vnd.android.package-archive and application/zip), ZIP structure integrity checks, and compression ratio limits for ZIP bomb protection are applied before any tool invocation.

**Why Retained:** Foundation of the entire pipeline. No other module functions without it. The graceful degradation contract is explicit: if jadx fails on heavily obfuscated bytecode, the pipeline falls back to Smali-only analysis; if apktool fails, the pipeline extracts what it can from the raw ZIP structure. Partial analysis results are always returned rather than pipeline failure.

---

## Module 2 — Static Feature Analysis Engine

**Purpose:** Classify the APK as malicious or benign and explain every signal that contributed to the verdict.

**Inputs:** Parsed AndroidManifest.xml (permission vector), disassembled Smali bytecode (API call families, opcode n-gram frequencies), string tables (entropy scores and pattern matching).

**Outputs:** Binary malicious/benign verdict, calibrated confidence score (0–1, isotonic regression calibrated), SHAP waterfall chart (per-feature signed contributions to verdict), top contributing features ranked by absolute SHAP value.

**Buildability:** High. XGBoost with SHAP TreeExplainer is a standard Python stack (xgboost, shap libraries). The model is pre-trained on a publicly available dataset (AndroZoo/AMD Dataset subset, balanced train/validation/test split at 70/15/15, APK-hash-deduplicated to prevent leakage) and shipped as a serialized artifact. No training occurs at demo time.

**Why Retained:** The SHAP waterfall chart is the most technically rigorous output in the platform and the primary visual response to "show me why it was flagged." It directly satisfies the explainability requirement and serves as a training tool for junior analysts building threat intuition.

---

## Module 3 — Certificate Relationship Intelligence Module

**Purpose:** Attribute the analyzed APK to known malware families and shared developer infrastructure through signing certificate analysis.

**Inputs:** APK META-INF certificate files.

**Outputs:** Parsed certificate fields (subject, issuer, serial number, SHA256 fingerprint, validity period), certificate graph query result (known/unknown), matched family attributions, interactive D3.js force-directed graph rendered in analyst dashboard.

**Buildability:** High. Python cryptography library parses certificates. NetworkX supports in-memory graph of 50–100 pre-populated known malware certificate fingerprints sourced from MalwareBazaar and Koodous. The D3.js graph is the most visually compelling output in the demo and is buildable using standard React + D3 patterns.

**Why Retained:** Malware developers routinely reuse signing certificates across campaigns — this is documented real-world attacker behavior (Cerberus, Anubis, and BankBot all reused signing infrastructure). The certificate graph is a genuine intelligence output, not a visualization for its own sake. Small corpus size (50–100 fingerprints) is an acknowledged scope constraint that is correctly framed as the seeded foundation of a growing intelligence graph.

---

## Module 4 — Malware Provenance Analysis Module

**Purpose:** Identify the specific builder kit used to construct the analyzed APK — the attribution question no existing scanner addresses.

**Inputs:** Package naming conventions, obfuscation style characteristics (identifier length distribution, character set composition, class hierarchy depth), resource fingerprints (icon SHA256 hash, string table format, asset naming patterns), code skeleton structural patterns.

**Outputs:** Builder kit identification result (High/Medium/Low/Unknown confidence), matched family (Cerberus, Anubis, SpyNote, or Drinik builder patterns at launch), complete list of matching signals that produced the attribution, structural documentation of unmatched builder patterns for analyst review.

**Buildability:** High. All inputs are derived from static artifacts already produced by Module 1. Pattern matching and structural comparison require no external dependencies. The four-family coverage is presented honestly as a seeded knowledge base, not a complete taxonomy — unknown builder structures are flagged, documented, and passed to the GenAI Unknown Builder Kit Characterizer for LLM-assisted profiling.

**Why Retained:** No publicly available tool identifies builder kit provenance. Builder kit identification places a new sample in its threat context immediately — if the analyzed APK was built with the Cerberus kit, all known Cerberus campaign intelligence becomes relevant. The Unknown Builder structural documentation also ensures that novel samples are never returned to the analyst as empty — they receive a structural characterization that supports further investigation.

---

## Module 5 — Threat Technique Mapping Engine

**Purpose:** Map all detected indicators to MITRE ATT&CK for Mobile techniques, producing a standardized attack chain compatible with SOC and CERT-In communication workflows.

**Inputs:** All detection signals from Modules 2, 3, and 4 (permission flags, API call patterns, manifest declarations, attribution results).

**Outputs:** MITRE ATT&CK for Mobile technique table (technique ID, technique name, evidence signal that triggered the mapping), attack chain narrative (produced by GenAI Narrative Engine using this table as structured input).

**Buildability:** Medium. ATT&CK for Mobile technique mappings are maintained as a deterministic mapping table (approximately 15–20 technique-to-signal mappings covering overlay attacks, accessibility service abuse, SMS interception, device admin abuse, and anti-analysis behaviors). Novel APK samples that do not match any mapping produce an empty table row rather than incorrect attributions.

**Why Retained:** MITRE ATT&CK is the universal language of threat communication in BFSI security operations. ATT&CK technique IDs in a report signal that the platform speaks the same vocabulary as SOC analysts, CERT-In, and peer institutions in the banking ISAC. The mapping table also serves as the structured input that gives the GenAI narrative engine its factual foundation.

---

## Module 6 — OTP Interception Detection Module

**Purpose:** Identify signals indicating SMS-based OTP interception capability — the primary authentication bypass mechanism in Indian banking fraud.

**Inputs:** Parsed AndroidManifest.xml (SMS-related permissions), Smali bytecode (SMS listener registration patterns, BroadcastReceiver declarations for SMS intents), string analysis (OTP-related keywords, Indian bank OTP format patterns).

**Outputs:** OTP interception risk level (High/Medium/Low/None), specific evidence signals detected, mapping to targeted authentication mechanism (SMS OTP, bank-specific OTP format if identifiable).

**Buildability:** High. All detection logic is pattern matching on static artifacts already produced by Module 1. No external dependencies. The module is small, independent, and contributes directly to the composite risk score.

**Why Retained:** OTP interception is the #1 fraud vector in Indian banking. Indian banks rely heavily on SMS-based two-factor authentication; OTP theft is the mechanism that converts credential capture into completed fraud. A module that explicitly flags this signal, named in the report in terms that banking operations staff understand, has immediate BFSI relevance.

---

## Module 7 — Fraud Interface Reconstruction Module

**Purpose:** Reconstruct the phishing overlay UI that a fraud victim would encounter, producing visual evidence of the attack from the victim's perspective.

**Inputs:** Extracted drawable resources, layout XML files, strings.xml bank-name and credential-field strings.

**Outputs:** Side-by-side comparison view (reconstructed malicious overlay alongside a reference screenshot of the legitimate banking app it impersonates), textual description of the impersonated institution and captured credential types.

**Buildability:** Medium. This module operates on pre-processed samples for which overlay resources have been identified and extracted. For the five demo APKs (Drinik and related Indian-targeting samples), the overlay reconstruction is prepared in advance. For unknown samples, the module performs best-effort resource extraction and presents available drawable and layout artifacts without guaranteed reconstruction. Scope is correctly bounded: this module produces compelling visual output for known demo samples and useful partial output for novel samples.

**Why Retained:** No comparable tool produces this output. Showing judges the exact fake HDFC or SBI login screen that a victim encounters is the single highest-impact visual in the demo. It transforms abstract technical analysis into tangible evidence of harm. It also serves three operational functions: fraud investigation evidence, customer advisory production, and law enforcement referral documentation.

---

## Module 8 — Composite Risk Scoring and Reporting Engine

**Purpose:** Aggregate all module outputs into a single severity verdict, produce the PDF intelligence report, and export IOCs in operational formats.

**Inputs:** All upstream module outputs.

**Outputs:** Composite risk score (0–100) with four-tier severity label (Critical/High/Medium/Low), decomposed score breakdown showing all five component contributions, PDF intelligence report, IOC export (JSON/CSV), STIX 2.1 formatted IOC bundle, analyst override log (analysts may override severity labels with documented justification, logged with audit trail).

**Buildability:** High for the scoring logic and IOC export; Medium for the PDF report (WeasyPrint with a clean CSS template is the implementation choice). The analyst override workflow is implemented as a simple API endpoint that accepts a case reference ID, revised severity label, and justification text, stored in the audit log.

**Why Retained:** The composite score is the platform's verdict delivery mechanism. The decomposed breakdown is what distinguishes it from black-box scores — every bank compliance team, CERT-In analyst, and RBI examiner can trace every point in the score to a specific analytical finding. The analyst override workflow addresses the human accountability requirement of regulated financial institution automated decision-making.

---

# Generative AI Layer

## Design Philosophy

The Generative AI layer is built on a single principle: **the model performs analysis that produces outputs unavailable by other means.** It does not reformat information. It does not paraphrase detection verdicts. It reasons about artifacts that pattern matching cannot classify, infers attacker intent from behavioral signals, and drafts structured regulatory documents that analysts currently produce manually.

Every GenAI function receives structured, verified inputs derived from upstream analytical modules. The model is never asked to analyze raw bytes or produce verdicts — those functions belong to the deterministic and ML pipeline. The model is asked to reason about what verified, structured analytical evidence implies — a task that genuinely requires language model capability.

## Model Selection

**Primary:** Claude claude-sonnet-4-6 (Anthropic API) or Gemini 1.5 Flash (Google AI Studio API). Both provide generous free-tier access appropriate for hackathon development and produce analyst-grade outputs for structured security reasoning tasks.

**Fallback:** If the LLM API is unavailable during demo, each GenAI function falls back to a structured template populated from the same input JSON. The template output is clearly labeled "Template Mode — LLM Unavailable." Demo reliability is never dependent on live API availability.

**Hallucination Prevention:** Every GenAI function uses a closed-world prompt design — the model is explicitly instructed that its analysis must be grounded in the provided structured inputs and that any claim without supporting evidence in the input JSON must be omitted. Output schemas enforce that every generated claim cites a specific supporting signal. All AI-generated content is labeled as AI-generated in the intelligence report and presented alongside the underlying structured data that produced it.

---

## GenAI Function 1 — Obfuscated Code Intent Reconstructor

**Role:** Primary analytical GenAI function. The model performs semantic inference on obfuscated Android bytecode — identifying what code does when traditional pattern matching cannot decode its intent. This is the function that distinguishes genuine GenAI analysis from prose generation.

**Why it matters:** Banking trojans extensively obfuscate their most dangerous code segments — the credential capture hooks, the C2 communication routines, and the OTP interception handlers. Traditional static analysis misses these when identifier names, class hierarchies, and string constants have been randomized. The LLM, reasoning about code semantics and behavioral patterns in Smali syntax, can infer intent from structure even when surface-level signals have been deliberately obscured.

**Input Schema:**
```json
{
  "smali_snippets": [
    {
      "class_name": "obfuscated class identifier",
      "method_name": "obfuscated method identifier",
      "bytecode": "raw Smali bytecode of the method body (max 150 lines)",
      "context": {
        "permissions_declared": ["list of permissions declared in manifest"],
        "api_calls_detected": ["list of Android API calls in this class"],
        "string_literals": ["non-obfuscated string literals in this class"]
      }
    }
  ],
  "analysis_context": {
    "ml_verdict": "malicious | benign | uncertain",
    "top_shap_features": ["top 5 SHAP-contributing features"],
    "targeted_banks_detected": ["list of targeted bank package names if found"]
  }
}
```

**System Prompt Strategy:**
```
You are an Android malware analyst specializing in banking trojans. 
You will be given decompiled Android Smali bytecode from a suspicious application, 
along with context about detected permissions and API calls.

Your task is to infer the operational intent of each provided code segment.

Rules:
- Base every claim strictly on evidence present in the provided code and context.
- If intent cannot be determined from the available evidence, state "Intent unclear from available signals."
- Do not introduce threat behaviors not supported by the provided code.
- Use precise technical language appropriate for a CERT-In incident report.
- For each code segment, cite the specific instruction sequence or API call that supports your inference.
```

**Output Schema:**
```json
{
  "code_intent_analysis": [
    {
      "class_reference": "obfuscated class identifier",
      "inferred_intent": "one-sentence description of operational function",
      "fraud_lifecycle_stage": "delivery | persistence | credential_capture | exfiltration | evasion | c2_communication | unknown",
      "confidence": "High | Medium | Low",
      "evidence_cited": "specific instruction sequence or API call supporting inference",
      "banking_relevance": "explanation of how this relates to the banking fraud mechanism, or null if not relevant"
    }
  ],
  "aggregate_behavioral_summary": "two-sentence summary of the overall behavioral profile inferred from all analyzed segments"
}
```

---

## GenAI Function 2 — Fraud Playbook Generator

**Role:** Given the complete structured analysis output, generate the step-by-step fraud playbook as the attacker designed it — from victim recruitment through fund exfiltration — in the format required by fraud investigators and law enforcement.

**Why it matters:** Fraud investigators and law enforcement need a documented, sequential description of the attack chain to support case files, FIR submissions, and customer communications. This documentation currently requires a senior analyst to produce manually from technical findings. The LLM can generate it directly from structured inputs.

**Input Schema:**
```json
{
  "verdict": "malicious",
  "family_attribution": "Drinik | Cerberus | Anubis | SpyNote | Unknown",
  "targeted_banks": ["SBI", "HDFC", "ICICI"],
  "mitre_techniques_mapped": [
    {"technique_id": "T1417.001", "technique_name": "Input Capture: Keylogging", "evidence": "accessibility_service_declared"}
  ],
  "otp_interception_risk": "High | Medium | Low | None",
  "overlay_target_detected": true,
  "permissions_flagged": ["RECEIVE_SMS", "READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
  "evasion_indicators": ["emulator_detection", "debugger_check"]
}
```

**System Prompt Strategy:**
```
You are a banking fraud intelligence analyst preparing a case documentation brief. 
Generate a numbered, step-by-step fraud playbook describing how this malware is used 
to commit fraud against banking customers. 

Write from the attacker's operational perspective.
Use only the information provided in the structured input — do not introduce attack steps 
not supported by the detected indicators.
Format for use by fraud investigators and law enforcement.
Number each step. Be specific about which detected capability enables each step.
```

**Output Schema:**
```json
{
  "fraud_playbook": {
    "title": "Attack Playbook: [Family] Targeting [Banks]",
    "steps": [
      {
        "step_number": 1,
        "phase": "Delivery | Installation | Persistence | Credential Capture | Exfiltration",
        "description": "What the attacker does at this step",
        "enabled_by": "which detected capability enables this step",
        "victim_experience": "what the victim observes at this step"
      }
    ],
    "fraud_completion_path": "one-sentence description of how fraud proceeds to financial loss"
  }
}
```

---

## GenAI Function 3 — CERT-In Incident Report Drafter

**Role:** Pre-fill all mandatory fields of a CERT-In incident notification using structured analysis outputs, producing a draft report ready for analyst review and submission. This eliminates one to two hours of analyst writing per reportable incident.

**Why it matters:** CERT-In incident reporting is a regulatory obligation for banking institutions. The mandatory report fields — sample hash, affected institutions, detected techniques, IOCs, recommended mitigations — map directly to the analytical outputs the platform already produces. No analyst should be writing this manually.

**Input Schema:** Full analysis output JSON (all module results, composite risk score, IOC table, attribution results).

**System Prompt Strategy:**
```
You are a CERT-In incident reporting assistant. 
Using the provided structured malware analysis output, populate a CERT-In incident notification draft.

Populate only the fields for which supporting information is present in the analysis output.
For any mandatory field where the analysis output provides insufficient information, 
write "[ANALYST INPUT REQUIRED: field description]" rather than generating content.
Use formal language appropriate for regulatory submission.
Do not introduce technical details not present in the provided analysis.
```

**Output Schema:** Structured JSON mapping to CERT-In mandatory report fields (incident type, affected sector, affected institutions, malware classification, IOC table, detected techniques, recommended mitigations, first-seen date, severity level, analyst certification placeholder).

---

## GenAI Function 4 — Executive Narrative Engine

**Role:** Transform the complete structured analysis into a plain-language executive summary and an attack chain narrative appropriate for CISO, senior management, and non-technical banking operations audiences.

**Input Schema:** Condensed analysis JSON (verdict, confidence, attribution, targeted banks, key techniques, risk score, OTP risk level).

**Output Schema:** Two outputs — a single executive summary paragraph (CISO-appropriate, names threat family, severity, targeted institutions, recommended immediate action) and an extended attack chain narrative (describes the complete fraud lifecycle in analyst voice, traces detected techniques to their operational consequences).

**Note on positioning:** This function produces the most visible GenAI output in the report but represents the minimum viable GenAI use case. It is intentionally subordinated in the design to Functions 1, 2, and 3, which perform analysis rather than presentation. When judges ask "where is the AI?" — Function 1 is the answer.

---

# Edge Case Coverage

**Heavily Obfuscated APK (jadx Decompilation Failure)**
If jadx fails to produce Java source from a heavily obfuscated APK, the pipeline falls back to Smali-only analysis. Feature extraction from Smali bytecode (opcode n-grams, API call patterns) continues normally. The SHAP verdict is produced from whatever features are extractable. GenAI Function 1 receives the Smali snippets directly — this is actually the scenario where GenAI bytecode analysis adds the most value, because traditional pattern matching is most limited against obfuscation. The report notes the decompilation limitation and labels all features as Smali-derived.

**Unknown Builder Kit (No Matching Fingerprint)**
Module 4 returns "Unknown Builder" with a structural characterization document (obfuscation style, resource patterns, code skeleton summary). This structural profile is passed to GenAI Function 1 with a prompt variant that asks the LLM to characterize the builder's likely sophistication level and operational focus from structural signals alone, explicitly framed as inference rather than attribution. No false attribution is produced.

**Legitimate Application with High-Risk Permissions**
Banking applications legitimately request SMS read permissions for UPI verification flows. The risk score includes a targeting specificity component that distinguishes malicious applications targeting specific bank package names from legitimate applications with similar permission profiles. The SHAP explanation surfaces this distinction — a legitimate banking app will show high SMS permission weight but low overlay and accessibility abuse signals. The analyst override workflow enables human review of borderline verdicts.

**Certificate Not in Pre-Populated Graph**
The certificate relationship module returns "No known associations — new certificate entry added to graph." This is the expected behavior for novel malware using fresh certificates. The Malware Provenance Module's builder kit fingerprinting then becomes the primary attribution pathway — which is precisely the dual-pathway attribution design's purpose.

**APK Targeting Banks Outside Pre-Configured List**
The target bank detection module uses a combination of exact package name matching and fuzzy string matching on bank-related string literals (bank names, domain patterns, login URL strings). Banks outside the five-name primary list may still trigger detection through string analysis. The report notes the confidence level of targeting detection.

**ZIP Bomb or Malformed APK**
File size limits (default 100MB), compression ratio threshold checks (rejection if uncompressed size exceeds compressed size by factor greater than 100), and MIME type validation are applied before any analysis tools are invoked. Malformed APKs that pass initial checks but fail apktool parsing result in a pipeline error report with hash, file size, and failure stage — never a silent failure.

**LLM API Unavailability During Demo**
Every GenAI function has a structured template fallback that populates from the same input JSON without API calls. Template output is explicitly labeled in the report. The demo can run to completion without the LLM API — GenAI features simply produce template-quality output instead of LLM-quality output. This is framed proactively: "the platform degrades gracefully if connectivity is unavailable."

---

# Risk Mitigation

## Dynamic Analysis Criticism
**Objection:** The problem statement explicitly says "Static AND Dynamic Analysis."
**Mitigation:** Dynamic analysis for live malware samples in a banking institution context presents three constraints that make static-first analysis the operationally correct design: legal risk of executing malicious code on bank infrastructure, throughput — static analysis completes in under sixty seconds versus ten to twenty minutes for a sandboxed execution, and completeness — banking trojans' forensically significant behaviors (overlay rendering, OTP interception, accessibility abuse) all leave complete signatures in static artifacts. The behavioral static analysis component (opcode n-gram frequency distributions from disassembled Smali bytecode) infers behavioral intent from execution-pattern signatures without execution risk. This is framed as behavioral static analysis throughout the submission, not as dynamic analysis absent.

## Attribution Scaling Criticism
**Objection:** The builder kit database covers only four families. Any judge who submits an out-of-scope APK will see "Unknown Builder."
**Mitigation:** Unknown Builder is a valid, honest output. The platform does not guess attributions it cannot support. The structural characterization of unknown builders — passed to GenAI Function 1 for LLM-assisted profiling — ensures that unknown samples receive a substantive analytical response rather than an empty result. The four-family coverage is framed as the seeded launch state of a knowledge base, not a complete taxonomy.

## AI-Washing Criticism
**Objection:** Using an LLM to write summaries is not genuine GenAI.
**Mitigation:** GenAI Function 1 — the Obfuscated Code Intent Reconstructor — performs analytical reasoning on Android bytecode, not prose generation. It infers what obfuscated code does when pattern matching cannot. This is the function that answers the AI-washing criticism definitively: no template could produce this output, because the input is variable, obfuscated bytecode that requires semantic reasoning. The executive narrative engine is the visible GenAI output; the bytecode reconstructor is the defensible one.

## Dataset Criticism
**Objection:** Without seeing the training data and metrics, ML credibility is unestablished.
**Mitigation:** Model metrics (F1 score, precision, recall, false positive rate) from the 15% test split appear directly in the submission document. The dataset is described with specificity: AndroZoo subset, sample count, malware/benign class balance, train/validation/test split ratios, and APK-hash deduplication procedure to prevent leakage. Calibration is addressed: "XGBoost confidence scores are calibrated using isotonic regression on a held-out validation set to produce true probability estimates."

## Builder Kit Coverage Criticism
**Objection:** Four families is too narrow.
**Mitigation:** Addressed under Attribution Scaling above. The additional mitigation is that GenAI Function 1's Unknown Builder Characterizer is explicitly positioned as the mechanism that extends coverage beyond the seeded knowledge base. A novel sample produces both a structural characterization and an LLM-inferred profile — which is more analytical depth than any existing tool provides for unknown malware.

## Obfuscation Criticism
**Objection:** Heavy obfuscation defeats static analysis.
**Mitigation:** This is the scenario where GenAI Function 1 adds the most value. Obfuscation defeats pattern matching — it does not defeat LLM semantic reasoning over code structure. The pipeline's graceful degradation contract ensures that heavy obfuscation reduces confidence rather than causing pipeline failure. The SHAP explanation surface explicitly shows which features were unavailable due to obfuscation.

## Demo Reliability Criticism
**Objection:** Live demos with LLM API calls and complex pipelines fail.
**Mitigation:** Three-layer demo hardening. Layer 1: pre-selected APKs (five known Indian-banking-targeting samples) analyzed in advance with results cached. Layer 2: LLM API template fallback ensures all report sections populate regardless of connectivity. Layer 3: pre-recorded video of a complete analysis run available as backup. The demo flow uses cached results for the primary run and triggers live analysis only if asked specifically. No demo component has a single point of failure.

---

# Innovation Highlights

## Builder Kit Attribution
No publicly available malware analysis tool — including MobSF, VirusTotal, Koodous, Intezer, or Joe Sandbox Mobile — identifies the specific builder kit used to construct a malicious APK. Existing tools classify malware families and detect behaviors; they treat each sample as an isolated artifact. The Malware Provenance Analysis Module treats APKs as manufactured products with traceable construction origins — which is technically accurate, since commodity Android banking malware is produced using builder kits sold on dark-web markets. Connecting a new sample to a specific builder kit immediately imports all campaign intelligence associated with that kit: known C2 patterns, target selection history, and peer samples from the same factory. This is attribution at a level of specificity that currently requires specialist researchers.

## Fraud Interface Reconstruction
Reconstructing the exact phishing overlay the fraud victim encounters — showing the fake HDFC login screen as the victim saw it, rendered from resources extracted from the malicious APK — transforms abstract threat classification into tangible evidence of harm. No comparable tool produces this output. The capability serves three operational functions simultaneously: visual evidence for fraud investigation case files, accurate source material for customer advisories warning customers about the specific fake interface, and compelling non-technical communication of the fraud mechanism to bank management and regulators.

## Analytical GenAI for Bytecode Semantics
Using a language model to infer the operational intent of obfuscated Android bytecode is a genuinely novel application of GenAI in the mobile security domain. Existing security tools use ML for classification; they use GenAI, if at all, for report writing. Applying LLM semantic reasoning to Smali bytecode — where the model must infer what obfuscated code does from instruction sequences, API call patterns, and code structure rather than clear identifier names — is analysis-layer GenAI rather than presentation-layer GenAI. This is the capability that no other team at this hackathon is likely to demonstrate.

---

# Final MVP Scope

The following components must be built and demonstrable before the June 15 submission and operational before the final presentation on August 27–28.

**For submission (documentation only — June 15):**
- Complete Solution Document with all module descriptions, GenAI specifications with actual prompt templates, model performance metrics (F1, precision, recall, FPR from test split), dynamic analysis defense paragraph, analyst override workflow description, SIEM integration path (STIX 2.1 feed and webhook for SOAR integration, naming Splunk and QRadar as targets), and confidence calibration statement.
- No contradictions between the submission document and the specification document — unified module naming, unified GenAI description.

**For prototype presentation (August 27–28):**

*Must have — demo fails without these:*
- APK upload interface and disassembly pipeline (apktool + jadx, graceful degradation documented)
- Static feature extraction and XGBoost classification with SHAP waterfall chart
- Certificate extraction and D3.js relationship graph (pre-populated with 50–100 known fingerprints)
- Composite risk score dashboard with five-component decomposition
- GenAI Function 1 — Obfuscated Code Intent Reconstructor (30–50 lines of API code)
- GenAI Function 4 — Executive Narrative Engine (30–50 lines of API code)
- IOC export (JSON/CSV)
- PDF intelligence report

*Should have — high demo impact:*
- Malware Provenance Analysis Module (builder kit fingerprinting for four families)
- Fraud Interface Reconstruction Module (pre-processed for five demo APKs)
- MITRE ATT&CK technique table
- GenAI Function 3 — CERT-In Report Drafter (20–30 lines of API code)

*Optional — build only if core is stable:*
- GenAI Function 2 — Fraud Playbook Generator
- OTP Interception Detection Module (low effort, high India-relevance signal)
- Anti-Analysis Indicator Detection Module

*Do not build — removed from scope:*
- CampaignClock timeline visualization (corpus too small; empty visualization undermines demo)
- Campaign Configuration Analysis Module as standalone (requires populated campaign database)
- Real-time WebSocket progress streaming (polling is demo-safe; WebSocket adds fragility)

---

# Final Judge Narrative

The platform being presented is not a detector. Detection — the binary malicious/benign verdict — is available in dozens of existing tools. What is not available, in any existing public tool, is what happens after detection: the attribution, the analyst communication, the regulatory reporting, and the victim-perspective evidence chain that convert a positive detection into an actionable intelligence product.

SENTINEL-X addresses the gap between detection and action. A BFSI analyst who receives a positive detection from an existing scanner faces five unanswered questions: why was this flagged, who built it, which Indian institutions are targeted, what does the fraud UI look like from the victim's side, and what needs to be reported to CERT-In before today ends. The platform answers all five, automatically, in under sixty seconds.

The three differentiators are buildable, demonstrable, and without comparable alternatives in the public tool landscape. Builder kit attribution gives every analyzed sample a provenance identity that connects it to a threat actor's toolkit and campaign history. Fraud UI reconstruction gives fraud investigators, bank management, and CERT-In analysts visual evidence of the exact deceptive interface that induced credential theft. LLM-powered bytecode semantic inference gives analysts analytical insight into obfuscated code segments that pattern matching cannot reach — this is what genuine GenAI looks like in a security tool, not prose formatting, but reasoning about code.

The platform is calibrated for the Indian banking threat context at every level: named bank targets, OTP interception weighting, CERT-In output formats, and Drinik attribution — the malware family that targeted 18 Indian banks by name. It speaks the operational language of Indian BFSI security, not generic threat intelligence.

For a solo developer with AI-assisted development tools, this is a buildable platform — not a research concept or a product vision. Every module in the MVP scope rests on well-established open-source libraries and pre-processable training and corpus data. The GenAI components are thirty to fifty lines of API code each. The SHAP chart, the D3 certificate graph, and the fraud overlay reconstruction are achievable within the development window. The architecture degrades gracefully when components encounter unusual inputs, ensuring that partial analysis is always available and demo reliability is never hostage to a single component.

This is a platform that answers the questions Indian banking security teams are actually asking, using methods that are technically defensible, visually demonstrable, and genuinely novel.

---

*Document produced June 12, 2026 — SENTINEL-X Final Project Concept v1.0*
*Synthesized from: Full Audit Report, Solution Document, Complete Specification, Architecture Document, Hackathon Constraints Document*
