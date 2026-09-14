# Final Project Name

**SENTINEL-X — Android Banking Malware Attribution Intelligence Platform**

---

# One-Line Pitch

Upload a suspicious banking APK and receive, in under 60 seconds, an explainable malware verdict, dual-pathway attribution, Indian fraud-signal detection, victim-facing overlay evidence, and a GenAI-authored intelligence brief ready for CERT-In and bank leadership—without executing the sample.

---

# Executive Summary

Indian public sector and private banks face a sustained wave of Android banking trojans—Cerberus, Anubis, Drinik, SOVA, and commodity builder-kit variants—that steal credentials through overlay phishing and defeat SMS-based two-factor authentication by intercepting OTP messages. CERT-In has issued repeated advisories on these families targeting SBI, HDFC, ICICI, Axis, Paytm, and other institutions. When a bank SOC, fraud desk, or CERT analyst receives a suspicious APK today, existing tools answer one question: is it malicious? They do not answer who built it, which campaign it belongs to, which banks are targeted, what the victim actually saw, or how to communicate findings to management and regulators.

SENTINEL-X closes that gap. It is a single analyst platform that accepts a suspicious APK and runs a static intelligence pipeline—no malware execution, no sandbox dependency—optimized for the legal, operational, and throughput constraints of BFSI environments. A submitted file is hashed, cached, and unpacked through industry-standard reverse-engineering tooling. Four parallel extraction streams produce permission and bytecode features for explainable machine learning, signing-certificate relationships for campaign linkage, structural fingerprints for builder-kit attribution, and India-specific fraud signals including OTP interception patterns and overlay triggers against known bank package names.

The platform's discriminative core is a pre-trained XGBoost classifier evaluated on held-out malware and benign samples, with SHAP TreeExplainer producing per-feature attribution so every verdict is auditable—not a black-box score. Attribution operates on two independent pathways: certificate graph analysis links samples sharing signing infrastructure, while structural fingerprinting identifies known builder kits (Cerberus, Anubis, SpyNote, Drinik) and documents unknown kits with structured anomaly profiles rather than false certainty. A composite risk score transparently combines ML confidence, banking fraud signal density, attribution evidence, evasion sophistication, and campaign linkage into a 0–100 severity rating with full decomposition. Analysts can override any verdict with logged justification, preserving human accountability required in regulated financial institutions.

Where SENTINEL-X diverges from conventional scanners is intelligence depth and communication. The Fraud Interface Reconstruction Module renders side-by-side comparisons of legitimate bank UI versus the phishing overlay extracted from the APK—visual evidence fraud investigators, law enforcement, and customer-advisory teams need but no mainstream tool provides. The Threat Technique Mapping Engine maps detected static indicators to MITRE ATT&CK for Mobile techniques with evidence-linked mappings, giving SOC teams a shared language with CERT-In and peer institutions.

Generative AI is not a cosmetic wrapper. SENTINEL-X deploys a structured GenAI layer with three distinct roles: (1) **Obfuscated Code Intent Reconstruction**—the LLM receives decompiled Smali snippets and infers semantic intent of obfuscated bytecode blocks, performing analysis that pattern matching cannot; (2) **Regulatory Incident Report Drafting**—pre-populating CERT-In advisory fields from verified structured outputs; and (3) **Fraud Playbook Generator**—producing step-by-step attacker workflow documentation from detected permissions, overlays, OTP signals, and C2 indicators. A fourth constrained task synthesizes executive summaries and attack-chain narratives strictly from structured JSON inputs, with all AI content labeled and verifiable against underlying evidence. If the LLM is unavailable, template fallbacks activate automatically so demos and production workflows never fail silently.

The platform addresses Problem Statement 1's dynamic analysis requirement through **behavioral static analysis**: opcode n-gram frequencies, manifest-declared capabilities, accessibility and SMS permission combinations, and overlay activity declarations capture behavioral intent without executing malware—a deliberate design for banking institutions where running live banking trojans introduces legal exposure, network risk, and analyst queue bottlenecks. Full sandbox dynamic analysis is explicitly out of hackathon scope; behavioral inference from static artifacts is the defensible, buildable substitute.

SENTINEL-X is scoped for a solo first-year engineering student using AI-assisted development over six to eight weeks. The ML model trains offline before build; certificate and builder-kit corpora are pre-curated from MalwareBazaar and public sources; overlay reconstruction is validated on three to five known Indian banking malware samples; demo APKs are pre-selected and end-to-end tested. The result is not a research prototype but an operational intelligence product: a suspicious APK becomes an attributable, explainable, documentable case file in the time it takes to open a ticket.

Judges should care because SENTINEL-X combines capabilities no single existing tool offers—SHAP-explainable detection, certificate relationship graphs, builder-kit attribution, victim overlay reconstruction, and GenAI that performs bytecode semantic inference—not merely prose formatting—all calibrated for India's banking fraud landscape and CERT-In reporting workflows.

---

# Problem Statement Mapping

| Requirement (PS1) | Module Covering It | How It Is Satisfied |
|---|---|---|
| **Generative AI** | GenAI Intelligence Layer (Obfuscated Code Intent Reconstructor, Regulatory Incident Report Drafter, Fraud Playbook Generator, Narrative Synthesizer) | LLM performs bytecode semantic inference on Smali snippets; drafts CERT-In reports and fraud playbooks from structured JSON; generates executive summaries with hallucination guards, evidence citations, and template fallback |
| **Automated Reverse Engineering** | APK Ingestion and Unpacking Pipeline | apktool decompiles to Smali and resources; jadx reconstructs Java with graceful Smali-only fallback; extracts manifest, certificates, layouts, assets |
| **Static Analysis** | Static Feature Analysis Engine; OTP Interception Detection Module; Threat Technique Mapping Engine; Anti-Analysis Indicator Detection (lightweight) | Permission vectors, API call families, opcode n-grams, string entropy, SMS/overlay/accessibility patterns, ATT&CK technique mapping, anti-emulator/debugger string detection |
| **Dynamic Analysis** | Behavioral Static Analysis Layer (cross-cutting) | Opcode n-grams and manifest-capability inference capture behavioral intent without execution; overlay triggers, OTP interception logic, and accessibility abuse patterns detected in bytecode; explicit acknowledgment that sandbox execution is deferred due to BFSI legal/operational constraints |
| **Threat Classification** | Static Feature Analysis Engine | Pre-trained XGBoost classifier with calibrated confidence; malicious/benign verdict with documented F1, precision, recall, and false positive rate on held-out test set |
| **Risk Scoring** | Composite Risk Score Engine | Five-signal weighted 0–100 score: ML confidence (30%), banking fraud signals (25%), attribution confidence (20%), evasion sophistication (15%), campaign linkage (10%); severity labels CRITICAL/HIGH/MEDIUM/LOW with full decomposition |
| **Explainable AI-Generated Reports** | SHAP Explainability + GenAI Report Assembly + PDF Intelligence Report | SHAP waterfall charts per verdict; evidence-linked ATT&CK mappings; AI-labeled narratives; downloadable PDF/HTML intelligence report with IOC table |
| **Automated Analyst Assistance** | Full pipeline + Analyst Override Workflow + IOC Export | End-to-end automation from upload to report; analyst can override verdicts with audit-logged justification; JSON/CSV IOC export for SIEM ingestion; case reference ID per analysis |

---

# Core Modules

## 1. APK Ingestion and Unpacking Pipeline

**Purpose:** Accept suspicious APKs safely and produce all artifacts downstream modules require.

**Inputs:** APK file (multipart upload or REST API); configurable size limit (default 100MB); MIME/ZIP integrity validation.

**Outputs:** MD5/SHA1/SHA256 hashes; cached result if previously analyzed; Smali bytecode; AndroidManifest.xml; res/ layouts and drawables; META-INF signing certificates; jadx Java output or Smali-only fallback flag.

**Buildability:** High. Standard subprocess wrappers with error handling and resource limits.

**Why retained:** Foundation of PS1 reverse engineering; every other module depends on it.

---

## 2. Static Feature Analysis Engine

**Purpose:** Classify APK as malicious or benign with explainable feature attribution.

**Inputs:** Permission vector (300+ dimensions); API call family frequencies; opcode n-gram distribution from Smali; string entropy histogram.

**Outputs:** Malicious/benign verdict; isotonic-regression-calibrated confidence score; SHAP waterfall data (top 10–15 features with signed contributions); completeness flag when jadx fails.

**Buildability:** High. Model pre-trained offline on AndroZoo/AMD subset; inference-only at runtime (~100ms).

**Why retained:** Primary ML component; SHAP visualization is the strongest explainability differentiator; audit marks as MUST BUILD.

---

## 3. Certificate Relationship Intelligence Module

**Purpose:** Attribute samples to known campaigns through signing-certificate reuse.

**Inputs:** Extracted certificate subject, issuer, serial, SHA256 fingerprint, validity, self-signed flag; pre-populated graph of 50–100 known malware certificates.

**Outputs:** Related malware families; shared-infrastructure subgraph JSON for D3 force-directed visualization; PageRank-style centrality on prolific signers; new certificate inserted into live graph.

**Buildability:** Medium. Certificate extraction is trivial; NetworkX in-memory graph avoids database setup.

**Why retained:** Highest visual demo impact; documented real-world attacker behavior; dual attribution pathway #1.

---

## 4. Malware Provenance Analysis Module

**Purpose:** Identify builder kit used to construct the APK.

**Inputs:** Package naming patterns; obfuscation style metrics; resource fingerprints (icon hash, string table format); code skeleton signatures.

**Outputs:** Builder kit name and confidence (Cerberus, Anubis, SpyNote, Drinik, or Unknown); structured evidence list; for Unknown—anomaly profile fed to GenAI Unknown Builder Characterizer.

**Buildability:** Medium. Pattern matching against four curated signatures; no ML training required.

**Why retained:** Unique claim no public scanner matches; answers "who built this?" beyond family detection.

---

## 5. OTP Interception Detection Module

**Purpose:** Detect India-specific banking fraud authentication bypass.

**Inputs:** Manifest permissions; Smali overlay trigger patterns; hardcoded bank package names.

**Outputs:** OTP theft risk rating (HIGH/MEDIUM/LOW); triggering signals (READ_SMS + RECEIVE_SMS + BIND_NOTIFICATION_LISTENER_SERVICE triplet, accessibility overlay patterns); targeted bank package list (SBI, HDFC, ICICI, Axis, Paytm).

**Buildability:** High. Deterministic permission and pattern matching.

**Why retained:** Directly addresses dominant Indian banking fraud vector; high judge impact for BFSI relevance.

---

## 6. Threat Technique Mapping Engine

**Purpose:** Map detected indicators to MITRE ATT&CK for Mobile.

**Inputs:** Feature detection results from all static streams.

**Outputs:** 15–20 technique IDs with evidence-linked justification per mapping; ATT&CK matrix highlight data for dashboard; structured technique list for GenAI narrative input.

**Buildability:** Medium. Deterministic mapping table via mitreattack-python metadata.

**Why retained:** Industry-standard threat language; SOC and CERT-In credibility signal.

---

## 7. Fraud Interface Reconstruction Module

**Purpose:** Show analysts exactly what the victim sees during credential theft.

**Inputs:** res/layout/*.xml overlay layouts; drawable bank logos; string resources; hardcoded target package names.

**Outputs:** Rendered overlay component; side-by-side legitimate-vs-fake comparison panel; target bank label; intercept mechanism (accessibility/activity injection/window overlay).

**Buildability:** Medium for 3–5 pre-processed samples; not generalized for arbitrary APKs in MVP.

**Why retained:** Highest emotional demo impact; unique forensic evidence for fraud investigations and customer advisories.

---

## 8. Composite Risk Score Engine

**Purpose:** Produce single defensible severity verdict from all signals.

**Inputs:** ML confidence; fraud signal count; attribution confidence; evasion sophistication; campaign linkage score.

**Outputs:** 0–100 composite score; CRITICAL/HIGH/MEDIUM/LOW label; five-dimension decomposition chart; analyst override capability with audit log entry.

**Buildability:** High. Weighted formula with transparent display.

**Why retained:** PS1 risk scoring requirement; judges expect clear verdict output.

---

## 9. Intelligence Report and IOC Export

**Purpose:** Deliver operational outputs analysts immediately use.

**Inputs:** All module structured outputs.

**Outputs:** PDF/HTML intelligence report (executive summary, technical verdict, attribution, attack chain, fraud UI, IOC table, recommended actions); JSON and CSV IOC bundles (hashes, C2 domains, certificate fingerprints, package names); unique case reference ID and timestamp.

**Buildability:** Medium for PDF; High for IOC export.

**Why retained:** Converts analysis into actionable intelligence product; CERT-In and SOC workflow alignment.

---

## 10. GenAI Intelligence Layer

**Purpose:** Provide genuine generative analysis and reporting—not template-only prose.

**Inputs:** Structured JSON from all modules; selected obfuscated Smali snippets; CERT-In report field schema; fraud signal bundle.

**Outputs:** Obfuscated code intent explanations; CERT-In incident report draft; step-by-step fraud playbook; executive summary; attack-chain narrative; unknown-builder hypothesis (clearly labeled as inference).

**Buildability:** Medium. Three focused LLM calls (~30–50 lines each) with schema validation and template fallback.

**Why retained:** PS1 Generative AI requirement; audit's #1 priority to avoid AI-washing disqualification.

---

# Generative AI Layer

## Design Principle

GenAI receives **only verified structured facts and selected code snippets**—never raw APK bytes or unconstrained threat intelligence queries. Every output is labeled AI-generated, mapped to source fields, and falls back to deterministic templates if the API fails.

## Model Selection

**Primary:** Claude Sonnet or GPT-4o via API—chosen for strong code-reasoning capability on Smali/Dalvik semantics, reliable JSON-mode structured output, and sufficient context window for multi-module input bundles. **Fallback:** Deterministic template engine producing equivalent section headers with `[TEMPLATE — LLM UNAVAILABLE]` watermark.

## Prompt Strategy

1. **System persona:** Senior mobile threat analyst writing for BFSI SOC and CERT-In audiences; must cite only provided evidence; must state uncertainty explicitly; must not invent IOCs, family names, or attribution not in input JSON.
2. **Temperature:** 0.2 for intent reconstruction and regulatory drafting; 0.4 for narrative synthesis.
3. **Validation:** Output parsed against JSON schema; reject and retry once if required fields missing; on second failure, use template.
4. **Anti-hallucination rules embedded in every prompt:** "Describe ONLY facts present in INPUT_JSON. If a field is null or Unknown, say 'not determined'—do not speculate. Do not name threat actors unless attribution.confidence ≥ High."

## Input Schema (Unified Analysis Bundle)

```json
{
  "case_id": "string",
  "sample_hashes": {"md5": "", "sha1": "", "sha256": ""},
  "verdict": {"label": "malicious|benign", "confidence": 0.0, "calibrated": true},
  "shap_top_features": [{"feature": "", "contribution": 0.0}],
  "analysis_completeness": {"jadx_success": true, "penalty_applied": 0.0},
  "otp_interception": {"risk": "HIGH|MEDIUM|LOW", "signals": [], "target_banks": []},
  "attribution": {
    "certificate": {"fingerprint": "", "related_families": [], "confidence": ""},
    "builder_kit": {"name": "", "confidence": "", "evidence": []}
  },
  "attack_techniques": [{"id": "T####", "name": "", "evidence_signal": ""}],
  "evasion": {"level": "", "techniques_detected": []},
  "iocs": {"domains": [], "cert_fingerprints": [], "packages": []},
  "obfuscated_snippets": [{"file": "", "smali_lines": "", "context": ""}],
  "risk_score": {"composite": 0, "severity": "", "decomposition": {}}
}
```

## Output Schema (GenAI Response)

```json
{
  "executive_summary": "string (max 150 words)",
  "attack_chain_narrative": "string",
  "obfuscated_intent": [
    {"snippet_id": "", "inferred_purpose": "", "confidence": "high|medium|low", "evidence_basis": ""}
  ],
  "fraud_playbook": {
    "steps": [{"step": 1, "actor_action": "", "victim_experience": "", "evidence_ref": ""}],
    "estimated_impact_segment": "string (conservative)"
  },
  "cert_in_draft": {
    "incident_title": "",
    "affected_sector": "BFSI",
    "sample_hash": "",
    "malware_family": "",
    "targeted_institutions": [],
    "attack_vectors": [],
    "iocs": {},
    "recommended_mitigations": [],
    "reporting_urgency": ""
  },
  "unknown_builder_characterization": {
    "sophistication_estimate": "",
    "structural_anomalies": [],
    "confidence": "low",
    "disclaimer": "Hypothesis only—not confirmed attribution"
  },
  "generation_metadata": {"model": "", "ai_generated": true, "fallback_used": false}
}
```

## Four GenAI Tasks (Priority Order)

| Task | Why Genuine GenAI | Judge Defense |
|---|---|---|
| Obfuscated Code Intent Reconstructor | LLM reasons about bytecode semantics | Not reproducible by template; output varies with obfuscation pattern |
| Regulatory Incident Report Drafter | Fills CERT-In mandatory fields contextually | Direct BFSI regulatory value |
| Fraud Playbook Generator | Synthesizes cross-module attack workflow | Fraud investigation deliverable |
| Narrative Synthesizer | Coherent prose from novel technique combinations | Templates break on unseen feature combinations |

---

# Edge Case Coverage

| Edge Case | Why It Matters | Handling |
|---|---|---|
| **jadx decompilation failure on obfuscated APK** | Common evasion; pipeline could crash or produce empty features | Automatic Smali-only fallback; feature vector computed from available Smali; confidence penalized; SHAP flags missing features; completeness score shown to analyst |
| **Heavily obfuscated string-encrypted C2 URLs** | IOC extraction claim could be overstated | High-entropy strings flagged as likely encrypted payloads; regex C2 extraction only on plaintext matches; report states "C2 not statically recoverable—encrypted payload suspected" |
| **Unknown builder kit (outside 4 signatures)** | Judges will upload unfamiliar samples | Returns structured Unknown profile with structural anomalies; GenAI Unknown Builder Characterizer produces low-confidence hypothesis with explicit disclaimer; no false named attribution |
| **ZIP bomb / oversized APK** | DoS against analysis platform | 100MB size limit; compression ratio check (>100:1 rejected); subprocess resource limits |
| **Reflection-hidden API calls** | Defeats static API analysis | java.lang.reflect usage detected as evasion feature; contributes to sophistication score; limitation documented in report blind-spot section |
| **Native library (.so) packed payloads** | Banking trojans increasingly use native code | Acknowledged limitation; native presence flagged as evasion indicator; full .so analysis explicitly out of MVP scope |
| **Legitimate banking apps with SMS permissions** | False positives on real apps | SHAP shows feature combination context; calibrated model with reported FPR; analyst override workflow |
| **Duplicate/resubmitted APK** | Wasted compute in SOC queues | Hash-based cache returns instant prior results |
| **LLM API unavailable during demo** | Demo crash = presentation failure | Template fallback with clear labeling; all structured outputs remain fully functional |
| **LLM hallucination of threat intelligence** | Dangerous in security context | Structured-input-only prompts; schema validation; AI labels; evidence refs alongside every claim |
| **Uncalibrated XGBoost probabilities** | "94% confidence" may mislead | Isotonic regression calibration on held-out validation set; calibration method documented |
| **Small certificate corpus (50–100 vs. millions)** | Scale criticism | Graph enables relationship clustering VirusTotal doesn't structure; corpus size labeled as prototype; new certs added per analysis |
| **Overlay reconstruction on unknown APK** | Generalization breaks | MVP limited to 3–5 pre-validated Indian banking malware samples; dashboard shows "template match found" or "overlay preview unavailable—manual review recommended" |
| **Encrypted/sample PII in APK config** | DPDP Act compliance | Configurable retention (default 30 days); no raw APK via public API; audit logging |
| **Pre-selected demo APK fails live** | Unrecoverable demo | Pre-recorded backup video; cached offline results; static PNG fallbacks for all visualizations |

---

# Risk Mitigation

## Dynamic Analysis Criticism

**Mitigation:** Frame the platform as **static-first with behavioral static analysis**. Banking trojans leave complete forensic signatures in manifests (permissions, overlay activities, SMS receivers), Smali (accessibility hooks, OTP listeners), and resources (fake bank UI). Opcode n-grams infer runtime behavior without execution. Explicitly state: executing live banking malware on bank infrastructure creates legal liability, network exposure, and 10–20 minute per-sample sandbox latency incompatible with 50+ daily APK intake. Behavioral intent is inferred; sandbox dynamic analysis is acknowledged as a production extension, not hackathon scope.

## Attribution Scaling Criticism

**Mitigation:** Dual-pathway design—certificate rotation defeats cert-only attribution; structural fingerprinting still matches builder patterns. Unknown kits produce structured anomaly profiles plus GenAI hypothesis labeled low-confidence. Corpus grows with each analyzed sample (new certs inserted live). Position prototype corpus as seed graph, not claimed global coverage.

## AI-Washing Criticism

**Mitigation:** Lead demo with **Obfuscated Code Intent Reconstructor**—LLM reasoning on Smali, not bullet-list summarization. Show side-by-side: same structured input through template vs. LLM on obfuscated snippet; LLM output differs meaningfully. Three distinct GenAI tasks with schemas, model name stated, live example ready. Template fallback is disclosed as reliability feature, not primary path.

## Dataset Criticism

**Mitigation:** Document exact training set: AndroZoo/AMD subset with sample counts, ~1:1 class balance, 70/15/15 hash-deduplicated split. Report held-out test metrics: F1, precision, recall, FPR. Sanity-check SHAP (READ_SMS high magnitude on banking trojans). State literature baseline comparison (Drebin-style XGBoost typically F1 ~0.95+ on clean datasets).

## Builder-Kit Coverage Criticism

**Mitigation:** Four kits cover documented India-targeting families (Cerberus, Anubis, SpyNote, Drinik). Unknown path is first-class—not failure state. GenAI characterizes structural patterns without inventing names. Demo uses samples with confirmed kit matches.

## Obfuscation Criticism

**Mitigation:** Graceful jadx→Smali degradation with confidence penalty. GenAI intent reconstruction on submitted Smali snippets. Reflection and anti-analysis patterns contribute to evasion score. Encrypted strings flagged, not falsely decoded. Blind-spot section in every report lists what static analysis cannot see.

## Demo Reliability Criticism

**Mitigation:** Pre-selected APKs end-to-end tested. Cached hash results for instant replay. Pre-recorded backup video. Static PNG exports of SHAP chart, cert graph, ATT&CK matrix, overlay panel. Polling-based progress (not WebSocket-dependent). LLM and backend failures degrade gracefully. No live analysis of unknown APK during presentation.

---

# Innovation Highlights

1. **Builder-kit attribution** — Identifies construction toolkit, not just malware family; no comparable public banking-focused tool.

2. **SHAP-explainable mobile malware classification** — Every verdict auditable with per-feature signed contributions; satisfies regulated-institution explainability requirements.

3. **Dual-pathway attribution** — Certificate graph plus structural fingerprinting; robust when attackers rotate signing keys.

4. **Fraud Interface Reconstruction** — Side-by-side victim overlay evidence; converts abstract phishing into investigatory visual proof.

5. **GenAI bytecode intent reconstruction** — LLM infers semantic purpose of obfuscated Smali; genuine analysis beyond prose generation.

6. **CERT-In incident report drafting** — Structured regulatory output from analysis pipeline; immediate BFSI operational value.

7. **India-calibrated fraud detection** — OTP interception triplet, named bank targeting, Drinik-era campaign awareness, RBI Mobile Security Guidelines alignment referenced in reports.

8. **Transparent composite risk scoring** — Five-signal decomposition with analyst override and audit trail; not a black-box score.

---

# Final MVP Scope

**Must be built and demonstrable before presentation:**

1. APK upload with hash caching, ZIP-bomb protection, apktool/jadx unpacking with Smali fallback
2. Static Feature Analysis Engine — pre-trained XGBoost, calibrated confidence, SHAP waterfall chart
3. Certificate Relationship Intelligence Module — 50–100 cert corpus, D3 force-directed graph
4. Malware Provenance Analysis Module — four builder-kit signatures plus Unknown handling
5. OTP Interception Detection Module — permission triplet, bank package targeting
6. Threat Technique Mapping Engine — 15–20 ATT&CK mappings with evidence links, matrix visualization
7. Fraud Interface Reconstruction Module — 3–5 pre-validated Indian banking malware overlays
8. Composite Risk Score Engine with decomposition and analyst override logging
9. GenAI Intelligence Layer — all four tasks with schema validation and template fallback
10. PDF/HTML intelligence report with case ID, AI-content labeling, IOC table
11. JSON/CSV IOC export
12. Analyst dashboard — upload, polling progress, verdict, visualizations, report download
13. Documented model metrics (F1, precision, recall, FPR) in submission materials
14. Demo hardening kit — pre-recorded video, cached results, PNG fallbacks

**Explicitly excluded from MVP (do not demo, do not claim):**

Campaign timeline visualization; standalone campaign configuration module; STIX 2.1 export; live OSINT C2 lookups; sandbox dynamic analysis; native .so binary analysis; WebSocket-dependent progress; generalized overlay reconstruction for arbitrary APKs; multi-phase product roadmaps.

---

# Final Judge Narrative

SENTINEL-X deserves shortlisting because it solves a real, measurable problem—Android banking fraud against Indian customers—with a complete analyst workflow, not a single-feature demo. It satisfies Problem Statement 1 across reverse engineering, static and behavioral-static analysis, explainable classification, risk scoring, and substantiated Generative AI. Where VirusTotal and MobSF stop at "malicious," SENTINEL-X answers who built it, which infrastructure links exist, which banks are targeted, what the victim saw, and what CERT-In report to file— in under 60 seconds without executing malware on bank systems.

The technical depth is defensible: pre-trained XGBoost with documented metrics and SHAP explainability; certificate graph analytics; builder-kit fingerprinting; evidence-linked MITRE ATT&CK mapping. The innovation is integrated and demonstrable—not a catalog of unreleased ambitions. GenAI goes beyond summarization: the Obfuscated Code Intent Reconstructor performs bytecode semantic analysis judges can watch live, while the CERT-In drafter and Fraud Playbook Generator produce outputs fraud and compliance teams use immediately.

The platform respects hackathon reality: buildable by a solo beginner with AI assistance, pre-trained models, pre-curated corpora, graceful degradation on obfuscated samples, and demo reliability hardening. It speaks directly to CERT-In, RBI incident workflows, and Indian OTP-based authentication fraud—the threat landscape this hackathon exists to address.

Judges selecting finalists reward completion, BFSI relevance, visual proof, and honest technical depth. SENTINEL-X delivers a coherent intelligence product with four compelling visuals (SHAP waterfall, certificate graph, ATT&CK matrix, victim overlay), regulatory alignment, and a GenAI layer that survives the "show me the AI" question. That combination moves it from strong concept to finalist-grade execution—provided the GenAI layer and model metrics are implemented, not merely described.
