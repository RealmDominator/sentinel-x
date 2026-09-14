# SENTINEL-X
## Android Banking Malware Attribution and Intelligence Platform

---

# One-Line Pitch

An automated Android APK analysis platform that combines explainable machine learning, certificate-based attribution, and a Generative AI layer to transform a suspicious banking app into a complete, actionable intelligence brief — in under 60 seconds.

---

# Executive Summary

Indian banking customers lose hundreds of crores annually to Android banking trojans. Every day, CERT-In analysts, BFSI SOC teams, and bank security officers receive suspicious APK files — and have no fast, integrated way to answer the questions that actually matter for fraud response: not just whether an app is malicious, but who built it, how the attack works, which Indian banks are targeted, and what the victim sees when the fraud is in progress.

Existing tools give a binary verdict. SENTINEL-X gives an intelligence brief.

The platform accepts a suspicious APK file through a web dashboard. Within 60 seconds, it produces a complete analyst report covering five dimensions that no single existing tool addresses together: an explainable malware verdict with SHAP feature attribution showing precisely which signals triggered the classification; a certificate relationship graph revealing which other malware families share the same signing infrastructure as the submitted sample; a builder kit identification that answers who constructed this malware; a MITRE ATT&CK for Mobile attack chain narrative mapping every detected technique to the standard framework language that banking SOC teams already use; and a visual reconstruction of the phishing overlay screen that banking customers see during credential theft — the exact fake SBI or HDFC login page that appeared on their phone.

A Generative AI layer is the platform's analytical reasoning engine, not a reporting afterthought. It serves three distinct functions that cannot be replicated by templates or pattern matching. First, it processes decompiled Smali code snippets and infers the functional intent of obfuscated code — reasoning about what the code does at a semantic level when static signatures cannot match it. Second, it synthesizes all structured analysis outputs into an executive summary paragraph calibrated for CISO and banking management audiences who cannot read technical output. Third, it drafts a pre-filled CERT-In incident report — a regulatory obligation that currently costs hours of analyst writing time — reducing that to a 10-second review-and-submit workflow.

The platform is designed to be built by a solo developer using AI-assisted development tools over a six-week prototype window. Every module prioritizes well-documented open-source tools, free public datasets, and API-first integrations over custom research-grade implementations. The architecture is modular — each analytical layer is independently functional, so a partially completed build still demonstrates meaningful capability. No proprietary datasets, paid enterprise APIs, or specialist malware research expertise are required for the core prototype.

This is not a scanner that competes with VirusTotal. It is the intelligence layer that transforms what VirusTotal and MobSF detect into something a bank's fraud team can act on, a CERT-In analyst can file, and a CISO can present to a board.

---

# Problem Statement Mapping

| PS1 Requirement | Module | How It Is Satisfied |
|---|---|---|
| **Harnessing Generative AI** | GenAI Analytical Layer (3 components) | LLM infers obfuscated code intent from Smali snippets; generates CISO-grade executive summary; drafts CERT-In incident report. Structured JSON inputs prevent hallucination. GenAI performs analysis — not just formatting. |
| **Automated Reverse Engineering** | APK Ingestion Pipeline | apktool disassembles APK to Smali bytecode and extracts all XML resources; jadx reconstructs approximate Java source with graceful fallback to Smali-only analysis. Fully automated — analyst only uploads a file. |
| **Static Analysis** | Static Feature Analysis Engine (XGBoost + SHAP) | 4-category feature extraction: permission vectors (300+ dimensions), API call families, opcode n-gram frequencies, string entropy. XGBoost classifier produces malicious/benign verdict. SHAP explains every contributing feature. |
| **Dynamic Analysis** | VirusTotal API Integration (dynamic enrichment) | Free VirusTotal API v3 returns dynamic analysis sandbox results, behavioral reports, and AV detections for any submitted APK hash. Addresses PS1 dynamic requirement without requiring a local sandbox. |
| **Risk Scoring** | Composite Risk Score Engine | 5-signal weighted composite (ML confidence 30%, fraud signal density 25%, attribution confidence 20%, evasion sophistication 15%, campaign activity 10%). Transparent decomposition shown in dashboard and report. |
| **Fraudulent APK / Malware focus** | OTP Interception Detection Module, Fraud Interface Reconstruction Module | OTP theft signal detection (READ_SMS + RECEIVE_SMS + NOTIFICATION_LISTENER combination); phishing overlay UI reconstruction for Indian banking apps (SBI, HDFC, ICICI, Paytm). |
| **Explainable AI-generated reports** | SHAP waterfall chart + GenAI executive summary + CERT-In report drafter | SHAP values explain the ML verdict feature-by-feature. GenAI produces plain-language narratives grounded in structured analytical facts, not speculation. Every AI-generated statement is labeled and traceable to its source data. |
| **Automated analyst assistance** | Intelligence Report Generator | Full PDF + HTML report auto-generated from all module outputs. Covers verdict, attribution, attack chain, fraud UI, IOC table, and recommended actions. Analyst time reduced from 4-8 hours to under 2 minutes of review. |

---

# Core Modules

## Module 1: APK Ingestion and Disassembly Pipeline

**Purpose:** Accept a suspicious APK, compute file fingerprints, check the analysis cache for previously analyzed samples, and extract all artifacts needed by downstream modules.

**Inputs:** APK file uploaded through web dashboard or REST API endpoint.

**Outputs:** AndroidManifest.xml (permissions, component declarations), Smali bytecode files (all application code disassembled), res/ directory (layout XML files, drawable resources, string tables), assets/ directory (embedded configuration files), META-INF/ directory (signing certificate chain). File hashes (MD5, SHA1, SHA256) for cache lookup and IOC export.

**Buildability:** High. apktool and jadx are both well-documented command-line tools invoked through Python subprocess calls. File upload handling and hash computation are standard library operations. An AI coding assistant can generate this component from a single prompt.

**Why retained:** This is the foundation. No analysis is possible without disassembly. The graceful fallback from jadx failure to Smali-only analysis (for obfuscated samples) is critical for demo reliability.

---

## Module 2: Static Feature Analysis Engine

**Purpose:** Classify the APK as malicious or benign using explainable machine learning, and produce a per-feature importance breakdown that makes the verdict auditable.

**Inputs:** AndroidManifest.xml (permission extraction), Smali bytecode files (opcode n-gram analysis), string literals (entropy computation), API call patterns from Smali.

**Outputs:** Malicious/benign verdict with confidence score; SHAP waterfall chart data (top 10-15 features with direction and magnitude); permission feature vector summary; API call family flags.

**Buildability:** Medium. The XGBoost model must be pre-trained on a labeled dataset before the prototype build. The Drebin dataset (215 features, 5,560 malware samples, 8,000+ benign) is publicly available and well-documented. scikit-learn's XGBoost implementation and the SHAP Python library are both pip-installable. SHAP waterfall chart rendering is a single function call. An AI assistant can generate the complete training script and inference wrapper.

**Why retained:** SHAP explainability is the answer to the most predictable judge question: "Why was this flagged?" It transforms the platform from a black-box detector into an analyst-grade tool. The waterfall chart is also one of the two most visually impressive outputs in the entire platform.

---

## Module 3: Certificate Relationship Intelligence Module

**Purpose:** Attribute the analyzed APK to known malware families by identifying whether its signing certificate has been reused across previously seen campaigns.

**Inputs:** META-INF/*.RSA file from the unpacked APK (signing certificate chain). Pre-populated certificate corpus (50-100 known malware certificate fingerprints from MalwareBazaar and Koodous public data).

**Outputs:** Certificate fingerprint (SHA256), signer details (subject, issuer, serial, validity period, self-signed flag); list of known malware families sharing this certificate; D3.js force-directed graph data (JSON) showing certificate-to-APK relationships; family attribution statement ("This certificate was previously observed in the Cerberus campaign").

**Buildability:** Medium. Python's cryptography library handles X.509 certificate parsing in under 10 lines. NetworkX builds the in-memory graph. The pre-populated corpus is a JSON file assembled from public sources before the prototype build. D3.js force graph rendering has abundant open-source examples. An AI assistant can generate all components.

**Why retained:** Certificate signer reuse across malware campaigns is a documented, real-world attacker technique (Cerberus, Anubis, and BankBot families all exhibited this). The interactive graph visualization is the single most compelling live demo visual in the platform — judges physically lean forward when they see a new APK connect to six known malware families through a shared signing key.

---

## Module 4: Malware Provenance Analysis Module

**Purpose:** Identify the builder kit or development toolkit used to create the APK, answering the attribution question that no existing scanner addresses: not just which family, but who built it and with what.

**Inputs:** Extracted Smali code structure (package naming patterns, class hierarchy), res/ directory (icon file hash, string table format, asset naming), AndroidManifest.xml (component naming patterns).

**Outputs:** Builder kit identification (e.g., "Cerberus v2 builder," "Anubis kit," or "Unknown builder — structural characterization provided"); confidence level (High/Medium/Low/Unknown); supporting evidence list (specific matching patterns that triggered the identification); for unknown builders, structural fingerprint description.

**Buildability:** Medium. Pattern matching against a small signature database (3-4 known builder kits: Cerberus, Anubis, SpyNote, Drinik) is pure Python string matching and regex — no ML required. The signature patterns are derivable from published malware research papers and CERT-In advisories. An AI assistant can help derive patterns from sample analysis. For unknown builders, the GenAI layer (Module 8) handles characterization.

**Why retained:** This is the platform's most distinctive attribution capability. No public tool identifies the specific builder kit. It elevates the attribution story from "this certificate was reused" to "we know which criminal toolkit was used and have seen this toolkit before in these campaigns."

---

## Module 5: OTP Interception Detection Module

**Purpose:** Detect the specific permission combinations and Smali code patterns that indicate SMS-based OTP theft — the primary banking fraud mechanism on Android in India.

**Inputs:** AndroidManifest.xml (permission declarations, activity declarations for target bank packages), Smali bytecode (overlay trigger patterns, accessibility event listener patterns).

**Outputs:** OTP interception risk rating (HIGH/MEDIUM/LOW); specific triggering signals listed (which permission combination was detected, which Smali patterns matched); targeted bank package names identified (com.onlinesbi.sbi, net.hdfcbank.customer.android, etc.); overlay intercept mechanism identified (accessibility service / activity injection / window overlay).

**Buildability:** Low. Permission triplet detection (READ_SMS + RECEIVE_SMS + BIND_NOTIFICATION_LISTENER_SERVICE) is a single set intersection operation. Smali pattern matching for overlay triggers is regex over text files. This is among the lowest-complexity modules in the platform relative to its demo impact.

**Why retained:** OTP theft is the dominant banking fraud authentication bypass in India. When the demo shows "This app will intercept every OTP sent to your phone while you use SBI YONO," it is the most operationally concrete finding in the entire analysis.

---

## Module 6: Fraud Interface Reconstruction Module

**Purpose:** Reconstruct and render the phishing overlay screen that banking customers see during credential theft, providing visual evidence of the attack from the victim's perspective.

**Inputs:** res/layout/*.xml files (overlay activity layout structures), drawable resources (bank logos, fake login UI assets), string resources (bank-specific UI text), targeted bank identification from Module 5.

**Outputs:** Side-by-side comparison panel rendered in the dashboard: "Legitimate Bank App" vs. "Malware Overlay." Identified target bank with package name and bank name. Overlay intercept mechanism labeled.

**Buildability:** Medium. For the prototype, reconstruct for 3-5 pre-processed known Indian banking malware samples (SBI, HDFC, ICICI, Paytm targets) sourced from MalwareBazaar. The reconstruction renders extracted drawables and layout structure as an HTML/React component. Generalized reconstruction for arbitrary unknown APKs is deferred — the pre-processed approach eliminates implementation risk while providing the full demo impact.

**Why retained:** This is the platform's "gasp moment." No technical explanation of phishing overlays has the same impact as showing a judge the fake SBI YONO login screen, pixel-perfect, reconstructed from inside the APK. It converts an abstract security concept into visceral, visual evidence. It is also the output most directly usable in fraud investigation case files and customer advisories.

---

## Module 7: Threat Technique Mapping Engine

**Purpose:** Map all detected indicators to MITRE ATT&CK for Mobile techniques, producing the standard threat intelligence framework description that banking SOC teams and CERT-In use for incident classification.

**Inputs:** All detection outputs from Modules 2-6 (permission flags, API calls, evasion patterns, OTP signals, attribution results).

**Outputs:** Set of matched MITRE ATT&CK for Mobile technique IDs with names and evidence signals (e.g., T1412 — Capture SMS Messages — triggered by READ_SMS + RECEIVE_SMS + overlay detected); ATT&CK matrix visualization with highlighted cells; technique-evidence mapping table for the intelligence report.

**Buildability:** Low-Medium. The feature-to-technique mapping table is a static JSON file created manually — no ML required. The mitreattack-python library provides technique metadata. ATT&CK matrix visualization components are available in open-source React libraries. This module is a lookup and display operation, not a learning algorithm.

**Why retained:** MITRE ATT&CK is the universal language of threat intelligence. Any judge with cybersecurity background will immediately recognize ATT&CK integration as a professional-grade capability. It provides the structured vocabulary that allows the GenAI narrative engine (Module 8) to produce technically accurate attack chain descriptions.

---

## Module 8: Generative AI Analytical Layer

*(Detailed design in the dedicated section below)*

**Purpose:** Perform three genuinely analytical GenAI tasks that cannot be replicated by templates or pattern matching: obfuscated code intent inference, executive narrative synthesis, and CERT-In report drafting.

**Why retained:** PS1 explicitly requires Generative AI. The three tasks chosen here all solve real analyst problems that existing tools cannot address, are grounded in structured factual inputs that prevent hallucination, and are demonstrably different from template-based text generation.

---

## Module 9: Dynamic Analysis Enrichment

**Purpose:** Complement the platform's static analysis with dynamic behavioral data, addressing the PS1 dynamic analysis requirement through API integration rather than local sandbox execution.

**Inputs:** APK SHA256 hash (computed at ingestion).

**Outputs:** VirusTotal dynamic analysis results (behavioral sandbox report if available), antivirus detection summary, behavioral indicators (network connections, file system writes, API calls observed during execution), any additional family attributions from AV engine consensus.

**Buildability:** Very Low. Free VirusTotal API v3 returns existing analysis results for any hash in their database via a single HTTP GET request. For new samples not yet in VirusTotal's database, the platform submits the APK and polls for results. Python requests library, 15 lines of code. No sandbox infrastructure required.

**Why retained:** This directly answers the judge's question "Where is your dynamic analysis?" with a concrete, working answer. Integrating with VirusTotal's existing sandbox infrastructure is architecturally legitimate and operationally identical to what enterprise security tools do. The platform adds attribution, explainability, and BFSI-specific analysis on top of VirusTotal's dynamic results — it does not try to compete with VirusTotal's sandbox.

---

## Module 10: Composite Risk Score Engine

**Purpose:** Aggregate all analytical signals into a single, transparent, auditable severity rating with a four-tier label and specific response recommendations.

**Inputs:** All module outputs (ML confidence, OTP signals, attribution confidence, evasion indicators, dynamic analysis results, campaign activity).

**Outputs:** Composite score (0-100); severity label (CRITICAL/HIGH/MEDIUM/LOW); per-dimension sub-scores with weights shown; recommended response actions mapped to severity; CERT-In notification trigger flag for CRITICAL results.

**Buildability:** Very Low. Weighted arithmetic formula applied to normalized sub-scores. Simple Python arithmetic. Dashboard display is a styled number with color coding.

**Why retained:** Judges and users need a single number they can act on. The decomposed display (showing each contributing dimension) is what separates a defensible risk score from a black-box number — it satisfies the explainability requirement for regulated financial institution automated decisions.

---

## Module 11: Intelligence Report Generator and IOC Exporter

**Purpose:** Assemble all analysis outputs into a downloadable PDF intelligence report and an exportable IOC bundle in formats that banking security teams can immediately operationalize.

**Inputs:** All module outputs across the complete analysis pipeline.

**Outputs:** PDF intelligence report (8 sections: executive summary, technical verdict with SHAP chart, attribution analysis, attack chain with ATT&CK matrix, fraud UI reconstruction, risk score decomposition, IOC table, recommended actions); HTML version for dashboard embedding; IOC bundle in JSON and CSV formats (file hashes, C2 domains, certificate fingerprints, malicious package names).

**Buildability:** Medium. WeasyPrint converts HTML to PDF in Python with pip install. HTML report template is generated by AI assistant. IOC JSON/CSV extraction is trivial once all module outputs are structured.

**Why retained:** The PDF report is the platform's proof-of-work artifact. A judge who takes the report home and reads it becomes an advocate. It is also the most directly usable output for regulatory reporting, legal proceedings, and customer advisories — the three contexts where BFSI security teams most need documentation.

---

# Generative AI Layer

## Design Rationale

The GenAI layer is designed around a single architectural principle: the language model receives structured factual inputs and performs analytical reasoning — not formatting. This distinction is what separates genuine GenAI from AI-washing, and it is what any technically competent judge will verify.

Three components are implemented. Each one solves a problem that pattern matching, templates, and rule-based systems demonstrably cannot.

---

## Component 1: Obfuscated Code Intent Inference Engine

**Why this is genuine GenAI:** Static signature matching identifies what code looks like. An LLM can reason about what code does — understanding loops, data transformations, and control flow in obfuscated Smali bytecode where no signature matches exist. This is analytical reasoning, not prose formatting.

**Analyst problem solved:** When jadx decompiles an obfuscated banking trojan, the resulting Smali code contains meaningless identifier names, XOR-encoded strings, and control flow designed to defeat pattern matching. A junior analyst cannot read it. A senior analyst takes hours. The LLM takes seconds and produces a functional description of what the code block does.

**Model selection:** Claude Sonnet 4.6 or GPT-4o. Both models have strong code reasoning capabilities. The API call is the same structure regardless of provider. For the prototype, use whichever API key is available.

**Prompt strategy:** Android-bytecode-specialized system prompt that instructs the model to act as an Android security researcher analyzing potentially malicious Smali code. The prompt explicitly prohibits speculation about code not in the input. It requests output in a structured format: function name (inferred), operation type, specific risk indicators identified, confidence level.

**Input schema:**
```json
{
  "task": "smali_intent_inference",
  "code_snippet": "<extracted Smali bytecode block, max 2000 tokens>",
  "context": {
    "surrounding_class_name": "com.a.b.C",
    "called_android_apis": ["android.telephony.SmsManager", "android.content.Intent"],
    "permissions_declared": ["READ_SMS", "RECEIVE_SMS"]
  },
  "instruction": "Infer the functional purpose of this code. Identify specific malicious behaviors if present. Do not speculate beyond what is visible in the code."
}
```

**Output schema:**
```json
{
  "inferred_function": "SMS interception and forwarding",
  "operation_type": "credential_theft",
  "specific_behaviors": ["registers broadcast receiver for incoming SMS", "extracts SMS body content", "forwards content to hardcoded URL endpoint"],
  "confidence": "HIGH",
  "risk_indicators": ["SMS forwarding to external URL", "triggered on RECEIVED_SMS broadcast"],
  "analyst_note": "This code block implements the OTP interception component of the banking trojan. The broadcast receiver will capture all incoming SMS messages and forward the body content to the C2 endpoint."
}
```

**Hallucination prevention:** The model receives only the code that is actually present. The system prompt explicitly prohibits inferring behaviors not visible in the provided snippet. The output schema enforces structured fields that can be validated against the actual code. Any output field referencing a behavior not present in the Smali input is flagged as an inference error in post-processing.

---

## Component 2: Executive Summary Synthesis Engine

**Why this is genuine GenAI:** A template can produce "This APK is malicious with 87% confidence. It targets SBI and HDFC." An LLM synthesizes heterogeneous facts from five different analytical modules — ML verdict, certificate attribution, builder kit ID, ATT&CK technique set, OTP interception status, and dynamic analysis results — into a coherent, contextually appropriate paragraph that varies in emphasis and framing based on the specific combination of findings. The same template cannot produce appropriate output for both a novel never-before-seen sample and a known Cerberus variant — the LLM can.

**Analyst problem solved:** BFSI security teams must communicate technical findings to CISOs, board members, fraud operations staff, and bank branch managers who cannot interpret technical output. Writing this summary currently requires a senior analyst. The LLM produces a first-rate first draft in two seconds.

**Input schema:** Structured JSON containing all analytical outputs — verdict with confidence, SHAP top features, certificate attribution result, builder kit ID, ATT&CK technique IDs, targeted bank packages, OTP risk level, dynamic analysis summary, risk score and severity label. All factual, all structured.

**Output schema:** Single paragraph (150-250 words) in plain English. Sentence 1: verdict and severity. Sentence 2: targeted institutions. Sentence 3: primary attack mechanism. Sentence 4: attribution to known campaign (if applicable). Sentence 5: recommended immediate action.

**Hallucination prevention:** The system prompt instructs the model to use only facts present in the structured input JSON. It prohibits adding threat actor names, technical claims, or severity assessments not present in the input. Post-processing validation checks that every institution name in the output is present in the `targeted_banks` field of the input.

---

## Component 3: CERT-In Incident Report Drafter

**Why this is genuine GenAI:** CERT-In incident reports have mandatory fields, specific language requirements, and a structured format that varies based on the nature of the threat and the affected institutions. Generating a correctly structured, contextually appropriate CERT-In report from analysis outputs requires understanding the reporting format and adapting generic threat intelligence to it. This is a constrained generation task, not a template fill.

**Analyst problem solved:** Filing a CERT-In report for a CRITICAL-severity banking malware finding currently requires an analyst to manually write a structured document, cross-referencing their analysis with CERT-In's advisory format requirements. For a banking SOC receiving 5-10 reportable incidents per month, this is 40-80 hours of writing time annually. The LLM reduces this to 5 minutes of review-and-submit per incident.

**Input schema:** Structured analysis output (same as Component 2 input) plus a `report_type` field ("CRITICAL_MALWARE_ADVISORY") and `affected_institution` field.

**Output schema:** CERT-In advisory format with pre-filled mandatory fields: incident category, threat severity, affected systems, technical details, indicators of compromise, recommended mitigations, and contact information placeholders. Output clearly labeled as "AI-GENERATED DRAFT — ANALYST REVIEW REQUIRED BEFORE SUBMISSION."

**Hallucination prevention:** The model is instructed to use only the provided IOC data for the IOC section — no additional indicators are to be added. Post-processing verifies that all file hashes in the output match the hashes in the input IOC bundle. Any discrepancy triggers a validation warning that blocks submission until analyst review.

---

# Edge Case Coverage

**Edge Case 1: jadx fails on heavily obfuscated APK**
Why it matters: Many banking trojans use obfuscation that defeats jadx decompilation entirely.
Handling: Graceful fallback to Smali-only analysis. Feature extraction continues on Smali bytecode directly — permission vector, opcode n-grams, and string entropy are all extractable from Smali without jadx. SHAP chart is generated from available features. GenAI Component 1 (code intent inference) is particularly valuable in this case because it can reason about obfuscated Smali that pattern matching cannot decode. The analysis report notes which features are unavailable due to decompilation failure and adjusts the confidence score accordingly.

**Edge Case 2: APK certificate not in the known corpus**
Why it matters: Novel malware from a new threat actor will not match any pre-populated certificate.
Handling: The platform returns "No known certificate reuse detected — first-seen certificate fingerprint" with the full certificate field set for analyst review. This is a meaningful intelligence output, not a failure state. A first-seen certificate for a CRITICAL-severity sample is itself a significant finding indicating a potentially new threat actor or freshly generated infrastructure.

**Edge Case 3: Builder kit not in the signature database (Unknown Builder)**
Why it matters: The prototype covers only 4 builder kit signatures. Novel or custom-built malware will not match.
Handling: The Malware Provenance Analysis Module returns structural characterization data rather than a named attribution — package naming style, obfuscation characteristics, class hierarchy patterns. This structural fingerprint is fed to GenAI Component 1 for characterization: "The structural patterns of this APK suggest a custom-built toolkit with moderate development sophistication, characterized by [specific patterns]. No known commercial builder kit signature matches." This converts a limitation into a finding.

**Edge Case 4: APK hash not in VirusTotal database (new/private sample)**
Why it matters: Freshly created banking trojans and private samples won't have VirusTotal results.
Handling: The platform submits the APK to VirusTotal for analysis (with analyst consent prompt) and polls for results with a configurable timeout. If results are unavailable within the timeout, the dynamic enrichment section of the report is marked "Pending VirusTotal analysis — estimated 2-5 minutes." All static analysis results are displayed immediately, unblocked by the VirusTotal API call.

**Edge Case 5: LLM API unavailable during demo**
Why it matters: Network unavailability or API rate limits during a live demo would eliminate the GenAI component.
Handling: The platform implements graceful degradation with pre-cached GenAI outputs for the demo APKs. If the LLM API returns an error, the report generates with the cached output and a label indicating the cache source. For the live demo, an offline mode with pre-generated outputs for all demo APKs is maintained as a backup that requires no internet connectivity.

**Edge Case 6: Legitimate banking app flagged as malicious (false positive)**
Why it matters: Banks submit legitimate APKs for security validation. A false positive for a bank's own app would be embarrassing and undermine trust.
Handling: The platform includes an analyst override mechanism. Any verdict can be overridden with a documented justification that is logged with analyst identity and timestamp. The SHAP chart for false positive review is particularly useful — a legitimate app flagged for READ_SMS permission will show that single feature as the driver, which an analyst can immediately recognize as insufficient evidence alone.

**Edge Case 7: ZIP bomb or malformed APK submitted**
Why it matters: Adversarial inputs can cause denial of service or unexpected behavior in apktool.
Handling: File size limit enforced at ingestion (configurable, default 100MB). ZIP compression ratio check before extraction (reject if >100:1 ratio). MIME type validation for APK/ZIP structure. apktool runs with process resource limits (memory cap, CPU time limit) via Python's subprocess module.

---

# Risk Mitigation

## Dynamic Analysis Criticism
**Judge challenge:** "The problem statement says Static AND Dynamic Analysis."
**Response:** "Dynamic analysis is implemented through VirusTotal API v3 integration, which returns behavioral sandbox analysis results for submitted APK hashes — the same dynamic execution environment used by enterprise security tools globally. This integration provides dynamic behavioral data (network connections observed, file system writes, API calls during execution) without the legal risk of executing malware on institution infrastructure or the implementation complexity of a local sandbox. For the prototype, this is the architecturally correct approach: API-first integration with existing sandbox infrastructure. A local sandbox integration (using Android emulator + Frida) is planned for the post-hackathon prototype phase."

## Attribution Scaling Criticism
**Judge challenge:** "Your builder kit database only covers 4 families."
**Response:** "The signature database covers the four most prevalent Indian banking trojan builder kits by reported incident volume: Cerberus, Anubis, SpyNote, and Drinik. For unknown builders, the GenAI Obfuscated Code Intent Inference Engine provides structural characterization — identifying the builder's technical capabilities and development practices without a named attribution. The certificate corpus (50-100 entries) combined with VirusTotal's attribution data covers a wider family set. The prototype demonstrates the attribution architecture at the correct depth; expanding signature coverage is a data-collection activity, not an architectural challenge."

## AI-Washing Criticism
**Judge challenge:** "Your GenAI is just ChatGPT writing summaries."
**Response:** "The executive summary generation is one of three GenAI functions, and it is the least analytically complex. The Obfuscated Code Intent Inference Engine is the component that distinguishes this platform from AI-washing. It performs semantic reasoning about Android Smali bytecode — inferring what obfuscated code does when pattern matching cannot identify it. No template or rule-based system can produce this output. Show the demo: submit an obfuscated APK snippet where no signature matches, and demonstrate the LLM identifying the SMS interception logic from bytecode semantics alone."

## Dataset Criticism
**Judge challenge:** "What is your training dataset and model accuracy?"
**Response:** "The XGBoost classifier is trained on the Drebin dataset — 215 features, 5,560 malware samples, 8,000+ benign Android applications, the most-cited Android malware dataset in published security research. Alternatively, the AMD Dataset (24,000+ malware samples across 71 families) provides a larger training corpus at the cost of additional preprocessing time. Expected F1 on held-out test split: >0.95 based on published Drebin baseline results. Actual metrics from our prototype training: [report actual numbers before submission]. Train/validation/test split: 70/15/15, hash-deduplicated to prevent data leakage."

## Builder Kit Coverage Criticism
*(Addressed in Attribution Scaling above — structural characterization via GenAI for unknown builders.)*

## Obfuscation Criticism
**Judge challenge:** "What happens with heavily obfuscated samples where your static analysis fails?"
**Response:** "Obfuscation affects two components differently. The XGBoost classifier uses permission vectors and opcode n-gram frequencies — both extractable from Smali regardless of identifier obfuscation. Identifier name obfuscation does not affect these features. The more severe case is control flow obfuscation, which affects the opcode n-gram distribution but still produces a feature vector — the obfuscation pattern itself becomes a signal (EvasionScope detects anti-analysis techniques as a feature). The GenAI Intent Inference Engine is most valuable precisely for heavily obfuscated samples where signatures fail — it reasons about semantics rather than surface patterns."

## Demo Reliability Criticism
**Judge challenge:** "What if your backend crashes during the live demo?"
**Response:** "Three layers of demo protection: (1) Pre-selected demo APKs only — never analyze an unknown APK live. The 2-3 demo APKs are tested end-to-end on the exact demo hardware with all outputs verified. (2) Pre-cached analysis results — the frontend can display pre-generated analysis outputs for demo APKs without a live backend call, using a static data mode that is toggled before the presentation. (3) Pre-recorded backup video — a complete screen recording of the demo with all outputs visible is available as a fallback if the live system fails."

---

# Innovation Highlights

## Innovation 1: Dual-Pathway Attribution Architecture
No existing public tool attributes an Android APK to both a certificate lineage AND a builder kit simultaneously. CertGraph answers "who else uses this signing infrastructure?" FactoryPrint answers "which toolkit was used to construct this APK?" Combined, they produce a forensic attribution picture that approaches what professional threat intelligence firms produce manually over weeks. The combination is demonstrated in the platform's live analysis flow.

## Innovation 2: Fraud Interface Reconstruction
No existing public security tool shows analysts what the victim saw. Presenting a side-by-side comparison of the legitimate SBI YONO interface and the malware overlay — reconstructed directly from the APK's own resources — is a capability that does not exist anywhere in the public tool landscape. It is demonstrably buildable (XML parsing + image extraction + React rendering) and demonstrably unique.

## Innovation 3: Semantic Code Intent Inference for Obfuscated Malware
Applying an LLM to Smali bytecode for semantic intent inference is not an obvious application of GenAI. Most GenAI applications in security generate text about findings. This one reasons about code. The output — "this loop decodes a C2 URL using XOR with key 0x42 and makes an HTTP POST request" — is analytical intelligence, not formatted text. It directly addresses the most common limitation of static analysis tools against obfuscated samples.

## Innovation 4: Automated CERT-In Report Generation
The regulatory reporting burden on banking security teams is substantial and poorly automated. Generating a pre-filled CERT-In advisory draft from structured analysis outputs reduces a 2-hour writing task to a 5-minute review task. No existing tool generates CERT-In formatted reports. This is demonstrably valuable to the exact government audience that IIT Hyderabad is evaluating submissions for.

---

# Final MVP Scope

The following components must be built and demonstrable before the final presentation (August 27-28, 2026). This scope is calibrated for a solo developer with AI-assisted development over a 6-7 week prototype window.

## Week 1-2: Foundation (Non-negotiable)
- APK upload interface (React drag-and-drop) → FastAPI backend → apktool/jadx disassembly pipeline
- Permission vector extraction from AndroidManifest.xml
- OTP Interception Detection (permission combination analysis — 50 lines of Python)
- Basic risk score display (hardcoded formula — build incrementally)
- End-to-end test on 2-3 pre-selected demo APKs

## Week 3-4: Core Intelligence
- XGBoost model training on Drebin dataset (AI-assisted with published tutorials)
- SHAP waterfall chart integration
- VirusTotal API v3 integration for dynamic enrichment
- Certificate extraction and NetworkX graph construction
- Pre-populate certificate corpus (50 entries from MalwareBazaar CSV exports)
- D3.js force graph visualization (use open-source templates)

## Week 5: GenAI and Attribution
- LLM API integration for all 3 GenAI components (30-60 lines total Python)
- Malware Provenance Analysis Module (3-4 builder kit signatures)
- MITRE ATT&CK static mapping table (15 technique mappings)

## Week 6: Reporting and Fraud UI
- Fraud Interface Reconstruction for 3 pre-processed samples (SBI, HDFC, ICICI)
- PDF intelligence report generation (WeasyPrint)
- ATT&CK matrix visualization in dashboard
- Demo hardening: cached analysis results, backup video recording, static screenshot fallbacks

## Stretch (Only if core is complete and stable):
- Additional builder kit signatures (expand to 6-8)
- ConfigDNA C2 pattern extraction
- EvasionScope anti-analysis detection
- STIX 2.1 IOC export format

---

# Final Judge Narrative

The PSB Cybersecurity Hackathon asks for solutions that harness Generative AI for automated malware analysis. SENTINEL-X delivers this — but more importantly, it delivers it in a way that produces intelligence a banking security team can act on in the next five minutes.

Every tool in this space tells you an APK is malicious. SENTINEL-X tells you who built it, what it does to the victim's phone, which Indian banks it targets, how it bypasses OTP authentication, and what to file with CERT-In before you close the browser tab.

The platform's three innovations — dual-pathway builder kit and certificate attribution, fraud UI reconstruction from within the APK itself, and semantic LLM-based code intent inference for obfuscated samples — represent capabilities that no existing public tool provides. They are not research-grade aspirations. They are demonstrable, buildable, and demonstrated.

The Generative AI integration is designed to pass the only test that matters: "Is the AI performing analysis, or just formatting text?" The Obfuscated Code Intent Inference Engine is demonstrably analytical — it reasons about Smali bytecode semantics when pattern matching cannot. The CERT-In Report Drafter is demonstrably valuable — it solves a real regulatory documentation problem that costs Indian banking security teams thousands of analyst-hours annually. The Executive Summary synthesizes heterogeneous analytical outputs into a coherent intelligence product that a CISO can read and act on in 90 seconds.

This solution is not ambitious beyond what can be built. The scope is calibrated for a single developer using modern AI-assisted development tools over the available prototype window. Every module uses well-documented open-source tools, public datasets, and standard API integrations. No custom research, proprietary data, or specialist expertise is required. The architecture is modular — a partial build still demonstrates meaningful capability at every intermediate stage.

SENTINEL-X deserves to reach IIT Hyderabad because it answers the question behind the problem statement: not "can AI analyze malware?" — which any LLM wrapper claims — but "can AI give a banking security analyst the intelligence they actually need to protect their customers, file their reports, and stop the next fraud campaign before it reaches scale?"

The answer is yes. And the platform demonstrates it, live, in under 60 seconds.

---
*SENTINEL-X Final Project Concept — Synthesized from all project documents — June 12, 2026*
