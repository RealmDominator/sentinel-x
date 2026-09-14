# FINAL PROJECT IDEA: SENTINEL-X

---

## Final Project Name

**SENTINEL-X — Android Banking Malware Attribution Intelligence Platform**

---

## One-Line Pitch

An automated intelligence platform that transforms a suspicious Android APK into a complete, attributed, explainable threat intelligence product — covering detection, attribution, attack chain reconstruction, regulatory reporting, and analyst communication — in under 60 seconds.

---

## Executive Summary

Banking fraud investigators, CERT-In analysts, and BFSI SOC teams in India face a daily operational problem that no existing tool solves adequately. When a suspicious Android APK arrives — reported by a customer, flagged by a threat feed, or discovered in the wild — the analyst faces a multi-hour manual investigation using five separate tools, producing a verdict that answers only one question: is this malicious? The financial cost of that gap is measurable in hundreds of crores of fraud loss annually.

SENTINEL-X is an Android banking malware analysis platform built specifically for the Indian BFSI threat landscape. It accepts any suspicious APK as input and produces a complete intelligence product as output. The platform answers five questions simultaneously: Is this APK malicious and why? Who built it and what toolkit did they use? Which Indian banks are targeted and how will the victim be deceived? What is the complete MITRE ATT&CK attack chain? What should the CERT-In incident report say?

The platform operates through an eight-stage analysis pipeline. In the first stage, the APK is disassembled using apktool and jadx, extracting Smali bytecode, XML manifests, resources, and signing certificates. Four parallel analysis streams then execute simultaneously. The Static Feature Analysis Engine extracts a high-dimensional feature vector from the APK's permission declarations, API usage patterns, opcode behavioral fingerprints, and string entropy profiles, passing it to a pre-trained XGBoost classifier. SHAP post-hoc explanation then decomposes the verdict into per-feature contributions, showing exactly which signals drove the malicious classification.

The Certificate Relationship Intelligence Module extracts the APK's signing certificate, fingerprints it, and queries a pre-populated graph of known malware certificates. When matches are found, the system surfaces which malware families share the same signing infrastructure — turning a single sample into a window into a campaign. The Malware Provenance Analysis Module examines the APK's structural code patterns, obfuscation style, resource naming conventions, and class hierarchy depth to identify which builder kit produced it. For samples matching known families such as Cerberus, Anubis, SpyNote, or Drinik, it produces a named attribution. For unknown builders, the Generative AI layer takes over.

The OTP Interception Detection Module identifies the specific permission combination and Smali-level code patterns that characterize SMS-based OTP theft — the dominant fraud mechanism against Indian banking customers. The Threat Technique Mapping Engine maps all detected signals to MITRE ATT&CK for Mobile technique identifiers, covering 15 to 20 techniques in the initial build.

The Generative AI Intelligence Engine is the component that separates SENTINEL-X from every existing tool. It operates in four distinct modes, each performing genuine analytical work rather than formatting pre-written facts. The Obfuscated Code Intent Reconstructor feeds decompiled Smali bytecode snippets that resist conventional static analysis to a large language model with a specialized Android bytecode semantics prompt, producing analyst-readable descriptions of what obfuscated code blocks actually do — analysis that no pattern matcher or signature database can perform. The Unknown Builder Characterizer activates when Provenance Analysis finds no known match, feeding the structural fingerprint to the model to generate a characterization of the builder's sophistication, likely origin indicators, and distinguishing patterns. The CERT-In Incident Report Drafter takes the complete structured analysis output and pre-populates every mandatory field of a CERT-In compliant incident notification, compressing hours of regulatory documentation into seconds. The Intelligence Narrative Engine generates a plain-language executive summary and technical attack chain description from structured JSON inputs, ensuring factual accuracy while producing communication-ready prose.

The Fraud Interface Reconstruction Module extracts layout XML files and drawable resources from the unpacked APK and reconstructs the phishing overlay screen that the victim sees during credential theft. For a demo build, this covers three to five pre-processed known Indian banking malware families — enough to provide the most viscerally compelling visual output in the platform. A composite Risk Score from five weighted signal dimensions produces a severity-labeled verdict. Every analysis concludes with a downloadable PDF intelligence report and IOC export in JSON and CSV formats.

The platform is designed to be built by a solo developer using AI-assisted development, with pre-trained model artifacts, a pre-populated certificate corpus, and pre-processed demo samples eliminating the highest-risk live dependencies. It is credible as a technical submission, demonstrable as a live prototype, and immediately applicable to the specific fraud threat that Indian banking customers face every day.

---

## Problem Statement Mapping

**Requirement: Harnessing Generative AI**
Module: Generative AI Intelligence Engine — four distinct analytical modes.
How satisfied: The Obfuscated Code Intent Reconstructor performs genuine AI analysis of Android bytecode semantics, not prose generation. The Unknown Builder Characterizer uses LLM reasoning to produce attribution hypotheses for novel malware factories. The CERT-In Drafter and Narrative Engine produce structured, factually grounded outputs. Generative AI is architecturally central, not cosmetic.

**Requirement: Automated Reverse Engineering**
Module: APK Disassembly Pipeline (apktool + jadx).
How satisfied: Every submitted APK is automatically disassembled to Smali bytecode and approximate Java source. Graceful fallback to Smali-only analysis when jadx fails on obfuscated samples. No manual analyst intervention required at any stage of the disassembly process.

**Requirement: Static Analysis**
Modules: Static Feature Analysis Engine, Certificate Relationship Intelligence Module, Malware Provenance Analysis Module, OTP Interception Detection Module, Anti-Analysis Indicator Module.
How satisfied: Multi-dimensional static analysis across permission vectors, API call graphs, opcode n-grams, string entropy, certificate relationships, structural code patterns, resource fingerprints, and permission combination signals. Covers the complete published feature set from Android malware literature.

**Requirement: Dynamic Analysis**
Handling: Static analysis of behavioral intent is prioritized over dynamic execution for three specific reasons. First, executing malicious Android code in a banking institution environment creates unacceptable operational and legal risk. Second, banking trojans' forensically critical behaviors — overlay rendering, OTP interception, accessibility service abuse — leave complete and reliable static signatures in APK artifacts; dynamic execution provides marginal additional evidence at high cost. Third, static analysis delivers complete results in under 60 seconds versus 10 to 20 minutes for dynamic sandbox execution, enabling the higher-volume coverage that SOC teams require. Dynamic sandbox integration is identified as a post-prototype enhancement.

**Requirement: Risk Scoring**
Module: Risk Score Engine — five-signal weighted composite (0–100 scale, four severity tiers).
How satisfied: Transparent, decomposed, auditable scoring across ML confidence, banking fraud signal density, attribution confidence, evasion sophistication, and campaign activity level. Every contributing sub-score is displayed alongside the composite for analyst review and override.

**Requirement: Fraudulent APK and Malware Focus**
Modules: All modules, calibrated specifically for banking malware targeting Indian financial institutions.
How satisfied: Target detection covers SBI YONO, HDFC MobileBanking, ICICI iMobile Pay, Axis Bank, and Paytm. OTP interception detection is weighted for India's SMS-based two-factor authentication infrastructure. Campaign coverage includes Drinik, Cerberus, Anubis, and BankBot families active in the Indian market.

---

## Core Modules

**Module 1: APK Disassembly Pipeline**
Purpose: Ingest and disassemble any submitted APK into analyzable artifacts.
Inputs: APK file (up to 100MB, ZIP structure validated pre-extraction).
Outputs: AndroidManifest.xml, Smali bytecode directory, approximate Java source (when jadx succeeds), res/ drawable resources, assets/ directory, META-INF/ signing certificate chain, file hashes (MD5/SHA1/SHA256).
Buildability: High. apktool and jadx are mature, well-documented tools with extensive AI coding assistant training data. ZIP bomb protection via compression ratio check is ten lines of Python. Graceful jadx fallback is a try/except wrapper.
Why retained: Foundation of every subsequent module. Nothing functions without it. It is also the component most familiar to beginners — file parsing and subprocess calls are undergraduate-level engineering.

**Module 2: Static Feature Analysis Engine**
Purpose: Classify the APK as malicious or benign and produce a fully explainable verdict.
Inputs: AndroidManifest.xml (permission vector), Smali bytecode (opcode n-grams, API call families), all string literals (entropy analysis).
Outputs: Malicious/benign verdict, calibrated confidence score, SHAP waterfall chart showing top 10–15 contributing features with direction and magnitude, feature vector summary.
Buildability: High. XGBoost and SHAP are well-documented Python libraries with extensive tutorials. The model must be pre-trained before the prototype phase on a subset of publicly available labeled samples (AndroZoo or Drebin dataset). Confidence scores calibrated using isotonic regression on a held-out validation set. Model performance metrics — F1, precision, recall, false positive rate — documented from the test split evaluation.
Why retained: The non-negotiable anchor of the platform. SHAP explainability is the direct answer to the most common criticism of automated security tools. It is also the component that most differentiates the platform from signature-based scanners.

**Module 3: Certificate Relationship Intelligence Module**
Purpose: Attribute the APK to known malware families through signing certificate reuse.
Inputs: META-INF/*.RSA certificate chain from disassembled APK.
Outputs: Certificate field set (subject, issuer, serial, SHA256 fingerprint, validity, self-signed flag), graph subgraph showing related malware families sharing the same signer, family attribution list, self-signed detection flag, masquerade detection flag (certificate mimicking legitimate application).
Buildability: High. Python `cryptography` library handles X.509 parsing in five lines. NetworkX graph construction is introductory-level Python. D3.js force-directed graph visualization has well-documented examples with AI coding assistant support. Pre-populate the corpus with 50–100 known malware certificate fingerprints from MalwareBazaar and Koodous public APIs.
Why retained: Produces the most visually compelling non-trivial output in the platform. Certificate reuse is a documented real-world attacker behavior. The D3 graph is the screenshot judges remember after the demo ends.

**Module 4: Malware Provenance Analysis Module**
Purpose: Identify which builder kit produced the APK and attribute it to a known development origin.
Inputs: Package naming patterns, class hierarchy structure, obfuscation style metrics (identifier length distribution, character set, nesting depth), resource identifier patterns, icon file hash, string table format.
Outputs: Named builder kit identification (Cerberus, Anubis, SpyNote, Drinik, or Unknown), confidence level (High/Medium/Low), list of matching structural signals, unknown builder structural characterization passed to GenAI layer.
Buildability: High. Pure pattern matching and structural analysis. No ML required. Signature database is a JSON file. Four family signatures are sufficient for initial demo; unknown builder handling via GenAI fills the gap for novel samples.
Why retained: The single most differentiated capability in the platform. No publicly available tool produces named builder kit attribution. This is the answer to "how is this different from MobSF?"

**Module 5: Threat Technique Mapping Engine**
Purpose: Map detected indicators to MITRE ATT&CK for Mobile techniques and generate a structured attack chain.
Inputs: All feature extraction outputs from Modules 2–4, OTP Interception signals.
Outputs: Set of matched ATT&CK for Mobile technique IDs (T-numbers) with supporting evidence for each mapping, ATT&CK matrix data structure for dashboard visualization with highlighted cells, structured technique table (ID + name + triggering evidence) for report inclusion. Attack chain narrative handed to GenAI Intelligence Engine.
Buildability: High. Deterministic mapping table (feature → technique ID) is a static dictionary. `mitreattack-python` library handles technique metadata lookup. ATT&CK matrix React visualization has open-source component libraries. 15–20 technique mappings are sufficient for a compelling demo.
Why retained: MITRE ATT&CK integration is the universal credibility signal for security professionals. Any CERT-In analyst, SOC lead, or banking CISO immediately recognizes ATT&CK-language output as professional-grade.

**Module 6: OTP Interception Detection Module**
Purpose: Detect the specific signals that indicate SMS-based OTP theft — the dominant banking fraud mechanism in India.
Inputs: AndroidManifest.xml permission declarations, Smali bytecode patterns.
Outputs: OTP interception risk rating (HIGH/MEDIUM/LOW), specific triggering permission triplets and code patterns identified, targeted bank package names extracted from manifest overlay declarations, overlay intercept mechanism identified (accessibility service / window overlay / activity injection).
Buildability: High. Permission triplet detection is a set membership check. Smali pattern matching is regex over bytecode text. This is the most straightforward module in the platform.
Why retained: India-specific fraud relevance is the platform's primary differentiator from generic tools. "This app will steal your OTP" is a concrete, terrifying, actionable finding that lands with every judge and every bank security officer.

**Module 7: Fraud Interface Reconstruction Module**
Purpose: Reconstruct the phishing overlay screen that the fraud victim sees during credential theft.
Inputs: res/layout/*.xml overlay activity layouts, drawable resources from the unpacked APK.
Outputs: Side-by-side comparison panel showing legitimate bank application UI versus the malware overlay, target bank identification with package name, overlay intercept mechanism label.
Buildability: Medium. Pre-process three to five known Indian banking malware samples from public repositories (MalwareBazaar) before the prototype phase. Extract their layout XML and drawable resources. Build a React component that renders the reconstructed overlay from those specific templates. Hardcoded reconstruction for known samples is zero-risk at demo time. Generalized reconstruction for arbitrary unknown APKs is explicitly deferred.
Why retained: The single most emotionally impactful visual output in the platform. A judge who sees the fake SBI YONO login screen reconstructed from malware assets understands the fraud in a way that permission vectors cannot communicate. This is the output that wins the room.

**Module 8: Anti-Analysis Indicator Module**
Purpose: Detect anti-analysis behaviors indicating the malware is aware of security research environments.
Inputs: Smali bytecode string literals and opcode patterns.
Outputs: Evasion sophistication level (Basic/Intermediate/Advanced), list of detected anti-analysis techniques (anti-emulator checks, debugger detection, root detection, timing attacks, virtual environment fingerprinting).
Buildability: Very High. Static string and pattern matching against a signature list. Under 100 lines of Python. Optional module — include if core platform is stable and time permits.
Why retained: Contributes directly to the evasion sophistication dimension of the risk score. Signals that the platform understands attacker tradecraft. Easy implementation win.

---

## Generative AI Layer

The GenAI layer is the component that satisfies the literal Generative AI requirement of Problem Statement 1 with genuine analytical capability, not prose generation over pre-written facts. It operates in four modes, each designed to be defensible against a judge asking "how is this different from ChatGPT summarizing a bullet list?"

**Model Selection:** Claude Sonnet 4.6 or GPT-4o-mini. Selection criteria: structured output support, API latency under two seconds for analytical tasks, cost suitable for a hackathon prototype, context window sufficient for Smali snippet batches. Either model works; commit to one and name it explicitly in the submission.

**Graceful Degradation:** All four GenAI modes implement API-unavailable fallback. Mode 1 (Code Intent) falls back to flagging obfuscated snippets as "requires manual review." Mode 2 (Unknown Builder) falls back to returning the raw structural fingerprint without interpretation. Modes 3 and 4 fall back to template-generated outputs clearly labeled as template-generated rather than AI-generated. All structured analysis outputs remain available regardless of LLM API status.

**Hallucination Prevention:** All four prompts share the same anti-hallucination architecture: the LLM receives structured, verified JSON inputs with explicit field labels. Every prompt contains a direct instruction to describe only what is present in the structured inputs and not to add information, make inferences beyond the provided data, or name threat actors, campaigns, or institutions not present in the inputs. All AI-generated content is labeled in the report and rendered alongside the underlying structured data for analyst verification.

---

**Mode 1: Obfuscated Code Intent Reconstructor**

This is the primary innovation of the GenAI layer. It performs analysis that no pattern matcher, signature database, or template engine can replicate.

When jadx or Smali analysis produces code blocks with obfuscated identifiers, encoded strings, or unusual control flow that defeats conventional static interpretation, up to 30 representative snippets are extracted and passed to the LLM with the following prompt architecture:

Input schema: `{ "smali_snippets": [{"id": "snippet_01", "code": "<Smali bytecode text>", "context": "found in class com.x.y.z, method a()"}], "app_metadata": {"permissions": [...], "target_banks": [...]} }`

System prompt: You are an Android security analyst specializing in malware bytecode analysis. You will receive Smali bytecode snippets from a suspicious Android application. For each snippet, describe in plain English what the code block functionally does — what Android APIs it calls, what data it accesses or modifies, and what purpose it appears to serve. Do not guess at intent beyond what the code demonstrates. If you cannot determine the function of a snippet, say so explicitly. Only describe what is shown in the code.

Output schema: `{ "intent_analysis": [{"id": "snippet_01", "functional_description": "...", "confidence": "High/Medium/Low", "analyst_note": "..."}], "overall_behavioral_summary": "..." }`

Why this is genuine GenAI: The model is reasoning about Android bytecode semantics from first principles, not summarizing provided facts. An obfuscated loop that XORs bytes against a static key and constructs a string looks like noise to a signature database. The LLM recognizes it as a decryption routine and describes the pattern. This is analysis. It changes non-deterministically for different obfuscation patterns in ways a template cannot replicate. This is the direct answer to "how is this different from ChatGPT summarizing a bullet list?"

---

**Mode 2: Unknown Builder Kit Characterizer**

Activates when the Malware Provenance Analysis Module returns "Unknown Builder" — covering any sample not matching the four pre-built signatures.

Input schema: `{ "structural_fingerprint": {"package_naming_style": "...", "obfuscation_metrics": {...}, "class_hierarchy_depth": N, "resource_patterns": [...], "code_skeleton_patterns": [...]} }`

System prompt: You are a mobile malware analyst evaluating an APK of unknown construction origin. Based on the structural fingerprint provided, characterize the likely builder's technical sophistication, identify any indicators of the builder's origin or development environment, describe what is distinctive about the construction patterns, and assess whether this resembles a known builder that may have been modified. Describe only what the structural evidence supports.

Output schema: `{ "sophistication_level": "Low/Medium/High/Advanced", "origin_indicators": [...], "distinctive_patterns": [...], "known_family_resemblance": "..." or "None detected", "analyst_recommendation": "..." }`

Why this matters: The four-signature limitation is the most predictable judge challenge against the Malware Provenance module. This mode converts "we don't know" into "we don't know the name, but here is what we do know structurally" — a meaningful intelligence output even for novel samples.

---

**Mode 3: CERT-In Incident Report Drafter**

Activates for all CRITICAL and HIGH severity results. Pre-populates a CERT-In compliant incident notification with every mandatory field drawn directly from the structured analysis outputs.

Input schema: `{ "verdict": "Malicious", "confidence": 0.94, "severity": "CRITICAL", "builder_kit": "Cerberus v2", "targeted_banks": ["SBI", "HDFC"], "otp_theft_risk": "HIGH", "attack_techniques": ["T1412", "T1417", "T1401"], "iocs": {"hashes": [...], "c2_domains": [...], "cert_fingerprint": "..."}, "first_seen": "..." }`

System prompt: You are drafting a cybersecurity incident notification for CERT-In India. Using only the provided analysis data, populate the following mandatory fields: incident type, affected sectors, incident description, technical indicators, recommended actions. Use formal regulatory language appropriate for government submission. Do not add information not present in the provided data.

Output schema: Structured fields mapped to CERT-In incident report format.

Why this matters: CERT-In reporting is a legal obligation for Indian banking institutions. No existing tool produces a pre-populated regulatory notification. This feature has immediate, demonstrable BFSI value that every banking judge will recognize as eliminating real operational work.

---

**Mode 4: Intelligence Narrative Engine**

Generates the executive summary and technical attack chain description from structured analysis outputs. This is the baseline GenAI capability present in the original specification, retained as the final mode because it addresses the BFSI communication gap.

Input schema: `{ "verdict": "...", "shap_top_features": [...], "builder_kit": "...", "targeted_banks": [...], "attack_techniques": [...], "otp_risk": "...", "evasion_level": "...", "cert_attribution": "..." }`

Executive summary prompt: Write a single paragraph in plain language for a bank's senior management audience. State the threat type, severity, targeted institutions, and single most important recommended action. Use only the provided data. No technical jargon beyond what bank management would recognize.

Attack chain prompt: Write a technical paragraph describing the complete attack lifecycle for a SOC analyst audience, referencing only the specific ATT&CK techniques and behavioral signals provided. Structure the description as a sequential narrative from initial installation through credential theft and data exfiltration.

---

## Edge Case Coverage

**Obfuscated APK — jadx fails completely.** Smali-only analysis activates automatically. The feature vector is computed from Smali-available features only. Missing features are recorded and logged in the report. The confidence score is penalized to reflect reduced analysis completeness — specifically, the ML confidence dimension of the risk score is reduced by 15 percentage points when jadx failure is detected. SHAP values are computed on the partial feature vector and results are labeled "partial analysis — decompilation failed." The GenAI Code Intent Reconstructor can partially compensate by analyzing available Smali snippets.

**Certificate not in corpus.** The module returns "No known family relationship identified" and provides the raw certificate characteristics (subject, issuer, validity, self-signed flag) as standalone intelligence. Self-signed certificates are flagged regardless of corpus presence. The absence of a match does not produce false attribution — it produces an honest negative result.

**Unknown builder kit.** The Malware Provenance module returns "Unknown Builder" with the structural fingerprint. GenAI Mode 2 activates to characterize the builder's patterns. The risk score is not penalized for unknown builders — an unknown factory may be equally dangerous; the attribution dimension simply contributes reduced confidence rather than zero.

**LLM API unavailable during demo.** All four GenAI modes have pre-computed fallback outputs for the three to five demo APKs. These fallback outputs are stored locally and served without API calls. The demo never depends on a live LLM call for the demonstration samples. For non-demo samples during production use, template-generated fallbacks are clearly labeled.

**APK with no SMS permissions.** OTP interception risk is rated LOW and explicitly stated as such. No false positive is generated. The absence of SMS signals is reported as a meaningful finding — the malware may use a different credential theft mechanism, which the overlay detection and accessibility service signals will surface.

**Reflection-based API hiding.** Detected as a feature in its own right. The presence of `java.lang.reflect` API usage is extracted as a feature contributing to the evasion sophistication score and explicitly flagged in the Anti-Analysis Indicator output. Complete static resolution of reflected calls is out of scope; the platform is transparent about this limitation in the SHAP output.

**ZIP bomb APK.** The APK is validated for compression ratio before any extraction begins. Any APK with uncompressed-to-compressed ratio exceeding 100:1 is rejected with a specific error message. apktool and jadx subprocess calls are wrapped with resource limits (maximum memory and CPU time) to prevent runaway processing on adversarially crafted inputs.

**Three to five known demo samples only for Fraud Interface Reconstruction.** This scope limitation is explicit in every output context where the module is shown. Unknown APKs receive a message stating that overlay reconstruction is available for known malware families only and that the sample's layout resources have been extracted and are available for manual review.

**Model confidence on novel malware families outside training data.** Samples with feature vectors far from the training distribution will receive lower confidence scores. This is correct behavior, not a bug. The SHAP output will show which features are driving the uncertain prediction and give the analyst the information needed to evaluate the verdict manually.

---

## Risk Mitigation

**Dynamic analysis criticism.** The defense must be delivered fluently, not as an apology. Three specific arguments: executing malicious code on bank infrastructure creates legal and operational risk that static analysis avoids entirely; banking trojans leave forensically complete signatures in their static artifacts because they must declare their capabilities in the manifest to function; and static analysis delivers complete results in under 60 seconds versus 10–20 minutes for dynamic sandbox, enabling the volume coverage SOC teams need. Frame the approach as "behavioral static analysis" — the platform infers behavioral intent from static signals — not "we skipped dynamic analysis." Dynamic sandbox integration is the highest-value post-prototype enhancement.

**Attribution scaling criticism — four builder kit signatures.** Acknowledge the limitation directly: four families is the initial signature database. Unknown Builder handling via GenAI Mode 2 produces meaningful intelligence for samples outside the database. The corpus grows with deployment — every analyzed unknown builder that analysts confirm as a new family can be added as a new signature in minutes. Position the database as a living resource, not a fixed constraint.

**AI-washing criticism.** The Code Intent Reconstructor is the decisive answer. Show a live example: take a Smali snippet with obfuscated method names and encoded strings, show what conventional static analysis produces (nothing interpretable), then show what the LLM produces (a functional description identifying the XOR decryption of a C2 URL). This is not prose generation. This is reasoning about code semantics from bytecode artifacts. No template engine produces this output.

**Dataset criticism.** State the specific dataset composition, train/test split methodology, and resulting F1 score. If AndroZoo subset: state the number of malware and benign samples, the class balance approach, and the held-out test performance. "We used publicly available labeled samples and achieved F1 of [N] on a held-out test set with [N]% false positive rate" is a complete and credible answer. Prepare these numbers before the submission.

**Builder kit coverage criticism.** Four named signatures plus LLM-powered unknown characterization. The coverage claim is honest: "We cover the four most prevalent Indian banking trojan builder families. Unknown builders receive structural characterization rather than named attribution." Honesty about methodology scope earns more judge trust than overclaiming.

**Obfuscation criticism.** Three-layer handling: Smali-only fallback when jadx fails, reflection detection as a feature in the evasion score, and the Code Intent Reconstructor for semantic analysis of obfuscated snippets. The platform degrades gracefully and transparently for obfuscated samples rather than producing silent false negatives.

**Demo reliability criticism.** Pre-recorded complete walkthrough video exists as backup. Static screenshots of every major visual output are saved as PNG fallbacks. All five GenAI outputs for demo samples are pre-computed and stored locally. The demo never analyzes an unknown APK live. The frontend can serve pre-cached analysis results without a live backend call. Twenty percent of prototype development time is allocated to demo hardening.

---

## Innovation Highlights

**Builder Kit Attribution with GenAI Extension.** No existing publicly available tool identifies the specific construction toolkit used to produce a malware sample. The Malware Provenance Analysis Module produces named attribution for known families; the Unknown Builder Characterizer extends this to novel samples using LLM structural reasoning. Together, these convert "we can detect this" into "we know who manufactures the malware" — intelligence that connects separate incidents, enables proactive defensive measures, and supports law enforcement referrals.

**Obfuscated Bytecode Semantic Analysis via LLM.** Applying a large language model to reason about Android bytecode semantics for obfuscated code interpretation is a novel capability with no comparable implementation in publicly available tools. The technical differentiator is real: signature databases fail on novel obfuscation patterns; the LLM reasons from general Android API knowledge and code structure rather than learned signatures. This is the most technically defensible GenAI claim in the platform.

**Fraud Interface Reconstruction.** Reconstructing the exact phishing overlay that the fraud victim sees — showing the fake SBI YONO or HDFC MobileBanking login screen extracted from the malware's own resources — converts abstract security analysis language into visual evidence. This capability is unique, immediately comprehensible to non-technical audiences, and directly usable in fraud investigation case files, customer advisories, and law enforcement referrals.

**Automated CERT-In Regulatory Reporting.** No tool in the Indian banking security landscape automates CERT-In incident report generation from malware analysis outputs. This is a compliance obligation for Indian banking institutions. The implementation is 20–30 lines of LLM integration code. The judge impact-to-implementation-effort ratio is the highest of any feature in the platform.

**Indian BFSI Threat Calibration.** The platform is not a generic mobile malware analyzer adapted for banking. It is a banking malware analyzer from the ground up, calibrated for the specific threat actors, specific Indian banking applications, and specific fraud mechanisms active in the Indian market. This specificity is a genuine competitive advantage over every global tool.

---

## Final MVP Scope

The following must be complete and demonstrable before the prototype presentation. This scope is achievable by a solo developer using AI-assisted development.

**APK Disassembly Pipeline:** Upload interface, hash computation and cache lookup, apktool disassembly to Smali and resources, jadx decompilation with Smali-only fallback, artifact extraction to working directory, ZIP bomb protection.

**Static Feature Analysis Engine:** Pre-trained XGBoost model loaded from joblib artifact, permission vector extraction from AndroidManifest.xml, opcode n-gram extraction from Smali, SHAP explanation generation, waterfall chart visualization, calibrated confidence score with F1/precision/recall metrics documented.

**Certificate Relationship Intelligence Module:** X.509 certificate extraction and parsing, pre-populated corpus of 50–100 known malware certificate fingerprints, NetworkX graph with attribution queries, D3.js force-directed graph visualization in the dashboard.

**Malware Provenance Analysis Module:** Structural fingerprint extraction, signature matching against four known builder kit patterns, confidence-scored attribution output, unknown builder flag passed to GenAI Mode 2.

**OTP Interception Detection Module:** Permission triplet detection, Smali-level overlay trigger pattern matching, targeted bank package name extraction, risk level output.

**Generative AI Intelligence Engine — all four modes:** Code Intent Reconstructor, Unknown Builder Characterizer, CERT-In Report Drafter, Intelligence Narrative Engine. Pre-computed outputs for all demo samples as fallback. Template fallback for non-demo samples when API is unavailable.

**Threat Technique Mapping Engine:** Static feature-to-technique mapping table for 15–20 ATT&CK for Mobile techniques, ATT&CK matrix visualization with highlighted cells.

**Fraud Interface Reconstruction Module:** Pre-processed for three to five known Indian banking malware families, side-by-side comparison panel in the dashboard.

**Risk Score Dashboard:** Five-signal composite computation, severity label display, decomposed contributing score breakdown.

**IOC Export:** File hashes, C2 domain candidates, certificate fingerprints, malicious package names, exported as JSON and CSV.

**PDF Intelligence Report:** All analysis sections assembled into a downloadable PDF. WeasyPrint or ReportLab — commit to one and use it.

**Analyst Override Workflow:** Any verdict can be manually overridden with documented justification. All overrides logged with analyst ID, timestamp, and reason.

**Demo Hardening:** Pre-recorded backup video of complete walkthrough. Static screenshot fallbacks for all major outputs. Pre-selected demo APKs tested end-to-end before prototype phase begins. Frontend capable of serving pre-cached results without live backend.

---

## Final Judge Narrative

This platform deserves shortlisting and finals selection for three reasons that correspond to three dimensions judges weight most heavily: genuine technical innovation, demonstrable BFSI relevance, and credible implementation.

The technical innovation is real and verifiable. Builder kit attribution identifying the specific construction toolkit is absent from every publicly available malware analysis tool. Obfuscated bytecode semantic analysis via LLM is a novel application of Generative AI to a problem that conventional pattern matching cannot solve. Fraud UI reconstruction converting malware resources into visual evidence of victim deception is unique. Each of these claims can be verified by a judge submitting any of the demo samples and observing the output.

The BFSI relevance is specific, not generic. The platform was designed for the Indian banking threat landscape, not adapted for it. Every module addresses a real operational gap: SOC analysts who spend hours on manual attribution, CERT-In reporters who manually populate incident notifications, fraud investigators who cannot show management what the victim saw, bank security teams that cannot connect related incidents across shared infrastructure. The platform solves each of these problems in seconds.

The implementation is credible because the scope is honest. The MVP uses mature, well-documented open-source tools. The model is pre-trained on established datasets. The demo samples are pre-verified. The GenAI components have API-unavailable fallbacks. The limitations — four builder kit signatures, known-sample-only overlay reconstruction, static-only analysis — are explicitly acknowledged and handled. A platform that knows its boundaries is more trustworthy than one that claims to solve everything.

The combination of these three attributes — verifiable innovation, specific BFSI value, and honest implementation — is uncommon in hackathon submissions. Most submissions maximize either ambition or completeness but not both. SENTINEL-X achieves both by making precise choices about what to build, what to defer, and where Generative AI genuinely contributes analysis rather than decoration.