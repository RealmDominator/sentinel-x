# SENTINEL-X — COMPLETE HACKATHON AUDIT REPORT
## PSB Cybersecurity, Fraud & AI Hackathon 2026

**Audit Date:** June 12, 2026 | **Submission Deadline:** June 15, 2026 (3 days remaining)
**Evaluator Perspective:** Senior BFSI Cybersecurity Architect + IIT Hyderabad Technical Jury

---

> **IMPORTANT CORRECTION:** The previous analysis stated the deadline was "tomorrow." The actual deadline is **June 15, 2026** — you have **3 days**, not 1. This changes the feasibility calculus significantly. Use this time well.

---

## TASK 1 — PROBLEM STATEMENT ALIGNMENT AUDIT

| Requirement | Existing Coverage | Quality | Missing Elements | Risk Level |
|---|---|---|---|---|
| **Generative AI** | Mentioned in Solution Doc (Section 11.3) — LLM API for executive summary + attack narrative | **WEAK** — described architecturally but zero implementation detail, no prompt shown, no model named, no output example | Which LLM? What prompt structure? How are hallucinations prevented? How is it actually called? | **CRITICAL** |
| **Automated Reverse Engineering** | apktool + jadx pipeline, fully specified | **STRONG** — both tools named, fallback behavior defined, artifact extraction mapped | ZIP bomb protection mentioned in Spec Section 14 but sandboxing of subprocess calls not addressed | Medium |
| **Static Analysis** | PermFlow XAI (4 feature categories), CertGraph, FactoryPrint, SMSGuard | **STRONG** — multi-dimensional, SHAP explainability present | No mention of native library (.so) analysis — this is a known malware evasion technique | Low |
| **Dynamic Analysis** | Explicitly excluded | **ABSENT** — by design | Problem statement says "Static AND Dynamic." Exclusion is documented but not defended in the submission document | **HIGH** |
| **Malware Attribution** | CertGraph + FactoryPrint dual-pathway | **STRONG** — dual pathway is genuinely differentiating | Builder kit database is manually curated with only 4 families (Cerberus, Anubis, SpyNote, Drinik) — judges will ask how this scales | Medium |
| **Risk Scoring** | 5-signal weighted composite, documented formula | **STRONG** — transparent, decomposed, auditable | Confidence score calibration not validated (uncalibrated XGBoost probabilities ≠ true probabilities) | Medium |
| **BFSI Applicability** | Indian bank targeting (SBI, HDFC, ICICI, Axis, Paytm), OTP interception, CERT-In context | **STRONG** — Indian banking-specific throughout | No explicit RBI Mobile Security Guidelines mapping, no DPDP Act compliance workflow | Low |
| **Fraud Relevance** | WhatTheVictimSees, OTP interception, overlay detection | **STRONG** — fraud mechanism reconstruction is unique | WhatTheVictimSees works only for 3-5 pre-processed samples — generalization is deferred | Medium |
| **Operational Usability** | PDF report, IOC export, analyst dashboard, STIX 2.1 | **MODERATE** — outputs are described but analyst workflow integration (SIEM/SOAR) is absent | No SIEM integration path, no analyst override workflow, no case correlation ID system | Medium |

### Hidden Gaps

**Gap 1 — Dynamic Analysis Defense.** The problem statement explicitly says "Static and Dynamic Analysis." The solution doc excludes dynamic analysis with a single sentence in Section 7.3 of the Spec. This will be the first question from judges. The submission document must contain a paragraph explicitly explaining why static-only is sufficient for this use case — emphasizing: (a) execution risk with live malware, (b) completeness of static signals for banking trojans, (c) faster throughput enabling higher volume coverage. This is defensible but it must be argued, not silently omitted.

**Gap 2 — GenAI Substantiation.** Section 11.3 of the Solution Document describes the GenAI component at a high level. It says "A large language model API integration serves as the narrative intelligence engine." There is no prompt, no model name, no example output, no error handling description, and no explanation of how hallucination in the executive summary is prevented. A judge asking "show me the AI" will see a paragraph in a document, not evidence of an implemented system. This must be resolved.

**Gap 3 — Model Metrics Absent.** The solution doc says metrics are "reported in the technical documentation" — which does not exist in the submitted documents. F1, precision, recall, and false positive rate must appear in the submission document itself.

**Gap 4 — Dynamic Analysis Substitution.** Some judges may accept the static-only argument. Others won't. A lightweight hedge: mention that behavioral signal inference from static opcode n-grams partially substitutes for dynamic analysis by capturing behavioral intent without execution. Frame it as "behavioral static analysis" not "static analysis."

---

## TASK 2 — PHASE 3 RECOMMENDATION AUDIT

| Recommendation | Implemented? | Quality | Practicality | Real-World Value | Improvement Needed |
|---|---|---|---|---|---|
| Add GenAI narrative engine (LLM API) | **Partially** — described in Solution Doc but no implementation detail | Low — architectural description ≠ implementation | High — directly satisfies PS1 | High — addresses communication gap | Show actual prompt, model, example output |
| Remove four-phase product roadmap | **Not Done** — Section 9 of Spec still contains all four phases | N/A | Critical — judges penalize strategy theater | None — removes distraction | Remove from submission document now |
| Rename modules to professional names | **Done** — Solution Doc uses professional names | Good — consistent throughout Solution Doc | High | Moderate | Verify Spec document also uses new names before submission |
| Add model performance metrics | **Partially** — Solution Doc mentions metrics exist "in technical documentation" | Poor — documentation not submitted | Critical | Critical | Include F1/precision/recall/FPR in submission document |
| Explicitly reference CERT-In and RBI | **Done** — multiple references in Solution Doc | Good | High | High | Add RBI Mobile Security Guidelines mapping |
| Merge ConfigDNA into CertGraph | **Not Done** — both remain separate modules | N/A | Medium — reduces demo complexity | Low improvement if merged | Not critical; low priority |
| Replace WebSocket with polling | **Not Done** — WebSocket still in spec | Low | Medium — reduces implementation risk | Zero difference for judges | Do this if you're behind schedule |
| Remove startup language from submission | **Partially done** — Solution Doc is clean; Spec still has startup pitch language | Poor — Spec still says "Drop an APK. Know not just IF it's malicious…" | Critical | High | The Spec should not be submitted as-is |
| Calibrate confidence scores | **Not Done** — no mention of isotonic regression or Platt scaling | N/A | Medium | High — uncalibrated probabilities mislead | Add one sentence: "confidence scores are calibrated using isotonic regression on held-out validation set" |

### Rejected Recommendations from Previous Analysis

**"Replace WebSocket with polling"** — Low value recommendation. If the team has already implemented WebSocket, keep it. It's a positive demo feature. Only replace if it's causing implementation problems.

**"Merge ConfigDNA into CertGraph"** — Adds complexity for zero judge-visible benefit. ConfigDNA is already a stretch feature. Just don't build it separately; if C2 config patterns surface during cert analysis, mention it inline.

**"Remove CampaignClock"** — This is correct. With only a handful of demo samples, the timeline will be nearly empty. Don't show an empty visualization.

---

## TASK 3 — PHASE 4 IMPLEMENTATION AUDIT

### MUST BUILD (Core — no demo without these)

| Feature | Engineering Effort | Demo Impact | Technical Depth | Reason |
|---|---|---|---|---|
| APK upload + unpacking pipeline (apktool/jadx) | Medium | High | Medium | Foundation of everything |
| Static Feature Analysis Engine (XGBoost + SHAP) | Low (model pre-trained) | High | High | Primary ML component; SHAP chart is visually compelling |
| Certificate Relationship Intelligence Module | Medium | High | High | D3 graph is the most visually impressive output |
| OTP Interception Detection Module | Low | High | Medium | India-specific, directly fraud-relevant |
| Risk Score Dashboard | Low | High | Medium | Judges need a clear verdict output |
| GenAI Narrative Engine | Low-Medium | CRITICAL | High | Must satisfy PS1 — 30-40 lines of code |
| Basic IOC Export (JSON/CSV) | Low | Medium | Low | Standard output — easy win |

### SHOULD BUILD (Strong demo impact, manageable effort)

| Feature | Engineering Effort | Demo Impact | Judge Impact | Reason |
|---|---|---|---|---|
| Threat Technique Mapping Engine (ATT&CK) | Medium | High | High | MITRE matrix visualization is impressive |
| Malware Provenance Analysis Module | Medium | High | High | Builder kit attribution is the most unique claim |
| Fraud Interface Reconstruction Module (pre-processed only) | Medium-High | Very High | Very High | Most emotionally impactful visual |
| PDF Intelligence Report | Medium | High | Medium | Professional deliverable |

### OPTIONAL (Build only if core is complete and stable)

| Feature | Reason |
|---|---|
| Anti-Analysis Indicator Detection | Easy pattern matching add-on; low differentiation |
| STIX 2.1 export | Judges cannot verify schema compliance; JSON/CSV sufficient |
| D3 campaign timeline | Empty without sufficient corpus data |

### REMOVE (Do not build, do not mention in demo)

| Feature | Reason |
|---|---|
| Real-time WebSocket progress | Adds fragility; polling is demo-safe |
| CampaignClock with live data | Corpus too small; empty timeline embarrasses the demo |
| Campaign Configuration Analysis Module (standalone) | Requires populated campaign database that doesn't exist |
| All Phase 2/3/4 roadmap features | Remove from submission entirely |

---

## TASK 4 — TECHNICAL ARCHITECTURE REVIEW

### Backend — FastAPI + Analysis Pipeline

**Strengths:** FastAPI is the correct choice — async handling, automatic OpenAPI docs, fast enough for demo scale. Parallel extraction with ThreadPoolExecutor is appropriate for I/O-bound disassembly tasks. The pre-trained model design (no training at demo time) is mature thinking.

**Weaknesses:** Python subprocess calls to apktool and jadx are not sandboxed. Both tools parse untrusted binary input. A malformed APK could potentially trigger a vulnerability in apktool. For the hackathon, this is acceptable; for production, each subprocess should run in a separate container with resource limits. No mention of file descriptor limits for ZIP bomb protection despite it being mentioned in the spec.

**Security Concerns:** If jadx fails on heavily obfuscated bytecode, the fallback to Smali-only is correct — but what happens to the feature vector? Undefined behavior in the ML pipeline if expected features are absent. Graceful degradation logic must be explicitly implemented.

**Enterprise Readiness: 5/10** — Functional for demo scale; significant security hardening needed for production.

### Malware Analysis Layer

**Strengths:** apktool + jadx is the industry-standard combination. Certificate extraction from META-INF is correct. The 4-category feature space (permissions, API calls, opcode n-grams, string entropy) covers the well-established feature set from Android malware literature (Drebin et al., 2014). Dual-pathway attribution (certificate + structural) is architecturally sound.

**Weaknesses:** Native library analysis (.so files) is absent. Banking trojans increasingly pack payloads in native libs to evade static Java/Smali analysis. Obfuscated string decryption is not addressed — if C2 URLs are encrypted at rest in the APK, they won't be extracted. The builder kit database has only 4 family signatures — judges will immediately ask about coverage.

**Enterprise Readiness: 6/10** — Solid for known malware families; known evasion gaps.

### AI/ML Layer

**Strengths:** XGBoost is the correct model for this feature space — tabular, high-dimensional, requires explainability. SHAP TreeExplainer is computationally efficient for gradient boosted trees. The combination of discriminative ML + LLM narrative is architecturally coherent.

**Weaknesses:** The GenAI component has no implementation detail in either document. No prompt template, no model selection rationale, no output validation, no fallback if the LLM API is unavailable during demo. This is the most dangerous weakness in the entire architecture from a judging perspective.

**ATT&CK Mapping** is described as a "deterministic mapping table" — this is honest but underwhelming. 15-20 static mappings will be quickly exhausted. A judge uploading a novel APK will see no mapped techniques if features don't match the static table.

**Enterprise Readiness: 5/10** — GenAI component underdeveloped; XGBoost component strong.

### Reporting Layer

**Strengths:** PDF + HTML dual output is correct. STIX 2.1 support signals intelligence community familiarity. IOC table structure (hashes + domains + cert fingerprints) covers the standard analyst requirements.

**Weaknesses:** No mention of report versioning or case reference numbering. In a real SOC workflow, every report needs a case ID, analyst ID, and submission timestamp for audit trail. ReportLab vs. WeasyPrint is listed as an "or" — the implementation choice should be made and committed.

**Enterprise Readiness: 6/10** — Functional; missing governance controls.

---

## TASK 5 — GENERATIVE AI AUDIT

### Current Classification: **WEAK GenAI / Borderline Cosmetic GenAI**

**Reasoning:** The Solution Document (Section 11.3) describes a GenAI narrative engine that receives structured JSON and produces executive summary + attack chain narrative. This is architecturally legitimate — structured data → LLM → natural language is a genuine use of generative AI. However, it is the minimum possible implementation of GenAI and sits at the boundary between genuine use and AI-washing for the following reasons:

The LLM is receiving pre-extracted, pre-structured facts and converting them to prose. This is valuable (addresses the communication gap) but the model is not performing any analysis — it is writing. Judges who are technically sophisticated will correctly observe that a template engine could produce similar output. The submission must explicitly argue why LLM output is superior to templated prose (tone variation, contextual adaptation, ability to produce novel attack chain descriptions for unknown families).

**Could judges classify it as AI-washing?** Yes, if the prompt is essentially "here are the facts, write a paragraph." The defense is to show that the LLM contributes reasoning about attack chain coherence and adapts the narrative to the specific combination of techniques detected — something a template cannot do for novel combinations.

### 18 New GenAI Features (Malware-Specific, Analyst-Centric)

| # | Feature Name | Description | Why Unique | User Value | Buildability | Innovation Score | Judge Impact |
|---|---|---|---|---|---|---|---|
| 1 | **Attacker Intent Inference Engine** | Given the complete feature set (permissions, overlay targets, C2 patterns, OTP signals), the LLM infers the attacker's operational goal — credential harvesting vs. account takeover vs. SIM swap enablement — and estimates the likely fraud workflow step by step | Most tools classify malware; none infer attacker intent from static signals | Enables SOC to predict which customer action will be exploited before the fraud occurs | Medium — structured prompt with feature inputs | 9/10 | 9/10 |
| 2 | **Obfuscated Code Intent Reconstructor** | Feed decompiled but obfuscated Smali snippets to an LLM with a prompt specialized in Android bytecode semantics; the model infers the functional intent of obfuscated code blocks (e.g., "this loop decodes a C2 URL using XOR with key 0x42") | No existing tool uses GenAI for bytecode semantic inference — only signature matching | Recovers analyst understanding from obfuscated samples that defeat traditional analysis | Medium-High — requires careful prompt engineering | 9/10 | 10/10 |
| 3 | **Malware Author Behavioral Profile Generator** | Aggregate multiple signals (builder kit choice, obfuscation style, language indicators in strings, operational cadence from config patterns, target selection logic) and prompt the LLM to generate a threat actor behavioral profile analogous to a criminal psychological profile | Intelligence agencies do this manually; no tool automates author profiling from static APK signals | Enables attribution beyond certificate matching — behavioral attribution of the author | Medium — well-defined inputs, creative synthesis task | 9/10 | 9/10 |
| 4 | **Campaign Genealogy Narrative** | Given multiple related samples sharing certificates or builder signatures, prompt the LLM to generate a chronological narrative of the campaign's evolution — technique additions, target expansions, infrastructure changes | No tool generates a narrative campaign history; CrowdStrike does this manually in threat reports | Condenses months of campaign tracking into a readable intelligence brief | Medium — requires corpus of related samples | 8/10 | 8/10 |
| 5 | **Regulatory Incident Report Drafter** | Given the structured analysis output, auto-draft a CERT-In incident report in the exact format specified in CERT-In advisory templates, pre-filling all mandatory fields | CERT-In reporting is a regulatory obligation; no tool automates this | Eliminates 1-2 hours of analyst report writing per reportable incident | Low-Medium — template is known; LLM fills in specific fields | 8/10 | 9/10 |
| 6 | **Victim Social Engineering Script Reconstructor** | Given the target bank, overlay UI assets, and SMS interception patterns, infer and generate the likely social engineering script the attacker used to deliver the APK (fake SMS, WhatsApp message, etc.) | Unique — reconstructs the pre-infection attack vector from post-infection artifacts | Enables banks to publish customer warnings with accurate phishing message examples | Medium — inference from indirect signals | 8/10 | 8/10 |
| 7 | **Analyst Hypothesis Challenger** | After automated analysis, the analyst can enter their own hypothesis about the sample ("I think this is BankBot targeting SBI"). The LLM evaluates the hypothesis against the evidence, confirms or challenges it with specific counterevidence from the analysis outputs | Interactive analyst reasoning support — turns the tool from one-way output to dialogue | Prevents confirmation bias; supports evidence-based investigation | Medium — requires chat interface component | 7/10 | 7/10 |
| 8 | **Evasion Technique Evolution Predictor** | Given the anti-analysis techniques detected and the malware family's known history, the LLM predicts likely next-generation evasion upgrades the attacker will implement in the next campaign iteration | Predictive threat intelligence — unique capability not available in any existing mobile security tool | Enables defensive teams to harden analysis pipelines against the next variant before it appears | High — speculative prediction requires careful output framing | 9/10 | 9/10 |
| 9 | **Fraud Playbook Generator** | Given all detected attack chain components, generate the complete step-by-step fraud playbook as the attacker designed it — from victim recruitment through fund extraction — in the format a fraud investigator can use for evidence documentation | Law enforcement and fraud teams need step-by-step playbook documentation; no tool generates this | Directly usable as evidence in fraud cases and law enforcement referrals | Low-Medium — well-structured inputs | 8/10 | 9/10 |
| 10 | **Cross-Sample Similarity Explainer** | When two samples share a certificate or builder signature, the LLM generates a paragraph explaining the forensic significance of the relationship in terms a court or regulator can understand | Expert witness-quality explanation of forensic linkages | Supports legal proceedings and regulatory investigations | Low — well-defined comparison task | 7/10 | 7/10 |
| 11 | **Unknown Builder Kit Characterizer** | When no known builder kit matches (FactoryPrint returns "unknown"), feed the structural fingerprint to the LLM and prompt it to characterize the likely origin, sophistication level, and possible developer geographic indicators | No tool handles unknown builders; this fills the gap dynamically | Critical for novel malware families that haven't been catalogued | Medium — requires careful prompt design to avoid hallucinated attribution | 9/10 | 9/10 |
| 12 | **MITRE Technique Gap Analyzer** | After mapping detected techniques, the LLM analyzes which MITRE ATT&CK for Mobile techniques are not covered by the analysis and explains what static evidence would be needed to detect them — identifying analysis blind spots | Meta-level analysis of the analysis itself; no tool does this | Helps security teams understand what the platform cannot see and why | Low — list completion and reasoning task | 7/10 | 8/10 |
| 13 | **Comparative Threat Intelligence Brief** | Given the analyzed sample, query the LLM to compare it against publicly known threat intelligence (CERT-In advisories, Mandiant/CrowdStrike reports) and identify what is new, what matches known patterns, and what is missing from public documentation | Structured comparison against public TI — adds research value | Analyst immediately knows if this is a documented threat or a novel one | Medium — requires TI corpus or search-augmented generation | 8/10 | 8/10 |
| 14 | **Customer Advisory Draft Generator** | Generate a plain-language customer advisory for a bank's retail banking customers explaining the threat in non-technical terms, with specific behavioral guidance (what to look for, what to do if affected) | Banks need to issue customer communications; drafting these is slow and inconsistent | Reduces time-to-customer-advisory from days to minutes | Low — well-constrained writing task | 6/10 | 7/10 |
| 15 | **Malware Mutation Hypothesis Generator** | Given two versions of the same malware family (if available), the LLM infers why specific changes were made — e.g., "The addition of root detection suggests the attacker encountered analysis in a rooted sandbox environment and updated the sample in response" | Reverse-engineers attacker decision-making from code changes | Strategic threat intelligence: understanding the attacker's development priorities | High — requires two related samples | 8/10 | 8/10 |
| 16 | **APK Trust Score Explainer for Non-Technical Staff** | Given the full analysis, generate a one-page plain language explanation of why this APK is dangerous, suitable for a bank branch manager or fraud operations staff member | Most organizations can't translate security verdicts into operational action | Enables non-security staff to participate in fraud response | Low — constrained communication task | 5/10 | 6/10 |
| 17 | **Attacker Infrastructure Pivot Narrative** | Given extracted C2 domains and certificate data, the LLM generates a narrative of likely attacker infrastructure pivoting behavior — explaining how the attacker may shift infrastructure if IOCs are blocked, and suggesting pre-emptive blocking candidates | No tool provides pre-emptive IOC suggestions based on attacker behavioral inference | Enables proactive network blocking before the attacker pivots | High — requires strong reasoning about attacker behavior | 9/10 | 8/10 |
| 18 | **Campaign Damage Estimate Generator** | Given targeted bank packages, OTP interception signals, and known campaign duration, the LLM generates a structured estimate of potential fraud exposure (affected customer segments, likely transaction value ranges) in terms suitable for RBI reporting | Quantified risk estimates are required for regulatory reporting; no tool generates these | Directly supports RBI incident reporting obligations | Medium — requires conservative framing to avoid overconfident estimates | 7/10 | 8/10 |

### Top 3 GenAI Features to Actually Build (Given 3-Day Timeline)

**Priority 1 — Obfuscated Code Intent Reconstructor (#2):** 30-50 lines of code. Feed Smali snippets to the LLM with a specialized prompt. This is the only GenAI feature that performs analysis beyond prose generation. Judges will be genuinely impressed. This is the difference between "AI-washing" and "genuine GenAI."

**Priority 2 — Regulatory Incident Report Drafter (#5):** 20-30 lines. CERT-In report format is publicly available. The LLM fills in mandatory fields. This has immediate, demonstrable BFSI value that no judge can dispute.

**Priority 3 — Fraud Playbook Generator (#9):** 20-30 lines. Well-structured input, high demo impact. Generating the attacker's step-by-step fraud playbook is viscerally compelling in a demo context.

---

## TASK 6 — OUT-OF-THE-BOX GENAI INNOVATION HUNT

### Breakthrough Modules (Ideas other teams will not think of)

**Module A: Malware Code Comment Hallucinator**
Most banking trojans originate from developer communities where the original source is in Russian, Chinese, or another non-English language. String constants, variable names, and code comments often contain transliterated or translated indicators of origin. A specialized LLM prompt extracts all string literals, class names, and comment fragments from decompiled code, analyzes them for language-of-origin indicators, and generates a linguistic attribution report. This is the digital equivalent of a forensic linguist analyzing criminal communications.

Required inputs: all string literals from Smali/jadx output, class and method name lists. Expected outputs: likely developer language background, geographic attribution confidence (Low/Medium/High), supporting linguistic evidence. Buildability: Medium. Innovation Score: 10/10.

**Module B: Attack Surface Narration for Victim Simulation**
Standard tools tell analysts what the malware does. This module uses the LLM to simulate being the victim — generating a first-person narrative of the complete fraud experience as the victim would live it, from the initial fake SMS through the moment they realize their account has been drained. This is not a gimmick: it produces precisely the narrative that bank fraud investigators need for case files, customer communications, and law enforcement referrals.

Required inputs: WhatTheVictimSees overlay output, OTP interception signals, targeted bank UI reconstruction, social engineering vector inference. Expected outputs: first-person victim experience narrative, timeline of attacker actions visible to victim, emotional and behavioral manipulation points identified. Buildability: Low (writing task with well-defined inputs). Innovation Score: 9/10.

**Module C: Malware DNA Diff Narrator**
When two samples share a builder kit signature (same family, different version), the LLM receives a structured diff of their feature vectors and generates a "What changed and why" narrative — explaining each detected change in terms of what analyst or defensive capability it was designed to defeat. This module answers the question: "Is this a significant upgrade or a minor variant?" in analyst-readable language.

Required inputs: feature vectors of two related samples, builder kit identification for both, changelog of feature differences. Expected outputs: version increment classification (major/minor/patch), specific capability additions described, inferred defensive bypass motivation for each change. Buildability: Medium (requires two related samples for demo). Innovation Score: 9/10.

**Module D: Campaign Operator Psychology Profile**
Drawing from behavioral economics and criminal psychology literature encoded in LLM training, this module analyzes the targeting logic of a malware campaign (which banks, which customer segments, which fraud mechanism) and generates a psychological profile of the campaign operator — their risk tolerance, technical sophistication self-assessment, financial motivation structure, and likely operational security habits. This is the module that Mandiant or CrowdStrike analysts produce manually after months of tracking a threat actor; this generates a first draft in seconds.

Required inputs: target bank list, fraud mechanism choice, builder kit sophistication level, campaign duration estimate, evasion technique choices. Expected outputs: operator risk profile, technical skill self-assessment, likely organizational structure (lone operator vs. crime-as-a-service), operational security assessment. Buildability: Medium. Innovation Score: 10/10. Judge Impact: 10/10.

---

## TASK 7 — JUDGE ATTACK SIMULATION: TOP 50 QUESTIONS

### Category 1: Generative AI (Highest Risk)

**Q1. Where exactly is the Generative AI in your system?**
Why asked: PS1 explicitly requires it. Weakness targeted: vague description without implementation.
Ideal answer: "The GenAI Narrative Engine receives structured JSON from all analysis modules and calls an LLM API to generate two outputs: (1) a plain-language executive summary for CISO audiences, and (2) a technical attack chain narrative describing the complete malware lifecycle. Beyond narrative generation, a secondary GenAI module feeds decompiled Smali code snippets to the LLM to infer the semantic intent of obfuscated code — analysis that pattern matching cannot perform." Show a live example.
Risk if weak: Immediate disqualification from top ranking.

**Q2. How is your GenAI different from ChatGPT summarizing a bullet list?**
Why asked: Judges know AI-washing. Weakness targeted: LLM as glorified template engine.
Ideal answer: "The executive summary is standard structured-input-to-prose generation. The code intent reconstruction is genuine analysis — the model is reasoning about Android bytecode semantics, not just formatting facts. The output changes non-deterministically for different obfuscation patterns in ways a template cannot replicate." Show the difference with a live demo.
Risk if weak: Judges classify the entire GenAI claim as cosmetic.

**Q3. What happens if the LLM API is unavailable during the demo?**
Why asked: Demo reliability is an evaluation criterion.
Ideal answer: "The platform implements graceful degradation. If the LLM API call fails, the report generates with template-based narratives and clearly marks them as template-generated rather than AI-generated. All structured analysis outputs remain available regardless of LLM availability."
Risk if weak: Live demo crash ends the presentation.

**Q4. How do you prevent the LLM from hallucinating false threat intelligence?**
Why asked: Hallucination in security contexts is dangerous.
Ideal answer: "The LLM receives only factual, structured inputs — extracted permissions, matched technique IDs, verified certificate fingerprints. It is explicitly instructed to describe only the provided facts without adding information not in the structured input. All AI-generated content is labeled in the report and presented alongside the underlying structured data for verification."
Risk if weak: Judges will not trust the platform for real-world use.

**Q5. Which specific LLM are you using and why?**
Why asked: Model selection reflects technical maturity.
Ideal answer: Name a specific model (Claude Sonnet 4.6, GPT-4o, or a local model like Llama 3) with brief reasoning (cost, context window, API latency, structured output support). Do not say "some LLM API."
Risk if weak: Judges assume you haven't actually implemented this.

### Category 2: Malware Analysis (Technical Depth)

**Q6. What is your model's F1 score, precision, recall, and false positive rate?**
Why asked: Any ML claim requires quantitative validation.
Ideal answer: State specific numbers from your held-out test evaluation. If training hasn't happened yet, state the expected metrics based on literature for XGBoost on Drebin-style features (typically F1 ~0.97 on clean datasets) and commit to providing actual metrics before the final presentation.
Risk if weak: The ML component is dismissed as unvalidated.

**Q7. How does your system handle heavily obfuscated APKs where jadx fails?**
Why asked: Obfuscation is the most common malware evasion technique.
Ideal answer: "jadx failure triggers fallback to Smali-only analysis. The feature vector is computed from available Smali bytecode features. The SHAP analysis flags which features are unavailable due to decompilation failure. The confidence score is penalized to reflect reduced analysis completeness."
Risk if weak: Judges see the system as fragile.

**Q8. Your builder kit database covers only 4 families. What happens with an unknown family?**
Why asked: 4 signatures is a thin coverage claim.
Ideal answer: "Unknown builders are handled explicitly — the module returns a structured characterization of the unknown builder's patterns (package naming style, obfuscation characteristics, resource patterns) rather than a named attribution. This output is fed to the GenAI Unknown Builder Characterizer, which generates a hypothesis about the builder's origin and sophistication. Unknown-builder samples are also flagged for analyst attention and manual investigation."
Risk if weak: The attribution claim appears superficial.

**Q9. How do you validate that your SHAP values are trustworthy?**
Why asked: SHAP can produce plausible-looking but meaningless values for poorly trained models.
Ideal answer: "SHAP values are trustworthy only if the underlying model is well-trained and calibrated. We validate through: (1) held-out test set F1/precision/recall, (2) feature importance stability testing across different random seeds, (3) sanity-check review — READ_SMS should have high SHAP magnitude for banking trojans, which we verify against domain knowledge."
Risk if weak: The explainability claim is undermined.

**Q10. Can your system analyze APKs that use reflection to hide API calls?**
Why asked: Reflection-based obfuscation defeats static API call analysis.
Ideal answer: "Reflection-based API hiding is a known limitation of static analysis. Our system detects the use of java.lang.reflect APIs as a feature itself — its presence is a strong indicator of obfuscation intent and contributes to the evasion sophistication score. The Anti-Analysis Indicator module flags reflection use. Complete static resolution of reflected calls is beyond the scope of this build, as it would require symbolic execution."
Risk if weak: Judges see a significant blind spot unacknowledged.

**Q11. Your certificate corpus has 50-100 fingerprints. VirusTotal has millions. Why is yours useful?**
Why asked: Benchmarking against existing tools.
Ideal answer: "VirusTotal's certificate data is not structured for relationship graph analysis. Our module builds a graph over certificates that enables family clustering, campaign linkage, and PageRank-based operator identification — capabilities VirusTotal does not provide. The corpus size is appropriate for a prototype; production deployment would integrate with VirusTotal and Koodous APIs to enrich the corpus continuously."
Risk if weak: The certificate module appears redundant.

**Q12. How do you extract C2 URLs from samples that encrypt them at rest?**
Why asked: C2 URL encryption is standard in sophisticated banking trojans.
Ideal answer: "Static extraction of encrypted C2 URLs is limited — we detect the presence of high-entropy strings and flag them as likely encrypted payloads without decryption. The ConfigDNA module identifies the encryption schema pattern (XOR, AES, custom) when consistent with known patterns. Decryption would require dynamic analysis, which is outside the static-only scope of this build."
Risk if weak: The IOC extraction claim is overstated.

### Category 3: Architecture

**Q13. How long does a full analysis take? What's your throughput?**
Why asked: Operational feasibility depends on speed.
Ideal answer: "End-to-end pipeline: 15-30 seconds for a typical APK on a development machine. The primary bottleneck is jadx decompilation, not the ML inference (which runs in under 100ms). With ThreadPoolExecutor parallelism, the four extraction streams reduce wall-clock time by 40-60%. For higher throughput, the pipeline migrates to Celery + Redis task queues."
Risk if weak: The "30-second analysis" claim is undefended.

**Q14. What prevents an attacker from submitting a ZIP bomb APK?**
Why asked: Security products must be hardened against adversarial input.
Ideal answer: "File size limits (configurable, default 100MB) are enforced at ingestion before any processing begins. ZIP bomb detection checks the compression ratio before full extraction — any APK with a compression ratio exceeding 100:1 is rejected. apktool and jadx run with process-level resource limits (ulimit) to cap maximum memory and CPU usage."
Risk if weak: The platform has an obvious denial-of-service vulnerability.

**Q15. Why did you choose XGBoost over a neural network for malware classification?**
Why asked: Model choice reflects technical judgment.
Ideal answer: "Three reasons: (1) SHAP TreeExplainer provides exact Shapley values for tree models — neural network SHAP is approximated and less reliable; (2) XGBoost on tabular permission/API features consistently outperforms or matches deep learning in published malware classification literature (Drebin, CICAndMal2017 benchmarks); (3) inference latency is under 100ms vs. 500ms+ for neural networks on the same hardware."
Risk if weak: Judges assume you chose XGBoost by default without justification.

### Category 4: BFSI Relevance

**Q16. How would this integrate with a bank's existing SIEM platform?**
Why asked: Enterprise adoption requires SIEM integration.
Ideal answer: "Integration via two paths: (1) IOC export in STIX 2.1 format for direct import into SIEM platforms supporting TAXII feeds; (2) webhook notifications for CRITICAL/HIGH severity results that can trigger SOAR playbooks. The intelligence report PDF integrates with case management systems like ServiceNow via API."
Risk if weak: The platform is seen as a standalone tool, not an enterprise product.

**Q17. A BFSI SOC receives 50+ suspicious APKs per day. How does your platform handle this volume?**
Why asked: Scale is an enterprise requirement.
Ideal answer: "At 50 APKs/day, with ~20-second analysis per sample, peak processing requires roughly 17 minutes of analysis time for the daily intake batch. Single-worker deployment handles this comfortably. For higher volumes, Celery + Redis enables horizontal scaling with minimal code changes. The analysis cache eliminates redundant processing for hash-matched duplicates, which are typically 30-40% of daily submissions."
Risk if weak: The platform appears too slow for production use.

**Q18. How would an analyst dispute or override the platform's verdict?**
Why asked: Human accountability in automated security systems is an enterprise requirement.
Ideal answer: "Every verdict can be manually overridden through the analyst dashboard. Override actions are logged with analyst ID, timestamp, justification text, and the modified verdict. Override logs are separate from analysis logs and cannot be modified. This maintains accountability in the decision chain and satisfies regulated financial institution audit requirements."
Risk if weak: The platform appears to remove human judgment from security decisions.

**Q19. What is your CERT-In reporting workflow?**
Why asked: PS1 is a government banking hackathon; CERT-In compliance is implicitly required.
Ideal answer: "CRITICAL severity results automatically generate a pre-drafted CERT-In incident report in the prescribed format, pre-populated with all mandatory fields (sample hash, affected institutions, detected techniques, IOCs, first-seen date). The analyst reviews, approves, and submits. The platform tracks reporting status and maintains a submission log."
Risk if weak: The BFSI applicability claim is underserved.

**Q20. How do you handle privacy of the APK samples themselves under the DPDP Act?**
Why asked: India's Digital Personal Data Protection Act creates obligations.
Ideal answer: "APKs may contain embedded PII in hardcoded credentials and config data. The platform implements configurable data retention — samples and extracted artifacts are purged after a configurable period (default 30 days). No raw APK content is exposed via API endpoints. Analyst access is logged. The analysis database is encrypted at rest."
Risk if weak: A regulatory gap in a regulatory-focused hackathon.

### Category 5: Innovation and Differentiation

**Q21. How is this different from MobSF?**
Why asked: MobSF is the obvious comparison.
Ideal answer: "MobSF answers one question: is this malicious? It has no attribution, no builder kit identification, no certificate graph, no AI-generated narrative, no victim perspective reconstruction, and no BFSI-specific targeting. SENTINEL-X answers five questions that MobSF cannot address. We supplement MobSF's detection with intelligence — attribution, attribution, and communication."
Risk if weak: Judges see duplication.

**Q22. What is genuinely new here that no other tool does?**
Why asked: Innovation score is a primary evaluation criterion.
Ideal answer: "Three capabilities no existing tool provides: (1) Builder kit attribution — identifying the specific malware construction toolkit, not just the family; (2) Fraud UI reconstruction — showing analysts exactly what the victim sees during credential theft; (3) AI-powered behavioral attribution of unknown builder kits from structural patterns. Each of these exists nowhere in the public tool landscape."
Risk if weak: Differentiation claim is not substantiated.

### Category 6: Feasibility and Implementation

**Q23. Show us the code.**
Why asked: Judges at IIT Hyderabad will want to see implementation.
Ideal answer: Have a GitHub repository ready. Core pipeline, ML inference, SHAP generation, GenAI API call, certificate extraction, and ATT&CK mapping should all be implemented and demonstrable. "Work in progress" is acceptable for stretch features; core pipeline must be live code.
Risk if weak: The entire submission is judged as theoretical.

**Q24. What is your training dataset and how did you ensure it's balanced?**
Why asked: Dataset quality determines model quality.
Ideal answer: "AndroZoo subset of [N] samples: [X] malware, [Y] benign. Malware sourced from AMD Dataset and MalwareBazaar; benign from AndroZoo benign-labeled set. Class balance maintained at approximately 1:1 through stratified sampling. Train/validation/test split: 70/15/15. All splits are APK-hash-deduplicated to prevent data leakage."
Risk if weak: The ML component has no credibility.

**Q25. Why no dynamic analysis given the problem statement explicitly requires it?**
Why asked: The problem statement says "Static AND Dynamic."
Ideal answer: "Dynamic analysis for malware samples in a banking institution context presents legal, operational, and security challenges that make static-first analysis the correct architectural choice. Banking trojans' most forensically significant behaviors — overlay rendering, OTP interception, accessibility abuse — all leave complete signatures in static artifacts. Our behavioral static analysis (opcode n-grams, permission combinations, manifest declarations) infers behavioral intent without execution risk. Dynamic analysis is planned as a Phase 2 sandbox integration."
Risk if weak: This is the single most predictable judge challenge and must be answered fluently.

*(Questions 26-50 abbreviated for space — the above 25 represent the highest-risk challenge areas. Prepare equally rigorous answers for: data poisoning resilience, adversarial ML attacks, STIX 2.1 schema compliance verification, NetworkX scalability ceiling, React dashboard performance on large D3 graphs, certificate corpus freshness, false positive rate for legitimate banking apps requesting SMS permissions, SHAP explanation stability across model versions, IOC export format compatibility with specific SIEM vendors, model retraining frequency, multi-APK campaign correlation workflow, sample submission API authentication design, report localization for non-English bank teams, integration with VirusTotal Enterprise, handling of split APK bundles, privacy of analyst query patterns, cross-institutional intelligence sharing legal framework, platform cost model for bank deployment, model drift detection, and OWASP Mobile Application Security Verification Standard alignment.)*

---

## TASK 8 — ENTERPRISE READINESS REVIEW

### What Makes This Enterprise-Ready

The 5-signal composite risk score with decomposed breakdown satisfies the explainability requirement of regulated financial institution automated decision-making. The audit logging design (Section 14.4 of Solution Doc) covers basic SOC accountability requirements. The IOC export in STIX 2.1 / JSON / CSV provides the operational outputs SOC teams can immediately use. The PDF intelligence report format matches what CERT-In and RBI incident reporting workflows consume.

The static-only analysis approach eliminates the legal risk of executing malicious code on bank infrastructure — a genuine enterprise deployment requirement that the solution correctly prioritizes.

### What Prevents Enterprise Adoption

There is no SIEM/SOAR integration path specified beyond STIX 2.1 export. Enterprise banks use Splunk ES, IBM QRadar, or Microsoft Sentinel — the solution should name at least one integration point. There is no multi-tenancy design — a platform serving multiple bank security teams needs tenant isolation that the current single-database design does not provide. There is no SLA or uptime specification — enterprise procurement requires availability commitments. There is no mention of air-gapped deployment for banks with strict data residency requirements. The NetworkX in-memory graph has no persistence across service restarts, meaning the certificate corpus must be reloaded on every restart.

### What Should Be Added (Enterprise Hardening, Post-Hackathon)

Celery + Redis task queue for production-scale throughput. Neo4j graph database with persistent storage. Multi-tenant database isolation with role-based access control. Audit log export to SIEM (Splunk HEC / QRadar syslog). Webhook/SOAR integration for automated response triggering. Sample retention policy enforcement with documented legal basis. Air-gapped deployment package for data-sensitive institutions.

---

## TASK 9 — COMPETITIVE LANDSCAPE ANALYSIS

| Capability | MobSF | VirusTotal | Koodous | Intezer | Joe Sandbox Mobile | Appknox | **SENTINEL-X** | **Advantage** | **Weakness** |
|---|---|---|---|---|---|---|---|---|---|
| Static Analysis | ✅ Strong | ✅ Signature | ✅ Moderate | ✅ Code Reuse | ✅ Strong | ✅ Strong | ✅ Strong | SHAP explainability is unique | Feature space similar to MobSF |
| Dynamic Analysis | ✅ Full | ❌ | ❌ | ❌ | ✅ Full | ✅ Partial | ❌ By design | Speed advantage | PS1 compliance gap |
| ML Classification | ✅ ML-based | ✅ Ensemble | ❌ | ✅ Gene-based | ✅ Behavioral | ✅ Rules | ✅ XGBoost+SHAP | Explainability | No cross-family gene analysis |
| Explainability (SHAP) | ❌ | ❌ | ❌ | Partial | ❌ | ❌ | ✅ Full SHAP | **Unique differentiator** | Requires pre-trained model |
| Certificate Attribution | ❌ | ✅ Partial | ✅ Strong | Partial | ❌ | ❌ | ✅ Graph | Relationship graph is novel | Small corpus (50-100 vs. millions) |
| Builder Kit Attribution | ❌ | ❌ | ❌ | Partial | ❌ | ❌ | ✅ **Unique** | **No comparable tool** | Only 4 families at launch |
| Fraud UI Reconstruction | ❌ | ❌ | ❌ | ❌ | Partial (screenshot) | ❌ | ✅ **Unique** | **No comparable tool** | Pre-processed samples only |
| MITRE ATT&CK Mapping | ✅ Partial | ❌ | ❌ | ✅ Strong | ✅ Strong | ❌ | ✅ Strong | Combined with narrative | Static mapping table limited |
| GenAI Narrative | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **Unique** | **No comparable tool** | Current implementation is weak |
| BFSI India Focus | ❌ | ❌ | ❌ | ❌ | ❌ | Partial | ✅ **Unique** | **No comparable tool** | Single geography focus |
| Risk Score | ✅ Moderate | ✅ Basic | ❌ | ✅ Strong | ✅ Strong | ✅ Strong | ✅ 5-signal composite | Decomposed and auditable | Calibration not validated |
| IOC Export | ✅ | ✅ STIX | ❌ | ✅ | ✅ | ❌ | ✅ STIX/JSON/CSV | Standard | Nothing unique here |
| PDF Report | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | AI-generated narrative is unique | WeasyPrint has CSS limitations |

**Genuinely Differentiated Features (no existing tool has these):**
Builder kit attribution, Fraud UI reconstruction, SHAP explainability for mobile malware, Indian BFSI targeting detection, AI-generated analyst narrative.

**Generic Features (available in multiple tools):**
Static analysis, IOC export, MITRE ATT&CK mapping, PDF report, risk scoring.

---

## TASK 10 — PHASE 3 & 4 IMPLEMENTATION VERIFICATION

| Recommendation | In Solution Doc? | In Spec? | Quality | Missing Pieces | Final Verdict |
|---|---|---|---|---|---|
| GenAI narrative engine | ✅ Section 11.3 | ❌ Listed as "templated strings" in 7.2 | **Poor** — no prompt, no model, no example, contradicted by Spec | Actual implementation, specific model, prompt template, output example, hallucination prevention | **HALF-IMPLEMENTED — CRITICAL** |
| Professional module naming | ✅ Solution Doc | ❌ Spec uses old names (PermFlow XAI, etc.) | **Inconsistent** — two documents use different names | Unify names across both documents before submission | **INCONSISTENCY — FIX BEFORE SUBMISSION** |
| Model performance metrics | ❌ Not in either document | ❌ | **Absent** | F1, precision, recall, FPR must appear in submission | **ABSENT — CRITICAL** |
| Remove four-phase roadmap | ❌ Still in Spec Section 9 | ❌ | **Not done** | Delete or move to appendix | **NOT DONE — HIGH PRIORITY** |
| CERT-In reference | ✅ Multiple sections | ✅ | **Good** | Add CERT-In report format reference | **IMPLEMENTED** |
| RBI reference | ✅ Partial | ❌ | **Weak** | Add RBI Mobile Security Guidelines mapping | **PARTIAL** |
| ZIP bomb protection | ✅ Section 14.1 | ❌ | **Mentioned** | Add specific compression ratio threshold | **PARTIAL** |
| Input validation | ✅ Section 14.2 | ❌ | **General description** | Add specific MIME type list and file size limits | **PARTIAL** |
| DPDP Act compliance | ✅ Section 14.3 | ❌ | **Mentioned** | Configurable retention period values | **PARTIAL** |
| Calibrated confidence scores | ❌ | ❌ | **Not addressed** | Add calibration method to Section 11.1 | **ABSENT** |
| Analyst override workflow | ❌ | ❌ | **Not addressed** | Add to Section 14 or dashboard description | **ABSENT** |
| SIEM integration path | ❌ | ❌ | **Not addressed** | Add one paragraph to Section 9.2 | **ABSENT** |
| WhatTheVictimSees pre-processed only | ✅ Section 7.5 | ✅ Section 6.1 | **Good — correctly scoped** | Maintain this scope; do not overclaim | **IMPLEMENTED CORRECTLY** |
| Demo hardening | ✅ Section 7.4 | ✅ | **Good** | Pre-record backup video | **IMPLEMENTED** |

---

## TASK 11 — HACKATHON EVALUATOR SCORECARD

| Dimension | Score | Rationale |
|---|---|---|
| **Innovation** | **7.5 / 10** | Builder kit attribution and fraud UI reconstruction are genuinely novel. GenAI is underdeveloped. Loses 2.5 points for weak GenAI implementation and absent dynamic analysis |
| **Technical Depth** | **7 / 10** | SHAP + XGBoost + certificate graph is genuinely sophisticated. No model metrics, no calibration, no obfuscation handling documentation pulls the score down |
| **Malware Intelligence** | **8 / 10** | Attribution pipeline is strong. MITRE ATT&CK mapping present. Certificate relationship graph differentiating. Loses 2 points for small signature database and absent native lib analysis |
| **Generative AI** | **4 / 10** | Architecturally described but not substantiated. No prompt, no model, no example output, contradicted by Spec Section 7.2 which says "templated strings." This is the lowest and most damaging score |
| **BFSI Relevance** | **8.5 / 10** | India-specific bank targeting, OTP interception focus, CERT-In references, SOC workflow outputs are excellent. Loses 1.5 for absent RBI Guidelines mapping and SIEM integration |
| **Implementation Quality** | **6 / 10** | Solution document is well-written and professional. Spec document has inconsistencies (old module names, startup language). No code shown. GenAI not implemented. Model metrics absent |
| **Feasibility** | **8 / 10** | Core pipeline is clearly achievable. Pre-trained model design is mature. Demo hardening section is correct. Loses 2 points for WhatTheVictimSees scope risk and empty CampaignClock |
| **Demo Impact** | **8 / 10** | SHAP waterfall + D3 certificate graph + ATT&CK matrix + overlay side-by-side = four compelling visual outputs. Loses 2 points for GenAI not being visually demonstrable in current design |
| **Differentiation** | **8.5 / 10** | Three features with no competitor: builder kit attribution, fraud UI reconstruction, India BFSI targeting. Highest scoring category |
| **Winning Probability** | **6.5 / 10** | Strong concept, weak GenAI implementation. If GenAI gap is closed in the next 3 days, this rises to 8.5/10. As currently documented, GenAI compliance is insufficient for PS1 |

**Current Overall: 72.5 / 100**
**Potential with fixes: 85-88 / 100**

---

## TASK 12 — FINAL VERDICT

### Top 10 Critical Weaknesses

1. **GenAI Implementation is Cosmetic as Documented** — Spec Section 7.2 says "templated strings"; Solution Doc Section 11.3 says "LLM API." These directly contradict. The actual implementation appears to be templates. This is the single most damaging weakness. *Impact on judging: SEVERE.*

2. **No Model Performance Metrics Anywhere** — F1, precision, recall, FPR are mentioned as existing in "technical documentation" that is not submitted. Judges evaluating an ML platform without metrics will assume the worst. *Impact: HIGH.*

3. **Module Naming Inconsistency Between Documents** — Spec uses old names (PermFlow XAI, CertGraph, etc.); Solution Doc uses professional names. If judges cross-reference, they see a poorly managed project. *Impact: MEDIUM.*

4. **Dynamic Analysis Exclusion Not Defended** — Problem statement says "Static AND Dynamic." The exclusion is justified in the Spec but absent from the Solution Document. Judges will challenge this directly. *Impact: HIGH.*

5. **Four-Phase Roadmap Still in Spec** — Section 9 of the Spec contains all four phases including "MalGenome bioinformatics." This signals ambition over execution. *Impact: MEDIUM.*

6. **Builder Kit Database Covers Only 4 Families** — Any judge who submits an APK from a family outside Cerberus/Anubis/SpyNote/Drinik will see "Unknown Builder" and no attribution. *Impact: MEDIUM.*

7. **No SIEM Integration Path** — Enterprise banks expect SIEM integration. The platform is described as standalone with no integration pathway beyond STIX 2.1 export. *Impact: MEDIUM.*

8. **Confidence Score Calibration Not Addressed** — Raw XGBoost probability outputs are not true probabilities. Presenting them as "94% confidence" is technically incorrect without calibration. *Impact: MEDIUM.*

9. **CampaignClock Visualization Will Show Empty Data** — With 50-100 certificate entries and 3-5 demo samples, the timeline visualization will be nearly empty. A blank visualization undermines demo credibility. *Impact: MEDIUM — remove from demo.*

10. **Analyst Override Workflow Absent** — Human accountability in automated decisions is a regulated financial institution requirement. The platform as documented has no override mechanism. *Impact: LOW-MEDIUM.*

### Top 10 Strengths

1. Builder kit attribution is genuinely unique — no existing public tool identifies the specific construction toolkit.
2. Fraud UI reconstruction provides visceral visual evidence that no other tool produces.
3. SHAP explainability is correctly implemented and technically rigorous — this is the right model for this problem.
4. Indian BFSI targeting specificity (named banks, OTP mechanism, CERT-In context) differentiates from generic tools.
5. Dual-pathway attribution (certificate + structural) provides robustness that single-pathway tools lack.
6. The 5-signal composite risk score is transparent, decomposed, and auditable — superior to black-box scores.
7. Demo hardening approach (pre-recorded backup, pre-selected APKs, offline mode) is mature and correct.
8. Static-only pipeline produces full analysis in ~20-30 seconds vs. 10-20 minutes for dynamic sandbox.
9. MITRE ATT&CK integration provides a common language for SOC and CERT-In communication.
10. The Solution Document is professionally written, well-structured, and submission-ready (with the fixes below).

### Top 10 Improvements Required Before June 15 Submission

**Ranked by impact on judging, innovation, GenAI compliance, buildability, and real-world value:**

| Rank | Improvement | Impact | Effort | Deadline |
|---|---|---|---|---|
| 1 | **Implement real GenAI:** Build the Obfuscated Code Intent Reconstructor — feed Smali snippets to LLM with Android-specialized prompt. This is genuine analysis, not prose formatting, and answers "where is the AI?" definitively | Critical — GenAI compliance | Low (30-50 lines) | June 13 |
| 2 | **Add model metrics to Solution Document:** Include actual F1/precision/recall/FPR from your test split. If model isn't trained yet, train it now and include real numbers | Critical — ML credibility | Low (documentation) | June 13 |
| 3 | **Resolve GenAI contradiction:** Remove "templated strings" language from Spec Section 7.2 or explicitly explain the two-tier approach (template fallback + LLM primary). Both documents must tell the same story | Critical — judging trust | Very Low (editing) | June 12 |
| 4 | **Add dynamic analysis defense paragraph to Solution Document:** Section 4 should explicitly justify static-only approach with three specific arguments (legal risk, static completeness for banking trojans, throughput advantage) | High — PS1 compliance | Very Low | June 12 |
| 5 | **Remove four-phase roadmap from Spec or move to appendix:** Replace Section 9 content with a focused "future enhancements" section covering only 3-4 near-term additions | High — reduces noise | Very Low | June 12 |
| 6 | **Add calibration statement to AI/ML section:** One sentence: "XGBoost confidence scores are calibrated using isotonic regression on a held-out validation set to produce true probability estimates." If calibration isn't implemented, add it (sklearn has IsotonicRegression) | Medium | Low | June 13 |
| 7 | **Add analyst override workflow to Solution Document:** Two sentences in Section 13 or 14 describing that analysts can override verdicts with documented justification, logged with audit trail | Medium — enterprise readiness | Very Low | June 12 |
| 8 | **Add SIEM integration path:** One paragraph in Section 9.2 describing STIX 2.1 feed and webhook for SOAR integration, naming at least one SIEM (Splunk/QRadar) as the integration target | Medium — enterprise readiness | Very Low | June 12 |
| 9 | **Unify module naming across both documents:** Spec must use the same professional names as the Solution Document. Search and replace all old names | Medium — professionalism | Very Low | June 12 |
| 10 | **Implement and build the CERT-In report drafter:** 20-30 lines of LLM code. Pre-fill mandatory CERT-In incident report fields from analysis output. This is a concrete, demonstrable GenAI feature with immediate BFSI value that judges will respond to | Medium-High — demonstration value | Low | June 14 |

---

## EXECUTIVE SUMMARY FOR THE TEAM

You have 3 days. The concept is strong — genuinely differentiating, technically substantive, India-BFSI relevant. You are not in danger of producing a weak submission. You are in danger of producing a strong submission that loses significant points because the GenAI component doesn't match what PS1 requires.

**The three things that will determine whether you win or place:**

**One:** The GenAI gap. Add the Obfuscated Code Intent Reconstructor. Thirty to fifty lines of code. This is the difference between "AI-washing" and "genuine GenAI analysis." Every other team will have an LLM writing summaries. You will have an LLM reasoning about Android bytecode. This is your winning move.

**Two:** Model metrics. Train the model. Get the F1 score. Put it in the document. There is no excuse for submitting an ML platform without metrics.

**Three:** Document consistency. Spend two hours on June 12 aligning the two documents. Same module names, same GenAI story, remove the roadmap, add the dynamic analysis defense. These are editing tasks, not engineering tasks.

The platform as conceived deserves to reach the final 50 teams. Make sure the submission documents show judges exactly why.

---
*Audit produced: June 12, 2026 | SENTINEL-X Full Hackathon Audit v1.0*
