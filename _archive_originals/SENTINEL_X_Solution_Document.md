PSB CYBERSECURITY, FRAUD & AI HACKATHON 2026

DFS | Ministry of Finance | IBA | Bank of India | IIT Hyderabad

ANDROID BANKING MALWARE

ATTRIBUTION INTELLIGENCE PLATFORM

Solution Approach Document

Problem Statement 1 — Automated Reverse Engineering, Static Analysis, and Risk Scoring of Fraudulent APKs and Malwares

CONFIDENTIAL — HACKATHON SUBMISSION

TABLE OF CONTENTS

1. Executive Summary

2. Problem Understanding

3. Existing Challenges

4. Proposed Solution

5. Solution Objectives

6. System Overview

7. Module Overview

8. Detailed Workflow

9. Technical Architecture

10. Data Flow

11. AI/ML Components

12. Risk Scoring Methodology

13. Explainability Approach

14. Security and Privacy Considerations

15. Scalability Considerations

16. Expected Outcomes

17. Innovation Highlights

18. Future Scope

19. Conclusion

1. EXECUTIVE SUMMARY

Android banking malware is the dominant mobile fraud vector threatening Indian financial infrastructure. Banks, CERTs, and SOC teams receive suspicious APKs daily—and the tools available to analyze them answer only a single question: is this file malicious? No existing platform answers the more critical questions: who built it, how the attack chain works, which Indian banks are targeted, and whether it belongs to an active threat campaign.

This submission proposes an Android Banking Malware Attribution Intelligence Platform that combines automated static analysis, explainable machine learning, certificate-based attribution, and MITRE ATT&CK technique mapping into a single coherent analysis pipeline. A submitted APK passes through nine sequential analysis stages and produces a structured intelligence report within seconds, covering the full range of forensic questions a banking security team needs answered.

The platform directly addresses Problem Statement 1 by delivering automated reverse engineering (apktool/jadx-based APK disassembly), static analysis across multiple analytical dimensions, and a composite risk score grounded in weighted ML confidence, attribution evidence, evasion sophistication, and fraud signal density. A Generative AI module transforms technical analysis outputs into plain-language executive narratives suitable for CISO-level reporting. The solution targets CERT-In analysts, BFSI SOC teams, and mobile fraud investigators as primary users.

All core technical components are buildable within the available development window. The machine learning model is pre-trained on publicly available malware datasets and ships as a serialized artifact. No live external API dependencies exist in the critical analysis path, ensuring demo reliability. The platform has been scoped to prioritize demonstrable depth over feature breadth.

2. PROBLEM UNDERSTANDING

2.1 The Fraud Mechanism

Banking malware on Android operates through a well-documented attack chain. A victim installs a trojanized application—typically delivered via SMS phishing, fake app stores, or social engineering. The malware requests accessibility service permissions and notification listener access. Once granted, it waits silently until the victim opens a legitimate banking application, then overlays a fake login screen that captures credentials. Simultaneously, it intercepts all incoming SMS messages, stealing the one-time passwords that would otherwise prevent unauthorized access. The attacker, operating from a command-and-control server, receives the credential pair and completes the fraudulent transaction before the victim suspects anything is wrong.

This attack model is not theoretical. Malware families including Cerberus, Anubis, BankBot, Drinik, and SOVA have all executed this pattern against Indian banking customers. Drinik specifically targeted customers of 18 Indian banks including SBI, HDFC, ICICI, and Axis Bank. The financial exposure is measurable in hundreds of crores of fraudulent transactions annually.

2.2 The Gap in Existing Tools

Tools available to banking security teams today address only detection—the binary malicious/benign classification question. VirusTotal aggregates antivirus signatures. MobSF performs static and dynamic analysis and produces a risk score. Neither provides the attribution, campaign linkage, or explainability that transforms a detection event into an actionable intelligence product.

A BFSI SOC analyst who receives a positive detection from an existing scanner faces the following unanswered questions: Why was this flagged—which specific features triggered the verdict? Which known malware family or campaign does this belong to? Which banks are being targeted? What does the fraud UI look like from the victim's perspective? Has this infrastructure been seen before? How should this finding be communicated to bank management and CERT-In?

None of these questions are answered by existing tools. Each requires a separate specialist, a separate tool, and hours of manual work. The result is that most detection events are handled as isolated incidents rather than as intelligence products that could protect many customers simultaneously.

2.3 Indian Banking Context

The Indian banking sector presents a specific threat profile that generic malware tools are not calibrated for. The dominant fraud vectors target UPI, IMPS, and net banking through overlay attacks impersonating SBI YONO, HDFC MobileBanking, ICICI iMobile Pay, and Paytm. OTP interception via SMS is the primary authentication bypass mechanism, as Indian banks rely heavily on SMS-based two-factor authentication. CERT-In has published multiple advisories specifically about Android banking trojans targeting Indian financial customers.

An effective solution in this context must speak the language of Indian banking operations: it must name the specific banks targeted, identify the OTP interception mechanism, reference CERT-In reporting requirements, and produce outputs that a non-technical bank operations team can act upon.

3. EXISTING CHALLENGES

3.1 Analysis Tool Fragmentation

A comprehensive malware investigation today requires VirusTotal for signature lookup, MobSF for static analysis, jadx or apktool for code review, Koodous for certificate lookup, MITRE ATT&CK Navigator for technique mapping, and a separate reporting tool for documentation. Each tool has a separate interface, output format, and skill requirement. Integrating findings across these tools into a coherent intelligence product requires experienced analysts who are in short supply at most banking security teams.

3.2 Absence of Explainability

Existing ML-based detectors produce binary verdicts without explanation. In a banking compliance environment, a verdict of 'malicious with 94% confidence' is insufficient for escalation, regulatory reporting, or customer communication. The inability to explain why a verdict was reached undermines trust in automated systems and forces manual review of every positive detection, eliminating the efficiency gain that automated analysis is supposed to provide.

3.3 No Attribution Capability

Knowing that a file is malicious answers the immediate question, but does not help the security team understand whether this is a new threat or a variant of a known campaign, whether the same attacker has been seen before, or whether blocking this sample's infrastructure will disrupt other related attacks. Attribution requires cross-referencing certificate fingerprints, code structure, and configuration patterns across a corpus of known samples—work that cannot be done manually at the volume banks receive.

3.4 Communication Gap

Technical malware analysis output—permission vectors, SHAP values, Smali bytecode snippets—is inaccessible to the bank management, legal teams, and fraud operations staff who need to act on it. Translating a technical finding into an executive-readable report currently requires a senior analyst to write a custom summary for each incident. This creates a bottleneck that delays response and limits the number of incidents that receive proper documentation.

3.5 Victim Perspective Missing

No available tool reconstructs the fraud UI from the attacker's APK. Security teams know intellectually that an overlay attack is occurring, but cannot show management, regulators, or law enforcement what the victim actually saw. This gap weakens the evidence chain in fraud investigations and limits the ability to produce customer advisories with accurate visual warnings.

4. PROPOSED SOLUTION

The proposed platform is an Android Banking Malware Attribution Intelligence Platform that accepts a suspicious APK as input and produces a complete, structured intelligence product as output. It does not replace the analyst—it eliminates the repetitive extraction and correlation work that currently consumes most of the analyst's time, allowing them to focus on judgment and response.

The platform executes nine analytical stages in a sequential pipeline with internal parallelization. Static feature extraction, certificate relationship analysis, builder kit attribution, and fraud signal detection run simultaneously across four parallel streams in Stage 2. Results are assembled into a composite risk score, a MITRE ATT&CK technique matrix, a fraud UI reconstruction, and a PDF intelligence report.

A Generative AI narrative engine processes all structured analysis outputs and produces two artifacts: an executive summary paragraph in plain language for CISO and management audiences, and a complete attack chain narrative mapping the detected techniques to a coherent description of how the malware operates. This component directly addresses the communication gap identified in Section 3 and satisfies the Generative AI requirement of Problem Statement 1.

The entire analysis pipeline operates on static features extracted from the APK—no dynamic execution, no sandboxing, no live network calls in the critical path. This design choice maximizes reliability in demo and production environments, eliminates the legal risks of executing malware samples, and allows analysis to complete in seconds rather than minutes.

5. SOLUTION OBJECTIVES

Automate the complete APK analysis lifecycle from ingestion to intelligence report, reducing analyst time from 4–8 hours to under 60 seconds per sample.

Provide explainable malware verdicts through SHAP-based feature attribution, enabling analysts to justify findings without manual code review.

Attribute suspicious samples to known malware families and builder kits through certificate graph analysis and structural fingerprinting.

Map all detected indicators to MITRE ATT&CK for Mobile techniques, producing a standardized attack chain description compatible with banking SOC workflows.

Reconstruct the fraud overlay UI to produce visual evidence of the attack from the victim's perspective, supporting fraud investigations and customer communications.

Generate plain-language executive summaries using Generative AI, enabling direct communication of technical findings to non-technical stakeholders.

Export Indicators of Compromise in standard formats for immediate operationalization at network perimeters and email gateways.

Provide a risk scoring framework that combines ML confidence, attribution evidence, fraud signal density, and evasion sophistication into a single, defensible severity rating.

6. SYSTEM OVERVIEW

The platform operates as a nine-stage analysis pipeline built on a Python/FastAPI backend serving a React-based analyst dashboard. An APK submitted through the web interface or REST API is processed through the following stages:

The backend exposes a REST API with WebSocket support for real-time progress reporting. The frontend is a single-page React application with D3.js visualizations for the certificate relationship graph and campaign timeline. All analysis outputs are aggregated into a downloadable PDF intelligence report.

7. MODULE OVERVIEW

The platform is composed of nine functional modules, each addressing a distinct analytical layer. All modules operate on static features extracted from the APK in Stage 1 and contribute outputs to the composite intelligence report.

7.1 Static Feature Analysis Engine

The primary detection engine extracts four categories of static features from every APK: a binary presence/absence permission vector encoding 300+ Android permissions, API call family groupings from dangerous telephony, SMS, crypto, accessibility, and device admin categories, opcode n-gram frequencies derived from disassembled Smali bytecode, and string entropy scores detecting encoded payloads and hardcoded C2 identifiers. An XGBoost classifier trained on publicly available malware datasets (AndroZoo/AMD Dataset) produces a malicious/benign verdict with a calibrated confidence score. SHAP post-hoc explanation generates a per-feature importance decomposition, rendering each contributing signal as a signed contribution to the final verdict.

7.2 Certificate Relationship Intelligence Module

Malware developers routinely reuse signing certificates across campaigns and builder kit deployments. This module extracts the APK signing certificate from the META-INF directory, parses subject, issuer, serial number, SHA256 fingerprint, and validity period, and queries a pre-populated graph of 50–100 known malware certificate fingerprints sourced from MalwareBazaar and Koodous. New APK certificates are inserted into the live graph, and certificate sharing relationships surface family attribution and shared infrastructure. Results are rendered as an interactive D3.js force-directed graph in the analyst dashboard.

7.3 Malware Provenance Analysis Module

Builder kit fingerprinting answers the attribution question that no existing scanner addresses: who built this malware, and using which toolkit? The module identifies the builder kit through a combination of package naming convention analysis, obfuscation style characterization (identifier length distribution, character set, class hierarchy depth), resource fingerprinting (icon hash, string table format, asset naming), and code skeleton pattern matching against known builder signatures. Signature coverage currently includes Cerberus, Anubis, SpyNote, and Drinik builder patterns, with unknown builder structures flagged and structurally documented for analyst review.

7.4 Threat Technique Mapping Engine

Extracted features are mapped to MITRE ATT&CK for Mobile techniques through a deterministic mapping table covering 15–20 technique IDs in the initial build. The mitreattack-python library supplies technique metadata and matrix structure. Matched techniques are assembled into a human-readable attack chain narrative through a Generative AI component that takes the structured technique list as input and produces a coherent paragraph-form description of the complete attack lifecycle. This approach combines the precision of rule-based technique detection with the communication clarity of AI-generated natural language.

7.5 Fraud Interface Reconstruction Module

The overlay reconstruction module extracts res/layout/*.xml files and drawable resources from the unpacked APK, identifies the target bank from resource names, string constants, and hardcoded package names, and reconstructs the phishing overlay as a rendered HTML/React component. The analyst dashboard presents a side-by-side comparison of the legitimate bank application interface and the malware overlay, providing visual evidence of the fraud mechanism. For the initial build, reconstruction is pre-processed for 3–5 known Indian banking malware families sourced from public repositories.

7.6 OTP Interception Detection Module

OTP theft via SMS interception is the dominant banking fraud authentication bypass in India. This module detects the specific permission triplet of READ_SMS, RECEIVE_SMS, and BIND_NOTIFICATION_LISTENER_SERVICE, identifies overlay trigger patterns in Smali bytecode, and flags fake activity declarations targeting specific bank package names. Output is an OTP interception risk rating (HIGH/MEDIUM/LOW) with the specific triggering signals and targeted bank package names listed.

8. DETAILED WORKFLOW

Step 1 — APK Ingestion

An analyst submits a suspicious APK through the web dashboard drag-and-drop interface or REST API endpoint. The platform computes MD5, SHA1, and SHA256 hashes immediately on receipt and checks against an analysis cache. Previously analyzed samples return cached results instantly, eliminating redundant processing. For new samples, apktool decompiles the APK to Smali bytecode and extracts all XML resources; jadx attempts Java source reconstruction with graceful fallback to Smali-only analysis if decompilation fails due to obfuscation.

Step 2 — Parallel Feature Extraction

Four extraction streams execute simultaneously via Python concurrent.futures.ThreadPoolExecutor. Stream A extracts permission vectors, API call signatures, opcode n-grams, and string entropy metrics for the ML engine. Stream B extracts and parses the APK signing certificate for graph insertion. Stream C performs structural code analysis and resource fingerprinting for builder kit identification, and extracts C2 URL patterns and configuration structures. Stream D analyzes permission combinations for OTP theft signals and scans Smali bytecode for anti-analysis patterns.

Step 3 — ML Classification and Explanation

The pre-serialized XGBoost model loads from joblib artifact and runs inference on the combined feature vector. SHAP TreeExplainer computes per-feature Shapley values. The waterfall chart shows the top contributing features with direction (toward malicious or benign) and magnitude, enabling analysts to understand and audit the verdict without examining raw feature values.

Step 4 — Graph Query and Attribution

The extracted certificate fingerprint is queried against the in-memory NetworkX graph pre-populated with known malware certificates. Matching certificates surface family attribution and shared infrastructure connections. Builder kit signature matching is applied to structural analysis outputs, producing a kit identification result with confidence level and supporting evidence signals.

Step 5 — ATT&CK Mapping and Narrative Generation

The feature-to-technique mapping table converts detection results to MITRE ATT&CK for Mobile technique IDs. The Generative AI module receives the structured list of matched techniques, the builder kit identification, targeted bank names, and OTP interception status, and generates two outputs: a concise executive summary paragraph and an extended technical attack chain narrative. This ensures that every report contains accurate, contextually appropriate natural language regardless of analyst writing capacity.

Step 6 — Risk Scoring and Report Assembly

The composite risk score is computed from five weighted signal categories. The PDF/HTML intelligence report is assembled from all module outputs, with sections corresponding to the analysis stages. The IOC table is compiled from file hashes, extracted C2 domains, certificate fingerprints, and malicious package names. The dashboard is populated with all interactive visualization components.

9. TECHNICAL ARCHITECTURE

9.1 Technology Stack

9.2 Deployment Architecture

The platform deploys as two containers: a Python/FastAPI backend container handling all analysis pipeline stages, and a React frontend container serving the analyst dashboard. The backend exposes REST endpoints for APK submission and result retrieval, and a WebSocket endpoint for real-time progress events. The analysis pipeline stores all extracted artifacts and results in a local SQLite database for the hackathon build, with a PostgreSQL migration path for production deployment.

Pre-trained model artifacts, certificate corpus, and builder kit signature database are bundled as static assets within the backend container, ensuring zero external dependency in the critical analysis path. All network calls to external services (CERT-In reporting, VirusTotal lookup) are optional enrichment steps, not required for core functionality.

10. DATA FLOW

10.1 Input

Input: A suspicious Android APK file (2MB–50MB typical). The APK is received as a multipart form upload and stored with a UUID-based filename in a local working directory. File fingerprints are computed immediately and serve as the primary cache and deduplication key.

10.2 Extracted Artifacts

apktool extracts: AndroidManifest.xml (permission declarations, component registrations), Smali bytecode files (all application code in disassembled form), res/ directory (layout XML files, drawable resources, string tables), assets/ directory (embedded configuration files, scripts, payload containers), and META-INF/ directory (signing certificates and manifest checksums).

jadx produces: Approximate Java source reconstruction from Dalvik bytecode classes. Fallback to Smali-only analysis is triggered automatically when decompilation fails due to obfuscation or unsupported bytecode patterns.

10.3 Feature Vectors

From extracted artifacts, the following feature structures are produced and passed to downstream modules: binary permission presence vector (300+ dimensions), API call family frequency vector (telephony, SMS, crypto, accessibility, device admin groups), opcode n-gram frequency distribution (extracted from Smali), string entropy histogram, certificate field set (subject, issuer, serial, SHA256 fingerprint, validity period, self-signed flag), structural fingerprint set (package naming pattern, obfuscation style metrics, class hierarchy depth, resource identifier patterns), regex-extracted C2 URL candidates and token strings.

10.4 Output Artifacts

The pipeline produces: malware verdict with confidence score and SHAP waterfall chart data, certificate graph subgraph JSON for D3.js rendering, builder kit identification result with evidence list, MITRE ATT&CK technique ID set with supporting evidence mappings, overlay UI HTML component (for known samples), AI-generated executive summary and attack chain narrative, composite risk score with severity label and contributing signal breakdown, IOC bundle (hashes, domains, certificate fingerprints, package names), and structured intelligence report (PDF and HTML).

11. AI / ML COMPONENTS

11.1 Discriminative ML — Malware Classification

The malware classifier is an XGBoost gradient boosting model trained on a labeled dataset of benign and malicious Android APK samples sourced from AndroZoo and the AMD Malware Dataset. The feature vector combines static permission analysis, API usage patterns, opcode behavioral fingerprints, and string characteristics into a high-dimensional representation that captures the behavioral intent of an application without requiring execution.

Training is completed offline prior to deployment. The serialized model loads from a joblib artifact at platform startup, with inference latency under 100 milliseconds per sample on commodity hardware. The model is evaluated on a held-out test set with precision, recall, F1, and false positive rate reported in the technical documentation.

11.2 Explainability — SHAP Analysis

SHAP (SHapley Additive exPlanations) provides post-hoc explanation for each individual prediction. The TreeExplainer implementation computes exact Shapley values for tree-based models efficiently. Output is a per-feature signed contribution vector: features pushing the prediction toward malicious carry positive values; features pushing toward benign carry negative values. The waterfall chart visualization renders the top 10–15 contributing features sorted by absolute magnitude, showing precisely which signals drove the verdict.

This explainability layer is not decorative. It enables analysts to audit predictions that conflict with prior knowledge, serves as a training tool for junior analysts learning which features indicate which malware behaviors, and satisfies regulatory requirements for explainable automated decision-making in financial security contexts.

11.3 Generative AI — Narrative Intelligence Engine

A large language model API integration serves as the narrative intelligence engine. It receives structured JSON inputs from all upstream modules: the ML verdict and top SHAP features, matched ATT&CK technique IDs with evidence, builder kit identification result, targeted bank package names, OTP interception risk level, and evasion sophistication rating. The model is prompted with a specific analytical persona and output format specification, producing two outputs per analysis.

The executive summary is a single paragraph in plain language appropriate for CISO and senior management audiences, naming the threat family, severity level, targeted institutions, and recommended immediate action. The technical attack chain narrative is an extended paragraph describing the complete attack lifecycle from installation through credential theft and exfiltration, in the voice of an experienced threat analyst rather than an automated system.

This component addresses the critical communication gap in existing tools. The structured inputs ensure factual accuracy; the language model contributes narrative coherence and professional tone. All AI-generated content is explicitly labeled in the report, and the underlying structured data on which it is based is always presented alongside the generated text.

11.4 Graph Analytics — Certificate and Campaign Clustering

Certificate relationship analysis uses a NetworkX undirected graph where nodes represent APK samples, certificates, developer identities, and campaign clusters. Edges represent signing relationships, shared certificates, and campaign membership. Pre-populated with 50–100 known malware certificate fingerprints, the graph enables immediate family attribution for samples sharing known signer infrastructure. PageRank-style centrality analysis identifies high-connectivity certificate nodes that indicate prolific builder kit operators.

12. RISK SCORING METHODOLOGY

The composite risk score aggregates evidence from five analytical dimensions into a single 0–100 score with a four-tier severity label. The weighting reflects the relative diagnostic value of each signal category for BFSI fraud assessment.

12.1 Severity Label Assignment

The scoring formula is transparent and auditable. All five contributing scores and their weighted contributions are displayed alongside the composite score in the analyst dashboard and included in the PDF report. Analysts can override severity labels with documented justification, maintaining human accountability in the decision chain.

13. EXPLAINABILITY APPROACH

13.1 Feature-Level Transparency

Every malware verdict produced by the platform is accompanied by a SHAP waterfall chart that identifies the specific features contributing to the decision, their direction of influence, and their magnitude. An analyst reading the output understands not only the verdict but which features produced it and how strongly. This eliminates the black-box criticism that undermines trust in automated classification systems in regulated financial environments.

13.2 Evidence-Linked ATT&CK Mappings

Every MITRE ATT&CK technique mapping is linked to the specific evidence signal that triggered it. The technique table in the intelligence report lists the technique ID, technique name, and the extracted feature or indicator that justified the mapping. An analyst can trace any element of the attack chain narrative back to a concrete artifact from the APK analysis, maintaining full analytical auditability.

13.3 Builder Kit Attribution Evidence

Builder kit identification outputs include the complete list of matching signals that contributed to the attribution—specific package naming patterns, obfuscation style characteristics, resource fingerprints, and code skeleton matches. Attribution confidence levels (High/Medium/Low/Unknown) are calibrated to the number and quality of matching signals, preventing overconfident attribution from sparse evidence.

13.4 Risk Score Decomposition

The composite risk score is presented as a decomposed breakdown showing each of the five contributing dimensions, the raw sub-score for each, its weight, and the weighted contribution to the composite. This decomposition enables analysts to understand why a sample received a particular severity label and to evaluate whether the contributing factors are consistent with their domain knowledge about the sample.

13.5 AI-Generated Content Labeling

All content generated by the AI narrative engine is clearly labeled in the intelligence report as AI-generated and distinguished from direct analytical findings. The structured inputs provided to the model are documented alongside the generated output, enabling verification of factual claims and identification of any generation errors.

14. SECURITY AND PRIVACY CONSIDERATIONS

14.1 Safe Processing of Malicious Files

APK files submitted to the platform are malicious by definition. All processing is static—no code execution occurs. apktool and jadx operate as disassemblers that parse file structures without executing bytecode. All extracted artifacts are written to isolated temporary directories with read-only permissions after extraction. Uploaded APKs and extracted artifacts are purged after analysis completion in accordance with configurable retention policies.

File size limits (configurable, default 100MB) and ZIP bomb detection are applied at ingestion to prevent resource exhaustion. MIME type validation ensures only valid APK/ZIP structures enter the pipeline.

14.2 Input Validation and API Security

All API endpoints enforce authenticated access through token-based authentication. File upload endpoints validate MIME type, file extension, and ZIP structure integrity before any processing begins. API rate limiting prevents automated bulk submission that could exhaust analysis resources.

14.3 Data Handling and Retention

Submitted APK files may contain embedded Personally Identifiable Information in hardcoded credentials, configuration files, or exfiltration targets. The platform treats all submitted samples as sensitive and does not expose raw APK content through any API endpoint. Analysis results stored in the database are logically isolated per submission session. Compliance with India's DPDP Act requirements is addressed through configurable data retention periods and audit logging of all analysis operations.

14.4 Audit Logging

All platform operations are logged with timestamp, analyst identity, sample hash, and action taken. Audit logs support forensic investigation of platform usage and compliance reporting requirements. Log entries are append-only and stored separately from the analysis database.

15. SCALABILITY CONSIDERATIONS

The platform is scoped for single-institution deployment handling tens to low hundreds of APK analyses per day—the realistic volume for a banking CERT or SOC team. The current architecture is designed to be demonstrable and correct at this scale. The following scalability paths are identified for production deployment.

15.1 Analysis Pipeline Parallelism

The four parallel extraction streams in Stage 2 currently use Python ThreadPoolExecutor, providing parallelism within a single process. For higher throughput, these streams can be migrated to Celery task queues with a Redis broker, distributing analysis work across multiple workers without changes to the pipeline logic.

15.2 Graph Database Migration

NetworkX provides in-memory graph analytics suitable for a corpus of up to approximately 10,000 samples. Production deployment with a growing sample corpus requires migration to Neo4j, a graph database with identical query semantics. The application layer abstracts all graph queries through a repository interface, enabling this migration without changes to analysis logic.

15.3 Model Versioning

The XGBoost model artifact is versioned and loaded from a configurable path. Re-training with an updated dataset requires only replacing the artifact file and restarting the backend service. Model performance metrics are logged at load time to support version comparison.

16. EXPECTED OUTCOMES

16.1 Operational Outcomes for BFSI Security Teams

Analysis time per suspicious APK reduced from 4–8 hours of manual investigation to under 60 seconds of automated pipeline execution.

Complete structured intelligence report available for every analyzed sample, enabling consistent documentation of incidents regardless of analyst experience level.

IOC packages ready for immediate operationalization at network perimeters, email gateways, and mobile threat management platforms within minutes of sample receipt.

Attribution to known campaigns enables security teams to search internal fraud logs for activity matching known IOC patterns, retrospectively identifying fraud that pre-dates the sample's analysis.

16.2 Analyst Capability Outcomes

SHAP feature attribution serves as a training tool for junior analysts, accelerating their development of intuition about which APK characteristics indicate specific threat behaviors.

MITRE ATT&CK technique mapping provides a common language for communicating threat details across teams and institutions, enabling consistent incident classification and trend analysis.

AI-generated executive summaries enable analysts to communicate findings to senior management without specialist writing support, increasing the fraction of incidents that receive proper documentation.

16.3 Regulatory and Compliance Outcomes

Structured intelligence reports provide the documentation baseline required for CERT-In incident reporting, with IOC tables and technical verdicts formatted for regulatory submission.

Audit logging of all platform operations supports RBI examination of cybersecurity incident response procedures.

STIX 2.1 formatted IOC export enables participation in banking ISAC information sharing programs.

17. INNOVATION HIGHLIGHTS

17.1 Builder Kit Attribution

No publicly available banking malware analysis tool identifies the specific builder kit used to create an analyzed sample. Existing tools detect malware behavior but treat each sample as an isolated artifact. The Malware Provenance Analysis Module's structural fingerprinting approach treats APKs as manufactured products with traceable factory origins—an analogy that is technically accurate, since commodity Android malware is genuinely produced using builder kits sold on dark web markets. Connecting a new sample to a known builder kit immediately places it in a wider threat context and enables proactive intelligence about other samples from the same factory.

17.2 Combined Attribution Pipeline

The combination of certificate relationship analysis and builder kit fingerprinting provides two independent attribution pathways for every sample. Samples that evade certificate attribution (by using a fresh certificate) may still be attributed through structural fingerprinting, and vice versa. The dual-pathway approach significantly improves attribution coverage compared to either technique alone—a design choice that reflects real-world attacker behavior, where threat actors rotate certificates but rarely rebuild their entire toolkit.

17.3 Fraud UI Forensic Reconstruction

Reconstructing the exact phishing overlay that a fraud victim encountered transforms abstract technical analysis into visual evidence. This capability serves three distinct functions: it provides compelling visual proof for fraud investigations and law enforcement referrals, it enables the production of accurate customer advisories showing the specific fake screen to watch for, and it demonstrates the direct customer harm pathway in a way that resonates with non-technical audiences including bank management and regulators.

17.4 Integrated Generative AI Narrative Layer

The integration of a Generative AI narrative engine as a structured post-processing stage—rather than as a free-form analysis assistant—represents a responsible and reliable approach to AI-augmented security analysis. By providing the model with structured, verified analytical inputs rather than raw APK bytes, the system ensures factual accuracy while leveraging the model's ability to produce clear, contextually appropriate communication. This architecture avoids the hallucination risks that accompany unconstrained LLM analysis of security artifacts.

17.5 Indian Banking Threat Calibration

The platform is calibrated for the Indian BFSI threat landscape specifically: target bank detection covers SBI, HDFC, ICICI, Axis, and Paytm; OTP interception detection is weighted for India's SMS-based two-factor authentication model; campaign coverage includes Drinik and other India-specific malware families; and intelligence report outputs reference CERT-In reporting requirements and RBI incident notification obligations. This domain specificity distinguishes the platform from generic malware analysis tools.

18. FUTURE SCOPE

18.1 Live Infrastructure Intelligence Integration

Production deployment would integrate optional OSINT enrichment through VirusTotal, Shodan, and PassiveDNS for live resolution of extracted C2 indicators. This would complement the current static analysis with current network-layer intelligence about attacker infrastructure, including recent IP assignments, co-hosted domains, and ASN ownership data.

18.2 Production Graph Database and Corpus Accumulation

Migrating to a Neo4j production graph and accumulating a growing sample corpus over 6–12 months would enable meaningful campaign timeline analysis, cross-institutional pattern detection, and early warning capability as new variants of tracked families appear. The current in-memory graph supports the analytical logic; corpus scale is the variable that determines intelligence value.

18.3 ML-Based Overlay Clustering

The current overlay reconstruction handles known samples. A production-scale ML clustering approach would group phishing overlay templates across hundreds of samples, enabling automatic identification of new overlay campaigns without pre-knowledge of specific samples. This capability requires a corpus of reconstructed overlays that can only be built through sustained platform operation.

18.4 CERT-In and Banking ISAC Integration

Federated intelligence sharing between participating institutions through a CERT-In connected API would enable coordinated response across the banking sector. An institution that analyzes a novel threat could automatically notify peer institutions through standardized STIX 2.1 formatted intelligence bundles, compressing the time between first detection and sector-wide protection.

18.5 Regulatory Compliance Automation

Automated generation of CERT-In incident notification documents, RBI cybersecurity incident reports, and DPDP Act data breach notifications from platform analysis outputs would significantly reduce the compliance documentation burden on banking security teams and improve reporting accuracy and timeliness.

19. CONCLUSION

Android banking malware represents a concrete, measurable threat to Indian banking customers and institutions. The tools available to defend against it are fragmented, non-explainable, and calibrated for generic threat detection rather than BFSI-specific attribution and response. The proposed Android Banking Malware Attribution Intelligence Platform addresses this gap through a coherent analysis pipeline that combines explainable machine learning, certificate-based attribution, builder kit fingerprinting, MITRE ATT&CK technique mapping, fraud UI reconstruction, and AI-generated intelligence narrative.

Every design decision in this platform is oriented toward BFSI applicability and operational realism. The ML component is explainable by design, not as an afterthought. The attribution methodology reflects documented real-world attacker behaviors—certificate reuse, builder kit tooling, campaign infrastructure sharing. The output format speaks to the operational needs of CERT-In analysts, SOC teams, fraud investigators, and bank management in a single coherent document. The Generative AI component serves a specific, bounded function that leverages its genuine capability—natural language synthesis from structured inputs—while avoiding the reliability risks of unconstrained AI analysis.

The platform is technically buildable within the available development window, with all critical path components relying on well-established libraries and pre-processable training and corpus data. The architecture supports graceful degradation when individual components encounter obfuscated or unusual samples, ensuring that partial analysis results are always available even when complete analysis is not possible.

The result is a platform that converts a suspicious APK from a static binary artifact into an actionable, attributable, documented intelligence product—in the time it takes to open a ticket.

END OF SOLUTION APPROACH DOCUMENT