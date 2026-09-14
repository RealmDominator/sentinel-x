# SENTINEL-X — Final Project Requirements
## PSB Cybersecurity, Fraud & AI Hackathon 2026

### Synthesized from: Audit Report (primary), Solution Document, Complete Specification, Architecture Document, Constraints Document

---

## R1 — APK Ingestion and Unpacking Pipeline

The system shall accept a suspicious Android APK file (up to 100 MB) via drag-and-drop web interface or REST API endpoint. On receipt, the system shall immediately compute MD5, SHA1, and SHA256 hashes and check against an analysis cache. Previously analyzed samples shall return cached results without reprocessing. New samples shall be unpacked using apktool (Smali bytecode and XML resources) with jadx Java decompilation attempted and gracefully falling back to Smali-only analysis on decompilation failure. All processing shall be static — no code execution shall occur.

## R2 — Static Feature Analysis Engine (XGBoost + SHAP)

The system shall extract four feature categories from every APK: (1) binary permission presence vector across 300+ Android permissions, (2) API call family frequency across telephony, SMS, crypto, accessibility, and device admin groups, (3) opcode n-gram frequencies from disassembled Smali bytecode, (4) string entropy scores. An XGBoost classifier pre-trained on the AndroZoo/AMD Dataset and serialized as a joblib artifact shall produce a malicious/benign verdict with a confidence score. Confidence scores shall be calibrated using isotonic regression on a held-out validation set to ensure they represent true probabilities. SHAP TreeExplainer shall generate per-feature signed contribution values, rendered as a waterfall chart showing the top 10–15 contributing features. Model performance metrics (precision, recall, F1, false positive rate on held-out test set) shall be documented in the submission.

## R3 — Certificate Relationship Intelligence Module

The system shall extract the APK signing certificate from the META-INF directory, parse subject, issuer, serial number, SHA256 fingerprint, validity period, and self-signed flag, and query a pre-populated in-memory graph of 50–100 known malware certificate fingerprints sourced from MalwareBazaar and Koodous. The new certificate shall be inserted into the graph, and sharing relationships shall be surfaced to indicate family attribution and shared infrastructure. Results shall be rendered as an interactive D3.js force-directed graph in the analyst dashboard, with nodes color-coded by malware family.

## R4 — OTP Interception Detection Module

The system shall detect the high-precision permission triplet READ_SMS + RECEIVE_SMS + BIND_NOTIFICATION_LISTENER_SERVICE, identify overlay trigger patterns in Smali bytecode, flag fake Activity declarations targeting specific Indian bank package names, and detect accessibility event monitoring patterns targeting banking applications. Output shall be an OTP interception risk rating (HIGH / MEDIUM / LOW) with specific triggering signals listed and targeted bank package names identified.

## R5 — Malware Provenance Analysis Module (Builder Kit Fingerprinting)

The system shall identify the malware builder kit through analysis of package naming conventions, obfuscation style characterization (identifier length distribution, character set, class hierarchy depth), resource fingerprinting (icon hash, string table format, asset naming), and code skeleton pattern matching. Initial signature coverage shall include Cerberus, Anubis, SpyNote, and Drinik. When no known signature matches, the system shall flag the sample as "Unknown Builder" and document all structural anomalies detected, feeding the structural fingerprint to the GenAI Unknown Builder Characterizer for hypothesis generation. Output shall include builder kit name, confidence level (High / Medium / Low / Unknown), and a list of supporting evidence signals.

## R6 — Threat Technique Mapping Engine (MITRE ATT&CK)

The system shall map detected features to MITRE ATT&CK for Mobile techniques through a deterministic mapping table covering 15–20 technique IDs, using the mitreattack-python library for technique metadata. The structured technique list shall be passed to the GenAI Narrative Engine for attack chain narrative generation. The ATT&CK matrix shall be visualized in the dashboard with highlighted cells per detected technique. Every mapping shall include the specific evidence signal that triggered it, maintaining full analytical auditability.

## R7 — Fraud Interface Reconstruction Module

The system shall extract res/layout/*.xml files and drawable resources from the unpacked APK, identify the target bank from resource names, string constants, and hardcoded package names, and reconstruct the phishing overlay as an HTML/React component. A side-by-side comparison panel shall display the legitimate bank application interface alongside the malware overlay. For the hackathon build, reconstruction shall be pre-processed and hardcoded for 3–5 known Indian banking malware samples (SBI, HDFC, ICICI, Paytm overlays) sourced from public repositories.

## R8 — GenAI Narrative Engine (Core — Three Genuine Capabilities)

The system shall implement three distinct GenAI capabilities that perform genuine AI reasoning, not template substitution:

**R8.1 — Executive Summary and Attack Chain Narrative:** The GenAI engine shall receive structured JSON inputs (ML verdict, top SHAP features, ATT&CK techniques with evidence, builder kit identification, targeted banks, OTP interception risk, evasion level) and produce a plain-language executive summary paragraph for CISO audiences and an extended technical attack chain narrative. The system shall explicitly argue that LLM output is superior to templated prose because it adapts contextually to novel technique combinations that templates cannot anticipate.

**R8.2 — Obfuscated Code Intent Reconstructor:** The system shall feed decompiled but obfuscated Smali code snippets (selected by entropy score or jadx decompilation failure flag) to the LLM with a prompt specialized in Android bytecode semantics. The model shall infer the functional intent of obfuscated code blocks (e.g., "this loop decodes a C2 URL using XOR with key 0x42"). This is genuine GenAI analysis — the model reasons about code semantics, not formatting facts. This is the primary differentiator from AI-washing.

**R8.3 — Regulatory Incident Report Drafter (CERT-In):** The system shall auto-draft a CERT-In incident report in the exact format specified in CERT-In advisory templates, pre-filling all mandatory fields from structured analysis outputs. This has immediate, demonstrable BFSI compliance value.

**R8.4 — Fraud Playbook Generator:** Given all detected attack chain components, the system shall generate the complete step-by-step fraud playbook as the attacker designed it — from victim recruitment through fund extraction — in a format usable for evidence documentation by fraud investigators and law enforcement.

**R8.5 — Unknown Builder Kit Characterizer:** When FactoryPrint returns "Unknown Builder," the system shall feed the structural fingerprint to the LLM to characterize the likely origin, sophistication level, and possible developer indicators. Output shall be clearly labeled as hypothesis, not confirmed attribution, with confidence framing to prevent over-reliance.

All GenAI outputs shall be explicitly labeled as AI-generated in the intelligence report. Structured inputs on which each output is based shall be presented alongside generated text to enable verification. A fallback to template-only output shall activate if the LLM API is unavailable during demo.

## R9 — Risk Score Dashboard

The system shall compute a composite risk score (0–100) from five weighted signal categories: ML confidence (30%), banking fraud signal count (25%), attribution confidence (20%), evasion sophistication (15%), campaign activity (10%). Severity labels shall be assigned as CRITICAL (85–100), HIGH (65–84), MEDIUM (40–64), LOW (0–39). All five contributing sub-scores, weights, and weighted contributions shall be displayed alongside the composite score. Analysts shall be able to override the severity label with documented justification, maintaining human accountability. The dashboard shall display the final verdict prominently with a severity label.

## R10 — IOC Export

The system shall compile and export file hashes (MD5, SHA1, SHA256), extracted C2 domains and IP addresses, certificate SHA256 fingerprints, and malicious package names in JSON and CSV formats. These shall be directly usable for blocking at network perimeters and email gateways.

## R11 — PDF Intelligence Report

The system shall auto-generate a structured PDF and HTML report containing: Executive Summary, Technical Verdict with SHAP chart, Attribution Analysis (CertGraph + FactoryPrint), Attack Chain (ATT&CK matrix + narrative), Fraud UI Reconstruction, IOC Table, and Recommended Actions. All AI-generated content shall be visually distinguished from direct analytical findings.

## R12 — Dynamic Analysis Defense

The system shall include an explicit written defense in the submission document explaining why static-only analysis is sufficient for this use case: (a) execution of live malware presents legal and safety risks in non-sandboxed environments, (b) banking trojans are highly detectable through static signals (the specific permission triplet, overlay activity declarations, and hardcoded bank package targets leave unambiguous static evidence), (c) opcode n-gram analysis from Smali bytecode provides behavioral signal inference without execution, functioning as "behavioral static analysis," and (d) static analysis supports 10× higher throughput than sandbox-based dynamic analysis, enabling volume coverage appropriate for banking SOC environments.

## R13 — Model Performance Documentation

The submission document shall include a dedicated section reporting XGBoost model performance on a held-out test set: precision, recall, F1 score, and false positive rate. The dataset source, train/test split ratio, and class balance shall be documented. Confidence score calibration method (isotonic regression) shall be noted.

## R14 — Analyst Override Workflow

The system shall provide an analyst override mechanism allowing manual severity label adjustment with a required justification text field. Overrides shall be logged with analyst identifier and timestamp. Override history shall be visible in the case record.

## R15 — Demo Reliability

The system shall be hardened for demo reliability: a pre-recorded backup video shall be available, static screenshot fallbacks for all key outputs shall be prepared, and the frontend shall be capable of displaying pre-cached analysis results without live backend calls. Only pre-selected and pre-verified APKs shall be used during demonstration.
