SENTINEL-X

Android Banking Malware Attribution Intelligence Platform

Complete Idea & Technical Specification Document

"Drop an APK. Know not just IF it's malware—know WHO built it, HOW it works, WHERE the campaign started, and WHAT the victim sees."

1. Product Identity

1.1 Product Name

SENTINEL-X

1.2 One-Line Pitch

1.3 Elevator Pitch

Banking malware on Android defrauds millions every year. Current solutions answer only one question: is this malicious? SENTINEL-X answers five.

Upload any suspicious APK to the platform and within seconds you receive:

An explainable ML verdict with SHAP feature analysis showing exactly why the file was flagged

A certificate graph revealing which other malware families share the same signing infrastructure

A factory fingerprint identifying the builder kit used to create the APK

An automated MITRE ATT&CK narrative of the complete attack chain

A visual reconstruction of the exact phishing overlay the fraud victim would see

SENTINEL-X is not a scanner. It is a complete threat intelligence platform that transforms raw APK bytes into actionable, attributable, documented intelligence—in the time it takes to open a ticket.

1.4 Problem Statement

Android banking malware causes an estimated $12–50 billion in fraud losses annually. Mobile security teams at banks, financial institutions, and CERTs receive suspicious APKs daily with no efficient way to accomplish the following:

Explain why a file is malicious to non-technical stakeholders

Attribute a sample to a known campaign or threat actor

Understand the attack flow in MITRE ATT&CK terms

Visualize what the fraud UI looks like from the victim's perspective

Connect a sample to other active campaigns through shared infrastructure

Existing tools such as VirusTotal and MobSF answer the first question at best. None answer all five together.

1.5 Target Users

Primary Users

Mobile Threat Analysts at banking CISO teams (SBI, HDFC, ICICI, Axis, Paytm)

CERT-In and RBI cybersecurity incident response teams

BFSI SOC analysts investigating active customer fraud complaints

Bug bounty researchers and independent mobile malware researchers

Secondary Users

Fintech app security teams validating third-party APKs before integration

Law enforcement digital forensics units

Academic malware research teams requiring structured attribution data

1.6 Core Value Proposition

SENTINEL-X compresses 4 to 8 hours of manual malware analysis into a 30-second automated intelligence brief. It replaces five separate specialist tools with one coherent platform. It communicates in MITRE ATT&CK language, not raw hexadecimal.

2. Module Overview

SENTINEL-X is composed of nine integrated modules. Each module addresses a distinct analytical layer. Together they form a complete intelligence pipeline.

3. Module Deep-Dive

3.1 PermFlow XAI — Explainable Malware Detection

Purpose: Classify an APK as malicious or benign and explain every contributing signal.

Method: Static feature extraction followed by XGBoost classification with SHAP post-hoc explanation.

Feature Extraction

Permission vector: 300+ Android permissions encoded as a binary presence/absence feature vector

API call families: dangerous API groups from telephony, SMS, crypto, accessibility, and device admin categories

Opcode n-gram frequency: extracted from disassembled Smali bytecode, capturing behavioral fingerprints

String entropy analysis: detects base64-encoded payloads, hardcoded C2 URLs, and encrypted strings

Classification

Model: XGBoost classifier

Training dataset: AndroZoo or AMD Dataset subset (pre-trained offline before hackathon; inference only at demo time)

Serialization: joblib for fast reload

Explainability

SHAP (SHapley Additive exPlanations) library generates per-feature importance scores

Output: SHAP waterfall chart visualizing which features pushed the prediction toward malicious

Example output: READ_SMS (+0.34), BIND_ACCESSIBILITY_SERVICE (+0.28), Self-signed certificate (+0.19)

Output: Malicious / Benign verdict with confidence score and SHAP feature chart.

3.2 CertGraph — Certificate Relationship Graph

Purpose: Attribute a suspicious APK to known malware families through certificate signer reuse.

Insight: Certificate signer reuse across campaigns is a documented real-world attacker behavior. Cerberus, Anubis, and BankBot families have all exhibited this pattern.

Certificate Extraction

Extract signing certificate from META-INF/*.RSA inside the APK ZIP structure

Parse fields: subject, issuer, serial number, SHA256 fingerprint, validity period, self-signed flag

Graph Construction

Nodes: APK samples, certificates, developer keys, package names

Edges: SIGNED_BY, SHARES_CERT_WITH, SAME_CAMPAIGN_AS

Pre-populate with 50 to 100 known malware certificate fingerprints from Koodous and MalwareBazaar

New APK's certificate is inserted into the live graph at analysis time

Graph Queries

Which known malware families share this signer?

Is this certificate self-signed? Does it masquerade as a legitimate app certificate?

What is the first-seen date for this certificate across the corpus?

Visualization: D3.js force-directed graph rendered in the React dashboard. Nodes are color-coded by malware family.

3.3 FactoryPrint — Builder Kit Fingerprinting

Purpose: Identify which malware builder kit was used to create the APK and link it to a known development origin.

Key Question: This module answers the question no existing scanner answers: who built this malware?

Fingerprinting Signals

Package naming conventions: prefix patterns, depth structure, separator styles

Obfuscation style: identifier length distribution, character set used, class hierarchy depth

Resource fingerprinting: icon file hash, string table format, asset naming conventions

Code skeleton: characteristic class names, method signatures, and interface patterns unique to known builder kits

Known Builder Kit Signatures

Cerberus builder: characteristic package prefix, accessibility service structure, overlay manager class

Anubis builder: SMS receiver pattern, keylogger class structure, string encoding style

SpyNote builder: remote access architecture, screen capture service pattern

Custom/unknown builder: flagged when no known signature matches; structural anomalies reported

Output: Builder kit name and version estimate (e.g., "Cerberus v2"), confidence level, and matching signal list.

3.4 AttackChainRecon — MITRE ATT&CK Mapping

Purpose: Map detected indicators to MITRE ATT&CK for Mobile techniques and auto-generate a human-readable attack narrative.

Technique Mappings (Examples)

READ_SMS + RECEIVE_SMS + overlay detected → T1412 (Capture SMS Messages)

BIND_ACCESSIBILITY_SERVICE permission → T1418 (Software Discovery) + T1417 (Input Capture)

Anti-emulator strings detected → T1523 (Evade Analysis Environment)

C2 URL extracted → T1437 (Standard Application Layer Protocol)

REQUEST_INSTALL_PACKAGES permission → T1474 (Supply Chain Compromise)

BIND_DEVICE_ADMIN permission → T1401 (Device Administrator Permissions)

Implementation

Uses the mitreattack-python library for technique metadata

Mapping table: static feature → technique ID (deterministic; no LLM dependency)

15 to 20 key technique mappings for the hackathon build

Narrative Generation

Templated string assembly from matched technique IDs

Example: "This sample establishes persistence via Device Administrator permissions [T1401], captures banking credentials through accessibility service abuse [T1417], intercepts OTP messages via SMS reading [T1412], and exfiltrates data over HTTP [T1437]."

Visualization: ATT&CK for Mobile matrix rendered in the dashboard with highlighted cells for each detected technique.

3.5 WhatTheVictimSees — Overlay UI Reconstruction

Purpose: Reconstruct and render the phishing overlay screen that a banking malware victim would see at the moment of credential theft.

Why This Matters: It converts abstract language about phishing into visceral visual proof. This is the most emotionally impactful output in the platform.

Technical Approach

Extract res/layout/*.xml files from the unpacked APK for all overlay activity layouts

Extract drawable resources: bank logos, fake login UI assets, icons, background images

Identify target bank from drawable file names, string resources, and hardcoded package names

Reconstruct the overlay as an HTML/React component replicating the XML layout structure

Target Bank Detection

SBI: com.onlinesbi.sbi, sbi_logo drawable, state_bank string resource

HDFC: net.hdfcbank.customer.android, hdfc_logo drawable

ICICI: com.csam.icici.bank, icici_logo drawable

Paytm: net.one97.paytm, paytm_logo drawable

Output

Side-by-side comparison panel: Legitimate Bank App UI vs. Malware Overlay UI

Target bank label and matched package name displayed

Overlay intercept mechanism identified (accessibility service / activity injection / window overlay)

Hackathon Implementation Note: Pre-process and hardcode reconstruction for 3 to 5 known banking malware samples from public repositories (MalwareBazaar). Generalized reconstruction for unknown APKs is a Phase 2 feature.

3.6 ConfigDNA — Campaign Configuration Intelligence

Purpose: Track how malware configurations evolve across versions and link samples to campaign clusters based on shared config patterns.

What Is Analyzed

C2 URL structure: domain pattern, path format, query string schema

Hardcoded token and key formats: API keys, bot IDs, panel passwords

Config structure fingerprint: JSON schema, protobuf patterns, custom encoding format

Target app list: package names of banks and apps the malware monitors

Campaign Linking

Two samples with matching config schema and C2 URL pattern are flagged as same-campaign

Pure string pattern matching and structural comparison; no ML required

Builds temporal clusters: "samples using this config format were active between Month X and Month Y"

Example Output: "This config structure matches the Drinik banking trojan campaign pattern. Config v3 format. 7 related samples in corpus."

3.7 SMSGuard — OTP Interception Detection

Purpose: Detect the specific permission combinations and code patterns that indicate OTP theft via SMS interception.

Context: OTP theft via SMS interception is the primary banking fraud mechanism on Android in India and globally.

Detection Signals

High-precision permission triplet: READ_SMS + RECEIVE_SMS + BIND_NOTIFICATION_LISTENER_SERVICE

Overlay trigger detection in Smali: activity injection patterns triggered on banking app launch

Fake activity injection: an overlay Activity declared for a bank package in the manifest

Accessibility event monitoring: WINDOWS_CHANGED + TYPE_WINDOW_CONTENT_CHANGED event listeners targeting banking apps

Output: OTP theft risk flag (HIGH/MEDIUM/LOW), specific triggering signals listed, targeted bank package names identified.

3.8 CampaignClock — Campaign Timeline Visualization

Purpose: Display the evolution of a malware family across time, showing when configurations changed, new targets were added, and evasion was upgraded.

Data Sources

First-seen timestamps from MalwareBazaar and Koodous corpus

Related samples identified via CertGraph and ConfigDNA linkages

Version delta: what changed between consecutive samples in the family

Timeline Milestones (auto-annotated)

Initial appearance of campaign

Addition of new target banks to the overlay list

Introduction of emulator detection or anti-analysis features

C2 infrastructure change (new domain or IP block)

Certificate rotation

Visualization: D3.js horizontal timeline with milestone markers. Clicking a milestone shows the sample hash and diff summary.

3.9 EvasionScope — Anti-Analysis Detection

Purpose: Detect anti-analysis behaviors that indicate the malware is aware of being run in security research environments.

Detection Categories

Anti-emulator checks: isEmulator() patterns, Build.FINGERPRINT checks, telephony hardware checks

Debugger detection: android.os.Debug.isDebuggerConnected(), Debug.waitingForDebugger()

Root detection: su binary checks, Superuser.apk checks, test-keys build tag

Timing attacks: elapsed time checks to detect accelerated sandbox execution

Virtual environment detection: IMEI 000000000000000, fake MAC address patterns

Method: Static string and opcode pattern matching in Smali bytecode. No dynamic execution required.

Output: Evasion sophistication level (Basic / Intermediate / Advanced), list of specific anti-analysis techniques detected.

4. System Architecture

SENTINEL-X operates as a nine-stage pipeline. The stages run sequentially at the structural level, but the four analysis streams within Stage 2 execute in parallel for performance.

Stage 1: APK Ingestion

User uploads a .apk file via the React dashboard drag-and-drop interface or via REST API

File is hashed with MD5, SHA1, and SHA256 immediately on receipt

Hash is checked against an existing analysis cache; previously analyzed samples return instantly

APK is unpacked using apktool (reverse to Smali + resources) and jadx (Java decompilation)

Extracted artifacts: AndroidManifest.xml, Smali code, classes.dex, res/ drawables, assets/, signing certificate chain

If jadx decompilation fails due to obfuscation, the pipeline falls back to Smali-only analysis gracefully

Stage 2: Feature Extraction (Four Parallel Streams)

All four streams receive the extracted artifact set simultaneously and execute in parallel using Python's concurrent.futures.ThreadPoolExecutor.

Stream A — PermFlow XAI

Permission vector construction from AndroidManifest.xml

API call graph extraction from Smali bytecode

Opcode n-gram frequency analysis

String entropy computation

XGBoost inference (model loaded from pre-serialized joblib artifact)

SHAP explanation generation

Stream B — CertGraph

Signing certificate extraction from META-INF directory

Certificate field parsing and SHA256 fingerprinting

Graph database query for known matching certificates

Subgraph generation for visualization

Stream C — FactoryPrint + ConfigDNA

Structural code pattern analysis

Resource fingerprinting

Builder kit signature matching

C2 URL extraction via regex + entropy

Config structure fingerprinting and campaign matching

Stream D — SMSGuard + EvasionScope

Permission combination analysis for OTP theft signals

Smali-level overlay trigger detection

Anti-analysis string and opcode pattern matching

Stage 3: Graph Analytics

In-memory NetworkX graph (hackathon); Neo4j graph (production)

Nodes: APK, Certificate, Domain, IP, PackageName, DeveloperKey

Edges: SIGNED_BY, CONNECTS_TO, SHARES_CERT_WITH, SAME_FACTORY_AS, SAME_CAMPAIGN_AS

Graph queries surface campaign clusters, certificate chains, and shared C2 infrastructure

Stage 4: MITRE ATT&CK Mapping

Feature-to-technique mapping table applied to stream results

15 to 20 ATT&CK for Mobile techniques mapped in hackathon build

Attack narrative assembled from matched technique templates

ATT&CK matrix data structure built for dashboard visualization

Stage 5: Overlay Reconstruction (WhatTheVictimSees)

Overlay layout XML files extracted and parsed from res/layout/

Drawable resources identified and catalogued

Target bank identified from resource names and string constants

HTML/React overlay component rendered from layout structure

Side-by-side comparison panel prepared for dashboard

Stage 6: Campaign Timeline

Related samples fetched from graph via cert/factory/config linkages

Sample timestamps sorted chronologically

Version deltas computed between consecutive samples

Timeline milestone events annotated

D3.js timeline data structure prepared for dashboard

Stage 7: Risk Scoring

Composite Risk Score (0 to 100) computed from five weighted signals:

Severity label assigned based on final score: CRITICAL (85–100), HIGH (65–84), MEDIUM (40–64), LOW (0–39).

Stage 8: Intelligence Report Generation

A PDF and HTML report is automatically generated containing the following sections:

Executive Summary: one paragraph in non-technical language, suitable for management

Technical Verdict: ML score, confidence, and SHAP feature importance chart

Attribution Analysis: CertGraph visualization and FactoryPrint builder kit identification

Attack Chain: MITRE ATT&CK matrix with highlighted techniques and narrative

Fraud UI Reconstruction: WhatTheVictimSees side-by-side comparison screenshots

Campaign Timeline: CampaignClock visualization with milestone annotations

IOC Table: file hashes, C2 domains, IP addresses, certificate fingerprints

Recommended Actions: prioritized response steps for the security team

Libraries: ReportLab or WeasyPrint for PDF generation in Python.

Stage 9: Dashboard

The React frontend exposes all analysis outputs through the following interface components:

APK upload interface with drag-and-drop and hash lookup

Real-time analysis progress tracker via WebSocket

Interactive D3.js force-directed graph for CertGraph visualization

MITRE ATT&CK for Mobile matrix with highlighted cells per detected technique

WhatTheVictimSees side-by-side overlay reconstruction panel

Campaign timeline slider with milestone detail popup

Risk score display with severity label and contributing signal breakdown

IOC export in STIX 2.1 / JSON / CSV formats

Report download button (PDF)

5. Technology Stack

6. Build Scope

6.1 MVP Features — Must Build (0–48 Hours)

These are the features that must exist for the platform to be demonstrable.

1. APK Upload and Unpacking Pipeline

Complexity: Low. apktool + jadx wrapped in Python subprocess calls.

Drag-and-drop file upload UI in React

File fingerprinting (MD5, SHA1, SHA256)

Analysis cache lookup before processing

apktool decompilation to Smali and resources

jadx Java decompilation with graceful fallback on failure

2. PermFlow XAI — Permission-Based Detection with SHAP

Complexity: Medium. Model pre-trained offline; inference only at demo.

Train XGBoost model on AndroZoo or AMD Dataset before the hackathon

Serialize model with joblib for fast reload

Permission vector extraction from AndroidManifest.xml

SHAP explanation generation and waterfall chart rendering

Malicious/benign verdict displayed with confidence percentage

Critical Note: The model MUST be pre-trained before the hackathon begins. Never attempt to train during the event.

3. CertGraph — Certificate Relationship Graph

Complexity: Medium. Certificate extraction is trivial; graph visualization requires D3.js.

Pre-populate graph with 50 to 100 known malware certificates from MalwareBazaar

Extract and fingerprint new APK's signing certificate

Insert into graph and identify related families

Render interactive D3 force-directed graph in dashboard

4. WhatTheVictimSees — Overlay Reconstruction

Complexity: Medium-High. The highest-risk MVP component.

Pre-process 3 to 5 known banking malware samples from public repositories

Extract layout XML and drawable resources for each

Build React component that renders the phishing overlay

Display side-by-side comparison panel

Risk Mitigation: Hardcode the reconstruction for known templates only. Generalized reconstruction for unknown APKs is deferred to Phase 2.

5. Risk Score Dashboard

Weighted scoring formula applied to stream outputs

Severity label (CRITICAL / HIGH / MEDIUM / LOW) displayed prominently

Contributing signal breakdown shown as a bar chart

6. IOC Export

Extract file hashes, C2 domains, IP addresses, certificate fingerprints

Export to JSON and CSV formats

STIX 2.1 format export as a stretch goal within MVP

6.2 Advanced Features — Should Build (48–96 Hours)

7. AttackChainRecon — MITRE ATT&CK Mapping

Complexity: Medium. Mapping table is static; ATT&CK matrix UI components exist in open source.

Implement feature-to-technique mapping table for 15 to 20 techniques

Install mitreattack-python and integrate technique metadata

Build ATT&CK matrix visualization in React with highlighted cells

Assemble attack narrative from matched technique templates

8. FactoryPrint — Builder Kit Fingerprinting

Complexity: Medium. Pattern matching; no ML required.

Implement signature database for Cerberus, Anubis, and SpyNote patterns

Structural code analysis pipeline

Builder kit identification output with confidence and evidence list

9. SMSGuard — OTP Interception Detector

Complexity: Low. Static pattern matching on permissions and Smali.

Permission triplet detection: READ_SMS + RECEIVE_SMS + NOTIFICATION_LISTENER

Overlay trigger pattern matching in Smali

Targeted bank package identification from manifest

10. ConfigDNA — Campaign Configuration Tracking

Complexity: Medium. Regex extraction and structural comparison.

C2 URL pattern extraction via regex and entropy analysis

Config schema fingerprinting

Campaign cluster matching against known config patterns in database

6.3 Stretch Features — Build If Time Allows

11. CampaignClock — Timeline Visualization

Complexity: Low-Medium. D3 timeline component; pure visualization.

Fetch related samples from graph via campaign linkage

Sort by timestamp and compute version deltas

Render D3.js horizontal timeline with milestone annotations

12. EvasionScope — Anti-Analysis Detection

Complexity: Low. Static string and opcode pattern matching.

Anti-emulator, debugger detection, and root detection pattern library

Evasion sophistication level output

13. Automated PDF Report

Complexity: Medium. ReportLab or WeasyPrint in Python.

Auto-generate formatted PDF containing all analysis sections

Download button in React dashboard

Pre-printed copies for demo theatre

14. Real-Time Analysis Progress Feed

Complexity: Low-Medium. WebSocket connection from FastAPI to React.

Stream pipeline stage completion events to the frontend

Show live progress bar as each analysis stream completes

7. Technical Implementation Notes

7.1 What Must Be Prepared Before the Hackathon

XGBoost model: download training data (AndroZoo subset or Drebin dataset), train, and serialize with joblib. Ship the .pkl file as a model artifact.

Certificate corpus: download 50 to 100 known malware certificate fingerprints from MalwareBazaar and Koodous. Store in a local SQLite or JSON database.

WhatTheVictimSees samples: obtain 3 to 5 known banking malware APKs from MalwareBazaar (publicly available), pre-process their overlay layouts, and test reconstruction.

Demo APK selection: choose 2 to 3 demo APKs that decompile cleanly with jadx and have rich features across all modules. Verify end-to-end pipeline on each.

Pre-resolve C2 infrastructure: look up C2 domains and IPs for demo APKs in advance and store results. Do not rely on live VirusTotal or Shodan calls during demo.

7.2 Simplifications for Hackathon Build

Replace Neo4j with NetworkX: same graph outputs, no database setup overhead. Neo4j is the production version mentioned in the roadmap.

Replace LLM-generated ATT&CK narrative with templated strings: a lookup table of technique ID to narrative text is deterministic, fast, and demo-safe.

Replace live OSINT C2 lookups with pre-resolved static data: demo speed matters more than live API calls.

WhatTheVictimSees for known samples only: build for 3 to 5 pre-processed APKs, not as a fully generalized reconstruction engine.

7.3 What Should Not Be Attempted

Dynamic analysis: any sandbox execution or emulator-based behavior monitoring

Native library analysis: binary analysis of .so files requires months of specialist work

Neural network training during the event: all model training must be completed beforehand

Dark web intelligence integration: access, legality, and time constraints make this impossible in a hackathon context

Blockchain for any component: no use case justifies it in this platform

7.4 Demo Hardening (Critical)

Invest at minimum 20 percent of total build time in demo reliability. A backend crash during demonstration is unrecoverable.

Pre-recorded backup video: record a complete walkthrough of the demo with all outputs visible

Static screenshot fallbacks: save PNG exports of all key outputs (SHAP chart, CertGraph, ATT&CK matrix, overlay reconstruction)

Offline mode with cached results: ensure the frontend can display pre-cached analysis results without a live backend call

Pre-selected demo APKs only: never analyze an unknown APK live during the demonstration

8. Intelligence Report Structure

Every SENTINEL-X analysis produces a structured PDF and HTML report. The report contains the following sections:

Section 1: Executive Summary

One paragraph in plain English, written for a non-technical audience (bank management, CISOs)

States verdict, threat severity, identified campaign, and immediate recommended action

Example: "This APK is a high-confidence banking trojan attributed to the Cerberus v2 builder kit. It targets SBI, HDFC, and ICICI customers by overlaying fake login screens and intercepting OTP messages. Immediate IOC blocking is recommended."

Section 2: Technical Verdict

PermFlow XAI classification result with confidence percentage

SHAP waterfall chart showing top contributing features and their direction/magnitude

Permission feature vector summary

Section 3: Attribution Analysis

CertGraph: certificate fingerprint, signer details, list of related malware families sharing the same signer

CertGraph visualization screenshot

FactoryPrint: identified builder kit name, version estimate, matching signals

Section 4: Attack Chain

MITRE ATT&CK for Mobile matrix with highlighted technique cells

Full attack narrative paragraph

Technique table: ID, name, evidence signal that triggered the mapping

Section 5: Fraud UI Reconstruction

WhatTheVictimSees side-by-side comparison: legitimate bank app vs. malware overlay

Target bank identification with package name

Overlay intercept mechanism identified

Section 6: Campaign Timeline

CampaignClock visualization showing family evolution

Related sample count and date range

Milestone annotations (target additions, evasion upgrades, infrastructure changes)

Section 7: Indicators of Compromise (IOC Table)

File hashes: MD5, SHA1, SHA256

C2 domains and IP addresses extracted from the sample

Signing certificate SHA256 fingerprint

Malicious package names

STIX 2.1 formatted bundle available for download

Section 8: Recommended Actions

Immediate: block IOCs at network perimeter and email gateway

Short-term: push mobile threat advisory to at-risk customer segment

Investigative: search internal fraud logs for activity matching these IOCs

Regulatory: report to CERT-In if sample is novel or demonstrates significant reach

9. Product Roadmap

Phase 1: Hackathon Version (48–96 Hours)

Deliverables

APK upload and unpacking pipeline

PermFlow XAI with SHAP visualization

CertGraph with D3 force-directed graph

WhatTheVictimSees for 3 to 5 known banking malware families

Risk Score dashboard with severity label

MITRE ATT&CK mapping for 15 to 20 techniques

FactoryPrint pattern matching

SMSGuard and EvasionScope detection

PDF report generation

IOC export in JSON and CSV

Stack

Backend: Python, FastAPI, XGBoost, SHAP, apktool, jadx, NetworkX, mitreattack-python

Frontend: React, D3.js, Tailwind CSS

Data: MalwareBazaar, Koodous API, AndroZoo subset

Phase 2: Post-Hackathon Product (1–3 Months)

APKLineage: version tracking of malware families across time; requires corpus accumulation over 6+ months

C2Mapper: live OSINT integration with VirusTotal, Shodan, and PassiveDNS for infrastructure mapping

MirrorMap: ML-based clustering of phishing overlay templates across hundreds of samples

SharedSecrets: reused token, credential, and string attribution across sample corpus

Neo4j production graph: replaces NetworkX for scalability beyond 10,000 samples

STIX 2.1 full export: complete threat intel sharing format for banking ISACs

Analyst API: REST API for banking security teams to programmatically submit APKs

Phase 3: Startup Version (3–12 Months)

MalwareRAG Analyst: LLM-powered analyst assistant over internal case history corpus. Only meaningful once 10,000+ analyzed samples exist; without corpus it is a generic ChatGPT wrapper.

ConfigDNA at scale: ML-based config similarity clustering across thousands of samples

CostGraph: attacker economics modeling — estimated fraud yield and campaign ROI for regulatory reporting

Operator Localization: language-of-origin detection from string resources and developer artifact analysis

CrosshairIndex: predictive targeting model for which banks are likely next campaign targets; requires 12+ months of training data

Banking ISAC Integration: bilateral federated intelligence sharing between participating institutions

Phase 4: Enterprise Threat Intelligence Platform (12–36 Months)

ThreatGraph Federated: multi-institution privacy-preserving threat intelligence network; requires organizational trust and legal agreements across institutions

ZeroHour: real-time early warning from new malware campaigns before widespread deployment

TempoIntel: campaign operational cadence modeling with day-of-week and time-of-day activity prediction

DropChain: full malware delivery chain reconstruction from initial distribution through exfiltration

MalGenome: bioinformatics-inspired evolutionary analysis of malware genomes

FollowMoney: integration with banking fraud management systems to correlate malware IOCs with actual fraud cases

RegTech Compliance Module: automated CERT-In reporting, RBI incident reporting, and DPDP Act compliance documentation

10. Platform Scores

SENTINEL-X — Complete Idea & Technical Specification

Android Banking Malware Attribution Intelligence Platform