# SENTINEL-X — Final Solution & Build Specification

**Android Banking-Malware Static Analysis & Intelligence Platform**
PSB Cybersecurity, Fraud & AI Hackathon 2026 — **Problem Statement 1**
*Automated Reverse Engineering, Static Analysis, Risk Scoring & Generative-AI reporting of fraudulent APKs.*

> This is the single authoritative document for the project. It consolidates ~15 earlier drafts
> (idea catalog, specification, audit, and six duplicate "final concept" files) into **one realistic,
> buildable plan** scoped for a **solo first-year engineering student building with AI assistance in ~6–8 weeks**.
> The earlier drafts are preserved in `_archive_originals/`.

---

## 1. Executive Summary

Android banking trojans (Drinik, Cerberus, Anubis, SOVA, SpyNote) are the dominant mobile-fraud vector against
Indian bank customers. They steal credentials via **fake overlay screens** and bypass 2FA by **intercepting
OTP SMS**. Tools available to bank SOC / CERT-In teams (VirusTotal, MobSF) answer only *"is this malicious?"*
— not *why*, *who built it*, *which banks are targeted*, or *what the victim saw*.

**SENTINEL-X** takes a suspicious `.apk`, runs a **static** analysis pipeline, and produces a structured
intelligence report in seconds: an **explainable ML verdict (XGBoost + SHAP)**, **certificate-based
attribution**, **OTP-interception / bank-targeting detection**, **MITRE ATT&CK mapping**, a **composite risk
score**, and a **Generative-AI narrative + CERT-In incident-report draft**. No malware is executed.

This document describes a version that is **actually built and runnable on a normal laptop** — every
technology choice is one a solo beginner can install and operate, and the ML model is trained on a **real,
free, balanced dataset** so its metrics are genuine rather than claimed.

---

## 2. Problem Statement Mapping (PS1)

| PS1 requirement | How SENTINEL-X satisfies it |
|---|---|
| **Generative AI** | GenAI layer produces the executive summary, attack-chain narrative, and a pre-filled **CERT-In incident report** from *structured, verified* inputs. Template-first (deterministic, demo-safe); live LLM optional. All AI output is labeled and shown beside its source data. |
| **Automated Reverse Engineering** | `androguard` decompiles the APK in-process — manifest, permissions, certificates, DEX, strings — fully automated from upload. |
| **Static Analysis** | Permission vector + fraud-signal rules + certificate + string analysis. No execution. |
| **Risk Scoring** | 5-signal weighted composite (0–100) with CRITICAL/HIGH/MEDIUM/LOW severity and a full decomposition. |
| **Explainable AI reports** | Every verdict carries a **SHAP** contribution chart; every ATT&CK mapping cites its evidence. |
| **Automated analyst assistance** | One upload → verdict + attribution + IOCs + ATT&CK + report (PDF/JSON/CSV). |
| **Dynamic Analysis** | *Deliberately out of scope.* Static-only is argued as correct: no legal/technical risk of running live banking malware on bank infrastructure; the forensically decisive behaviours (overlay, OTP theft, accessibility abuse) leave complete **static** signatures. Documented as "behavioural static analysis". |

---

## 3. Architecture (as built)

```
                 ┌──────────────── FastAPI backend (Python 3.13) ────────────────┐
  browser  ─────▶│  POST /api/analyze  ──▶  Ingestion ──▶  Feature extraction     │
 (static HTML    │                                   (androguard)                 │
  dashboard,     │        ┌───────────── parallel-ish analysis ─────────────┐     │
  Chart.js/D3)   │        │ 1 Classifier+SHAP  2 CertGraph  3 Fraud/OTP      │     │
        ▲        │        │ 4 ATT&CK map       5 Risk score 6 GenAI narrative │     │
        │        │        └──────────────────────┬───────────────────────────┘     │
  GET /api/cases/{id}  ◀───── case JSON ─────────┤                                  │
  GET .../report.pdf   ◀───── fpdf2 PDF ─────────┤  cache: data/cases/{sha256}.json │
  GET .../iocs.{json,csv} ◀── IOC export ────────┘                                  │
                 └───────────────────────────────────────────────────────────────┘
   models/  xgb.joblib · calibrator.joblib · feature_vocab.json · metrics.json
```

Single process, single command to run. No React build, no database server, no message queue.

---

## 4. Technology Stack (final, installed)

| Layer | Choice | Note |
|---|---|---|
| API | **FastAPI + uvicorn** | async, auto OpenAPI docs |
| APK reverse engineering | **androguard** | pure-pip; replaces the fragile apktool + jadx subprocess pipeline |
| ML | **XGBoost + scikit-learn** | gradient-boosted classifier; `IsotonicRegression` calibration |
| Explainability | **SHAP** `TreeExplainer` | exact Shapley values for trees |
| Graph | **NetworkX** (in-memory) | certificate relationship graph; D3 JSON for the dashboard |
| ATT&CK | static mapping table (JSON) | ~15 Mobile techniques with evidence links |
| GenAI | **template engine** (default) + **Anthropic SDK** (optional) | activates live only if `ANTHROPIC_API_KEY` is set |
| Report | **fpdf2** + HTML | pure-pip; avoids WeasyPrint's Windows GTK dependency |
| Dashboard | **static HTML + vanilla JS + Chart.js + D3** (CDN) | served by FastAPI; no node build |
| Dataset | **NATICUSdroid** (UCI ML Repository) | 29,333 apps, ~1:1 benign/malware, 86 permission features |

---

## 5. Dataset (real & reproducible)

**NATICUSdroid Android Permissions Dataset** — UCI ML Repository (ID 722). CSV, 29,333 rows, 86 binary
permission columns + `Result` label (1 = malware, 0 = benign), class balance ≈ 14,700 / 14,632.
`scripts/train_model.py` downloads it, does a **70/15/15 hash-free stratified split**, trains XGBoost,
calibrates with isotonic regression, and writes real held-out metrics to `models/metrics.json`.

> The APK feature extractor (`features.py`) maps a live APK's declared permissions onto exactly these 86
> columns, so the model trained on the dataset scores real uploaded APKs directly.

### Measured model performance (held-out test set)

Measured on the 15% held-out test split (4,400 apps), XGBoost (400 trees, depth 6) + isotonic calibration:

| Metric | Value |
|---|---|
| Accuracy | **0.9664** |
| Precision | **0.9840** |
| Recall | **0.9483** |
| F1 | **0.9658** |
| ROC-AUC | **0.9937** |
| False-positive rate | **0.0155** |

Confusion matrix (test): TN 2161 · FP 34 · FN 114 · TP 2091. These are real numbers produced by
`scripts/train_model.py`, not literature estimates — see `models/metrics.json`. The low FPR (1.55%) is the
figure that matters most for a bank: legitimate apps are rarely misflagged.

### Two honest limitations of this model (found during the build, not hidden)

**1. Vocabulary gap.** NATICUSdroid's 86 features do **not** include five of the most
banking-trojan-specific permissions: `BIND_ACCESSIBILITY_SERVICE`,
`BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_DEVICE_ADMIN`, `READ_CALL_LOG`, `QUERY_ALL_PACKAGES`.
The model is therefore blind to the exact signals that define an overlay/OTP-theft trojan.

**2. Temporal bias.** SHAP analysis of a crafted trojan profile showed `REQUEST_INSTALL_PACKAGES`
contributing **−2.59** (i.e. strongly *benign*) and `FOREGROUND_SERVICE` −1.60. The cause is
corpus composition: in NATICUSdroid, `P(malware | REQUEST_INSTALL_PACKAGES) = 0.000`, because these
newer permissions appear almost exclusively in the modern, benign half of the dataset. The model
learned "modern permission ⇒ benign".

**Why this strengthens rather than weakens the design.** These findings are exactly why SENTINEL-X
does not ship a single-model verdict:

* The **rule engine** (§6.4) detects precisely the signals the ML vocabulary lacks.
* The **composite score** weights ML at only 35%, so rules, attribution, evasion and targeting still
  drive the outcome.
* A dedicated **ML/rule reconciliation** step raises an explicit `ml_rule_disagreement` flag, replaces
  the headline verdict with `SUSPICIOUS (rule-driven)`, and explains the conflict in the dashboard
  and the PDF.

Observed on the built system: the banking-trojan demo case is scored **BENIGN by the ML model**
(P=0.012) yet lands at **62.9 / 100 → HIGH** with the disagreement flag raised. The platform reaches
the right answer *and* shows its working — which is what an explainable-AI requirement actually means.

---

## 6. Modules (7)

1. **Ingestion** (`ingest.py`) — MIME/ZIP/size + compression-ratio (ZIP-bomb) checks, MD5/SHA1/SHA256,
   SHA256 cache lookup, `androguard.APK` load. Graceful `PARTIAL` degrade if parsing is incomplete.
2. **Classifier + SHAP** (`classify.py`) — 86-permission vector → XGBoost → isotonic-calibrated confidence;
   SHAP top-15 signed contributions for the verdict.
3. **Certificate graph** (`certgraph.py`) — extract X.509 signer (subject, issuer, serial, SHA256, self-signed);
   insert into a NetworkX graph seeded from `data/cert_corpus.json`; return family attribution + D3 subgraph.
4. **Fraud / OTP** (`fraud.py`) — *covers the ML vocabulary gap above* — OTP triplet `READ_SMS + RECEIVE_SMS + BIND_NOTIFICATION_LISTENER_SERVICE`,
   accessibility/overlay/device-admin perms, and Indian-bank package match → HIGH/MEDIUM/LOW with evidence.
5. **ATT&CK mapping** (`attack.py`) — deterministic feature→technique table (~15 Mobile techniques), each
   mapping carrying the exact triggering signal.
6. **Risk score** (`risk.py`) — composite = ML 35% · fraud 25% · attribution 20% · evasion 10% · targeting 10%
   → CRITICAL (80–100) / HIGH (60–79) / MEDIUM (40–59) / LOW (0–39), fully decomposed. Also performs
   **ML/rule reconciliation**: when the classifier says benign but the fraud rules find OTP-interception
   capability or bank targeting, it flags the disagreement and issues a `SUSPICIOUS (rule-driven)` headline.
7. **GenAI narrative** (`genai.py`) — executive summary + attack-chain + **CERT-In draft**. Template engine
   by default (deterministic); live Anthropic call when a key is present. JSON-validated, `[AI GENERATED]` /
   `[TEMPLATE]` labeled, source data shown alongside.

**Outputs:** HTML + `fpdf2` PDF report (`report.py`); JSON + CSV IOC export (`iocs.py`).

---

## 7. Dashboard

Single page (`sentinelx/static/index.html`): drag-drop upload → poll `/api/cases/{id}` → render verdict card,
SHAP bar chart, risk decomposition, D3 certificate graph, ATT&CK grid, fraud/OTP panel, GenAI narrative, and
IOC / report download buttons. An **offline demo mode** loads pre-baked `data/demo/*.json` so the full UI is
always demonstrable even with no sample APK or backend.

---

## 8. Security & honesty controls

- Static only — no code execution; artefacts in isolated per-case dirs; configurable retention.
- ZIP-bomb / size / MIME guards before any parsing.
- **Blind-spot section** in every report: names what static analysis cannot see for *this* sample
  (native `.so`, reflection, dynamic DEX loading, encrypted C2).
- GenAI: structured input only, labeled output, template fallback — no hallucinated IOCs or attribution.

---

## 9. Explicitly out of scope (documented as "future", not built)

Dynamic sandbox execution · native `.so` analysis · Neo4j / Celery / Redis · live VirusTotal / OSINT ·
STIX 2.1 · WebSockets · React SPA · generalized overlay reconstruction for arbitrary APKs · multi-tenant auth.
Builder-kit fingerprinting is kept only as a light structural heuristic. These are named so a judge sees a
scoped, honest prototype rather than an unbuildable roadmap.

---

## 9a. Build status — what is actually implemented

Verified end-to-end against two real APKs downloaded from F-Droid, plus two demo cases.

| Component | Status |
|---|---|
| Ingest guards (size / ZIP / MIME / ZIP-bomb) | working, 4 tests |
| androguard parsing | working on real APKs |
| XGBoost + calibration + SHAP | working — F1 0.966 |
| Certificate graph (NetworkX + D3) | working — **seed corpus is synthetic placeholder data**, `scripts/fetch_cert_corpus.py` loads real data with a free MalwareBazaar key |
| OTP / bank-targeting rules | working, 4 tests |
| ATT&CK mapping (15 techniques) | working, 2 tests |
| Evasion + blind-spot section | working |
| Composite risk + reconciliation | working, 5 tests |
| GenAI narrative + CERT-In draft | working in template mode; live LLM optional via `ANTHROPIC_API_KEY` |
| PDF report / IOC JSON / IOC CSV | working, 2 tests |
| Dashboard | working (upload, SHAP chart, risk chart, cert graph, ATT&CK grid, downloads) |
| Real-world evaluation (`scripts/real_world_eval.py`) | working — see §9b |

Test suite: **50 passing** (19 are end-to-end runs on real benign APKs).

## 9b. Real-world evaluation (measured, 2026-09-13)

The full pipeline was run on real banking trojans from MalwareBazaar (downloaded and parsed in
memory, never executed or written to disk) and on real benign apps from F-Droid, chosen to include
hard negatives: SMS clients, KDE Connect (mirrors SMS + notifications, uses accessibility),
Gadgetbridge (notification listener), Key Mapper (accessibility + device admin), Shelter and
Island (device admin), App Manager, Aurora Store.

A sample counts as *flagged* when the headline verdict is not BENIGN or severity is MEDIUM+.

Rules evolved in two rounds, each followed by a fresh held-out draw so every published number has
a blind set behind it.

| Set | Rules | Trojans | Pipeline detection | ML-only | Benign | Pipeline FPR | ML-only FPR |
|---|---|---|---|---|---|---|---|
| Design set | v1 (tuned here) | 27 | 85.2% | 29.6% | 19 | 10.5% | 10.5% |
| Held-out 1 | v1, frozen | 51 | 86.3% | 21.6% | 13 | 7.7% | 7.7% |
| Held-out 1, re-scored | v2 (designed from its misses — **not blind**) | 51 | 96.1% | 21.6% | 13 | 7.7% | 7.7% |
| **Held-out 2** | **v2, frozen** | **42** | **83.3%** | 11.9% | **19** | **5.3%** | 5.3% |

v1 = trojan kit (accessibility + device admin + SMS) or bank targeting. v2 adds: the overlay kit
without device admin when paired with a machine-generated package name or anti-analysis checks;
segment-prefix brand matching (`iciciofficial`); and a bank-like name only counting together with
OTP or accessibility capability. Held-out 2 = APKs 13–18 per family (`--skip 12 --keep-corpus`);
SOVA, Octo and Hookbot have no unseen APKs left, so the v2 overlay-kit rule is not yet validated
out of sample. Benign hold-out 2 adds device-admin panic apps (Wasted, Sentry), accessibility apps
(Duress, Screenshot Tile), keyboards and an overlay app (Red Moon).

Families: Alien, Anubis, BankBot, Cerberus, Ermac, Hookbot, Hydra, Octo, SOVA, SpyNote.

**Real Indian-bank targeting was found statically.** A held-out Anubis sample carries the package
names of Axis Bank, ICICI iMobile, SBI YONO Lite and HDFC MobileBanking as DEX string constants;
a BankBot sample targets Google Pay, PhonePe and Paytm; another impersonates HDFC (`com.app.hdfc`).

**Reading the numbers honestly**

* The rule layer caused **zero** false positives across all 32 benign apps. Every benign false
  positive (Fossify Messages, SMSSecure, Neo Backup) is the NATICUSdroid model's own verdict.
* The ML model alone misses ~4 in 5 real trojans — the vocabulary gap and temporal bias in §5 are
  confirmed on real samples, not just the crafted demo profile.
* n is small (51 + 13 held-out). Treat these as a credible prototype measurement, not a benchmark.

**Known misses on held-out 2 (not tuned away)**

* 4/6 Anubis: accessibility + SMS + overlay or notification listener, strong anti-analysis, but
  neither the full kit nor the full overlay kit. Two have machine-generated names.
* A Cerberus build disguised as a VPN with only package enumeration declared, a Hydra *payload* with
  no manifest permissions, and a BankBot with SMS interception only — too little static signal.
* Held-out 1 misses that v2 still does not catch: two BankBot droppers (4 and 12 permissions).

**Bugs this evaluation exposed and fixed**

* `BIND_ACCESSIBILITY_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_DEVICE_ADMIN` are
  declared on `<service>`/`<receiver>` elements, not `<uses-permission>`; androguard's
  `get_permissions()` returned them for **0/23** trojans. `features.component_permissions()` now reads
  them, so the fraud rules can actually fire on real APKs.
* The "real" certificate corpus is dominated by shared keys — the AOSP test key (CN=Android) and a
  copied debug key each appear under 5–6 families. Attribution from them was noise (one sample was
  attributed to 6 families). Shared keys and generic CNs now raise a `shared_or_test_key` flag
  instead of a family name.
* The loose "OTP risk MEDIUM ⇒ override ML" rule flagged 4/19 benign apps. The override now requires
  the **banking-trojan kit** (accessibility + device admin + SMS interception) or concrete bank
  targeting; OTP capability is still reported, but as a capability rather than a verdict.
* Signers are now read from v2/v3 signature blocks (SpyNote samples carry no v1 certificate).

### Fixes from the post-build audit

* **Evasion false positives.** Both benign F-Droid apps were rated evasion HIGH/MEDIUM because needles
  such as `generic`, `getInstance` and `forName` occur in ordinary library code. Indicators are now
  tiered: reflection / crypto / debugger checks are *weak* (LOW at most); emulator fingerprints, root
  checks, runtime DEX loading and commercial packers are *strong*. Blind-spot statements are unchanged.
* **Bank targeting.** A genuine bank app no longer "targets itself"; target lists are now also read from
  DEX string constants (where overlay trojans keep them); impersonation is whole-word; the package list
  now covers SBI, PNB, Bank of Baroda, Canara, Kotak, PhonePe, Google Pay and BHIM.
* **Attribution graph growth.** Every analysed upload is a certificate observation; later samples with
  the same signer are linked (`shared_signer_samples`).
* **Real certificate corpus.** MalwareBazaar's `code_sign` is Windows Authenticode data, so the previous
  fetcher could never return APK certificates. It now downloads APKs in memory and parses their signers.
* **Live GenAI never ran.** Anthropic SDK 1.x removed `temperature`, so the call raised and silently fell
  back to templates. The live path now uses schema-constrained output and a grounding check that rejects
  any hash, family, bank or ATT&CK ID absent from the verified bundle.
* **Ingestion.** Samples are held in memory only (never written to disk); unparseable APKs return 422;
  cached cases are purged after `SENTINELX_RETENTION_DAYS`.

---

## 10. How to run

```bash
python scripts/setup.py            # install deps + train the model (one time)
uvicorn sentinelx.app:app --reload # start the server
# open http://127.0.0.1:8000  → "Load demo" or drag in a real .apk
pytest -q                          # unit tests (feature extraction + rules)
```

---

*SENTINEL-X — consolidated final specification. Supersedes all files in `_archive_originals/`.*
