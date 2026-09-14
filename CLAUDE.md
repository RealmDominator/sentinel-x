# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SENTINEL-X — Android banking-malware **static** analysis platform. Upload an `.apk`, get an
explainable ML verdict, certificate attribution, MITRE ATT&CK chain, composite risk score, GenAI narrative, PDF report and IOC exports.

`Final_md.md` is the authoritative solution specification — read it before changing analysis behaviour.
`_archive_originals/` (local only, git-ignored) holds superseded planning documents; they are historical, not requirements.

## Commands

```bash
python scripts/setup.py                          # bootstrap: deps + train model + demo cases
python -m uvicorn sentinelx.app:app --reload      # serve API + dashboard on :8000

python -m pytest tests/ -q -p no:logging           # full suite (48 tests; 19 parse samples/*.apk)
python -m pytest tests/test_sentinelx.py::test_ml_rule_disagreement_flagged -q   # single test
python -m pytest tests/ -q -k "rejects"            # subset by name (4 ingest-guard tests)

python scripts/train_model.py                     # retrain; rewrites models/*.joblib + metrics.json
python scripts/make_demo.py                       # rebuild data/demo/*.json (required after risk.py edits)
python scripts/fetch_cert_corpus.py               # replace synthetic cert seed with real MalwareBazaar data
python scripts/real_world_eval.py [--bazaar]      # full-pipeline detection rate / FPR on real APKs -> data/real_eval.json
```

Verify a change end-to-end against a real APK (two are kept in `samples/`):

```bash
curl -F "file=@samples/fdroid_privacybrowser.apk" http://127.0.0.1:8000/api/analyze
```

## Architecture

**One linear pipeline, one shared contract.** `pipeline.analyse()` orchestrates every module and
assembles a single **case JSON**. Each analysis module owns one top-level key in that dict
(`classification`, `attribution`, `fraud`, `evasion`, `attack`, `risk`, `narrative`). Three consumers
read the assembled case and nothing else: `report.py` (PDF), `iocs.py` (JSON/CSV export), and
`static/index.html` (dashboard). Adding a field means touching the producing module plus whichever
consumers should surface it.

**Feature extraction deliberately produces two separate things** (`features.py`):
- `ml_vector(apk)` — an 86-column binary permission vector aligned to `models/feature_vocab.json`.
  Column order is fixed by the training CSV; never reorder or filter it.
- `signal_bundle(apk)` — a rich dict (permissions, referenced packages, certs, URLs/IPs) consumed by
  the *rule* modules.

These are kept apart on purpose — see below.

**The ML/rule reconciliation in `risk.py` is the single most important design decision.** The model is
trained on NATICUSdroid, whose 86 features omit five of the most banking-trojan-specific permissions
(`BIND_ACCESSIBILITY_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`, `BIND_DEVICE_ADMIN`,
`READ_CALL_LOG`, `QUERY_ALL_PACKAGES`), and it carries a temporal bias from its corpus
(`P(malware | REQUEST_INSTALL_PACKAGES) = 0.000`, so newer permissions push *benign*). The classifier
therefore scores real banking trojans BENIGN.

The system compensates architecturally rather than by tuning the data: ML is weighted at only 35% of
the composite score, `fraud.py` detects exactly the signals the model is blind to, and `risk.py` raises
`ml_rule_disagreement` with a `SUSPICIOUS (rule-driven)` headline when the two conflict. **Do not
"fix" a BENIGN verdict on a trojan by adjusting training data or demo permissions** — that flag is the
intended, documented behaviour and is asserted in the tests.

## Invariants

- **Never execute a sample, and never write one to disk.** Everything is static parsing via androguard
  from in-memory bytes (`APK(data, raw=True)`). MalwareBazaar downloads are decrypted in memory
  (`scripts/bazaar.py`) — writing them to OneDrive gets them quarantined by Defender.
- **Evasion indicators are tiered.** Reflection / `javax.crypto` / debugger checks exist in nearly every
  benign APK, so they are `weak` and can only rate LOW. Don't add bare-word needles like `generic`.
- **GenAI output must pass `genai.grounding_errors()`** — no hash, family, bank or ATT&CK ID that isn't in
  the verified bundle. SDK 1.x has no `temperature`; the live call uses `output_config.format`.
- **Bump `SCHEMA_VERSION` in `pipeline.py` whenever the case JSON shape changes.** Cached results in
  `data/cases/{sha256}.json` are invalidated by version mismatch; stale entries otherwise get served
  and silently omit new fields.
- **`data/cert_corpus.json` is real MalwareBazaar signer data, but mostly shared keys.** The AOSP test
  key and a copied debug key span 5–6 families; `certgraph.attribute()` must keep refusing to name a
  family for multi-family fingerprints or generic CNs.
- **The ML override lives in `risk.override_reasons()`.** Full trojan kit (accessibility + device admin
  + SMS), or bank references in code/manifest, override alone. OTP capability, the overlay kit, and a
  bank-like package name only count with a second independent signal — KDE Connect holds the overlay
  kit and Gadgetbridge holds OTP capability legitimately.
- **Measure rule changes with `real_world_eval.py --replay`** (re-scores cached cases, no downloads)
  and never tune on the newest held-out file (`data/real_eval_holdout2.json`) — that set is the honest
  number. `real_eval_holdout.json` was used to design the v2 rules and is no longer blind.
- **Component permissions matter.** BIND_* capabilities live on `<service android:permission>`, not
  `<uses-permission>`; rule modules read `short_permissions` (both), the ML vector reads uses-permission only.
- **GenAI is template-first.** `genai.py` runs deterministic templates unless an LLM key is in `.env`
  (`GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`; picked in that order by
  `config._pick_provider`), and falls back to them on API failure or grounding/schema failure. The three
  free providers use their OpenAI-compatible endpoints via `urllib` — don't add the `openai` SDK.
- **All keys live in the project `.env`** (template: `.env.example`), loaded by `config.load_dotenv()`.
  Tests (`tests/conftest.py`), `make_demo.py` and `real_world_eval.py` force `SENTINELX_LLM_PROVIDER=none`
  before importing `sentinelx` so they never spend free-tier quota — keep it that way. Every output carries a
  `[AI GENERATED]` / `[TEMPLATE]` label. Analysis results must never depend on the LLM.
- **Every report states its blind spots.** `evasion.py` maps detected evasion techniques to explicit
  statements about what static analysis could not see for that specific sample.

## Gotchas

- **androguard's loguru logging is extremely noisy.** Start scripts with
  `from loguru import logger; logger.remove()` or output becomes unreadable.
- **fpdf2 `multi_cell` leaves the cursor at the right edge.** Always `set_x(self.l_margin)` first and
  pass `new_x="LMARGIN", new_y="NEXT"`, or the next row throws
  "Not enough horizontal space to render a single character".
- **fpdf2 core fonts are latin-1 only** — all report text goes through `report._clean()`.
- `scripts/make_demo.py` re-runs the *real* analysis modules over a crafted permission profile
  (only APK parsing is substituted), so demo cases go stale whenever scoring logic changes.
- The dashboard has no build step. It is plain HTML/JS served by FastAPI, with Chart.js and D3 from
  CDN, so it needs network access to render charts.

## Out of scope

Dynamic sandbox execution, native `.so` analysis, reflection resolution, Neo4j/Celery/Redis, live
VirusTotal, STIX 2.1, WebSockets, React, generalized overlay reconstruction, auth/multi-tenancy.
These are named as "future" in `Final_md.md` deliberately — the honest scoping is part of the
project's argument. Don't add them without the user asking.
