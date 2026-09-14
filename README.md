# SENTINEL-X

**Android banking-malware static analysis & intelligence platform.**
Drop in a suspicious `.apk` → get an explainable verdict, attribution, MITRE ATT&CK chain,
a composite risk score, IOCs and a PDF intelligence report. The sample is **never executed**.

Built for **PSB Cybersecurity, Fraud & AI Hackathon 2026 — Problem Statement 1**.
The full solution specification is in **[`Final_md.md`](Final_md.md)**.

---

## Quick start

```bash
python scripts/setup.py          # install deps + train model + build demo cases
python -m uvicorn sentinelx.app:app --reload
# open http://127.0.0.1:8000
```

Then either click **Load demo case**, or drag a real `.apk` onto the drop zone.

Run the tests:

```bash
python -m pytest tests/ -q       # 50 tests (19 run end-to-end on real benign APKs)
```

## Measured on real malware

| Latest held-out set (rules frozen) | Trojans | Pipeline detection | ML-only | Benign | FPR |
|---|---|---|---|---|---|
| Held-out 2 | 42 | **83.3%** | 11.9% | 19 | 5.3% (from the ML model; rules: 0) |

Ten families from MalwareBazaar, hard-negative benign apps from F-Droid. Details, misses and
caveats: [`Final_md.md` §9b](Final_md.md).

```bash
```

---

## What actually works

| Capability | Status |
|---|---|
| APK ingest, hashing, ZIP-bomb / size / MIME guards | working |
| androguard parsing (manifest, permissions, certs, DEX strings) | working |
| XGBoost verdict + isotonic calibration + SHAP explanation | working — **F1 0.966**, FPR 0.016 |
| Certificate extraction + NetworkX attribution graph (D3) | working (seed corpus is synthetic — see below) |
| OTP-interception / Indian-bank targeting rules | working |
| MITRE ATT&CK for Mobile mapping (15 techniques, evidence-linked) | working |
| Evasion profiling + per-sample blind-spot section | working |
| Composite risk score with 5-signal decomposition | working |
| ML/rule disagreement reconciliation | working |
| GenAI narrative + CERT-In draft | working (template mode; live LLM optional) |
| PDF report, IOC JSON/CSV export | working |
| Dashboard (upload, SHAP chart, risk chart, cert graph, ATT&CK grid) | working |

Verified end-to-end against two real APKs downloaded from F-Droid (kept in `samples/`).
To re-verify after any change:

```bash
python -m pytest tests/ -q
curl -F "file=@samples/fdroid_privacybrowser.apk" http://127.0.0.1:8000/api/analyze
```

---

## Honest limitations

These are real and are stated in the report output, not hidden:

1. **Certificate attribution is weak evidence.** `data/cert_corpus.json` now holds real signers
   from MalwareBazaar samples, but most banking trojans are signed with shared public test/debug
   keys, which are flagged rather than attributed. Only family-unique keys yield a family name.
   Every analysed upload also becomes a certificate observation, so samples sharing a signer are linked.
2. **The ML model is a permission-profile classifier.** NATICUSdroid's 86 features do **not**
   include `BIND_ACCESSIBILITY_SERVICE`, `BIND_NOTIFICATION_LISTENER_SERVICE`,
   `BIND_DEVICE_ADMIN`, `READ_CALL_LOG` or `QUERY_ALL_PACKAGES` — five of the most
   banking-trojan-specific permissions. The rule engine covers exactly this gap, and the
   platform raises an explicit **ML/rule disagreement** flag when they conflict.
3. **The model carries a temporal bias from its corpus.** `REQUEST_INSTALL_PACKAGES` and
   `FOREGROUND_SERVICE` push *benign* because NATICUSdroid's benign half is more modern.
   SHAP surfaces this; the composite score does not rely on the model alone.
4. **Static only.** No sandbox, no native `.so` analysis, no reflection resolution. Every report
   names what it could not see for that specific sample.
5. **Prototype scope.** No auth, no multi-tenancy, single-process, SQLite-free JSON cache.

---

## Layout

```
Final_md.md            the solution specification (start here)
sentinelx/             the application
  app.py               FastAPI routes + static dashboard
  pipeline.py          ingest guards + orchestration + versioned cache
  features.py          androguard -> ML vector + signal bundle
  classify.py          XGBoost + calibration + SHAP
  certgraph.py         certificate extraction + NetworkX graph
  fraud.py             OTP interception + Indian bank targeting
  attack.py            MITRE ATT&CK mapping
  evasion.py           anti-analysis detection + blind spots
  risk.py              composite score + ML/rule reconciliation
  genai.py             narrative + CERT-In draft (template / live LLM)
  report.py            PDF report
  iocs.py              IOC JSON/CSV export
  static/index.html    dashboard
scripts/
  setup.py             one-command bootstrap
  train_model.py       download dataset, train, calibrate, emit metrics
  make_demo.py         build demo cases
  fetch_cert_corpus.py load real certificate data (needs API key)
  real_world_eval.py   full-pipeline detection / FPR on real APKs (+ --replay)
  bazaar.py            in-memory MalwareBazaar client
.env.example           copy to .env and fill in API keys
tests/                 unit + end-to-end tests
models/                trained artifacts + metrics.json
data/                  cert corpus, analysis cache, demo cases
_archive_originals/    the 15 superseded planning documents
```

## API keys (`.env`)

All keys go in one file at the project root:

```bash
copy .env.example .env      # Windows   (cp on macOS/Linux)
```

Then edit `.env`, for example:

```
MALWAREBAZAAR_API_KEY=your-abuse-ch-key
GEMINI_API_KEY=your-google-ai-studio-key
```

`.env` is git-ignored and loaded automatically by the app and every script; a real environment
variable with the same name takes precedence. The project lives under OneDrive, so `.env` is
synced to your Microsoft account like any other file there.

## Real-world evaluation

NATICUSdroid metrics cover the classifier alone. To measure the whole pipeline on real APKs:

```bash
python scripts/real_world_eval.py                                   # benign controls in samples/
python scripts/real_world_eval.py --bazaar --per-family 6           # + real trojans (needs key)
python scripts/real_world_eval.py --bazaar --skip 12 --keep-corpus  # draw samples not seen before
python scripts/real_world_eval.py --replay data/real_eval.json      # re-score cached cases, no downloads
```

With `--bazaar`, each family is split: half seeds the certificate corpus, half is evaluated, so
attribution cannot leak. Results go to `data/real_eval.json` (or `--out`).

## Optional: live GenAI (free options)

Set **one** key in `.env`; the first one found is used.

| Provider | Key variable | Default model | Free tier (Sept 2026) |
|---|---|---|---|
| **Google Gemini** (recommended) | `GEMINI_API_KEY` | `gemini-3.8-flash` | free, no card — [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| **Groq** | `GROQ_API_KEY` | `openai/gpt-oss-120b` | free, no card — [console.groq.com/keys](https://console.groq.com/keys) |
| OpenRouter | `OPENROUTER_API_KEY` | set `SENTINELX_MODEL` to a `:free` model | ~50 free requests/day |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-opus-5` | paid |

Gemini, Groq and OpenRouter are called through their OpenAI-compatible endpoints with the Python
standard library — no extra package. Free tiers often answer `503 high demand`; the call retries
once and then falls back to other free models (`gemini-3.5-flash`, `gemini-flash-latest`,
`gemini-2.5-flash`; override with `SENTINELX_FALLBACK_MODELS`). A live narrative adds ~25 s to an
upload. Tests, `make_demo.py` and `real_world_eval.py` never call the LLM (`make_demo.py --live` does). Free-tier rate limits change without notice, and free tiers may
use prompts for training; the prompt contains only the structured analysis (hashes, package name,
permissions, ATT&CK IDs), never the APK.

Without a key the narrative layer runs deterministic templates labelled `[TEMPLATE]`. With a key,
output is schema-constrained where the provider supports it and then **grounding-checked**: any
hash, malware family, bank or ATT&CK ID not present in the verified analysis rejects the response
and the template is used instead, with the reason recorded. Analysis results are identical either way.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` / `GROQ_API_KEY` / `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` | unset | enables live GenAI narrative |
| `SENTINELX_LLM_PROVIDER` | `auto` | force `gemini`, `groq`, `openrouter` or `anthropic` |
| `SENTINELX_MODEL` | provider default | model for the narrative |
| `MALWAREBAZAAR_API_KEY` | unset | real cert corpus + real-trojan evaluation |
| `SENTINELX_RETENTION_DAYS` | `30` | cached cases older than this are purged at startup (`0` = keep) |
