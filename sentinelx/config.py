"""Shared paths and constants for SENTINEL-X."""
from __future__ import annotations
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Read KEY=VALUE lines from the project .env into os.environ.

    Real environment variables win, so `set KEY=...` in a shell still overrides.
    Deliberately tiny: no quoting rules beyond stripping matching quotes.
    """
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (s.strip() for s in line.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_dotenv()

MODELS = ROOT / "models"
DATA = ROOT / "data"
CASES = DATA / "cases"
DEMO = DATA / "demo"
STATIC = ROOT / "sentinelx" / "static"

for _p in (CASES, DEMO):
    _p.mkdir(parents=True, exist_ok=True)

# Ingestion guards
MAX_APK_BYTES = 100 * 1024 * 1024      # 100 MB
MAX_COMPRESSION_RATIO = 100            # ZIP-bomb guard

# Live GenAI is used only if a key is present; otherwise deterministic templates.
# Free options: Gemini (aistudio.google.com) and Groq (console.groq.com) — no card needed.
LLM_PROVIDERS = {
    # name: (API-key env var, OpenAI-compatible base URL or None, default model)
    "gemini": ("GEMINI_API_KEY",
               "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-3.8-flash"),
    "groq": ("GROQ_API_KEY", "https://api.groq.com/openai/v1", "openai/gpt-oss-120b"),
    "openrouter": ("OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", ""),
    "anthropic": ("ANTHROPIC_API_KEY", None, "claude-opus-5"),
}


def _pick_provider() -> tuple[str, str, str | None, str]:
    """(provider, api_key, base_url, model). provider == 'none' means templates only."""
    wanted = os.environ.get("SENTINELX_LLM_PROVIDER", "auto").strip().lower()
    order = list(LLM_PROVIDERS) if wanted == "auto" else [wanted]
    for name in order:
        if name not in LLM_PROVIDERS:
            break
        key_var, base, default_model = LLM_PROVIDERS[name]
        key = os.environ.get(key_var, "").strip()
        model = os.environ.get("SENTINELX_MODEL", "").strip() or default_model
        if key and model:
            return name, key, base, model
    return "none", "", None, ""


LLM_PROVIDER, LLM_API_KEY, LLM_BASE_URL, GENAI_MODEL = _pick_provider()

# Tried in order when the primary model is overloaded (HTTP 429/5xx) — common on free tiers.
_FALLBACKS = {
    "gemini": ["gemini-3.5-flash", "gemini-flash-latest", "gemini-2.5-flash"],
    "groq": ["openai/gpt-oss-20b"],
}
LLM_FALLBACK_MODELS = [m.strip() for m in
                       os.environ.get("SENTINELX_FALLBACK_MODELS", "").split(",") if m.strip()
                       ] or _FALLBACKS.get(LLM_PROVIDER, [])
ANTHROPIC_API_KEY = LLM_API_KEY if LLM_PROVIDER == "anthropic" else ""

# Case retention: cached analyses older than this are purged at startup (0 = keep forever).
RETENTION_DAYS = int(os.environ.get("SENTINELX_RETENTION_DAYS", "30") or 0)

# --- Dynamic analysis (the only code path that executes a sample) ------------
# Off by default and opt-in per upload: an analysis detonates nothing unless asked.
#   none      static only (default)
#   emulator  local throwaway rooted AVD + Frida, DNS pointed at the local sinkhole
#   triage    Hatching Triage — shares the sample, so it is allowed only for
#             already-public MalwareBazaar samples on the evaluation path
#   mock      scripted events, for tests and for demoing without an emulator
DYNAMIC_BACKEND = os.environ.get("SENTINELX_DYNAMIC_BACKEND", "none").strip().lower()
DYNAMIC_TIMEOUT = int(os.environ.get("SENTINELX_DYNAMIC_TIMEOUT", "180") or 180)
# Dedicated AVD. Must be a `google_apis` (NOT `google_apis_playstore`) image: Play
# Store images are production-signed, so `adb root` is refused and frida-server
# cannot start. scripts/setup_dynamic.py creates it.
AVD_NAME = os.environ.get("SENTINELX_AVD_NAME", "sentinelx_detonator")
ANDROID_SDK = Path(os.environ.get("ANDROID_SDK_ROOT")
                   or os.environ.get("ANDROID_HOME")
                   or Path.home() / "AppData/Local/Android/Sdk")
# Scratch space for the one authorised disk write (the APK handed to `adb install`,
# deleted immediately after). Keep this OUT of OneDrive: Defender quarantines
# malware in synced folders, which corrupts the run and the sync history.
DYNAMIC_WORKDIR = Path(os.environ.get("SENTINELX_DYNAMIC_WORKDIR")
                       or Path(os.environ.get("LOCALAPPDATA", "/tmp"))
                       / "sentinelx" / "detonation")
# Every DNS answer inside the sandbox points here, so C2 traffic is recorded and
# contained instead of reaching the real host. 10.0.2.2 is the emulator's alias
# for the host loopback.
SINKHOLE_IP = os.environ.get("SENTINELX_SINKHOLE_IP", "10.0.2.2")
SINKHOLE_DNS_PORT = int(os.environ.get("SENTINELX_SINKHOLE_DNS_PORT", "5354") or 5354)
SINKHOLE_HTTP_PORT = int(os.environ.get("SENTINELX_SINKHOLE_HTTP_PORT", "8081") or 8081)
TRIAGE_API_KEY = os.environ.get("TRIAGE_API_KEY", "").strip()
TRIAGE_BASE_URL = os.environ.get("TRIAGE_BASE_URL",
                                 "https://tria.ge/api").rstrip("/")

# Indian banking / UPI app packages (target detection). Verify against the Play Store
# before relying on a match — a wrong package name silently never fires.
BANK_PACKAGES = {
    # Public-sector banks
    "com.sbi.lotusintouch": "SBI YONO",
    "com.sbi.SBIFreedomPlus": "SBI YONO Lite",
    "com.onlinesbi.sbi": "SBI",
    "com.Version1": "PNB ONE",
    "com.bankofbaroda.mconnect": "Bank of Baroda bob World",
    "com.canarabank.mobility": "Canara Bank ai1",
    # Private banks
    "com.snapwork.hdfc": "HDFC MobileBanking",
    "net.hdfcbank.customer.android": "HDFC",
    "com.csam.icici.bank.imobile": "ICICI iMobile Pay",
    "com.csam.icici.bank": "ICICI",
    "com.axis.mobile": "Axis Bank",
    "com.msf.kbank.mobile": "Kotak Mobile Banking",
    # UPI / wallets
    "net.one97.paytm": "Paytm",
    "com.phonepe.app": "PhonePe",
    "com.google.android.apps.nbu.paisa.user": "Google Pay (India)",
    "in.org.npci.upiapp": "BHIM UPI",
}

# Brand tokens for package-name impersonation (matched as whole words, so "axis"
# does not fire inside "maxis").
BANK_BRAND_TOKENS = {
    "sbi": "SBI", "yono": "SBI YONO", "pnb": "PNB", "canara": "Canara Bank",
    "bankofbaroda": "Bank of Baroda",
    "hdfc": "HDFC", "icici": "ICICI", "axis": "Axis Bank", "kotak": "Kotak",
    "paytm": "Paytm", "phonepe": "PhonePe", "bhim": "BHIM UPI",
}
