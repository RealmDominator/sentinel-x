"""Anti-analysis / evasion profiling and the report's blind-spot section.

Static string scanning over the DEX bytes. This module is also responsible for
being honest: whatever it detects here becomes an explicit statement in the
report about what static analysis could NOT see for this specific sample.

Indicators are split by strength. Reflection, javax.crypto and debugger checks
appear in almost every modern APK (AndroidX, OkHttp, Kotlin runtime), so on
their own they can only rate the sample LOW. Emulator fingerprints, root
checks, runtime DEX loading and commercial packers are rare in benign apps and
drive MEDIUM/HIGH. Needles are matched as DEX type descriptors where possible
("Ldalvik/system/DexClassLoader;") rather than bare words, which previously
matched ordinary library code ("generic", "getInstance").
"""
from __future__ import annotations
from typing import Any

# (key, needles, label, strength)
PATTERNS: list[tuple[str, list[bytes], str, str]] = [
    ("anti_emulator", [b"goldfish", b"ranchu", b"google_sdk", b"Genymotion",
                       b"vbox86", b"generic_x86", b"sdk_gphone"],
     "Emulator fingerprint checks", "strong"),
    ("root_detection", [b"/system/xbin/su", b"Superuser.apk", b"test-keys",
                        b"/system/bin/su", b"eu.chainfire.supersu",
                        b"com.topjohnwu.magisk"],
     "Root detection", "strong"),
    ("dynamic_loading", [b"Ldalvik/system/DexClassLoader;",
                         b"Ldalvik/system/InMemoryDexClassLoader;"],
     "Runtime DEX loading", "strong"),
    ("anti_debugger", [b"isDebuggerConnected", b"waitingForDebugger",
                       b"TracerPid"],
     "Debugger detection", "weak"),
    ("reflection", [b"Ljava/lang/reflect/Method;"],
     "Reflection-based API concealment", "weak"),
    ("crypto", [b"Ljavax/crypto/Cipher;"],
     "Runtime string/payload decryption", "weak"),
]

# Native stubs shipped by commercial Android packers / protectors.
PACKER_LIBS = {
    "libjiagu": "Qihoo 360 Jiagu",
    "libsecexe": "Bangcle",
    "libDexHelper": "SecNeo / Bangcle",
    "libshella": "Tencent Legu",
    "libshellx": "Tencent Legu",
    "libprotectClass": "APKProtect",
}

BLIND_SPOTS = {
    "reflection": "API calls hidden behind reflection are not resolved — "
                  "static API inventory may be incomplete.",
    "dynamic_loading": "A DEX payload is loaded at runtime and is not present "
                       "in the analysed file — its behaviour is unseen.",
    "crypto": "Strings/config appear to be decrypted at runtime — any C2 URL "
              "may be encrypted at rest and not statically recoverable.",
    "native_libs": "Native .so libraries are present but are not disassembled "
                   "by this platform — native payload behaviour is unseen.",
    "packer": "The APK is wrapped by a commercial packer — the real DEX is "
              "decrypted at runtime, so permissions and strings may be all that "
              "static analysis can see.",
}

LABELS = {k: label for k, _, label, _ in PATTERNS}
STRENGTH = {k: strength for k, _, _, strength in PATTERNS}
STRENGTH.update({"packer": "strong", "native_libs": "info"})


def summarise(found: dict[str, str]) -> dict[str, Any]:
    """Turn {technique_key: label} into the case-JSON evasion block.

    Shared with scripts/make_demo.py so demo cases are scored by the same rules.
    """
    strong = sum(1 for k in found if STRENGTH.get(k) == "strong")
    weak = sum(1 for k in found if STRENGTH.get(k) == "weak")
    level = ("HIGH" if strong >= 2 or "packer" in found else
             "MEDIUM" if strong == 1 else
             "LOW" if weak else "NONE")

    blind = [BLIND_SPOTS[k] for k in found if k in BLIND_SPOTS]
    if not blind:
        blind.append("No specific static-analysis blind spots detected for this "
                     "sample beyond the platform's general static-only scope.")

    return {
        "sophistication": level,
        "techniques_detected": [{"key": k, "label": v,
                                 "strength": STRENGTH.get(k, "weak")}
                                for k, v in found.items()],
        "evasion_count": strong + weak,
        "strong_indicators": strong,
        "blind_spots": blind,
    }


def analyse(apk) -> dict[str, Any]:
    found: dict[str, str] = {}
    try:
        blobs = list(apk.get_all_dex())
    except Exception:
        blobs = []

    for key, needles, label, _ in PATTERNS:
        for blob in blobs:
            if any(n in blob for n in needles):
                found[key] = label
                break

    try:
        so_files = [f for f in apk.get_files()
                    if f.startswith("lib/") and f.endswith(".so")]
    except Exception:
        so_files = []
    packers = sorted({name for f in so_files for stub, name in PACKER_LIBS.items()
                      if f.rsplit("/", 1)[-1].startswith(stub)})
    if packers:
        found["packer"] = "Commercial packer: " + ", ".join(packers)
    if so_files:
        found["native_libs"] = "Native .so libraries bundled"

    return summarise(found)
