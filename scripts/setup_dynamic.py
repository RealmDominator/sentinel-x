"""One-time setup for local dynamic analysis. Run once, then detonate freely.

    python scripts/setup_dynamic.py            # check what is missing
    python scripts/setup_dynamic.py --install  # create the AVD + push frida-server

What it provisions:

  * a dedicated **google_apis** (NOT google_apis_playstore) x86_64 AVD. Play
    Store images are production-signed, so `adb root` is refused and frida-server
    cannot run - which is why the AVD you already use for app development will
    not work here;
  * an arch-matched frida-server binary at /data/local/tmp on that AVD;
  * a Windows Defender exclusion reminder for the detonation work directory.

Nothing here downloads or touches malware.
"""
from __future__ import annotations
import argparse
import lzma
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.config import ANDROID_SDK, AVD_NAME, DYNAMIC_WORKDIR  # noqa: E402

SYSTEM_IMAGE = "system-images;android-33;google_apis;x86_64"
EXE = ".exe" if os.name == "nt" else ""
OK, BAD, WARN = "[ ok ]", "[fail]", "[warn]"


def tool(*parts: str) -> Path:
    return ANDROID_SDK.joinpath(*parts).with_suffix(EXE)


SDKMANAGER = ANDROID_SDK / "cmdline-tools" / "latest" / "bin" / (
    "sdkmanager.bat" if os.name == "nt" else "sdkmanager")
AVDMANAGER = ANDROID_SDK / "cmdline-tools" / "latest" / "bin" / (
    "avdmanager.bat" if os.name == "nt" else "avdmanager")
ADB, EMULATOR = tool("platform-tools", "adb"), tool("emulator", "emulator")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("      $", " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], **kw)


def avds() -> list[str]:
    if not EMULATOR.exists():
        return []
    out = subprocess.run([str(EMULATOR), "-list-avds"], capture_output=True)
    return out.stdout.decode("utf-8", "replace").split()


def frida_version() -> str:
    try:
        import frida
        return frida.__version__
    except ImportError:
        return ""


def check() -> bool:
    print("SENTINEL-X dynamic analysis — readiness\n")
    rows = [
        ("Android SDK", ANDROID_SDK.exists(), str(ANDROID_SDK)),
        ("adb", ADB.exists() or bool(shutil.which("adb")), str(ADB)),
        ("emulator", EMULATOR.exists(), str(EMULATOR)),
        ("cmdline-tools", SDKMANAGER.exists(), str(SDKMANAGER)),
        ("frida (python)", bool(frida_version()),
         frida_version() or "pip install frida frida-tools"),
        (f"AVD {AVD_NAME!r}", AVD_NAME in avds(),
         ", ".join(avds()) or "no AVDs found"),
        ("work dir (keep out of OneDrive)",
         "OneDrive" not in str(DYNAMIC_WORKDIR), str(DYNAMIC_WORKDIR)),
    ]
    for name, ok, detail in rows:
        print(f"  {OK if ok else BAD} {name:34s} {detail}")
    ready = all(ok for _, ok, _ in rows)
    print("\n" + ("Ready. Set SENTINELX_DYNAMIC_BACKEND=emulator in .env."
                  if ready else
                  "Not ready — re-run with --install to provision what is missing."))
    if "OneDrive" in str(DYNAMIC_WORKDIR):
        print(f"  {WARN} Defender quarantines malware inside synced folders. Set "
              "SENTINELX_DYNAMIC_WORKDIR to a local path.")
    print(f"\n  {WARN} Add a Defender exclusion for {DYNAMIC_WORKDIR} or the APK "
          "will be quarantined mid-run:")
    print(f'      Add-MpPreference -ExclusionPath "{DYNAMIC_WORKDIR}"')
    return ready


def install_frida_server() -> None:
    version = frida_version()
    if not version:
        print(f"  {BAD} install the python package first: pip install frida frida-tools")
        return
    name = f"frida-server-{version}-android-x86_64"
    url = (f"https://github.com/frida/frida/releases/download/{version}/{name}.xz")
    dest = DYNAMIC_WORKDIR / name
    DYNAMIC_WORKDIR.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        print(f"      downloading {url}")
        with urllib.request.urlopen(url, timeout=120) as r:
            dest.write_bytes(lzma.decompress(r.read()))
    print(f"  {OK} frida-server {version} at {dest}")
    print("      push it once the AVD is running:")
    print(f'      adb push "{dest}" /data/local/tmp/frida-server')
    print("      adb shell chmod 755 /data/local/tmp/frida-server")


def install() -> None:
    if not SDKMANAGER.exists():
        print(f"  {BAD} cmdline-tools missing. In Android Studio: Settings > "
              "Languages & Frameworks > Android SDK > SDK Tools > "
              "'Android SDK Command-line Tools'.")
        return
    print(f"  ..   installing {SYSTEM_IMAGE}")
    run([SDKMANAGER, SYSTEM_IMAGE])
    if AVD_NAME in avds():
        print(f"  {OK} AVD {AVD_NAME!r} already exists")
    else:
        print(f"  ..   creating AVD {AVD_NAME!r}")
        run([AVDMANAGER, "create", "avd", "-n", AVD_NAME, "-k", SYSTEM_IMAGE,
             "-d", "pixel_5", "--force"], input=b"no\n")
    install_frida_server()
    print("\nRe-run without --install to verify.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install", action="store_true",
                    help="provision the AVD and frida-server")
    args = ap.parse_args()
    if args.install:
        install()
    else:
        sys.exit(0 if check() else 1)
