"""Local detonation: a throwaway rooted AVD, Frida instrumentation, no route out.

The containment argument, in order of importance:

1. **Nothing reaches the internet.** The emulator boots with its DNS pointed at
   `sinkhole.py`, which answers every lookup with the sinkhole address. C2
   traffic is recorded on the host instead of delivered.
2. **The device is disposable.** `-wipe-data -no-snapshot-save` means the machine
   the sample infects exists only for this run and is discarded at the end.
3. **The host keeps no sample.** The APK is written once, to a work directory
   outside OneDrive (Defender quarantines malware inside synced folders), because
   `adb install` needs a path - and is deleted in a `finally` block.

This module never raises: `dynamic.analyse()` turns any failure here into an
ERROR block so a broken sandbox cannot cost the caller its static result.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from . import schema
from .sinkhole import Sinkhole
from ..config import (ANDROID_SDK, AVD_NAME, DYNAMIC_WORKDIR, SINKHOLE_DNS_PORT,
                      SINKHOLE_IP)

HOOKS = Path(__file__).with_name("frida_hooks.js")
BOOT_TIMEOUT = 180
_EXE = ".exe" if os.name == "nt" else ""


def _tool(*parts: str) -> str:
    """Path to an SDK tool, falling back to whatever is on PATH."""
    candidate = ANDROID_SDK.joinpath(*parts).with_suffix(_EXE)
    if candidate.exists():
        return str(candidate)
    return shutil.which(Path(parts[-1]).name) or str(candidate)


ADB = _tool("platform-tools", "adb")
EMULATOR = _tool("emulator", "emulator")


def _adb(*args: str, serial: str = "", timeout: int = 60) -> str:
    cmd = [ADB] + (["-s", serial] if serial else []) + list(args)
    out = subprocess.run(cmd, capture_output=True, timeout=timeout)
    return out.stdout.decode("utf-8", "replace").strip()


def _avd_exists() -> bool:
    try:
        listed = subprocess.run([EMULATOR, "-list-avds"], capture_output=True,
                                timeout=30).stdout.decode("utf-8", "replace")
    except Exception:
        return False
    return AVD_NAME in listed.split()


def _boot(port: int = 5584) -> tuple[subprocess.Popen, str]:
    """Start the AVD headless with its DNS captured, and wait for boot."""
    serial = f"emulator-{port}"
    proc = subprocess.Popen(
        [EMULATOR, "-avd", AVD_NAME, "-port", str(port),
         "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot-save",
         "-wipe-data", "-writable-system",
         # Every name the sample resolves comes back as the sinkhole.
         "-dns-server", f"{SINKHOLE_IP}:{SINKHOLE_DNS_PORT}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    deadline = time.monotonic() + BOOT_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("the emulator exited during boot")
        if _adb("shell", "getprop", "sys.boot_completed", serial=serial,
                timeout=20) == "1":
            return proc, serial
        time.sleep(3)
    raise TimeoutError(f"the emulator did not finish booting in {BOOT_TIMEOUT}s")


def _start_frida_server(serial: str) -> None:
    _adb("root", serial=serial, timeout=30)
    time.sleep(2)
    _adb("shell", "/data/local/tmp/frida-server -D", serial=serial, timeout=20)
    time.sleep(2)


def _collect(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Fold Frida hook reports into the normalized block's fields."""
    observed: dict[str, Any] = {
        "api_calls": [], "sms_sent": [], "dynamic_code_loading": [],
        "runtime_permissions_requested": [],
        "overlay_observed": False, "accessibility_used": False,
        "sms_intercepted": False,
    }
    for m in messages:
        kind = m.get("kind", "")
        if kind == "ready":
            continue
        observed["api_calls"].append({"class": m.get("class", ""),
                                      "method": m.get("method", ""),
                                      "args_summary": m.get("args_summary", ""),
                                      "count": m.get("count", 1)})
        if kind == "sms_sent":
            summary = m.get("args_summary", "")
            to = summary.split("to=")[-1].split(" ")[0] if "to=" in summary else "unknown"
            observed["sms_sent"].append({"to": to, "body_summary": summary[:80]})
        elif kind == "sms_intercepted":
            observed["sms_intercepted"] = True
        elif kind == "overlay":
            observed["overlay_observed"] = True
        elif kind == "accessibility":
            observed["accessibility_used"] = True
        elif kind == "code_load":
            observed["dynamic_code_loading"].append(
                {"loader": m.get("class", "").rsplit(".", 1)[-1],
                 "path_or_hash": m.get("args_summary", "")})
        elif kind == "permission":
            observed["runtime_permissions_requested"].append(m.get("args_summary", ""))
        elif kind == "content_query" and "sms" in m.get("args_summary", "").lower():
            observed["sms_intercepted"] = True
    return observed


def _instrument(package: str, serial: str, timeout: int) -> list[dict[str, Any]]:
    """Spawn the app under Frida and collect hook reports for `timeout` seconds."""
    import frida                                   # imported late: optional dependency

    device = frida.get_device(serial, timeout=30)
    messages: list[dict[str, Any]] = []
    pid = device.spawn([package])
    session = device.attach(pid)
    script = session.create_script(HOOKS.read_text(encoding="utf-8"))
    script.on("message", lambda message, _data:
              messages.append(message["payload"])
              if message.get("type") == "send" and message.get("payload") else None)
    script.load()
    device.resume(pid)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # Nudge the UI so code behind the first screen actually runs.
        _adb("shell", "monkey", "-p", package, "--throttle", "300", "-v", "40",
             serial=serial, timeout=40)
        time.sleep(5)
    try:
        session.detach()
    except Exception:
        pass
    return messages


def run(apk_bytes: bytes, package: str = "", *, timeout: int = 180,
        sha256: str = "") -> dict[str, Any]:
    if not package:
        return schema.error("emulator", "the APK's package name could not be "
                                        "determined, so it cannot be launched")
    if not Path(ADB).exists() and not shutil.which("adb"):
        return schema.error("emulator", "adb was not found; set ANDROID_SDK_ROOT "
                                        "or run scripts/setup_dynamic.py")
    if not _avd_exists():
        return schema.error("emulator", f"AVD {AVD_NAME!r} does not exist. Run "
                                        "scripts/setup_dynamic.py to create it.")
    try:
        import frida  # noqa: F401
    except ImportError:
        return schema.error("emulator", "the `frida` package is not installed "
                                        "(pip install frida frida-tools)")

    started = time.monotonic()
    DYNAMIC_WORKDIR.mkdir(parents=True, exist_ok=True)
    # The single authorised disk write, outside OneDrive, removed in `finally`.
    apk_path = DYNAMIC_WORKDIR / f"{(sha256 or 'sample')[:16]}.apk"
    proc = None
    serial = ""
    status, detail = "COMPLETED", ""
    messages: list[dict[str, Any]] = []

    with Sinkhole() as sink:
        try:
            apk_path.write_bytes(apk_bytes)
            proc, serial = _boot()
            _start_frida_server(serial)
            if "Success" not in _adb("install", "-g", "-t", str(apk_path),
                                     serial=serial, timeout=180):
                raise RuntimeError("the sample could not be installed on the device")
            messages = _instrument(package, serial, timeout)
        except TimeoutError as exc:
            status, detail = "TIMEOUT", str(exc)
        except Exception as exc:                   # noqa: BLE001
            return schema.error("emulator", f"{type(exc).__name__}: {exc}")
        finally:
            apk_path.unlink(missing_ok=True)
            if serial:
                _adb("emu", "kill", serial=serial, timeout=30)
            if proc is not None:
                try:
                    proc.wait(timeout=20)
                except Exception:
                    proc.kill()

        observed = _collect(messages)
        observed["network"] = sink.observations
        if sink.errors:
            detail = (detail + " " + " ".join(sink.errors)).strip()

    detail = (detail + " Network was sinkholed; nothing left the host.").strip()
    return schema.build("emulator", status, detail=detail,
                        duration_seconds=time.monotonic() - started, **observed)
