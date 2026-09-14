"""Scripted stand-in for a real detonation.

Exists so the whole dynamic path — pipeline wiring, risk override, PDF section,
IOC export, dashboard panel — can be exercised on a machine with no emulator and
with no malware present. The tests use it; a user can set
``SENTINELX_DYNAMIC_BACKEND=mock`` to see the feature end to end.

The events below are **fabricated and labelled as such** in the block's `detail`
field, which every consumer surfaces. Nothing here is presented as a real
observation of the uploaded file.
"""
from __future__ import annotations
import time
from typing import Any

from . import schema

DETAIL = ("SIMULATED RUN — scripted events from the mock backend, not observations "
          "of this sample. Set SENTINELX_DYNAMIC_BACKEND=emulator for a real detonation.")


def run(apk_bytes: bytes, package: str = "", *, timeout: int = 180,
        sha256: str = "") -> dict[str, Any]:
    started = time.monotonic()
    pkg = package or "com.example.sample"

    observed = {
        "runtime_permissions_requested": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "api_calls": [
            {"class": "android.telephony.SmsMessage", "method": "createFromPdu",
             "args_summary": "incoming SMS PDU", "count": 3},
            {"class": "android.telephony.TelephonyManager", "method": "getDeviceId",
             "args_summary": "", "count": 1},
            {"class": "android.view.WindowManager", "method": "addView",
             "args_summary": "TYPE_APPLICATION_OVERLAY", "count": 2},
            {"class": "dalvik.system.DexClassLoader", "method": "<init>",
             "args_summary": "/data/data/%s/files/payload.jar" % pkg, "count": 1},
            {"class": "java.net.HttpURLConnection", "method": "connect",
             "args_summary": "POST /gate.php", "count": 4},
        ],
        "network": {
            "dns_queries": ["c2-panel.mock.invalid", "cdn.mock.invalid"],
            "http_requests": [
                {"method": "POST", "host": "c2-panel.mock.invalid", "path": "/gate.php"},
                {"method": "GET", "host": "cdn.mock.invalid", "path": "/payload.jar"},
            ],
            "contacted_ips": ["10.0.2.2"],
        },
        "dynamic_code_loading": [
            {"loader": "DexClassLoader",
             "path_or_hash": f"/data/data/{pkg}/files/payload.jar"},
        ],
        "overlay_observed": True,
        "accessibility_used": True,
        "sms_intercepted": True,
        "sms_sent": [{"to": "+910000000000", "body_summary": "<forwarded OTP>"}],
        "artifacts": {"logcat_lines": 412, "pcap_captured": True},
    }

    return schema.build("mock", "COMPLETED", detail=DETAIL,
                        duration_seconds=time.monotonic() - started, **observed)
