"""Feature extraction from an androguard APK object.

Two products:
  * `ml_vector(apk)`   -> np.ndarray aligned to models/feature_vocab.json (86 perms) for XGBoost.
  * `signal_bundle(apk)` -> rich dict (perms, packages, certs, strings) used by the rule modules.

The NATICUSdroid columns are full Android permission names (e.g. 'android.permission.READ_SMS'),
which is exactly what androguard's get_permissions() returns, so the alignment is direct.
"""
from __future__ import annotations
import json
import re
from functools import lru_cache
from typing import Any

import numpy as np

from .config import BANK_PACKAGES, MODELS

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@lru_cache(maxsize=1)
def feature_vocab() -> list[str]:
    return json.loads((MODELS / "feature_vocab.json").read_text())["features"]


def _permissions(apk) -> list[str]:
    try:
        return list(apk.get_permissions() or [])
    except Exception:
        return []


def ml_vector(apk) -> np.ndarray:
    """Binary presence vector over the model's 86 permission columns."""
    perms = set(_permissions(apk))
    vocab = feature_vocab()
    return np.array([[1.0 if p in perms else 0.0 for p in vocab]], dtype=np.float32)


def _short_perms(perms: list[str]) -> set[str]:
    """Short permission names, e.g. READ_SMS."""
    return {p.rsplit(".", 1)[-1] for p in perms}


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Intent-filter actions that imply a BIND_* capability even when an obfuscated
# manifest omits the android:permission attribute.
ACTION_IMPLIES = {
    "android.accessibilityservice.AccessibilityService":
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.service.notification.NotificationListenerService":
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.app.action.DEVICE_ADMIN_ENABLED":
        "android.permission.BIND_DEVICE_ADMIN",
}


def component_permissions(apk) -> list[str]:
    """Permissions guarding manifest components (<service android:permission=...>).

    The most banking-trojan-specific capabilities - BIND_ACCESSIBILITY_SERVICE,
    BIND_NOTIFICATION_LISTENER_SERVICE, BIND_DEVICE_ADMIN - are declared here,
    not as <uses-permission>, so get_permissions() never returns them. Measured
    on 23 real MalwareBazaar trojans: 0/23 via get_permissions().
    """
    found: set[str] = set()
    try:
        root = apk.get_android_manifest_xml()
        for el in root.iter("service", "receiver", "activity", "provider"):
            if perm := el.get(ANDROID_NS + "permission"):
                found.add(perm)
            for action in el.iter("action"):
                if implied := ACTION_IMPLIES.get(action.get(ANDROID_NS + "name") or ""):
                    found.add(implied)
    except Exception:
        pass
    return sorted(found)


def signal_bundle(apk) -> dict[str, Any]:
    perms = _permissions(apk)
    comp_perms = component_permissions(apk)
    # Rule modules see both; the ML vector (ml_vector) stays uses-permission only,
    # matching how NATICUSdroid was built.
    short = _short_perms(perms) | _short_perms(comp_perms)

    activities, services, receivers = [], [], []
    package = ""
    try:
        package = apk.get_package() or ""
    except Exception:
        pass
    for getter, sink in ((("get_activities",), activities),
                         (("get_services",), services),
                         (("get_receivers",), receivers)):
        try:
            sink.extend(getattr(apk, getter[0])() or [])
        except Exception:
            pass

    # Referenced package names across manifest components (bank-targeting hints).
    referenced = set()
    for comp in activities + services + receivers:
        for tok in re.findall(r"[a-zA-Z0-9_.]+", comp or ""):
            if tok.count(".") >= 2:
                referenced.add(tok)
    referenced.add(package)

    strings, urls, ips, bank_refs = _strings(apk)

    return {
        "package": package,
        "permissions": perms,
        "component_permissions": comp_perms,
        "short_permissions": sorted(short),
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "referenced_packages": sorted(referenced),
        # Bank app package names found as DEX string constants — where overlay
        # trojans keep their target lists.
        "string_referenced_packages": sorted(bank_refs),
        "urls": sorted(set(urls))[:50],
        "ips": sorted(set(ips))[:50],
        "n_strings": len(strings),
    }


def _strings(apk) -> tuple[list[str], list[str], list[str], set[str]]:
    """Pull candidate strings (DEX) for URL/IP IOCs and bank targets. Best-effort."""
    urls: list[str] = []
    ips: list[str] = []
    collected: list[str] = []
    bank_refs: set[str] = set()
    url_budget_spent = False
    try:
        for dex in apk.get_all_dex():
            text = dex.decode("latin-1", "ignore")
            # Every DEX is scanned for bank targets; only URL/IP extraction is capped.
            bank_refs.update(pkg for pkg in BANK_PACKAGES
                             if pkg in text and re.search(rf"(?<![\w.]){re.escape(pkg)}(?![\w])", text))
            collected.append("")  # count marker
            if url_budget_spent:
                continue
            urls.extend(URL_RE.findall(text)[:200])
            ips.extend(IP_RE.findall(text)[:200])
            url_budget_spent = len(urls) > 200
    except Exception:
        pass
    # DEX string data is packed end to end, so one regex match can swallow several
    # URLs ("https://8https://bugs.kde.org..."). Split them apart and drop fragments.
    urls = [part.rstrip(".,;)") for u in urls for part in re.split(r"(?=https?://)", u)
            if re.match(r"https?://[\w-]+(\.[\w-]+)+", part)]
    # Filter out schema/framework noise from URLs.
    urls = [u for u in urls if "schemas.android.com" not in u
            and "w3.org" not in u and "apache.org" not in u]
    return collected, urls, ips, bank_refs
