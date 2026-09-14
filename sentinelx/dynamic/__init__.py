"""Dynamic (behavioural) analysis — the one part of SENTINEL-X that executes a sample.

Everything else in this platform is static parsing from memory. This package is
the deliberate, isolated exception, and it is **opt-in per upload**: an analysis
never detonates anything unless it is explicitly asked to.

Backends all return `schema`'s normalized block:

  * ``none``      - not requested. The default.
  * ``emulator``  - local throwaway rooted AVD + Frida, network sinkholed (Phase C).
  * ``triage``    - Hatching Triage. Submitting **shares the sample**, so it is
                    refused unless the caller passes ``allow_upload=True``, which
                    only the evaluation path does, and only for samples that are
                    already public on MalwareBazaar.
  * ``mock``      - a deterministic scripted run. Used by the tests and the demo
                    cases so the whole feature is exercisable with no emulator
                    and no malware.

A backend that fails returns an ERROR block rather than raising: dynamic analysis
is an enrichment, and a broken sandbox must never cost the caller its static result.
"""
from __future__ import annotations
from typing import Any

from . import behaviours, schema
from ..config import DYNAMIC_BACKEND, DYNAMIC_TIMEOUT

__all__ = ["analyse", "available", "behaviours", "schema"]


def available(backend: str | None = None) -> bool:
    """Whether the configured backend can run without being asked to."""
    return (backend or DYNAMIC_BACKEND) in ("emulator", "mock")


def analyse(apk_bytes: bytes, package: str = "", *,
            backend: str | None = None,
            timeout: int | None = None,
            allow_upload: bool = False,
            sha256: str = "",
            evasion: dict[str, Any] | None = None) -> dict[str, Any]:
    """Detonate a sample and return the normalized dynamic block.

    `evasion` is the static evasion block, used only to decide which of that
    sample's admitted blind spots this run closed.

    Never raises: every failure path produces an ERROR block instead.
    """
    backend = (backend or DYNAMIC_BACKEND or "none").strip().lower()
    timeout = int(timeout or DYNAMIC_TIMEOUT)

    if backend in ("none", "", "off"):
        return schema.skipped()

    if backend not in schema.BACKENDS:
        return schema.error(backend, f"Unknown dynamic backend {backend!r}. "
                                     f"Valid: {', '.join(schema.BACKENDS)}.")

    if backend == "triage" and not allow_upload:
        return schema.error(
            "triage",
            "Refused: submitting to Triage publishes the sample to a third party. "
            "This backend is enabled only for samples that are already public "
            "(the MalwareBazaar evaluation path passes allow_upload=True).")

    try:
        if backend == "mock":
            from .mock import run
        elif backend == "emulator":
            from .emulator import run
        else:
            from .triage import run
    except ImportError as exc:
        return schema.error(backend, f"Backend {backend!r} is not installed: {exc}")

    try:
        block = run(apk_bytes, package, timeout=timeout, sha256=sha256)
    except Exception as exc:                      # noqa: BLE001 - never break the case
        return schema.error(backend, f"{type(exc).__name__}: {exc}")

    if not schema.ran(block):
        return block
    flagged = ({t.get("key") for t in (evasion or {}).get("techniques_detected", [])}
               if evasion is not None else None)
    return behaviours.enrich(block, flagged)
