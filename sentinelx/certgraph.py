"""Signing-certificate extraction and NetworkX relationship graph.

Attribution pathway 1: if the sample's signer fingerprint matches a known-family
entry in data/cert_corpus.json, we attribute it. The graph grows with every
analysed sample, and a D3-ready subgraph is returned for the dashboard.

Shared keys are not attribution. Evaluation against real MalwareBazaar samples
showed the corpus is dominated by the public AOSP test key (CN=Android) and a
widely copied debug key, each seen under 5-6 unrelated families. A fingerprint
that the corpus associates with more than one family, or a generic subject CN,
therefore yields a `shared_or_test_key` flag instead of a family name.
"""
from __future__ import annotations
import hashlib
import json
from collections import defaultdict
from functools import lru_cache
from typing import Any

import networkx as nx

from .config import CASES, DATA

MAX_PRIOR = 12   # keep the D3 view readable

# Subject CNs that thousands of unrelated developers share (default/test keystores).
GENERIC_CNS = {"", "android", "android debug", "unknown", "debugging", "test",
               "testkey", "platform", "release", "key0", "none"}


@lru_cache(maxsize=1)
def corpus() -> list[dict[str, Any]]:
    path = DATA / "cert_corpus.json"
    if not path.exists():
        return []
    return json.loads(path.read_text()).get("certificates", [])


def reload_corpus() -> None:
    """Drop cached corpus views after data/cert_corpus.json is rewritten."""
    corpus.cache_clear()
    _families_by_fingerprint.cache_clear()


@lru_cache(maxsize=1)
def _families_by_fingerprint() -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for e in corpus():
        out[e["sha256"]].add(e.get("family", "Unknown"))
    return out


def _families_by_cn() -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for e in corpus():
        out[(e.get("subject_cn") or "").strip().lower()].add(e.get("family", "Unknown"))
    return out


def is_generic_cn(cn: str | None) -> bool:
    return (cn or "").strip().lower() in GENERIC_CNS


def _build_base_graph() -> nx.Graph:
    g = nx.Graph()
    for entry in corpus():
        fp = entry["sha256"]
        fam = entry.get("family", "Unknown")
        g.add_node(fp, kind="certificate", label=entry.get("subject_cn", fp[:12]),
                   family=fam, known=True)
        g.add_node(fam, kind="family", label=fam)
        g.add_edge(fp, fam, relation="ATTRIBUTED_TO")
    return g


def _name(x) -> str:
    """Readable name from an asn1crypto Name: CN, else O/OU/C, else 'unknown'."""
    try:
        native = x.native
    except Exception:
        return "unknown"
    for key in ("common_name", "organization_name", "organizational_unit_name",
                "country_name"):
        if native.get(key):
            val = native[key]
            return ", ".join(val) if isinstance(val, list) else str(val)
    return "unknown"


def extract_certificate(apk) -> dict[str, Any]:
    """Parse the APK's X.509 signer (v1, then v2/v3 schemes). {} when unsigned."""
    certs, scheme = [], None
    for scheme_name, getter in (("v1", "get_certificates_v1"), ("v2", "get_certificates_v2"),
                                ("v3", "get_certificates_v3"), ("v1", "get_certificates")):
        try:
            certs = list(getattr(apk, getter)() or [])
        except Exception:
            certs = []
        if certs:
            scheme = scheme_name
            break
    if not certs:
        return {}
    c = certs[0]
    try:
        der = c.dump()
    except Exception:
        return {}

    subject, issuer = _name(c.subject), _name(c.issuer)
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject_cn": subject,
        "issuer_cn": issuer,
        "self_signed": subject == issuer,
        "serial": str(getattr(c, "serial_number", "")),
        "signature_scheme": scheme,
    }


def prior_samples_signed_by(fp: str, exclude_sha256: str) -> list[dict[str, Any]]:
    """Previously analysed cases whose signer fingerprint is `fp`.

    This is what makes the graph grow: every cached analysis is a certificate
    observation, so a new upload signed with the same key as an earlier one is
    linked to it even when the key is absent from the seed corpus.
    """
    out = []
    for path in CASES.glob("*.json"):
        if path.stem == exclude_sha256:
            continue
        try:
            case = json.loads(path.read_text())
        except Exception:
            continue
        signer = (case.get("attribution", {}).get("certificate") or {}).get("sha256")
        if signer == fp:
            out.append({"sha256": case.get("hashes", {}).get("sha256", path.stem),
                        "package": case.get("package", ""),
                        "filename": case.get("filename", ""),
                        "severity": case.get("risk", {}).get("severity"),
                        "analysed_at": case.get("analysed_at")})
    return sorted(out, key=lambda d: d.get("analysed_at") or "", reverse=True)[:MAX_PRIOR]


def attribute(cert: dict[str, Any]) -> tuple[list[str], str, list[str]]:
    """(families, confidence, signer_flags) for one certificate."""
    if not cert:
        return [], "NONE", []
    fp, cn = cert["sha256"], cert.get("subject_cn")
    flags: list[str] = []

    exact = _families_by_fingerprint().get(fp, set())
    if len(exact) > 1 or (exact and is_generic_cn(cn)):
        flags.append("shared_or_test_key")
        return [], "NONE", flags
    if exact:
        return sorted(exact), "HIGH", flags

    if is_generic_cn(cn):
        flags.append("generic_subject_cn")
        return [], "NONE", flags
    by_cn = _families_by_cn().get((cn or "").strip().lower(), set())
    if len(by_cn) == 1:
        return sorted(by_cn), "MEDIUM", flags     # distinctive CN, different key
    return [], "NONE", flags


FLAG_TEXT = {
    "shared_or_test_key": "Signed with a key shared across unrelated malware families "
                          "(public test or leaked debug key) - not usable for attribution.",
    "generic_subject_cn": "Signer subject CN is a default keystore name - "
                          "CN-based attribution skipped.",
}


def analyse(cert: dict[str, Any], sample_sha256: str) -> dict[str, Any]:
    """Attribute the certificate and return a D3-ready subgraph."""
    g = _build_base_graph()
    related_families, confidence, flags = attribute(cert)
    prior: list[dict[str, Any]] = []

    if cert:
        fp = cert["sha256"]
        g.add_node(fp, kind="certificate", label=cert.get("subject_cn", fp[:12]),
                   family=None, known=fp in _families_by_fingerprint())
        g.add_node(sample_sha256, kind="sample",
                   label=f"sample:{sample_sha256[:10]}")
        g.add_edge(sample_sha256, fp, relation="SIGNED_BY")

        # Linking every app signed with the AOSP test key would be noise, not intel.
        if "shared_or_test_key" not in flags:
            prior = prior_samples_signed_by(fp, sample_sha256)
        for p in prior:
            g.add_node(p["sha256"], kind="prior_sample",
                       label=p["package"] or f"sample:{p['sha256'][:10]}",
                       severity=p["severity"])
            g.add_edge(p["sha256"], fp, relation="SIGNED_BY")

        for fam in related_families:
            g.add_edge(fp, fam, relation="ATTRIBUTED_TO")

    # Keep the visualisation readable: sample, its signer, prior samples, attributed
    # families. Neighbours of a shared key are deliberately not expanded.
    if cert:
        keep = {sample_sha256, cert["sha256"]} | set(related_families)
        keep |= {p["sha256"] for p in prior}
        sub = g.subgraph(keep).copy()
    else:
        sub = nx.Graph()

    return {
        "certificate": cert,
        "related_families": related_families,
        "confidence": confidence,
        "signer_flags": [{"flag": f, "text": FLAG_TEXT[f]} for f in flags],
        "shared_signer_samples": prior,
        "graph": {
            "nodes": [{"id": n, **{k: v for k, v in d.items() if k != "known"},
                       "known": bool(d.get("known", False))}
                      for n, d in sub.nodes(data=True)],
            "links": [{"source": u, "target": v, "relation": d.get("relation", "")}
                      for u, v, d in sub.edges(data=True)],
        },
        "corpus_size": len(corpus()),
    }
