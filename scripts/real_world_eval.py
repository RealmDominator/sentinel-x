"""Evaluate the FULL pipeline (not just the ML model) on real APKs.

NATICUSdroid metrics measure the permission classifier on its own corpus. This
script measures what an analyst actually cares about: does the platform's
headline verdict flag real banking trojans while leaving real benign apps alone?

    # benign controls only (works offline, uses samples/*.apk)
    python scripts/real_world_eval.py

    # + real banking trojans from MalwareBazaar, analysed in memory
    set MALWAREBAZAAR_API_KEY=...
    python scripts/real_world_eval.py --bazaar --per-family 6

    # + malware APKs you already hold locally (e.g. AndroZoo / CIC-AndMal)
    python scripts/real_world_eval.py --malware D:/quarantine/apks

With --bazaar, each family's samples are split alternately: one half seeds the
certificate corpus, the other half is evaluated. Evaluated samples never have
their own certificate in the corpus, so attribution cannot leak into the score.

A sample counts as FLAGGED when the headline verdict is not BENIGN or the
composite severity is MEDIUM or above. Writes data/real_eval.json.
"""
from __future__ import annotations
import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from loguru import logger  # noqa: E402
logger.remove()

import os  # noqa: E402
# Batch evaluation measures detection, not prose: never spend free-tier LLM quota here.
os.environ["SENTINELX_LLM_PROVIDER"] = "none"

from sentinelx import certgraph, pipeline  # noqa: E402

OUT = ROOT / "data" / "real_eval.json"


def flagged(case: dict) -> bool:
    return (case["risk"]["headline_verdict"] != "BENIGN"
            or case["risk"]["severity"] in ("MEDIUM", "HIGH", "CRITICAL"))


def run_one(data: bytes, name: str, label: str, family: str = "") -> dict | None:
    try:
        pipeline.validate(data)
        case = pipeline.analyse(data, None, name, use_cache=False)
    except (pipeline.IngestError, pipeline.ParseError) as exc:
        print(f"  skip {name}: {exc}")
        return None
    return row_for(case, name, label, family)


def rescore(case: dict) -> dict:
    """Recompute rule-derived blocks on a cached case with the CURRENT code.

    Parsing, the ML verdict and evasion are kept; attribution, fraud, ATT&CK and
    risk are rebuilt. Lets rule changes be measured without re-downloading malware.
    """
    from sentinelx import attack, fraud, risk
    case["attribution"] = certgraph.analyse(case["attribution"].get("certificate") or {},
                                            case["hashes"]["sha256"])
    case["fraud"] = fraud.analyse(case["signals"])
    case["attack"] = attack.analyse(case["signals"], case["fraud"])
    completeness = 1.0 if case.get("analysis_completeness") == "FULL" else 0.85
    case["risk"] = risk.compute(case["classification"], case["fraud"],
                                case["attribution"], case["evasion"], completeness)
    return case


def row_for(case: dict, name: str, label: str, family: str = "") -> dict:
    row = {
        "name": name, "label": label, "family": family,
        "sha256": case["hashes"]["sha256"], "package": case["package"],
        "ml_verdict": case["classification"]["verdict"],
        "ml_p_malicious": case["classification"]["malicious_probability"],
        "headline": case["risk"]["headline_verdict"],
        "score": case["risk"]["composite_score"],
        "severity": case["risk"]["severity"],
        "disagreement": case["risk"]["ml_rule_disagreement"],
        "otp_risk": case["fraud"]["otp_interception_risk"],
        "banks": [b["bank"] for b in case["fraud"]["targeted_banks"]],
        "attribution": case["attribution"]["confidence"],
        "evasion": case["evasion"]["sophistication"],
        "flagged": flagged(case),
    }
    print(f"  {label:7s} {name[:34]:34s} ML={row['ml_verdict']:9s} "
          f"score={row['score']:6.2f} {row['severity']:8s} "
          f"{'FLAGGED' if row['flagged'] else 'clear'}")
    return row


def local_apks(folder: Path) -> list[Path]:
    return sorted(folder.glob("*.apk")) if folder.is_dir() else []


def summarise(rows: list[dict]) -> dict:
    mal = [r for r in rows if r["label"] == "malware"]
    ben = [r for r in rows if r["label"] == "benign"]
    rate = lambda xs, key: round(sum(1 for r in xs if key(r)) / len(xs), 4) if xs else None
    return {
        "n_malware": len(mal), "n_benign": len(ben),
        "pipeline_detection_rate": rate(mal, lambda r: r["flagged"]),
        "ml_only_detection_rate": rate(mal, lambda r: r["ml_verdict"] == "MALICIOUS"),
        "pipeline_false_positive_rate": rate(ben, lambda r: r["flagged"]),
        "ml_only_false_positive_rate": rate(ben, lambda r: r["ml_verdict"] == "MALICIOUS"),
        "disagreement_flags_on_malware": sum(1 for r in mal if r["disagreement"]),
        "per_family": {
            fam: {"n": len(fr), "detected": sum(1 for r in fr if r["flagged"])}
            for fam in sorted({r["family"] for r in mal if r["family"]})
            for fr in [[r for r in mal if r["family"] == fam]]
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Real-world evaluation of SENTINEL-X")
    ap.add_argument("--benign", type=Path, default=ROOT / "samples")
    ap.add_argument("--malware", type=Path, help="folder of local malware APKs")
    ap.add_argument("--bazaar", action="store_true", help="fetch trojans from MalwareBazaar")
    ap.add_argument("--families", nargs="+")
    ap.add_argument("--per-family", type=int, default=6)
    ap.add_argument("--replay", type=Path, nargs="+", metavar="EVAL_JSON",
                    help="re-score the samples listed in earlier eval JSONs from "
                         "data/cases (no parsing, no downloads)")
    ap.add_argument("--out", type=Path, help=f"output JSON (default {OUT})")
    ap.add_argument("--skip", type=int, default=0,
                    help="skip the newest N APKs per family (draw unseen samples)")
    ap.add_argument("--keep-corpus", action="store_true",
                    help="evaluate every downloaded sample; leave cert_corpus.json as is")
    args = ap.parse_args()

    rows: list[dict] = []

    if args.replay:
        print("== replay (cached cases, current rules) ==")
        seen = set()
        for src in args.replay:
            for old in json.loads(src.read_text())["samples"]:
                path = pipeline.CASES / f"{old['sha256']}.json"
                if old["sha256"] in seen or not path.exists():
                    continue
                seen.add(old["sha256"])
                case = rescore(json.loads(path.read_text()))
                rows.append(row_for(case, old["name"], old["label"], old.get("family", "")))
        args.bazaar = False                     # replay replaces fresh downloads

    print("== benign controls ==")
    replayed = {r["sha256"] for r in rows}
    for p in local_apks(args.benign):
        if args.replay:
            import hashlib
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            if sha in replayed:
                continue
            if (pipeline.CASES / f"{sha}.json").exists():
                case = rescore(json.loads((pipeline.CASES / f"{sha}.json").read_text()))
                rows.append(row_for(case, p.name, "benign"))
                continue
        if (r := run_one(p.read_bytes(), p.name, "benign")) is not None:
            rows.append(r)

    if args.malware:
        print("== local malware ==")
        for p in local_apks(args.malware):
            if (r := run_one(p.read_bytes(), p.name, "malware")) is not None:
                rows.append(r)

    if args.bazaar:
        import bazaar
        from fetch_cert_corpus import build_entry, write_corpus
        print("== MalwareBazaar (in memory) ==")
        corpus_entries, holdout, seen = [], [], {}
        for fam, sha, data in bazaar.iter_family_samples(
                args.families or bazaar.DEFAULT_FAMILIES, args.per_family, args.skip):
            idx = seen[fam] = seen.get(fam, -1) + 1
            if idx % 2 == 0 and not args.keep_corpus:
                if (e := build_entry(fam, sha, data)) is not None:
                    corpus_entries.append(e)
            else:
                holdout.append((fam, sha, data))
        if corpus_entries:
            write_corpus(corpus_entries, "Real signing certificates from the corpus half "
                         "of a MalwareBazaar split (see scripts/real_world_eval.py).")
            certgraph.reload_corpus()
        for fam, sha, data in holdout:
            if (r := run_one(data, f"{fam}_{sha[:12]}.apk", "malware", fam)) is not None:
                rows.append(r)

    summary = summarise(rows)
    out = args.out or OUT
    out.write_text(json.dumps({
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "flag_rule": "headline != BENIGN or severity >= MEDIUM",
        "summary": summary, "samples": rows}, indent=2))
    print("\n== summary ==")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"[done] -> {out}")


if __name__ == "__main__":
    main()
