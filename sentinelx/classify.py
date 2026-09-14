"""XGBoost verdict + isotonic-calibrated confidence + SHAP explanation."""
from __future__ import annotations
from functools import lru_cache
from typing import Any

import joblib
import numpy as np

from .config import MODELS
from .features import feature_vocab, ml_vector


@lru_cache(maxsize=1)
def _artifacts():
    clf = joblib.load(MODELS / "xgb.joblib")
    calibrator = joblib.load(MODELS / "calibrator.joblib")
    import shap
    explainer = shap.TreeExplainer(clf)
    return clf, calibrator, explainer


def classify(apk) -> dict[str, Any]:
    clf, calibrator, explainer = _artifacts()
    vec = ml_vector(apk)
    proba = float(calibrator.predict_proba(vec)[:, 1][0])
    verdict = "MALICIOUS" if proba >= 0.5 else "BENIGN"

    vocab = feature_vocab()
    try:
        sv = explainer.shap_values(vec)
        sv = np.asarray(sv)
        row = sv[0] if sv.ndim == 2 else sv
        contributions = sorted(
            ({"feature": vocab[i].rsplit(".", 1)[-1],
              "full_name": vocab[i],
              "contribution": round(float(row[i]), 4),
              "present": bool(vec[0][i])}
             for i in range(len(vocab)) if abs(row[i]) > 1e-6),
            key=lambda d: abs(d["contribution"]), reverse=True)[:15]
    except Exception as exc:  # SHAP is best-effort; verdict still stands.
        contributions = []
        _ = exc

    return {
        "verdict": verdict,
        "confidence": round(proba if verdict == "MALICIOUS" else 1 - proba, 4),
        "malicious_probability": round(proba, 4),
        "shap_top_features": contributions,
    }
