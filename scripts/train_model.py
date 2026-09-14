"""Download NATICUSdroid, train an XGBoost malware classifier, calibrate it, and
save artifacts + real held-out metrics for SENTINEL-X.

Run:  python scripts/train_model.py
Outputs (into models/):  xgb.joblib, calibrator.joblib, feature_vocab.json, metrics.json
"""
from __future__ import annotations
import io
import json
import urllib.request
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "models"
DATA = ROOT / "data"
DATA_CSV = DATA / "naticusdroid.csv"
URL = ("https://archive.ics.uci.edu/static/public/722/"
       "naticusdroid+android+permissions+dataset.zip")


def load_dataset() -> pd.DataFrame:
    if DATA_CSV.exists():
        print(f"[data] using cached {DATA_CSV}")
        return pd.read_csv(DATA_CSV)
    print(f"[data] downloading NATICUSdroid ...")
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    blob = urllib.request.urlopen(req, timeout=120).read()
    z = zipfile.ZipFile(io.BytesIO(blob))
    name = next(n for n in z.namelist() if n.endswith(".csv"))
    df = pd.read_csv(io.BytesIO(z.read(name)))
    DATA.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATA_CSV, index=False)
    print(f"[data] cached -> {DATA_CSV}  shape={df.shape}")
    return df


def main() -> None:
    MODELS.mkdir(parents=True, exist_ok=True)
    df = load_dataset()

    label_col = "Result"
    feature_cols = [c for c in df.columns if c != label_col]
    X = df[feature_cols].astype(np.float32).values
    y = df[label_col].astype(int).values
    print(f"[data] {X.shape[0]} samples, {len(feature_cols)} features, "
          f"malware={int(y.sum())}, benign={int((y == 0).sum())}")

    # 70 / 15 / 15 stratified split
    X_tmp, X_test, y_tmp, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tmp, y_tmp, test_size=0.1765, stratify=y_tmp, random_state=42)  # 0.1765*0.85 ≈ 0.15
    print(f"[split] train={len(y_train)} val={len(y_val)} test={len(y_test)}")

    clf = XGBClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
        n_jobs=-1, random_state=42,
    )
    clf.fit(X_train, y_train)

    # Isotonic calibration on the validation split (prefit estimator)
    try:
        calibrator = CalibratedClassifierCV(clf, method="isotonic", cv="prefit")
    except TypeError:  # newer sklearn drops cv="prefit" -> use FrozenEstimator
        from sklearn.frozen import FrozenEstimator
        calibrator = CalibratedClassifierCV(FrozenEstimator(clf), method="isotonic")
    calibrator.fit(X_val, y_val)

    # Held-out test metrics (calibrated)
    proba = calibrator.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    metrics = {
        "dataset": "NATICUSdroid (UCI ML Repository #722)",
        "n_samples": int(X.shape[0]),
        "n_features": len(feature_cols),
        "split": "70/15/15 stratified",
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall": round(float(recall_score(y_test, pred)), 4),
        "f1": round(float(f1_score(y_test, pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "model": "XGBoost (400 trees, depth 6) + isotonic calibration",
    }

    joblib.dump(clf, MODELS / "xgb.joblib")
    joblib.dump(calibrator, MODELS / "calibrator.joblib")
    (MODELS / "feature_vocab.json").write_text(
        json.dumps({"features": feature_cols, "label": label_col}, indent=2))
    (MODELS / "metrics.json").write_text(json.dumps(metrics, indent=2))

    print("\n[metrics]")
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc",
              "false_positive_rate"):
        print(f"  {k:20s} {metrics[k]}")
    print(f"\n[done] artifacts written to {MODELS}")


if __name__ == "__main__":
    main()
