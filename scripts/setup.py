"""One-command bootstrap for SENTINEL-X.

    python scripts/setup.py

Installs dependencies, trains the classifier (downloading the dataset if needed),
and builds the demo cases. Safe to re-run.
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(label: str, args: list[str]) -> bool:
    print(f"\n=== {label} ===")
    rc = subprocess.call(args, cwd=str(ROOT))
    print(f"--- {label}: {'OK' if rc == 0 else f'FAILED (exit {rc})'}")
    return rc == 0


def main() -> None:
    ok = run("1/3 install dependencies",
             [sys.executable, "-m", "pip", "install", "-q", "-r", "requirements.txt"])
    if not ok:
        print("\nDependency install failed. Fix the errors above and re-run.")
        return

    if (ROOT / "models" / "xgb.joblib").exists():
        print("\n=== 2/3 train model ===\n--- model already present, skipping "
              "(delete models/xgb.joblib to retrain)")
    elif not run("2/3 train model", [sys.executable, "scripts/train_model.py"]):
        print("\nTraining failed — check your internet connection (the dataset "
              "is downloaded from the UCI ML Repository).")
        return

    run("3/3 build demo cases", [sys.executable, "scripts/make_demo.py"])

    print("\n" + "=" * 62)
    print("Setup complete. Start the platform with:\n")
    print("    python -m uvicorn sentinelx.app:app --reload\n")
    print("then open http://127.0.0.1:8000")
    print("=" * 62)


if __name__ == "__main__":
    main()
