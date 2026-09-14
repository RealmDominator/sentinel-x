# samples/

APK files are **not committed** (third-party apps, large). This folder layout is what the
tests and `scripts/real_world_eval.py` expect:

| Folder | Contents | Used by |
|---|---|---|
| `samples/*.apk` | benign F-Droid apps (design set, incl. hard negatives) | `pytest` end-to-end tests, `real_world_eval.py` |
| `samples/holdout/` | benign held-out set 1 | `real_world_eval.py --benign samples/holdout` |
| `samples/holdout2/` | benign held-out set 2 | `real_world_eval.py --benign samples/holdout2` |

## Getting benign apps

* **F-Droid** — `https://f-droid.org/api/v1/packages/<package>` gives `suggestedVersionCode`;
  download `https://f-droid.org/repo/<package>_<versionCode>.apk`.
* **APKMirror** — real Indian bank apps (SBI YONO, PNB ONE, BoB World, ICICI iMobile, HDFC,
  PhonePe, Paytm). Useful hard negatives for a banking-fraud detector.
* **Your own phone** — `adb shell pm path <package>` then `adb pull <path>`.

## Malware

Never store or install malware here. `scripts/real_world_eval.py --bazaar` downloads
MalwareBazaar samples and analyses them **in memory only** (needs `MALWAREBAZAAR_API_KEY`
in `.env`).
