import sys
from pathlib import Path

import kagglehub
import pandas as pd
from kagglehub import KaggleDatasetAdapter
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from url_features import extract_features  

from build_features import FEATURE_COLUMNS  

DATA_DIR = Path(__file__).resolve().parent / "data"
FEATURES_CSV_PATH = DATA_DIR / "features.csv"

DATASET_HANDLE = "sid321axn/malicious-urls-dataset"
KAGGLE_FILE_PATH = "malicious_phish.csv"

TYPE_TO_LABEL = {
    "benign": 0,
    "phishing": 1,
}


def _load_kaggle_dataframe() -> pd.DataFrame:
    try:
        return kagglehub.dataset_load(KaggleDatasetAdapter.PANDAS, DATASET_HANDLE, KAGGLE_FILE_PATH)
    except Exception as exc:
        if "codec" in str(exc) or "utf-8" in str(exc).lower():
            print(f"UTF-8 decoding failed ({exc}).")
            print("Retrying with latin-1 encoding (file likely has non-UTF-8 bytes from international URLs)...")
            return kagglehub.dataset_load(
                KaggleDatasetAdapter.PANDAS,
                DATASET_HANDLE,
                KAGGLE_FILE_PATH,
                pandas_kwargs={"encoding": "ISO-8859-1"},
            )

        print(f"Could not load '{KAGGLE_FILE_PATH}' directly ({exc}).")
        print("Downloading the full dataset to inspect available files...")
        dataset_dir = kagglehub.dataset_download(DATASET_HANDLE)
        print(f"Files found in {dataset_dir}:")
        for f in Path(dataset_dir).iterdir():
            print(f"  - {f.name}")
        raise SystemExit(
            "Update KAGGLE_FILE_PATH at the top of this script to match one "
            "of the filenames printed above, then run it again."
        ) from exc


def main():
    if not FEATURES_CSV_PATH.exists():
        raise SystemExit(f"{FEATURES_CSV_PATH} not found - run build_features.py first.")

    print(f"Loading '{KAGGLE_FILE_PATH}' from Kaggle dataset '{DATASET_HANDLE}'...")
    kaggle_df = _load_kaggle_dataframe()

    kaggle_df = kaggle_df[kaggle_df["type"].isin(TYPE_TO_LABEL.keys())]
    print(f"Using {len(kaggle_df)} rows (benign + phishing only, "
          f"defacement/malware excluded) out of the full file.")

    rows = []
    skipped = 0

    for url, url_type in tqdm(
        zip(kaggle_df["url"], kaggle_df["type"]), total=len(kaggle_df), desc="Extracting features"
    ):
        try:
            f = extract_features(str(url))
        except Exception:
            skipped += 1
            continue

        rows.append(
            {
                "url_length": f.url_length,
                "domain_length": f.domain_length,
                "dot_count": f.dot_count,
                "hyphen_count": f.hyphen_count,
                "digit_count": f.digit_count,
                "special_char_count": f.special_char_count,
                "has_ip_address": int(f.has_ip_address),
                "has_at_symbol": int(f.has_at_symbol),
                "is_suspicious_tld": int(f.is_suspicious_tld),
                "is_https": int(f.is_https),
                "subdomain_count": f.subdomain_count,
                "typosquat_similarity": f.typosquat_similarity,
                "has_path": int(f.has_path),
                "label": TYPE_TO_LABEL[url_type],
            }
        )

    kaggle_features_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"])

    existing_df = pd.read_csv(FEATURES_CSV_PATH)
    combined_df = pd.concat([existing_df, kaggle_features_df], ignore_index=True)
    combined_df.to_csv(FEATURES_CSV_PATH, index=False)

    print(f"\nAdded {len(kaggle_features_df)} rows ({skipped} skipped) from Kaggle.")
    print(f"New total: {len(combined_df)} rows")
    print(f"New class balance: {combined_df['label'].value_counts().to_dict()} (1=phishing, 0=legitimate)")

    has_path = combined_df[combined_df["has_path"] == 1]
    print(f"\n'Has path' subgroup after augmentation: {has_path['label'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()