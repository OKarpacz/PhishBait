import sys
import zipfile
from pathlib import Path

import pandas as pd
import requests
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from url_features import extract_features

from build_features import FEATURE_COLUMNS 

DATA_DIR = Path(__file__).resolve().parent / "data"
FEATURES_CSV_PATH = DATA_DIR / "features.csv"
TRANCO_ZIP_PATH = DATA_DIR / "tranco_top1m.csv.zip"
TRANCO_CSV_PATH = DATA_DIR / "tranco_top1m.csv"

TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"

TOP_N_DOMAINS = 20_000


def _download_tranco_list():
    if TRANCO_CSV_PATH.exists():
        print(f"Tranco list already downloaded at {TRANCO_CSV_PATH}, skipping.")
        return

    print("Downloading Tranco top-1m list...")
    response = requests.get(TRANCO_DOWNLOAD_URL, timeout=30)
    response.raise_for_status()
    TRANCO_ZIP_PATH.write_bytes(response.content)

    with zipfile.ZipFile(TRANCO_ZIP_PATH) as zf:
        inner_name = zf.namelist()[0]
        with zf.open(inner_name) as src, open(TRANCO_CSV_PATH, "wb") as dst:
            dst.write(src.read())

    TRANCO_ZIP_PATH.unlink()
    print(f"Saved Tranco list to {TRANCO_CSV_PATH}")


def main():
    if not FEATURES_CSV_PATH.exists():
        raise SystemExit(f"{FEATURES_CSV_PATH} not found - run build_features.py first.")

    _download_tranco_list()

    tranco_df = pd.read_csv(TRANCO_CSV_PATH, names=["rank", "domain"], nrows=TOP_N_DOMAINS)

    rows = []
    for domain in tqdm(tranco_df["domain"], desc="Extracting features for Tranco domains"):
        url = f"https://{domain}"
        try:
            f = extract_features(url)
        except Exception:
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
                "label": 0,
            }
        )

    tranco_features_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"])

    existing_df = pd.read_csv(FEATURES_CSV_PATH)
    combined_df = pd.concat([existing_df, tranco_features_df], ignore_index=True)
    combined_df.to_csv(FEATURES_CSV_PATH, index=False)

    print(f"\nAdded {len(tranco_features_df)} legitimate root-domain examples from Tranco.")
    print(f"New total: {len(combined_df)} rows")
    print(f"New class balance: {combined_df['label'].value_counts().to_dict()} (1=phishing, 0=legitimate)")

    no_subdomain = combined_df[combined_df["subdomain_count"] == 0]
    print(f"\nNo-subdomain subgroup after augmentation: {no_subdomain['label'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()