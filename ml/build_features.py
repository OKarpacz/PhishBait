import sys
from pathlib import Path
 
import pandas as pd
from tqdm import tqdm
 
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from url_features import extract_features
 
DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_CSV_PATH = DATA_DIR / "phiusiil_raw.csv"
FEATURES_CSV_PATH = DATA_DIR / "features.csv"
 
FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "has_ip_address",
    "has_at_symbol",
    "is_suspicious_tld",
    "is_https",
    "subdomain_count",
    "typosquat_similarity",
]
 
 
def main():
    if not RAW_CSV_PATH.exists():
        raise SystemExit(f"{RAW_CSV_PATH} not found - run download_dataset.py first.")
 
    df = pd.read_csv(RAW_CSV_PATH)
 
    url_col = "URL" if "URL" in df.columns else "url"
    if url_col not in df.columns:
        raise SystemExit(
            f"Could not find a URL column in the dataset. "
            f"Columns present: {list(df.columns)}"
        )
 
    rows = []
    skipped = 0
 
    for url, raw_label in tqdm(
        zip(df[url_col], df["raw_label"]), total=len(df), desc="Extracting features"
    ):
        try:
            f = extract_features(str(url))
        except Exception:
           
            skipped += 1
            continue
 
        is_phishing = 1 - int(raw_label)
 
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
                "label": is_phishing,
            }
        )
 
    out_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"])
    out_df.to_csv(FEATURES_CSV_PATH, index=False)
 
    print(f"\nSaved {len(out_df)} rows ({skipped} skipped) to {FEATURES_CSV_PATH}")
    print(f"Class balance: {out_df['label'].value_counts().to_dict()} (1=phishing, 0=legitimate)")
 
 
if __name__ == "__main__":
    main()
 