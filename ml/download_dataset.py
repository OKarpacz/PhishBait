from pathlib import Path

from ucimlrepo import fetch_ucirepo

DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_CSV_PATH = DATA_DIR / "phiusiil_raw.csv"


def main():
    DATA_DIR.mkdir(exist_ok=True)

    if RAW_CSV_PATH.exists():
        print(f"Dataset already cached at {RAW_CSV_PATH}, skipping download.")
        return

    print("Downloading PhiUSIIL Phishing URL dataset from UCI ML Repository (id=967)...")
    dataset = fetch_ucirepo(id=967)

    X = dataset.data.features
    y = dataset.data.targets

    df = X.copy()

    
    raw_label_col = y.columns[0]
    df["raw_label"] = y[raw_label_col]

    df.to_csv(RAW_CSV_PATH, index=False)
    print(f"Saved {len(df)} rows to {RAW_CSV_PATH}")
    print(f"Columns: {list(df.columns)}")


if __name__ == "__main__":
    main()