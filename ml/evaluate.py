import sys
from dataclasses import dataclass
from pathlib import Path
 
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
 
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from decision import aggregate 
from heuristics import score_url 
 
from build_features import FEATURE_COLUMNS 
 
DATA_DIR = Path(__file__).resolve().parent / "data"
FEATURES_CSV_PATH = DATA_DIR / "features.csv"
 
MODELS_DIR = Path(__file__).resolve().parent.parent / "backend" / "models"
MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
SCALER_PATH = MODELS_DIR / "phishing_scaler.joblib"
 
CLASSIFICATION_THRESHOLD = 50
 
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.75
 
 
@dataclass
class FeatureRow:
   
    url_length: float
    domain_length: float
    dot_count: float
    hyphen_count: float
    digit_count: float
    special_char_count: float
    has_ip_address: bool
    has_at_symbol: bool
    is_suspicious_tld: bool
    is_https: bool
    subdomain_count: float
    typosquat_similarity: float
    has_path: bool
 
    @property
    def typosquat_target(self):
        return "reconstructed" if self.typosquat_similarity >= TYPOSQUAT_SIMILARITY_THRESHOLD else None
 
 
def _row_to_features(row: pd.Series) -> FeatureRow:
    return FeatureRow(
        url_length=row["url_length"],
        domain_length=row["domain_length"],
        dot_count=row["dot_count"],
        hyphen_count=row["hyphen_count"],
        digit_count=row["digit_count"],
        special_char_count=row["special_char_count"],
        has_ip_address=bool(row["has_ip_address"]),
        has_at_symbol=bool(row["has_at_symbol"]),
        is_suspicious_tld=bool(row["is_suspicious_tld"]),
        is_https=bool(row["is_https"]),
        subdomain_count=row["subdomain_count"],
        typosquat_similarity=row["typosquat_similarity"],
        has_path=bool(row["has_path"]),
    )
 
 
def _report(name: str, y_true, probabilities) -> dict:
    predictions = (probabilities >= CLASSIFICATION_THRESHOLD).astype(int)
 
    accuracy = accuracy_score(y_true, predictions)
    precision = precision_score(y_true, predictions, zero_division=0)
    recall = recall_score(y_true, predictions, zero_division=0)
    f1 = f1_score(y_true, predictions, zero_division=0)
    roc_auc = roc_auc_score(y_true, probabilities)
    cm = confusion_matrix(y_true, predictions)
 
    return {
        "name": name,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": cm,
    }
 
 
def _print_report(report: dict):
    cm = report["confusion_matrix"]
    tn, fp, fn, tp = cm.ravel()
 
    print(f"\n--- {report['name']} ---")
    print(f"Accuracy:  {report['accuracy']}")
    print(f"Precision: {report['precision']}")
    print(f"Recall:    {report['recall']}")
    print(f"F1:        {report['f1']}")
    print(f"ROC-AUC:   {report['roc_auc']}")
    print("Confusion matrix:")
    print(f"                 Predicted safe   Predicted phishing")
    print(f"  Actual safe    {tn:>13d}   {fp:>18d}")
    print(f"  Actual phish   {fn:>13d}   {tp:>18d}")
 
 
def main():
    if not FEATURES_CSV_PATH.exists():
        raise SystemExit(f"{FEATURES_CSV_PATH} not found - run build_features.py first.")
    if not MODEL_PATH.exists():
        raise SystemExit(f"{MODEL_PATH} not found - run train.py first.")
 
    df = pd.read_csv(FEATURES_CSV_PATH)
    X = df[FEATURE_COLUMNS]
    y = df["label"]
 
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
 
    print(f"Evaluating on {len(X_test)} held-out rows (never used in training).")
 
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH) if SCALER_PATH.exists() else None
 
    model_input = scaler.transform(X_test) if scaler is not None else X_test
    ml_probabilities = model.predict_proba(model_input)[:, 1] * 100
 
    heuristic_probabilities = np.array(
        [score_url(_row_to_features(row)).probability for _, row in X_test.iterrows()]
    )
 
    hybrid_probabilities = np.array(
        [
            aggregate(
                heuristic_probability=h,
                heuristic_signals=[],
                ml_probability=m,
                live_check_probability=None,  
                live_check_signals=[],
            ).probability
            for h, m in zip(heuristic_probabilities, ml_probabilities)
        ]
    )
 
    print("\n" + "=" * 60)
    print("EVALUATION REPORT")
    print("=" * 60)
 
    reports = [
        _report("Heuristic only", y_test, heuristic_probabilities),
        _report("ML only", y_test, ml_probabilities),
        _report("Hybrid, no live-checks", y_test, hybrid_probabilities),
    ]
 
    for report in reports:
        _print_report(report)
 
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    header = f"{'Approach':32s} {'Accuracy':>9s} {'Precision':>10s} {'Recall':>9s} {'F1':>7s} {'ROC-AUC':>8s}"
    print(header)
    for report in reports:
        print(
            f"{report['name']:32s} {report['accuracy']:9.4f} {report['precision']:10.4f} "
            f"{report['recall']:9.4f} {report['f1']:7.4f} {report['roc_auc']:8.4f}"
        )
 
    print(
        "\nNote: 'Hybrid' here excludes live-checks, which require real "
        "network calls per URL and cannot be run in bulk over a ~150k-row test "
        "set. The full three-source hybrid is validated separately on individual "
        "real examples - backend/tests/test_ml_predictions.py."
    )
 
 
if __name__ == "__main__":
    main()
 