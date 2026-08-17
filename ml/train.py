import json
from pathlib import Path
 
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
 
from build_features import FEATURE_COLUMNS, FEATURES_CSV_PATH
 
MODELS_DIR = Path(__file__).resolve().parent.parent / "backend" / "models"
 
 
def evaluate(name: str, model, X_test, y_test) -> dict:
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    return {
        "name": name,
        "accuracy": round(accuracy_score(y_test, preds), 4),
        "precision": round(precision_score(y_test, preds), 4),
        "recall": round(recall_score(y_test, preds), 4),
        "f1": round(f1_score(y_test, preds), 4),
        "roc_auc": round(roc_auc_score(y_test, probs), 4),
    }
 
 
def main():
    if not FEATURES_CSV_PATH.exists():
        raise SystemExit(f"{FEATURES_CSV_PATH} not found - run build_features.py first.")
 
    df = pd.read_csv(FEATURES_CSV_PATH)
    X = df[FEATURE_COLUMNS]
    y = df["label"]
 
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
 
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
 
    results = []
 
    print("Training Logistic Regression...")
    log_reg = LogisticRegression(max_iter=1000)
    log_reg.fit(X_train_scaled, y_train)
    results.append((evaluate("Logistic Regression", log_reg, X_test_scaled, y_test), log_reg, True))
 
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    results.append((evaluate("Random Forest", rf, X_test, y_test), rf, False))
 
    print("Training XGBoost...")
    xgb = XGBClassifier(n_estimators=200, random_state=42, eval_metric="logloss")
    xgb.fit(X_train, y_train)
    results.append((evaluate("XGBoost", xgb, X_test, y_test), xgb, False))
 
    print("\n=== Model comparison (US-23) ===")
    header = f"{'Model':22s} {'Accuracy':>9s} {'Precision':>10s} {'Recall':>9s} {'F1':>7s} {'ROC-AUC':>8s}"
    print(header)
    for metrics, _, _ in results:
        print(
            f"{metrics['name']:22s} {metrics['accuracy']:9.4f} {metrics['precision']:10.4f} "
            f"{metrics['recall']:9.4f} {metrics['f1']:7.4f} {metrics['roc_auc']:8.4f}"
        )
 
    best_metrics, best_model, needs_scaler = max(results, key=lambda r: r[0]["roc_auc"])
    print(f"\nBest model: {best_metrics['name']} (roc_auc={best_metrics['roc_auc']})")
 
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, MODELS_DIR / "phishing_model.joblib")
    if needs_scaler:
        joblib.dump(scaler, MODELS_DIR / "phishing_scaler.joblib")
 
    info = {
        "feature_columns": FEATURE_COLUMNS,
        "best_model": best_metrics["name"],
        "needs_scaler": needs_scaler,
        "all_results": [m for m, _, _ in results],
    }
    with open(MODELS_DIR / "model_info.json", "w") as f:
        json.dump(info, f, indent=2)
 
    print(f"\nSaved model to {MODELS_DIR / 'phishing_model.joblib'}")
    print(f"Saved metadata to {MODELS_DIR / 'model_info.json'}")
 
 
if __name__ == "__main__":
    main()