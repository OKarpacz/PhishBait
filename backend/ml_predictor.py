import json
from pathlib import Path
 
import joblib
 
from url_features import UrlFeatures
 
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
SCALER_PATH = MODELS_DIR / "phishing_scaler.joblib"
INFO_PATH = MODELS_DIR / "model_info.json"
 
_model = None
_scaler = None
_feature_columns: list[str] | None = None
_model_name: str | None = None
 
 
def load_model() -> bool:
    global _model, _scaler, _feature_columns, _model_name
 
    if not MODEL_PATH.exists() or not INFO_PATH.exists():
        return False
 
    _model = joblib.load(MODEL_PATH)
    info = json.loads(INFO_PATH.read_text())
    _feature_columns = info["feature_columns"]
    _model_name = info["best_model"]
 
    if info.get("needs_scaler") and SCALER_PATH.exists():
        _scaler = joblib.load(SCALER_PATH)
 
    return True
 
 
def is_available() -> bool:
    return _model is not None
 
 
def model_name() -> str | None:
    return _model_name
 
 
def _features_to_row(features: UrlFeatures) -> list[float]:
    values = []
    for column in _feature_columns:
        value = getattr(features, column)
        values.append(int(value) if isinstance(value, bool) else float(value))
    return values
 
 
def predict_probability(features: UrlFeatures) -> float | None:
    if _model is None:
        return None
 
    row = [_features_to_row(features)]
    if _scaler is not None:
        row = _scaler.transform(row)
 
    probability = _model.predict_proba(row)[0][1]
    return round(probability * 100, 1)