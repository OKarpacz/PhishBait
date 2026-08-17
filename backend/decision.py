from dataclasses import dataclass
 
from heuristics import HeuristicSignal
 
HEURISTIC_WEIGHT = 0.35
ML_WEIGHT = 0.30
LIVE_CHECK_WEIGHT = 0.35
 
 
@dataclass
class AggregatedSignal:
    name: str
    description: str
    severity: str  
    source: str
 
 
@dataclass
class AggregatedResult:
    probability: float
    signals: list[AggregatedSignal]
    heuristic_probability: float
    ml_probability: float | None
    live_check_probability: float | None
 
 
def _ml_signal(ml_probability: float) -> AggregatedSignal:
    if ml_probability >= 65:
        severity = "high"
        description = "The trained model flagged this URL as high risk"
    elif ml_probability >= 30:
        severity = "medium"
        description = "The trained model flagged this URL as somewhat risky"
    else:
        severity = "low"
        description = "The trained model found this URL to be low risk"
    return AggregatedSignal(
        name="ML Model Assessment",
        description=description,
        severity=severity,
        source="ml",
    )
 
 
def aggregate(
    heuristic_probability: float,
    heuristic_signals: list[HeuristicSignal],
    ml_probability: float | None,
    live_check_probability: float | None,
    live_check_signals: list,
) -> AggregatedResult:
 
    weights = {"heuristic": HEURISTIC_WEIGHT}
    scores = {"heuristic": heuristic_probability}
 
    if ml_probability is not None:
        weights["ml"] = ML_WEIGHT
        scores["ml"] = ml_probability
 
    if live_check_probability is not None:
        weights["live"] = LIVE_CHECK_WEIGHT
        scores["live"] = live_check_probability
 
    total_weight = sum(weights.values())
    final_probability = sum(scores[k] * (weights[k] / total_weight) for k in weights)
    final_probability = round(min(final_probability, 100.0), 1)
 
    signals: list[AggregatedSignal] = [
        AggregatedSignal(name=s.name, description=s.description, severity=s.severity, source="heuristic")
        for s in heuristic_signals
    ]
    if ml_probability is not None:
        signals.append(_ml_signal(ml_probability))
    signals.extend(
        AggregatedSignal(name=s.name, description=s.description, severity=s.severity, source="live_check")
        for s in live_check_signals
    )
 
    return AggregatedResult(
        probability=final_probability,
        signals=signals,
        heuristic_probability=heuristic_probability,
        ml_probability=ml_probability,
        live_check_probability=live_check_probability,
    )
 