import re
from concurrent.futures import ThreadPoolExecutor
 
import ml_predictor
from decision import aggregate
from heuristics import score_url
from live_checks import (
    check_domain_age,
    check_redirects,
    check_safe_browsing,
    check_security_headers,
    check_ssl_certificate,
)
from live_scoring import score_live_checks
from schemas import AnalyzeRequest, AnalyzeResponse, InputType, RiskLevel, Signal
from url_features import extract_features
 
URL_REGEX = re.compile(r"https?://[^\s]+")
 
 
def _extract_url_from_email(text: str) -> str | None:
    match = URL_REGEX.search(text)
    return match.group(0) if match else None
 
 
def _run_live_checks(target: str):
    with ThreadPoolExecutor(max_workers=5) as executor:
        ssl_future = executor.submit(check_ssl_certificate, target)
        safe_browsing_future = executor.submit(check_safe_browsing, target)
        domain_age_future = executor.submit(check_domain_age, target)
        redirects_future = executor.submit(check_redirects, target)
        headers_future = executor.submit(check_security_headers, target)
 
        return (
            ssl_future.result(),
            safe_browsing_future.result(),
            domain_age_future.result(),
            redirects_future.result(),
            headers_future.result(),
        )
 
 
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    analyzed_url = None
    if request.input_type == InputType.email:
        analyzed_url = _extract_url_from_email(request.content)
        target = analyzed_url or request.content
    else:
        target = request.content
 
    features = extract_features(target)
    heuristic_result = score_url(features)
 
    ml_probability = ml_predictor.predict_probability(features) if ml_predictor.is_available() else None
 
    ssl_result, safe_browsing_result, domain_age_result, redirects_result, headers_result = _run_live_checks(target)
    live_score = score_live_checks(
        ssl_result, safe_browsing_result, domain_age_result, redirects_result, headers_result
    )
 
    aggregated = aggregate(
        heuristic_probability=heuristic_result.probability,
        heuristic_signals=heuristic_result.signals,
        ml_probability=ml_probability,
        live_check_probability=live_score.probability,
        live_check_signals=live_score.signals,
    )
 
    probability = aggregated.probability
    signals = [
        Signal(name=s.name, description=s.description, severity=s.severity)
        for s in aggregated.signals
    ]
 
    if probability < 30:
        verdict = RiskLevel.safe
        summary = "No significant phishing indicators were detected."
    elif probability < 65:
        verdict = RiskLevel.suspicious
        summary = "Some suspicious characteristics were detected - proceed with caution."
    else:
        verdict = RiskLevel.dangerous
        summary = "High probability of phishing - do not click the link and do not provide any data."
 
    return AnalyzeResponse(
        verdict=verdict,
        phishing_probability=probability,
        signals=signals,
        analyzed_url=analyzed_url,
        summary=summary,
    )
 