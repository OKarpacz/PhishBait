import re

from heuristics import score_url
from schemas import AnalyzeRequest, AnalyzeResponse, InputType, RiskLevel, Signal
from url_features import extract_features

URL_REGEX = re.compile(r"https?://[^\s]+")


def _extract_url_from_email(text: str) -> str | None:
    match = URL_REGEX.search(text)
    return match.group(0) if match else None


def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    analyzed_url = None
    if request.input_type == InputType.email:
        analyzed_url = _extract_url_from_email(request.content)
        target = analyzed_url or request.content
    else:
        target = request.content

    features = extract_features(target)
    result = score_url(features)

    signals = [
        Signal(name=s.name, description=s.description, severity=s.severity)
        for s in result.signals
    ]
    probability = result.probability

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