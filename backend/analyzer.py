"""
UWAGA: to jest MOCK.
"""

import random
import re

from schemas import AnalyzeRequest, AnalyzeResponse, RiskLevel, Signal, InputType

URL_REGEX = re.compile(r"https?://[^\s]+")


def _extract_url_from_email(text: str) -> str | None:
    match = URL_REGEX.search(text)
    return match.group(0) if match else None


def _fake_signals_for(target: str) -> list[Signal]:
    """Losuje kilka 'wykrytych sygnałów', żeby lista w UI miała co pokazać."""
    pool = [
        Signal(name="Suspicious TLD", description="The domain has a suspicious top-level domain (e.g., .zip, .top)", severity="medium"),
        Signal(name="Missing SSL Certificate", description="The website does not use encrypted HTTPS connection", severity="high"),
        Signal(name="Recently Registered Domain", description="The domain was registered recently (less than 30 days)", severity="high"),
        Signal(name="IP Address Instead of Domain", description="The URL points directly to an IP address", severity="high"),
        Signal(name="Suspicious Characters Found", description="The URL contains unusual characters that may mimic other domains", severity="medium"),
        Signal(name="Short Domain Lifetime in Reputation Databases", description="The domain does not yet appear in known trusted domain lists", severity="low"),
        Signal(name="Long, Obfuscated URL", description="The URL is unusually long or contains encoded fragments", severity="low"),
    ]
    random.shuffle(pool)
    count = random.randint(0, 4)
    return pool[:count]


def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    analyzed_url = None
    if request.input_type == InputType.email:
        analyzed_url = _extract_url_from_email(request.content)
        target = analyzed_url or request.content
    else:
        target = request.content

    signals = _fake_signals_for(target)

    base = random.uniform(0, 30)
    probability = min(100.0, base + len(signals) * 18)

    if probability < 30:
        verdict = RiskLevel.safe
        summary = "There was no evidence of phishing."
    elif probability < 65:
        verdict = RiskLevel.suspicious
        summary = "Some suspicious characteristics detected - proceed with caution."
    else:
        verdict = RiskLevel.dangerous
        summary = "High probability of phishing - do not click the link and do not provide any data."

    return AnalyzeResponse(
        verdict=verdict,
        phishing_probability=round(probability, 1),
        signals=signals,
        analyzed_url=analyzed_url,
        summary=summary,
    )