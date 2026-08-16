from dataclasses import dataclass
from typing import Callable, Literal
 
from url_features import UrlFeatures
 
Severity = Literal["low", "medium", "high"]
 
@dataclass
class HeuristicRule:
    name: str
    description: str
    severity: Severity
    points: int
    predicate: Callable[[UrlFeatures], bool]
 
 
@dataclass
class HeuristicSignal:
    name: str
    description: str
    severity: Severity
 
 
@dataclass
class HeuristicResult:
    """US-16: the aggregated outcome of scoring a URL."""
    probability: float
    signals: list[HeuristicSignal]
 
MAX_SCORE = 100
 
RULES: list[HeuristicRule] = [
    HeuristicRule(
        name="Typosquatting Detected",
        description="Domain closely resembles a known brand ({target})",
        severity="high",
        points=30,
        predicate=lambda f: f.typosquat_target is not None,
    ),
    HeuristicRule(
        name="IP Address Instead of Domain",
        description="The URL points directly to an IP address instead of a domain name",
        severity="high",
        points=25,
        predicate=lambda f: f.has_ip_address,
    ),
    HeuristicRule(
        name="'@' Symbol in URL",
        description="Browsers ignore everything before '@' - a classic link-spoofing trick",
        severity="high",
        points=20,
        predicate=lambda f: f.has_at_symbol,
    ),
    HeuristicRule(
        name="No HTTPS",
        description="The connection to this site is not encrypted",
        severity="medium",
        points=15,
        predicate=lambda f: not f.is_https,
    ),
    HeuristicRule(
        name="Suspicious TLD",
        description="The domain uses a top-level domain often associated with spam and abuse",
        severity="medium",
        points=15,
        predicate=lambda f: f.is_suspicious_tld,
    ),
    HeuristicRule(
        name="Unusual Characters",
        description="The URL contains characters outside the normal expected range",
        severity="medium",
        points=10,
        predicate=lambda f: f.special_char_count > 0,
    ),
    HeuristicRule(
        name="Many Subdomains",
        description="The URL has an unusually deep subdomain structure",
        severity="medium",
        points=10,
        predicate=lambda f: f.subdomain_count >= 3,
    ),
    HeuristicRule(
        name="Very Long URL",
        description="The URL is unusually long, which can indicate obfuscation",
        severity="low",
        points=10,
        predicate=lambda f: f.url_length > 75,
    ),
    HeuristicRule(
        name="Multiple Hyphens",
        description="The domain contains several hyphens, common in look-alike domains",
        severity="low",
        points=5,
        predicate=lambda f: f.hyphen_count >= 2,
    ),
]
 
 
def score_url(features: UrlFeatures) -> HeuristicResult:
    signals: list[HeuristicSignal] = []
    total = 0
 
    for rule in RULES:
        if not rule.predicate(features):
            continue
 
        total += rule.points
 
        description = rule.description
        if "{target}" in description:
            description = description.format(target=features.typosquat_target)
 
        signals.append(
            HeuristicSignal(name=rule.name, description=description, severity=rule.severity)
        )
 
    probability = float(min(total, MAX_SCORE))
    return HeuristicResult(probability=probability, signals=signals)
 