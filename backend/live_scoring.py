from dataclasses import dataclass
 
from live_checks import (
    DomainAgeResult,
    RedirectResult,
    SafeBrowsingResult,
    SecurityHeadersResult,
    SslCheckResult,
)
 
MAX_SCORE = 100
 
 
@dataclass
class LiveCheckSignal:
    name: str
    description: str
    severity: str
 
 
@dataclass
class LiveCheckScore:
    probability: float | None 
    signals: list[LiveCheckSignal]
    checks_succeeded: int
    checks_attempted: int
 
 
def score_live_checks(
    ssl_result: SslCheckResult,
    safe_browsing_result: SafeBrowsingResult,
    domain_age_result: DomainAgeResult,
    redirects_result: RedirectResult,
    headers_result: SecurityHeadersResult,
) -> LiveCheckScore:
    signals: list[LiveCheckSignal] = []
    total = 0
    succeeded = 0
 
    if safe_browsing_result.checked:
        succeeded += 1
        if safe_browsing_result.is_flagged:
            total += 60
            threats = ", ".join(safe_browsing_result.threat_types) or "unknown"
            signals.append(LiveCheckSignal(
                name="Flagged by Google Safe Browsing",
                description=f"This URL is on Google's known-threat list ({threats})",
                severity="high",
            ))
 
    if ssl_result.checked:
        succeeded += 1
        if ssl_result.is_valid is False:
            total += 25
            signals.append(LiveCheckSignal(
                name="Invalid SSL Certificate",
                description="The site's TLS certificate could not be verified",
                severity="high",
            ))
        elif ssl_result.is_valid and ssl_result.expiring_soon:
            total += 5
            signals.append(LiveCheckSignal(
                name="SSL Certificate Expiring Soon",
                description=f"Certificate expires in {ssl_result.days_until_expiry} days",
                severity="low",
            ))
 
    if domain_age_result.checked:
        succeeded += 1
        if domain_age_result.is_new_domain:
            total += 25
            signals.append(LiveCheckSignal(
                name="Recently Registered Domain",
                description=f"Domain was registered {domain_age_result.age_days} days ago",
                severity="high",
            ))
 
    if redirects_result.checked:
        succeeded += 1
        if redirects_result.crosses_domain:
            total += 10
            signals.append(LiveCheckSignal(
                name="Redirects to a Different Domain",
                description=f"Final destination: {redirects_result.final_url}",
                severity="medium",
            ))
 
    if headers_result.checked:
        succeeded += 1
        if not headers_result.has_hsts and not headers_result.has_csp:
            total += 5
            signals.append(LiveCheckSignal(
                name="Missing Security Headers",
                description="No HSTS or CSP headers were found in the response",
                severity="low",
            ))
 
    attempted = 5
    if succeeded == 0:
        return LiveCheckScore(probability=None, signals=[], checks_succeeded=0, checks_attempted=attempted)
 
    probability = float(min(total, MAX_SCORE))
    return LiveCheckScore(
        probability=probability,
        signals=signals,
        checks_succeeded=succeeded,
        checks_attempted=attempted,
    )
 