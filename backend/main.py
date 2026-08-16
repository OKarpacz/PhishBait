from pathlib import Path
 
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

load_dotenv()
 
from analyzer import analyze
from live_checks import (
    check_domain_age,
    check_redirects,
    check_safe_browsing,
    check_security_headers,
    check_ssl_certificate,
)
from schemas import AnalyzeRequest, AnalyzeResponse
from url_features import extract_features

app = FastAPI(title="PhishBait", version="0.0.1", description="Phishing URL detection and analysis service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    return analyze(request)


@app.get("/api/health")
def health() -> dict:
    return {"status": "healthy"}


@app.get("/api/debug/url-features")
def debug_url_features(url: str) -> dict:
    features = extract_features(url)
    return {
        "url": features.url,
        "scheme": features.scheme,
        "domain": features.domain,
        "subdomain": features.subdomain,
        "tld": features.tld,
        "url_length": features.url_length,
        "domain_length": features.domain_length,
        "dot_count": features.dot_count,
        "hyphen_count": features.hyphen_count,
        "digit_count": features.digit_count,
        "special_char_count": features.special_char_count,
        "has_ip_address": features.has_ip_address,
        "has_at_symbol": features.has_at_symbol,
        "is_suspicious_tld": features.is_suspicious_tld,
        "is_https": features.is_https,
        "typosquat_target": features.typosquat_target,
        "typosquat_similarity": features.typosquat_similarity,
        "subdomain_count": features.subdomain_count,
    }


@app.get("/api/debug/live-checks")
def debug_live_checks(url: str) -> dict:
    ssl_result = check_ssl_certificate(url)
    safe_browsing_result = check_safe_browsing(url)
    domain_age_result = check_domain_age(url)
    redirects_result = check_redirects(url)
    headers_result = check_security_headers(url)

    return {
        "ssl": ssl_result.__dict__,
        "safe_browsing": safe_browsing_result.__dict__,
        "domain_age": domain_age_result.__dict__,
        "redirects": redirects_result.__dict__,
        "security_headers": headers_result.__dict__,
    }

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")