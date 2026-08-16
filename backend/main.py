from pathlib import Path
 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
 
from analyzer import analyze
from schemas import AnalyzeRequest, AnalyzeResponse
from url_features import extract_features

app = FastAPI(
    title="PhishBait",
    description="A phishing detection API for websites and emails.",
    version="0.0.1",
)

#Narazie tylko dla develeopmentu:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    return analyze(request)

@app.get("/api/health")
def health():
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

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")