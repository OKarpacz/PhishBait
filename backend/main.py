from pathlib import Path
 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
 
from analyzer import analyze
from schemas import AnalyzeRequest, AnalyzeResponse

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
    """
    US-44 / US-45: przyjmuje wklejony URL albo treść e-maila.
    Zwraca werdykt w kształcie potrzebnym dla US-46, US-47, US-48, US-49.
    """
    return analyze(request)

@app.get("/api/health")
def health():
    return {"status": "healthy"}

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
 