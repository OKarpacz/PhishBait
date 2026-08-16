from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class InputType(str, Enum):
    url = "url"
    email = "email"


class AnalyzeRequest(BaseModel):
    """
    Body requestu POST /api/analyze.
    """
    input_type: InputType
    content: str = Field(..., min_length=1, description="URL or email content to analyze")


class RiskLevel(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    dangerous = "dangerous"


class Signal(BaseModel):
    """
    np. { "name": "No SSL Certificate", "severity": "high" }
    """
    name: str
    description: str
    severity: Literal["low", "medium", "high"]


class AnalyzeResponse(BaseModel):
    verdict: RiskLevel                     
    phishing_probability: float = Field(   
        ..., ge=0, le=100, description="Probability of phishing in percentages (0-100)"
    )
    signals: list[Signal]                  
    analyzed_url: Optional[str] = None     
    summary: str                          