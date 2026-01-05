from pydantic import BaseModel
from typing import Optional, Dict


class DecisionMetadata(BaseModel):
    remaining_requests: int
    risk_score: float


class DecisionResponse(BaseModel):
    decision: str
    reason: str
    metadata: DecisionMetadata


class HealthResponse(BaseModel):
    status: str


class ErrorResponse(BaseModel):
    detail: str
