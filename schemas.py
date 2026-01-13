from pydantic import BaseModel
from typing import Optional


class DecisionMetadata(BaseModel):
    remaining_requests: int
    risk_score: float


class DecisionResponse(BaseModel):
    decision: str          # ALLOW | THROTTLE | BLOCK
    reason: Optional[str]  # human-readable enum
    metadata: DecisionMetadata


class HealthResponse(BaseModel):
    status: str


class ErrorResponse(BaseModel):
    detail: str
