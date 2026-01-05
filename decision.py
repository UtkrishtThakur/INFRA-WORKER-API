from enum import Enum
from typing import Dict, Any


class Decision(str, Enum):
    ALLOW = "ALLOW"
    THROTTLE = "THROTTLE"
    BLOCK = "BLOCK"


def make_decision(
    *,
    rate_limit_allowed: bool,
    remaining_requests: int,
    ml_risk_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Combine all security signals and return a final decision.

    Inputs:
    - rate_limit_allowed: result from rate limiter
    - remaining_requests: remaining quota in current window
    - ml_risk_score: anomaly score (0.0 - 1.0)

    Output:
    - decision: ALLOW | THROTTLE | BLOCK
    - reason: human-readable explanation
    - metadata: structured info for logs / dashboards
    """

    # ---- HARD BLOCK CONDITIONS ----
    if not rate_limit_allowed:
        return {
            "decision": Decision.BLOCK,
            "reason": "Rate limit exceeded",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    # ---- ML-BASED BLOCK (future expansion) ----
    if ml_risk_score >= 0.9:
        return {
            "decision": Decision.BLOCK,
            "reason": "High risk traffic detected",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    # ---- THROTTLE ZONE ----
    if ml_risk_score >= 0.6:
        return {
            "decision": Decision.THROTTLE,
            "reason": "Suspicious traffic pattern",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    # ---- DEFAULT ALLOW ----
    return {
        "decision": Decision.ALLOW,
        "reason": "Request allowed",
        "metadata": {
            "remaining_requests": remaining_requests,
            "risk_score": ml_risk_score,
        },
    }
