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
    Progressive decision engine.

    Philosophy:
    - Allow by default
    - Throttle when behavior drifts
    - Block only when clearly abusive
    """

    # -------------------------
    # HARD BLOCK (Confirmed Abuse)
    # -------------------------
    if not rate_limit_allowed:
        return {
            "decision": Decision.BLOCK,
            "reason": "Confirmed abuse: rate limit exceeded",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    if ml_risk_score >= 0.9:
        return {
            "decision": Decision.BLOCK,
            "reason": "Confirmed abuse: high risk behavior",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    # -------------------------
    # SOFT ENFORCEMENT (Early Warning)
    # -------------------------
    if ml_risk_score >= 0.6:
        return {
            "decision": Decision.THROTTLE,
            "reason": "Abnormal usage pattern detected",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    if remaining_requests <= 5:
        return {
            "decision": Decision.THROTTLE,
            "reason": "Approaching rate limit",
            "metadata": {
                "remaining_requests": remaining_requests,
                "risk_score": ml_risk_score,
            },
        }

    # -------------------------
    # DEFAULT (Healthy Traffic)
    # -------------------------
    return {
        "decision": Decision.ALLOW,
        "reason": "Usage within expected behavior",
        "metadata": {
            "remaining_requests": remaining_requests,
            "risk_score": ml_risk_score,
        },
    }
