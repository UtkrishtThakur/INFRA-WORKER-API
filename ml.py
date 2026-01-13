import time
from typing import Dict

from redis_client import redis_client


WINDOW_SECONDS = 60


def compute_risk_score(
    *,
    api_key_hash: str,
    ip_address: str,
    endpoint: str,
) -> Dict[str, any]:
    """
    Compute multi-signal behavior risk score.
    """

    signals = {}

    # -------------------------
    # 1. Velocity Signal
    # -------------------------
    velocity_key = f"ml:velocity:{api_key_hash}:{ip_address}:{endpoint}"
    velocity = redis_client.incr(velocity_key)
    if velocity == 1:
        redis_client.expire(velocity_key, WINDOW_SECONDS)

    velocity_score = min(velocity / 30.0, 1.0)
    signals["velocity"] = velocity_score

    # -------------------------
    # 2. Burst Signal
    # -------------------------
    burst_score = 1.0 if velocity > 20 else velocity / 20.0
    signals["burst"] = burst_score

    # -------------------------
    # 3. Endpoint Drift Signal
    # -------------------------
    drift_key = f"ml:endpoints:{api_key_hash}:{ip_address}"
    redis_client.sadd(drift_key, endpoint)
    redis_client.expire(drift_key, WINDOW_SECONDS)

    endpoint_count = redis_client.scard(drift_key)
    drift_score = min(endpoint_count / 5.0, 1.0)
    signals["endpoint_drift"] = drift_score

    # -------------------------
    # 4. Fanout Signal (future-ready)
    # -------------------------
    # Placeholder for Control API aggregation
    fanout_score = 0.0
    signals["fanout"] = fanout_score

    # -------------------------
    # Final Risk Score (Weighted)
    # -------------------------
    risk_score = (
        0.4 * velocity_score +
        0.3 * burst_score +
        0.3 * drift_score
    )

    primary_reason = max(signals, key=signals.get)

    return {
        "risk_score": round(risk_score, 2),
        "signals": signals,
        "primary_reason": primary_reason,
    }
