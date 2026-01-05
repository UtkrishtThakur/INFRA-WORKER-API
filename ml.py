import time
from typing import Dict

from redis_client import redis_client


# ---- CONFIG (v1 heuristics) ----
REQ_RATE_THRESHOLD = 30          # requests per minute per IP
NEW_IP_WEIGHT = 0.3
RATE_SPIKE_WEIGHT = 0.4
PATH_ABUSE_WEIGHT = 0.3


def _minute_bucket() -> int:
    return int(time.time() // 60)


def _ip_rate_key(api_key_hash: str, ip: str) -> str:
    return f"ml:ip_rate:{api_key_hash}:{ip}:{_minute_bucket()}"


def _path_key(api_key_hash: str, path: str) -> str:
    return f"ml:path:{api_key_hash}:{path}:{_minute_bucket()}"


def compute_risk_score(
    *,
    api_key_hash: str,
    ip_address: str,
    path: str,
) -> Dict[str, float]:
    """
    Compute a behavioral risk score for the request.

    Returns:
        {
          "score": float (0.0 - 1.0),
          "ip_rate": int,
          "path_hits": int
        }
    """

    score = 0.0

    score = 0.0

    # ---- IP RATE FEATURE ----
    ip_key = _ip_rate_key(api_key_hash, ip_address)
    ip_rate = redis_client.incr(ip_key)
    if ip_rate == 1:
        redis_client.expire(ip_key, 60)

    if ip_rate > REQ_RATE_THRESHOLD:
        score += RATE_SPIKE_WEIGHT

    # ---- PATH ABUSE FEATURE ----
    path_key = _path_key(api_key_hash, path)
    path_hits = redis_client.incr(path_key)
    if path_hits == 1:
        redis_client.expire(path_key, 60)

    if path_hits > (REQ_RATE_THRESHOLD // 2):
        score += PATH_ABUSE_WEIGHT

    # ---- CLAMP SCORE ----
    score = min(score, 1.0)

    return {
        "score": score,
        "ip_rate": ip_rate,
        "path_hits": path_hits,
    }
