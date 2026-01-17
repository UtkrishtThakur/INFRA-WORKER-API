import time
from typing import Tuple

from redis_client import redis_client


# =========================
# Default Rate Limit Profiles (MVP)
# =========================

ENDPOINT_LIMITS = {
    "HIGH": {"rpm": 10, "burst": 5},     # auth, sensitive
    "MEDIUM": {"rpm": 60, "burst": 20},  # normal APIs
    "LOW": {"rpm": 300, "burst": 50},    # read-heavy / public
}

DEFAULT_PROFILE = "MEDIUM"


# =========================
# Helpers
# =========================

def _current_minute() -> int:
    return int(time.time() // 60)


def rate_limit_key(api_key_hash: str, ip_address: str, endpoint: str) -> str:
    return f"rate_limit:{api_key_hash}:{ip_address}:{endpoint}:{_current_minute()}"


def check_rate_limit(
    api_key_hash: str,
    ip_address: str,
    endpoint: str,
) -> Tuple[bool, int]:
    """
    Global default rate limiting for all endpoints.
    SecureX does not classify application routes.

    Returns:
        allowed (bool)
        remaining_requests (int)
    """

    profile = DEFAULT_PROFILE
    limits = ENDPOINT_LIMITS[profile]

    rpm = limits["rpm"]
    burst = limits["burst"]

    key = rate_limit_key(api_key_hash, ip_address, endpoint)

    current_count = redis_client.incr(key)

    if current_count == 1:
        redis_client.expire(key, 60)

    # ---- HARD BLOCK ----
    if current_count > rpm + burst:
        return False, 0

    remaining = max(rpm - current_count, 0)
    return True, remaining
