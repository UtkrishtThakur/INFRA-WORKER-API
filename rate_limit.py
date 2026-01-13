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


def classify_endpoint(endpoint: str) -> str:
    """
    Very simple v1 endpoint classification.
    Can be improved later or fetched from Control API.
    """
    endpoint = endpoint.lower()

    if "auth" in endpoint or "login" in endpoint or "otp" in endpoint:
        return "HIGH"

    if "search" in endpoint or "list" in endpoint:
        return "LOW"

    return DEFAULT_PROFILE


# =========================
# Dynamic Rate Limiter
# =========================

def check_rate_limit(
    api_key_hash: str,
    ip_address: str,
    endpoint: str,
) -> Tuple[bool, int]:
    """
    Dynamic endpoint-aware rate limiting.

    Returns:
        allowed (bool)
        remaining_requests (int)
    """

    profile = classify_endpoint(endpoint)
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
