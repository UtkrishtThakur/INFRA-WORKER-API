import time
from typing import Tuple

from redis_client import redis_client


# Rate limit configuration (v1 defaults)
REQUESTS_PER_MINUTE = 60
BURST_LIMIT = 20


def _current_minute() -> int:
    """
    Returns the current time window (minute-level).
    """
    return int(time.time() // 60)


def rate_limit_key(api_key_hash: str, ip_address: str) -> str:
    """
    Construct a unique Redis key for rate limiting.
    """
    return f"rate_limit:{api_key_hash}:{ip_address}:{_current_minute()}"


def check_rate_limit(
    api_key_hash: str,
    ip_address: str,
) -> Tuple[bool, int]:
    """
    Check whether the request is allowed under rate limits.

    Returns:
        allowed (bool): Whether request is allowed
        remaining (int): Remaining requests in the window
    """
    key = rate_limit_key(api_key_hash, ip_address)

    # Atomically increment the counter
    current_count = redis_client.incr(key)

    # Set TTL only on first request in this window
    if current_count == 1:
        redis_client.expire(key, 60)

    # Hard block if burst exceeded
    if current_count > REQUESTS_PER_MINUTE + BURST_LIMIT:
        return False, 0

    remaining = max(REQUESTS_PER_MINUTE - current_count, 0)
    return True, remaining
