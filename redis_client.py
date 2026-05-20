import logging
import redis
from config import settings

logger = logging.getLogger("securex.redis")

is_ssl = settings.REDIS_URL.startswith("rediss://")

if is_ssl:
    logger.info("Initializing Redis client in SSL mode")
    redis_client = redis.Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        ssl_cert_reqs=None,  # REQUIRED for Upstash
    )
else:
    logger.info("Initializing Redis client in normal (non-SSL) mode")
    redis_client = redis.Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
    )
