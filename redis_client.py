import redis
from config import settings

redis_client = redis.Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    ssl_cert_reqs=None,  # REQUIRED for Upstash
)
