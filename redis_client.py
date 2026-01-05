import redis
from config import settings


# Create a Redis client using the connection URL
redis_client = redis.Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    ssl=True,
    ssl_cert_reqs=None,
)
