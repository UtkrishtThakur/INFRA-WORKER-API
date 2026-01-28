import asyncio
import logging
import httpx
from typing import Dict
from config import settings

logger = logging.getLogger("securex.worker.traffic")

# ---- TUNABLE SAFETY LIMITS ----
QUEUE_MAX_SIZE = 1000        # Max logs kept in memory
SEND_TIMEOUT = 0.3           # Hard timeout per request (seconds)
MAX_CONNECTIONS = 50
KEEPALIVE_CONNECTIONS = 10

# ---- INTERNAL STATE ----
_log_queue: asyncio.Queue[Dict] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
_worker_started = False


# ---- SHARED HTTP CLIENT (IMPORTANT) ----
_http_client = httpx.AsyncClient(
    timeout=httpx.Timeout(SEND_TIMEOUT),
    limits=httpx.Limits(
        max_connections=MAX_CONNECTIONS,
        max_keepalive_connections=KEEPALIVE_CONNECTIONS,
    ),
)


async def _traffic_worker():
    """
    Background worker that drains the log queue.
    This runs forever and MUST NEVER crash.
    """
    while True:
        event = await _log_queue.get()
        try:
            await _http_client.post(
                f"{settings.CONTROL_API_BASE_URL}/internal/traffic",
                json=event,
                headers={
                    "x-control-secret": settings.CONTROL_WORKER_SHARED_SECRET
                },
            )
        except Exception:
            # Silent drop: control plane MUST NOT affect data plane
            pass
        finally:
            _log_queue.task_done()


def start_traffic_logger():
    """
    Must be called ONCE on worker startup.
    """
    global _worker_started

    if _worker_started:
        return

    if not settings.CONTROL_API_BASE_URL:
        logger.warning("Traffic logging disabled: CONTROL_API_BASE_URL not set")
        return

    asyncio.create_task(_traffic_worker())
    _worker_started = True


def emit_traffic_event(event: Dict) -> None:
    """
    TRUE fire-and-forget traffic emission.

    Guarantees:
    - Zero await
    - Never blocks request path
    - Bounded memory
    - Control plane can be DEAD
    """

    if not _worker_started:
        # If logger isn't ready, drop silently
        return

    # Normalize schema
    if "normalized_path" in event:
        event["endpoint"] = event.pop("normalized_path")

    try:
        _log_queue.put_nowait(event)
    except asyncio.QueueFull:
        # Drop logs when under pressure — THIS IS CORRECT
        pass
