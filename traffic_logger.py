import asyncio
import logging
from typing import Dict, Optional

import httpx
from config import settings

logger = logging.getLogger("securex.worker.traffic")

# ======================================================
# Tunables
# ======================================================

QUEUE_MAX_SIZE = 1000        # Max logs kept in memory
SEND_TIMEOUT = 0.3           # Hard timeout per request (seconds)
MAX_CONNECTIONS = 50
KEEPALIVE_CONNECTIONS = 10

# ======================================================
# Internal State
# ======================================================

_log_queue: asyncio.Queue[Dict] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
_worker_task: Optional[asyncio.Task] = None
_worker_started = False


# ======================================================
# Shared HTTP Client
# ======================================================

_http_client = httpx.AsyncClient(
    timeout=httpx.Timeout(SEND_TIMEOUT),
    limits=httpx.Limits(
        max_connections=MAX_CONNECTIONS,
        max_keepalive_connections=KEEPALIVE_CONNECTIONS,
    ),
)


# ======================================================
# Background Worker
# ======================================================

async def _traffic_worker():
    """
    Drains the traffic queue forever.

    HARD GUARANTEE:
    - MUST NEVER crash
    - MUST NEVER block request path
    """
    logger.info("Traffic worker started")

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
        except Exception as e:
            # Control plane failure must NOT affect data plane
            logger.debug(f"Traffic send failed (dropped): {e}")
        finally:
            _log_queue.task_done()


# ======================================================
# Lifecycle
# ======================================================

def start_traffic_logger():
    """
    Must be called ONCE after event loop is running.
    """
    global _worker_started, _worker_task

    if _worker_started:
        return

    if not settings.CONTROL_API_BASE_URL:
        logger.warning("Traffic logging disabled: CONTROL_API_BASE_URL not set")
        return

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.error("Traffic logger start attempted without running event loop")
        return

    _worker_task = loop.create_task(_traffic_worker())
    _worker_started = True

    logger.info("Traffic logger initialized")


async def shutdown_traffic_logger():
    """
    Graceful shutdown (best-effort).
    """
    global _worker_task

    if _worker_task:
        _worker_task.cancel()

    await _http_client.aclose()
    logger.info("Traffic logger shut down")


def is_logger_ready() -> bool:
    return _worker_started


# ======================================================
# Public API
# ======================================================

def emit_traffic_event(event: Dict) -> None:
    """
    TRUE fire-and-forget emission.

    Guarantees:
    - Zero await
    - Never blocks request path
    - Bounded memory
    - Control plane can be DEAD
    """

    if not _worker_started:
        return

    # Schema hardening
    if "normalized_path" in event and "endpoint" not in event:
        event["endpoint"] = event.pop("normalized_path")

    try:
        _log_queue.put_nowait(event)
    except asyncio.QueueFull:
        # Correct behavior: drop under pressure
        logger.debug("Traffic queue full — dropping event")
