import httpx
import logging
from config import settings

logger = logging.getLogger("securex.worker.traffic")

async def emit_traffic_event(event: dict) -> None:
    """
    Fire-and-forget traffic export to Control API.
    MUST NEVER block request flow.
    """
    if not settings.CONTROL_API_BASE_URL:
        return

    try:
        async with httpx.AsyncClient(timeout=0.5) as client:
            await client.post(
                f"{settings.CONTROL_API_BASE_URL}/internal/traffic",
                json=event,
                headers={"x-control-secret": settings.CONTROL_WORKER_SHARED_SECRET}
            )
    except Exception as e:
        # Never break worker on logging failure
        # Swallow error, but log warning for visibility
        logger.warning(f"Failed to emit traffic event: {str(e)}")
        pass
