import httpx
import os

CONTROL_API_URL = os.getenv("CONTROL_API_URL")


async def emit_traffic_event(event: dict) -> None:
    """
    Fire-and-forget traffic export.
    MUST NEVER block request flow.
    """
    if not CONTROL_API_URL:
        return

    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            await client.post(
                f"{CONTROL_API_URL}/internal/traffic/ingest",
                json=event,
            )
    except Exception:
        # Never break worker on logging failure
        pass
