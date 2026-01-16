import httpx
import asyncio
import logging
from typing import Optional
from config import settings

logger = logging.getLogger("securex.worker.traffic")


async def emit_traffic_event(event: dict) -> None:
    """
    Fire-and-forget traffic export to Control API.
    
    Design guarantees:
    - NEVER blocks request flow (background task only)
    - Hard 500ms timeout enforced
    - Retries with exponential backoff (50ms, 100ms)
    - Single error log on permanent failure (no spam)
    - All exceptions swallowed
    
    Payload contract:
    - Sends to POST /internal/traffic ONLY
    - Field 'endpoint' contains normalized path (canonical routing identifier)
    """
    if not settings.CONTROL_API_BASE_URL:
        return

    # Rename normalized_path to endpoint for Control API schema alignment
    if "normalized_path" in event:
        event["endpoint"] = event.pop("normalized_path")

    max_retries = 2
    retry_delays = [0.05, 0.1]  # 50ms, 100ms
    
    for attempt in range(max_retries + 1):
        try:
            # Hard timeout: 500ms total for the entire request
            async with httpx.AsyncClient(timeout=0.5) as client:
                await client.post(
                    f"{settings.CONTROL_API_BASE_URL}/internal/traffic",
                    json=event,
                    headers={"x-control-secret": settings.CONTROL_WORKER_SHARED_SECRET}
                )
            # Success - exit immediately
            return
            
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
            # Retry on network/timeout errors
            if attempt < max_retries:
                await asyncio.sleep(retry_delays[attempt])
                continue
            else:
                # Permanent failure after all retries - log once
                logger.error(
                    f"Traffic emission failed permanently after {max_retries + 1} attempts: {type(e).__name__}"
                )
                
        except Exception as e:
            # Unexpected error - log and swallow to prevent worker crash
            logger.error(f"Unexpected error in traffic emission: {type(e).__name__}: {str(e)}")
            return
