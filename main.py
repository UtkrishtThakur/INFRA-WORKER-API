import logging
import time
import asyncio
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status
from pydantic import BaseModel

from config_manager import config_manager
from security import extract_api_key, validate_api_key
from rate_limit import check_rate_limit
from ml import compute_risk_score
from decision import make_decision, Decision
from proxy import forward_request
from traffic_logger import emit_traffic_event


# =========================
# App Setup
# =========================

app = FastAPI(title="SecureX Worker")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securex.worker")


# =========================
# Request Context (FACTS ONLY)
# =========================

class RequestContext(BaseModel):
    timestamp: str
    project_id: str
    api_key_hash: str

    method: str
    path: str
    normalized_path: str

    ip: str
    user_agent: Optional[str]

    risk_score: float
    decision: str
    reason: Optional[str]

    status_code: int
    latency_ms: int


# =========================
# Startup
# =========================

@app.on_event("startup")
async def startup():
    config_manager.start_background_refresh()


# =========================
# Health
# =========================

@app.get("/health")
def health_check():
    try:
        _ = config_manager.get_instance()
        return {"status": "ok"}
    except Exception:
        return {"status": "initializing"}


# =========================
# Gateway
# =========================

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def gateway(
    path: str,
    request: Request,
    raw_api_key: str = Depends(extract_api_key),
):
    start_time = time.monotonic()

    # ---- Auth ----
    api_key_hash = validate_api_key(raw_api_key)
    project_config = config_manager.get_project_by_key(api_key_hash)

    if not project_config:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # ---- Request Info ----
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent")
    normalized_path = normalize_path(path)

    # ---- Rate Limit ----
    rate_allowed, remaining = check_rate_limit(
        api_key_hash=api_key_hash,
        ip_address=client_ip,
        endpoint=normalized_path,
    )

    # ---- ML Brain ----
    ml_result = compute_risk_score(
        api_key_hash=api_key_hash,
        ip_address=client_ip,
        endpoint=normalized_path,
    )

    risk_score = ml_result["risk_score"]

    # ---- Decision ----
    decision_result = make_decision(
        rate_limit_allowed=rate_allowed,
        remaining_requests=remaining,
        ml_risk_score=risk_score,
    )

    decision = decision_result["decision"]
    reason = decision_result.get("reason")

    # ---- Progressive Enforcement ----
    if decision == Decision.THROTTLE:
        # MVP throttling: deterministic delay
        await asyncio.sleep(0.3)

    if decision == Decision.BLOCK:
        latency_ms = int((time.monotonic() - start_time) * 1000)

        ctx = RequestContext(
            timestamp=datetime.utcnow().isoformat(),
            project_id=project_config.project_id,
            api_key_hash=api_key_hash,
            method=request.method,
            path=path,
            normalized_path=normalized_path,
            ip=client_ip,
            user_agent=user_agent,
            risk_score=risk_score,
            decision=decision.value,
            reason=reason,
            status_code=429,
            latency_ms=latency_ms,
        )

        logger.info(ctx.json())
        asyncio.create_task(emit_traffic_event(ctx.dict()))

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=reason or "Request blocked",
        )

    # ---- Forward ----
    upstream_url = f"{project_config.upstream_base_url.rstrip('/')}/{path}"
    response = await forward_request(request=request, upstream_url=upstream_url)

    latency_ms = int((time.monotonic() - start_time) * 1000)

    # ---- Emit Success Event ----
    ctx = RequestContext(
        timestamp=datetime.utcnow().isoformat(),
        project_id=project_config.project_id,
        api_key_hash=api_key_hash,
        method=request.method,
        path=path,
        normalized_path=normalized_path,
        ip=client_ip,
        user_agent=user_agent,
        risk_score=risk_score,
        decision=decision.value,
        reason=None,
        status_code=response.status_code,
        latency_ms=latency_ms,
    )

    logger.info(ctx.json())
    asyncio.create_task(emit_traffic_event(ctx.dict()))

    return response


# =========================
# Utils
# =========================

def normalize_path(path: str) -> str:
    return "/" + "/".join(
        ":id" if segment.isdigit() else segment
        for segment in path.split("/")
        if segment
    )
