import logging
import time
import asyncio
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status, Response
from pydantic import BaseModel

from config_manager import config_manager
from security import extract_api_key, validate_api_key
from rate_limit import check_rate_limit
from ml import compute_risk_score
from decision import make_decision, Decision
from proxy import forward_request
from traffic_logger import emit_traffic_event


# ======================================================
# App Setup
# ======================================================

app = FastAPI(title="SecureX Worker")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securex.worker")


# ======================================================
# Request Context (FACTS ONLY)
# ======================================================

class RequestContext(BaseModel):
    timestamp: str
    project_id: str
    api_key_hash: str

    method: str
    path: str
    endpoint: str

    ip: str
    user_agent: Optional[str]

    risk_score: float
    decision: str
    reason: Optional[str]

    status_code: int
    latency_ms: int


# ======================================================
# Startup
# ======================================================

@app.on_event("startup")
async def startup():
    config_manager.start_background_refresh()


# ======================================================
# Health
# ======================================================

@app.get("/health")
def health_check():
    try:
        config_manager.get_instance()
        return {"status": "ok"}
    except Exception:
        return {"status": "initializing"}


# ======================================================
# Gateway (ALL REAL TRAFFIC)
# ======================================================

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"],
)
async def gateway(
    path: str,
    request: Request,
    raw_api_key: str = Depends(extract_api_key),
):
    start_time = time.monotonic()
    method = request.method
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent")

    canonical_endpoint = normalize_path(path)

    # --------------------------------------------------
    # API Key Validation (IDENTITY ONLY)
    # --------------------------------------------------

    try:
        api_key_hash = validate_api_key(raw_api_key)
    except Exception:
        return await reject(
            start_time,
            "unknown",
            "invalid",
            method,
            path,
            canonical_endpoint,
            client_ip,
            user_agent,
            "Missing or invalid API key",
            401,
        )

    project = config_manager.get_project_by_key(api_key_hash)

    if not project:
        return await reject(
            start_time,
            "unknown",
            api_key_hash,
            method,
            path,
            canonical_endpoint,
            client_ip,
            user_agent,
            "Invalid API key",
            401,
        )

    # --------------------------------------------------
    # Rate Limit (Advisory)
    # --------------------------------------------------

    rate_allowed, remaining = check_rate_limit(
        api_key_hash=api_key_hash,
        ip_address=client_ip,
        endpoint=canonical_endpoint,
    )

    # --------------------------------------------------
    # ML Risk (Advisory)
    # --------------------------------------------------

    risk_score = compute_risk_score(
        api_key_hash=api_key_hash,
        ip_address=client_ip,
        endpoint=canonical_endpoint,
    ).get("risk_score", 0.0)

    # --------------------------------------------------
    # Decision
    # --------------------------------------------------

    decision_result = make_decision(
        rate_limit_allowed=rate_allowed,
        remaining_requests=remaining,
        ml_risk_score=risk_score,
    )

    decision = decision_result["decision"]
    reason = decision_result.get("reason")

    if decision == Decision.THROTTLE:
        await asyncio.sleep(0.3)

    if decision == Decision.BLOCK:
        return await reject(
            start_time,
            project.project_id,
            api_key_hash,
            method,
            path,
            canonical_endpoint,
            client_ip,
            user_agent,
            reason or "Blocked",
            429,
            risk_score,
        )

    upstream_url = (
        f"{project.upstream_base_url.rstrip('/')}/{path}"
    )

    # --------------------------------------------------
    # Forward (TRANSPARENT)
    # --------------------------------------------------

    try:
        response = await forward_request(
            request=request,
            upstream_url=upstream_url,
        )
    except HTTPException as e:
        await emit_event(
            start_time,
            project.project_id,
            api_key_hash,
            method,
            path,
            canonical_endpoint,
            client_ip,
            user_agent,
            risk_score,
            Decision.ALLOW.value,
            "Upstream error",
            e.status_code,
        )
        raise

    await emit_event(
        start_time,
        project.project_id,
        api_key_hash,
        method,
        path,
        canonical_endpoint,
        client_ip,
        user_agent,
        risk_score,
        Decision.ALLOW.value,
        None,
        response.status_code,
    )

    return response


# ======================================================
# Helpers
# ======================================================

def normalize_path(path: str) -> str:
    return "/" + "/".join(
        ":id" if segment.isdigit() else segment
        for segment in path.split("/")
        if segment
    )


async def emit_event(
    start_time,
    project_id,
    api_key_hash,
    method,
    path,
    endpoint,
    ip,
    user_agent,
    risk_score,
    decision,
    reason,
    status_code,
):
    latency_ms = int((time.monotonic() - start_time) * 1000)

    ctx = RequestContext(
        timestamp=datetime.utcnow().isoformat(),
        project_id=project_id,
        api_key_hash=api_key_hash,
        method=method,
        path=path,
        endpoint=endpoint,
        ip=ip,
        user_agent=user_agent,
        risk_score=risk_score,
        decision=decision,
        reason=reason,
        status_code=status_code,
        latency_ms=latency_ms,
    )

    logger.info(ctx.json())
    asyncio.create_task(emit_traffic_event(ctx.dict()))


async def reject(
    start_time,
    project_id,
    api_key_hash,
    method,
    path,
    endpoint,
    ip,
    user_agent,
    reason,
    status_code,
    risk_score=0.0,
):
    await emit_event(
        start_time,
        project_id,
        api_key_hash,
        method,
        path,
        endpoint,
        ip,
        user_agent,
        risk_score,
        Decision.BLOCK.value,
        reason,
        status_code,
    )
    raise HTTPException(status_code=status_code, detail=reason)
