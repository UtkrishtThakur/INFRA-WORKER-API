import json
import logging
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

# =========================
# Setup
# =========================

app = FastAPI(title="Infra Worker API")

# Configure JSON logging for stdout (Infrastructure will capture this)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("traffic")

class TrafficLogEntry(BaseModel):
    timestamp: str
    project_id: str
    host: str
    ip: str
    path: str
    method: str
    status: int
    risk_score: float
    decision: str
    blocked: bool
    reason: Optional[str] = None

# =========================
# Startup (FAIL CLOSED)
# =========================

@app.on_event("startup")
async def startup():
    """
    Worker Startup Lifecycle:
    1. Start background config refresh.
       - Does NOT block startup.
       - Worker starts serving immediately (empty config until first fetch).
    """
    config_manager.start_background_refresh()


# =========================
# Health
# =========================

@app.get("/health")
def health_check():
    # If ConfigManager isn't ready, we are effectively unhealthy (though startup should block)
    try:
        # A simple check to ensure we can read config
        _ = config_manager.get_instance()
    except Exception:
         return {"status": "initializing"}

    return {
        "status": "ok",
        "worker_type": "stateless",
    }


# =========================
# Gateway (HOST-BASED)
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
    # 1️⃣ Validate + hash API key
    api_key_hash = validate_api_key(raw_api_key)

    # 2️⃣ Resolve project by API key
    project_config = config_manager.get_project_by_key(api_key_hash)

    if not project_config:
        logger.warning("Invalid API key used")
        raise HTTPException(status_code=401, detail="Invalid API key")

    # 3️⃣ Client IP
    client_ip = request.client.host

    # 4️⃣ Rate limiting
    rate_allowed, remaining = check_rate_limit(
        api_key_hash=api_key_hash,
        ip_address=client_ip,
    )

    # 5️⃣ ML risk
    risk_data = compute_risk_score(
        api_key_hash=api_key_hash,
        ip_address=client_ip,
        path=path,
    )
    ml_risk_score = risk_data["score"]

    # 6️⃣ Decision
    decision_result = make_decision(
        rate_limit_allowed=rate_allowed,
        remaining_requests=remaining,
        ml_risk_score=ml_risk_score,
    )

    decision = decision_result["decision"]
    blocked = (decision == Decision.BLOCK)

    # 7️⃣ Log
    log_entry = TrafficLogEntry(
        timestamp=datetime.utcnow().isoformat(),
        project_id=project_config.project_id,
        host="gateway",
        ip=client_ip,
        path=path,
        method=request.method,
        status=429 if blocked else 200,
        risk_score=ml_risk_score,
        decision=decision.value,
        blocked=blocked,
        reason=decision_result.get("reason"),
    )
    logger.info(log_entry.json())

    if blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=decision_result.get("reason", "Request blocked"),
        )

    # 8️⃣ Forward
    upstream_url = f"{project_config.upstream_base_url.rstrip('/')}/{path}"

    return await forward_request(
        request=request,
        upstream_url=upstream_url,
    )
