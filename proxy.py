import httpx
from typing import Dict

from fastapi import Request, HTTPException, status
from fastapi.responses import StreamingResponse

# --------------------------------------------------
# Hop-by-hop headers (RFC compliant)
# --------------------------------------------------

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def _filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


# --------------------------------------------------
# SHARED HTTP CLIENT (IMPORTANT)
# --------------------------------------------------

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=30.0)
    return _client


async def close_client():
    global _client
    if _client:
        await _client.aclose()
        _client = None


# --------------------------------------------------
# Proxy Forwarder
# --------------------------------------------------

async def forward_request(
    *,
    request: Request,
    upstream_url: str,
) -> StreamingResponse:
    """
    Transparently forward request to upstream and stream response back.
    """
    client = get_client()

    try:
        upstream_req = client.build_request(
            method=request.method,
            url=upstream_url,
            headers=_filter_headers(dict(request.headers)),
            params=request.query_params,
            content=request.stream(),
        )

        upstream_resp = await client.send(upstream_req, stream=True)

        return StreamingResponse(
            upstream_resp.aiter_raw(),
            status_code=upstream_resp.status_code,
            headers=_filter_headers(dict(upstream_resp.headers)),
            media_type=upstream_resp.headers.get("content-type"),
        )

    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream service unreachable: {str(e)}",
        )
