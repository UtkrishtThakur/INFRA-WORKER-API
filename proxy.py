import httpx
from typing import Dict, Generator

from fastapi import Request, HTTPException, status
from fastapi.responses import StreamingResponse


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",  # Let httpx set the host header based on URL
}


def _filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Remove hop-by-hop headers as per RFC 2616.
    These must not be forwarded by proxies.
    """
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


async def forward_request(
    *,
    request: Request,
    upstream_url: str,
) -> StreamingResponse:
    """
    Forward the incoming request to the upstream service
    and return the upstream response transparently using streaming.
    """
    client = httpx.AsyncClient(timeout=30.0)

    try:
        req = client.build_request(
            method=request.method,
            url=upstream_url,
            headers=_filter_headers(dict(request.headers)),
            params=request.query_params,
            content=request.stream(),
        )
        
        r = await client.send(req, stream=True)
        
        return StreamingResponse(
            r.aiter_raw(),
            status_code=r.status_code,
            headers=_filter_headers(dict(r.headers)),
            media_type=r.headers.get("content-type"),
            background=None,  # Optimization: explicit none if we don't have bg tasks
        )

    except httpx.RequestError as e:
        await client.aclose()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream service unreachable: {str(e)}",
        )
    except Exception:
        await client.aclose()
        raise

