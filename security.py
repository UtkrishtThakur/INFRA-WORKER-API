import hashlib
from fastapi import HTTPException, status, Request

# =========================
# API KEY EXTRACTION
# =========================

def extract_api_key(request: Request) -> str:
    """
    Extract API key from request headers.
    Header: X-API-Key
    """
    api_key = request.headers.get("x-api-key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key missing",
        )
    return api_key


# =========================
# HASHING
# =========================

def hash_api_key(raw_key: str) -> str:
    """
    Hash API key using SHA-256.
    Raw keys are NEVER stored or logged.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


# =========================
# VALIDATION (PROJECT-BASED)
# =========================

def validate_api_key(raw_api_key: str) -> str:
    """
    Validate API key format and return hash.
    Project existence is checked elsewhere.
    """
    if not raw_api_key or len(raw_api_key) < 20:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return hash_api_key(raw_api_key)
