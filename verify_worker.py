
import asyncio
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

# Mock Redis before importing app modules that use it
with patch("redis.Redis") as mock_redis:
    from main import app
    from config_manager import config_manager, DomainConfig
    from decision import Decision

client = TestClient(app)

# Mock Data
VALID_HOST = "api.example.com"
VALID_KEY = "test-key-123"
VALID_KEY_HASH = "8facc86a1005a8f2730ca74cd6622ec92b3c7b3967d74f266c2dbf37b605af6c" # sha256 of test-key-123
PROJECT_ID = "proj_123"
UPSTREAM_URL = "http://backend.internal"

@pytest.mark.asyncio
async def test_startup_fail_closed():
    """Ensure worker crashes if config fails to load"""
    with patch.object(config_manager, "_fetch_and_update", side_effect=RuntimeError("Control API down")):
        with pytest.raises(RuntimeError):
            await config_manager.initialize()

@pytest.mark.asyncio
async def test_startup_success():
    """Ensure worker loads config correctly"""
    mock_data = [{
        "hostname": VALID_HOST,
        "project_id": PROJECT_ID,
        "upstream_base_url": UPSTREAM_URL,
        "api_key_hashes": [VALID_KEY_HASH]
    }]
    
    # Mock the HTTP call inside _fetch_and_update
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: mock_data)
        await config_manager.initialize()
        
    assert config_manager.get_domain_config(VALID_HOST) is not None

def test_unknown_domain():
    """404 for unknown host"""
    # config_manager state is global, assumed initialized from previous test if running sequence, 
    # but better to force clean state or mock get_domain_config
    
    with patch.object(config_manager, "get_domain_config", return_value=None):
        resp = client.get("/foo", headers={"Host": "unknown.com", "X-API-Key": VALID_KEY})
        assert resp.status_code == 404
        assert "Unknown domain" in resp.json()["detail"]

def test_missing_api_key():
    """401 for missing key"""
    with patch.object(config_manager, "get_domain_config", return_value=MagicMock()):
        resp = client.get("/foo", headers={"Host": VALID_HOST})
        assert resp.status_code == 401

def test_invalid_api_key():
    """401 for invalid key"""
    domain_config = DomainConfig(
        project_id=PROJECT_ID,
        upstream_base_url=UPSTREAM_URL,
        api_key_hashes={VALID_KEY_HASH}, # Set
        hostname=VALID_HOST
    )
    
    with patch.object(config_manager, "get_domain_config", return_value=domain_config):
        resp = client.get("/foo", headers={"Host": VALID_HOST, "X-API-Key": "wrong-key"})
        assert resp.status_code == 401

@patch("main.forward_request")
@patch("main.check_rate_limit")
@patch("main.compute_risk_score")
@patch("main.make_decision")
def test_happy_path(mock_decision, mock_risk, mock_limit, mock_forward):
    """Full flow: Host -> Auth -> RateLimit -> ML -> Decision -> Proxy"""
    
    # Setup Mocks
    domain_config = DomainConfig(
        project_id=PROJECT_ID,
        upstream_base_url=UPSTREAM_URL,
        api_key_hashes={VALID_KEY_HASH},
        hostname=VALID_HOST
    )
    
    mock_limit.return_value = (True, 100)
    mock_risk.return_value = {"score": 0.1}
    mock_decision.return_value = {"decision": Decision.ALLOW}
    mock_forward.return_value = MagicMock(status_code=200) # Simple mock response
    
    # Request
    with patch.object(config_manager, "get_domain_config", return_value=domain_config):
        resp = client.get("/users/123", headers={"Host": VALID_HOST, "X-API-Key": VALID_KEY})
        
        # Assertions
        assert resp.status_code == 200 # Since mock_forward returns a MagicMock which verify_worker might interpret
        
        # Verify proxy call args
        call_args = mock_forward.call_args
        assert call_args is not None
        _, kwargs = call_args
        assert kwargs["upstream_url"] == f"{UPSTREAM_URL}/users/123"

# Run logic
if __name__ == "__main__":
    import sys
    # We can't easily run pytest from inside the script without installing it, 
    # but we can try to run simple assertions manually if pytest isn't there.
    # However, user likely has pytest. Let's try running via command line.
    print("Please run: pytest verify_worker.py")
