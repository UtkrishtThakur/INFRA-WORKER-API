
import asyncio
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

import hashlib

# Mock Redis before importing app modules that use it
with patch("redis.Redis") as mock_redis:
    from main import app
    from config_manager import config_manager, ProjectConfig
    from decision import Decision

client = TestClient(app)

# Mock Data
VALID_KEY = "test-key-123-must-be-longer-than-20-chars"
VALID_KEY_HASH = hashlib.sha256(VALID_KEY.encode()).hexdigest()
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
    # Structure of /internal/worker/config response
    mock_data = {
        "projects": [
            {
                "id": PROJECT_ID,
                "upstream_url": UPSTREAM_URL,
                "api_keys": [VALID_KEY_HASH]
            }
        ]
    }
    
    # Mock the HTTP call inside _fetch_and_update
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, json=lambda: mock_data)
        await config_manager.initialize()
        
    assert config_manager.get_project_by_key(VALID_KEY_HASH) is not None

def test_missing_api_key():
    """401 for missing key"""
    resp = client.get("/foo", headers={})
    assert resp.status_code == 401
    assert "API key missing" in resp.json()["detail"]

def test_invalid_api_key():
    """401 for invalid key"""
    # Mock validation passing hashing but config lookup failing
    
    with patch("main.validate_api_key", return_value="bad_hash"):
        with patch.object(config_manager, "get_project_by_key", return_value=None):
            resp = client.get("/foo", headers={"x-securex-api-key": "wrong-key"})
            assert resp.status_code == 401
            assert "Invalid API key" in resp.json()["detail"]

@patch("main.forward_request")
@patch("main.check_rate_limit")
@patch("main.compute_risk_score")
@patch("main.make_decision")
def test_happy_path(mock_decision, mock_risk, mock_limit, mock_forward):
    """Full flow: Auth -> RateLimit -> ML -> Decision -> Proxy"""
    
    # Setup Mocks
    project_config = ProjectConfig(
        project_id=PROJECT_ID,
        upstream_base_url=UPSTREAM_URL,
        api_key_hash=VALID_KEY_HASH
    )
    
    mock_limit.return_value = (True, 100)
    mock_risk.return_value = {"risk_score": 0.1} # Adjusted to match key usage
    mock_decision.return_value = {"decision": Decision.ALLOW}
    mock_forward.return_value = MagicMock(status_code=200) 
    
    # Needs to match main.py expectations
    
    with patch.object(config_manager, "get_project_by_key", return_value=project_config):
        resp = client.get("/users/123", headers={"x-securex-api-key": VALID_KEY})
        
        # Assertions
        assert resp.status_code == 200
        
        # Verify proxy call args
        call_args = mock_forward.call_args
        assert call_args is not None
        _, kwargs = call_args
        assert kwargs["upstream_url"] == f"{UPSTREAM_URL}/users/123"

@pytest.mark.asyncio
async def test_no_involuntary_query_validation():
    """
    Ensure the gateway does NOT require a 'request' query parameter.
    This validates the fix for 'Field required' in query.
    """
    print("\n--- STARTING test_no_involuntary_query_validation ---")
    project_config = ProjectConfig(
        project_id=PROJECT_ID,
        upstream_base_url=UPSTREAM_URL,
        api_key_hash=VALID_KEY_HASH
    )
    
    with patch.object(config_manager, "get_project_by_key", return_value=project_config):
        with patch("main.forward_request") as mock_forward:
            mock_forward.return_value = MagicMock(status_code=200)
            
            with patch("main.check_rate_limit", return_value=(True, 100)):
                with patch("main.compute_risk_score", return_value={"risk_score": 0.0}):
                    with patch("main.make_decision", return_value={"decision": Decision.ALLOW}):
                        
                        resp = client.post(
                            "/auth/login", 
                            headers={"x-securex-api-key": VALID_KEY},
                            json={"username": "foo", "password": "bar"}
                        )
                        
                        print(f"Response Status: {resp.status_code}")
                        print(f"Response Body: {resp.text}")
                        
                        if resp.status_code == 422:
                            print("FAILURE: Got 422. Fix did not work.")
                        elif resp.status_code != 200:
                            print(f"FAILURE: Got {resp.status_code}.")
                        else:
                            print("SUCCESS: Got 200.")

                        assert resp.status_code == 200, f"Got error: {resp.text}"

@pytest.mark.asyncio
async def test_traffic_logging_fire_and_forget():
    """
    Ensure traffic logging is attempted and doesn't break request on failure.
    """
    project_config = ProjectConfig(
        project_id=PROJECT_ID,
        upstream_base_url=UPSTREAM_URL,
        api_key_hash=VALID_KEY_HASH
    )
    
    with patch.object(config_manager, "get_project_by_key", return_value=project_config):
         # Mock traffic logger's internal http client
         with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            # We want to verify it IS called.
            # Since it's a background task, we might need to wait or rely on test client's context?
            # FastAPI TestClient runs the app in the same thread/loop usually, but background tasks 
            # might need explicit handling or just time.
            
            with patch("main.forward_request", return_value=MagicMock(status_code=200)):
                with patch("main.check_rate_limit", return_value=(True, 100)):
                    with patch("main.compute_risk_score", return_value={"risk_score": 0.0}):
                         with patch("main.make_decision", return_value={"decision": Decision.ALLOW}):
                            
                            client.get("/logs/test", headers={"x-securex-api-key": VALID_KEY})
                            
                            # Give asyncio a moment to schedule the background task
                            await asyncio.sleep(0.1)
                            
                            assert mock_post.called
                            ctx = mock_post.call_args[1]["json"]
                            # FastAPI {path:path} param usually excludes leading slash
                            assert ctx["path"] == "logs/test" 
                            assert ctx["project_id"] == PROJECT_ID
                            # Validates normalized path logic roughly
                            assert ctx["normalized_path"] == "/logs/test"

@pytest.mark.asyncio
async def test_traffic_logging_swallows_error():
    """
    Ensure worker stays up even if logging API is down.
    """
    project_config = ProjectConfig(
        project_id=PROJECT_ID,
        upstream_base_url=UPSTREAM_URL,
        api_key_hash=VALID_KEY_HASH
    )
    
    with patch.object(config_manager, "get_project_by_key", return_value=project_config):
         with patch("httpx.AsyncClient.post", side_effect=Exception("Connection Refused")) as mock_post:
            with patch("main.forward_request", return_value=MagicMock(status_code=200)):
                 with patch("main.check_rate_limit", return_value=(True, 100)):
                    with patch("main.compute_risk_score", return_value={"risk_score": 0.0}):
                         with patch("main.make_decision", return_value={"decision": Decision.ALLOW}):
                            
                            resp = client.get("/logs/fail", headers={"x-securex-api-key": VALID_KEY})
                            
                            # Request should still succeed
                            assert resp.status_code == 200

if __name__ == "__main__":
    import asyncio
    import sys
    try:
        asyncio.run(test_traffic_logging_fire_and_forget())
        asyncio.run(test_traffic_logging_swallows_error())
        print("Tests Passed: Traffic Logging")
    except Exception as e:
        print(f"Test Failed: {e}")
        import traceback
        traceback.print_exc() 
    sys.stdout.flush()
