"""
test_health.py - Unit and Integration Tests for Health & Diagnostics.
"""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient):
    """Verify root endpoint returns 200 and platform information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert "service" in data
    assert "version" in data


def test_health_endpoint(client: TestClient):
    """Verify health endpoint checks database and ML model readiness."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["HEALTHY", "DEGRADED"]
    assert "database_connected" in data
    assert "ml_model_loaded" in data
    assert data["database_connected"] is True
    assert data["ml_model_loaded"] is True
