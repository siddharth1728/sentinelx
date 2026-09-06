"""
test_invalid_input.py - Tests for Pydantic Schema Validation and Error Handling.
"""

from fastapi.testclient import TestClient


def test_missing_required_fields(client: TestClient):
    """Verify 422 error when required telemetry fields are missing."""
    invalid_payload = {
        "source_ip": "192.168.1.1",
        "duration": 0.5,
        # Missing protocol_type, service, flag, src_bytes, etc.
    }
    response = client.post("/api/v1/detect", json=invalid_payload)
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert data["error_type"] == "ValidationError"
    assert len(data["details"]) > 0


def test_negative_numeric_values(client: TestClient, sample_benign_flow: dict):
    """Verify 422 error when non-negative fields receive negative values."""
    bad_flow = sample_benign_flow.copy()
    bad_flow["src_bytes"] = -100  # Invalid negative bytes

    response = client.post("/api/v1/detect", json=bad_flow)
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert any("src_bytes" in str(err) for err in data["details"])


def test_rate_value_out_of_bounds(client: TestClient, sample_benign_flow: dict):
    """Verify 422 error when rate ratios exceed [0.0, 1.0]."""
    bad_flow = sample_benign_flow.copy()
    bad_flow["same_srv_rate"] = 1.5  # Invalid rate > 1.0

    response = client.post("/api/v1/detect", json=bad_flow)
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert any("same_srv_rate" in str(err) for err in data["details"])


def test_port_out_of_range(client: TestClient, sample_benign_flow: dict):
    """Verify 422 error when port number exceeds 65535."""
    bad_flow = sample_benign_flow.copy()
    bad_flow["destination_port"] = 70000  # Invalid port > 65535

    response = client.post("/api/v1/detect", json=bad_flow)
    assert response.status_code == 422
    data = response.json()
    assert any("destination_port" in str(err) for err in data["details"])


def test_empty_batch_flows(client: TestClient):
    """Verify 422 error when submitting an empty batch list."""
    response = client.post("/api/v1/detect/batch", json={"flows": []})
    assert response.status_code == 422
