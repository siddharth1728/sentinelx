"""
test_prediction.py - Unit and Integration Tests for ML Prediction & Event Logging.
"""

from fastapi.testclient import TestClient


def test_predict_single_benign_flow(client: TestClient, sample_benign_flow: dict):
    """Test single flow inspection on normal HTTPS traffic."""
    response = client.post("/api/v1/detect", json=sample_benign_flow)
    assert response.status_code == 200
    data = response.json()

    assert data["is_intrusion"] is False
    assert "Normal" in data["predicted_label"]
    assert data["confidence"] > 0.5
    assert data["event_id"] is not None
    assert data["prediction_id"] is not None
    assert data["alert_id"] is None  # Benign should NOT trigger an alert
    assert data["inference_time_ms"] >= 0


def test_predict_single_attack_flow(client: TestClient, sample_syn_flood_flow: dict):
    """Test single flow inspection on SYN flood DoS traffic."""
    response = client.post("/api/v1/detect", json=sample_syn_flood_flow)
    assert response.status_code == 200
    data = response.json()

    assert data["is_intrusion"] is True
    assert "Attack" in data["predicted_label"]
    assert data["confidence"] >= 0.70
    assert data["event_id"] is not None
    assert data["prediction_id"] is not None
    assert data["alert_id"] is not None  # Malicious flow SHOULD trigger an alert


def test_predict_batch_flows(
    client: TestClient,
    sample_benign_flow: dict,
    sample_syn_flood_flow: dict,
):
    """Test batch flow inspection with mixed benign and attack flows."""
    payload = {
        "flows": [sample_benign_flow, sample_syn_flood_flow, sample_benign_flow]
    }
    response = client.post("/api/v1/detect/batch", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["total_processed"] == 3
    assert data["intrusions_detected"] == 1
    assert data["benign_count"] == 2
    assert len(data["results"]) == 3


def test_list_network_events(client: TestClient, sample_benign_flow: dict):
    """Test querying ingested network events."""
    # Ingest one event first
    client.post("/api/v1/detect", json=sample_benign_flow)

    response = client.get("/api/v1/detect/events?page=1&page_size=10")
    assert response.status_code == 200
    data = response.json()

    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 1
    assert data["items"][0]["protocol_type"] == "tcp"
