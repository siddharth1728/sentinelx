"""
test_alerts.py - Unit and Integration Tests for Security Alerts & Triage.
"""

from fastapi.testclient import TestClient


def test_alert_generation_and_triage_flow(
    client: TestClient, sample_syn_flood_flow: dict
):
    """Test full alert lifecycle: automatic generation -> triage query -> patch update."""
    # 1. Ingest attack flow to trigger alert
    detect_resp = client.post("/api/v1/detect", json=sample_syn_flood_flow)
    assert detect_resp.status_code == 200
    alert_id = detect_resp.json()["alert_id"]
    assert alert_id is not None

    # 2. Query alerts list
    list_resp = client.get("/api/v1/alerts")
    assert list_resp.status_code == 200
    alerts_data = list_resp.json()
    assert alerts_data["total"] >= 1
    assert any(a["id"] == alert_id for a in alerts_data["items"])

    # 3. Fetch single alert by ID
    get_resp = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_resp.status_code == 200
    alert = get_resp.json()
    assert alert["id"] == alert_id
    assert alert["status"] == "NEW"
    assert "DoS" in alert["threat_type"] or "Attack" in alert["title"]

    # 4. Update alert status to IN_PROGRESS and assign analyst
    patch_payload = {
        "status": "IN_PROGRESS",
        "assigned_to": "analyst_alice",
        "analyst_notes": "Investigating high SYN packet rate from host 203.0.113.19.",
    }
    patch_resp = client.patch(f"/api/v1/alerts/{alert_id}", json=patch_payload)
    assert patch_resp.status_code == 200
    updated_alert = patch_resp.json()
    assert updated_alert["status"] == "IN_PROGRESS"
    assert updated_alert["assigned_to"] == "analyst_alice"
    assert "203.0.113.19" in updated_alert["analyst_notes"]

    # 5. Resolve alert
    resolve_resp = client.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "RESOLVED", "analyst_notes": "Rate-limiting applied at edge firewall."},
    )
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["status"] == "RESOLVED"


def test_manual_alert_creation(client: TestClient, sample_benign_flow: dict):
    """Test manual creation of an alert linked to an ingested event."""
    # Ingest event
    resp = client.post("/api/v1/detect", json=sample_benign_flow)
    event_id = resp.json()["event_id"]

    alert_payload = {
        "network_event_id": event_id,
        "title": "Manual Anomaly Flag",
        "description": "Analyst flagged suspicious egress pattern during manual hunt.",
        "threat_type": "Suspicious Egress",
        "severity": "MEDIUM",
        "confidence": 0.82,
    }
    create_resp = client.post("/api/v1/alerts", json=alert_payload)
    assert create_resp.status_code == 201
    created_alert = create_resp.json()
    assert created_alert["title"] == "Manual Anomaly Flag"
    assert created_alert["network_event_id"] == event_id


def test_get_nonexistent_alert(client: TestClient):
    """Verify 404 response for invalid alert ID."""
    response = client.get("/api/v1/alerts/999999")
    assert response.status_code == 404
