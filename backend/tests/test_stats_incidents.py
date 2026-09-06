"""
test_stats_incidents.py - Tests for Incident Management and Security Statistics.
"""

from fastapi.testclient import TestClient


def test_incident_creation_and_stats(
    client: TestClient, sample_syn_flood_flow: dict
):
    """Test incident creation, alert association, and overview statistics."""
    # 1. Trigger alert
    detect_resp = client.post("/api/v1/detect", json=sample_syn_flood_flow)
    alert_id = detect_resp.json()["alert_id"]

    # 2. Create Incident case linking the alert
    inc_payload = {
        "title": "Major SYN Flood Campaign",
        "summary": "Correlated high-frequency SYN floods targeting edge web servers.",
        "severity": "CRITICAL",
        "assigned_analyst": "analyst_bob",
        "mitigation_steps": "Configure upstream BGP blackholing / cloud scrubber.",
        "alert_ids": [alert_id] if alert_id else [],
    }
    inc_resp = client.post("/api/v1/incidents", json=inc_payload)
    assert inc_resp.status_code == 201
    incident = inc_resp.json()
    incident_id = incident["id"]
    assert incident["title"] == "Major SYN Flood Campaign"
    assert incident["status"] == "OPEN"

    # 3. Query Incidents
    list_inc_resp = client.get("/api/v1/incidents")
    assert list_inc_resp.status_code == 200
    assert list_inc_resp.json()["total"] >= 1

    # 4. Fetch Overview Statistics
    stats_resp = client.get("/api/v1/stats/overview")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_events_processed"] >= 1
    assert stats["total_intrusions_detected"] >= 1
    assert stats["total_alerts_generated"] >= 1
    assert stats["total_incidents_opened"] >= 1
    assert stats["average_inference_latency_ms"] >= 0.0
