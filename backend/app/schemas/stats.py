"""
stats.py - Pydantic Schemas for Security Dashboard Statistics.
"""

from typing import Dict, List, Any
from pydantic import BaseModel, Field


class ThreatBreakdownItem(BaseModel):
    threat_type: str
    count: int
    percentage: float


class SeverityBreakdownItem(BaseModel):
    severity: str
    count: int


class SecurityStatsResponse(BaseModel):
    """
    Overview metrics for real-time security analytics dashboards.
    """
    total_events_processed: int
    total_intrusions_detected: int
    total_benign_events: int
    total_alerts_generated: int
    active_alerts_count: int
    total_incidents_opened: int
    average_inference_latency_ms: float
    threat_distribution: List[ThreatBreakdownItem] = Field(default_factory=list)
    alert_severity_distribution: List[SeverityBreakdownItem] = Field(default_factory=list)
    recent_activity_summary: Dict[str, Any] = Field(default_factory=dict)
