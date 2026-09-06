"""
alert.py - Pydantic Schemas for Alert Triage and Lifecycle Management.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from ..models.alert import AlertSeverity, AlertStatus
from .network_flow import NetworkEventResponse


class AlertBase(BaseModel):
    title: str = Field(..., description="Short descriptive title of the alert")
    description: str = Field(..., description="Detailed description of the anomaly or intrusion pattern")
    threat_type: str = Field(..., description="Classification category (e.g. DoS SYN Flood, Port Scan)")
    severity: AlertSeverity = Field(default=AlertSeverity.HIGH)
    confidence: float = Field(..., ge=0.0, le=1.0)


class AlertCreate(AlertBase):
    network_event_id: int
    incident_id: Optional[int] = None


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    severity: Optional[AlertSeverity] = None
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None
    incident_id: Optional[int] = None


class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    network_event_id: int
    incident_id: Optional[int] = None
    status: AlertStatus
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    network_event: Optional[NetworkEventResponse] = None
