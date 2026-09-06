"""
incident.py - Pydantic Schemas for Security Incident Cases.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field
from ..models.incident import IncidentSeverity, IncidentStatus


class IncidentBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Incident case title")
    summary: str = Field(..., description="Summary of investigation and threat indicators")
    severity: IncidentSeverity = Field(default=IncidentSeverity.HIGH)


class IncidentCreate(IncidentBase):
    assigned_analyst: Optional[str] = None
    mitigation_steps: Optional[str] = None
    alert_ids: Optional[List[int]] = Field(default_factory=list, description="List of alert IDs to link to this incident")


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_analyst: Optional[str] = None
    mitigation_steps: Optional[str] = None


class IncidentResponse(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: IncidentStatus
    assigned_analyst: Optional[str] = None
    mitigation_steps: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    alert_count: Optional[int] = 0
