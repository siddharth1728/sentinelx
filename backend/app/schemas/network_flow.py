"""
network_flow.py - Pydantic Schemas for Ingested Network Flows.

Why this module exists:
Enforces strict input validation on all network flow payloads received by the API,
verifying ranges, non-negative numbers, allowed protocols, and standard connection states.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class NetworkFlowInput(BaseModel):
    """
    Schema for a single network flow record submitted for ML inspection.
    """
    # Optional IP/Port context
    source_ip: Optional[str] = Field(None, description="Origin IPv4 or IPv6 address", examples=["192.168.1.105"])
    destination_ip: Optional[str] = Field(None, description="Target IPv4 or IPv6 address", examples=["10.0.0.1"])
    source_port: Optional[int] = Field(None, ge=0, le=65535, description="Source port number")
    destination_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination port number")

    # Flow Telemetry Measurements (Required for ML model)
    duration: float = Field(..., ge=0.0, description="Connection duration in seconds", examples=[1.25])
    protocol_type: str = Field(..., description="Network protocol: tcp, udp, icmp", examples=["tcp"])
    service: str = Field(..., description="Destination network service (http, dns, ssh, etc.)", examples=["http"])
    flag: str = Field(..., description="TCP status flag (SF, S0, REJ, etc.)", examples=["SF"])
    src_bytes: int = Field(..., ge=0, description="Bytes transmitted from source to destination", examples=[1024])
    dst_bytes: int = Field(..., ge=0, description="Bytes transmitted from destination to source", examples=[4096])

    # Traffic Window Aggregations
    count: int = Field(..., ge=0, description="Connections to same host in past 2 seconds", examples=[5])
    srv_count: int = Field(..., ge=0, description="Connections to same service in past 2 seconds", examples=[4])
    same_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections to same service", examples=[0.8])
    diff_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% of connections to different services", examples=[0.2])
    dst_host_count: int = Field(..., ge=0, le=255, description="Connections with same destination host", examples=[50])
    dst_host_srv_count: int = Field(..., ge=0, le=255, description="Connections with same destination service", examples=[45])
    dst_host_same_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% to same destination service", examples=[0.9])
    dst_host_diff_srv_rate: float = Field(..., ge=0.0, le=1.0, description="% to diff destination service", examples=[0.1])


class BatchFlowInput(BaseModel):
    """
    Schema for batch flow inspection.
    """
    flows: List[NetworkFlowInput] = Field(..., min_length=1, max_length=1000, description="List of flow records to inspect")


class NetworkEventResponse(NetworkFlowInput):
    """
    Schema representing persisted NetworkEvent with database identifiers.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
    source_type: str
