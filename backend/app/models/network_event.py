"""
network_event.py - SQLAlchemy Model for Network Flow Events.

Why this model exists:
Captures raw network flow telemetry ingested by the platform.
Stores both connection metadata (duration, protocol, service, flags, bytes)
and optional network identifiers (source/destination IP and port) for security forensics.
"""

from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import String, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

if TYPE_CHECKING:
    from .prediction_log import PredictionLog
    from .alert import Alert


class NetworkEvent(Base, TimestampMixin):
    """
    Represents an observed network flow event / session record.
    """
    __tablename__ = "network_events"

    # Optional Network Identifiers for Forensics
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Core Flow Features (ML compatible)
    duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    protocol_type: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    service: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    flag: Mapped[str] = mapped_column(String(15), nullable=False)
    src_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dst_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Statistical Flow Window Features
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    srv_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    same_srv_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    diff_srv_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    dst_host_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dst_host_srv_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    dst_host_same_srv_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    dst_host_diff_srv_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Ingestion Metadata
    source_type: Mapped[str] = mapped_column(String(50), default="api_ingest", nullable=False)
    raw_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    predictions: Mapped[List["PredictionLog"]] = relationship(
        "PredictionLog",
        back_populates="network_event",
        cascade="all, delete-orphan",
    )
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert",
        back_populates="network_event",
        cascade="all, delete-orphan",
    )
