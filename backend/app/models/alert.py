"""
alert.py - SQLAlchemy Model for Security Alerts.

Why this model exists:
When the ML detection engine detects malicious flows (e.g. DoS floods, port scans, brute force)
exceeding confidence thresholds, an Alert is generated. SOC analysts use alerts to triage,
investigate, acknowledge, and escalate threats.
"""

from enum import Enum
from typing import Optional, TYPE_CHECKING
from sqlalchemy import String, Float, Integer, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

if TYPE_CHECKING:
    from .network_event import NetworkEvent
    from .incident import Incident


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Alert(Base, TimestampMixin):
    """
    Represents an actionable security alert triggered by ML intrusion detection.
    """
    __tablename__ = "alerts"

    # Foreign Keys
    network_event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("network_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Alert Attributes
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    threat_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity),
        default=AlertSeverity.HIGH,
        nullable=False,
        index=True,
    )
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus),
        default=AlertStatus.NEW,
        nullable=False,
        index=True,
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # Analyst Remediation Metadata
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    network_event: Mapped["NetworkEvent"] = relationship(
        "NetworkEvent",
        back_populates="alerts",
    )
    incident: Mapped[Optional["Incident"]] = relationship(
        "Incident",
        back_populates="alerts",
    )
