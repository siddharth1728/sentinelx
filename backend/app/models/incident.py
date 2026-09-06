"""
incident.py - SQLAlchemy Model for Security Incidents.

Why this model exists:
In enterprise security operations, multiple related alerts (e.g. coordinated port scanning
followed by brute-force authentication attempts) are correlated into a single Incident case.
This model tracks investigation status, severity, assigned response team members, and resolution notes.
"""

from enum import Enum
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import String, Text, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

if TYPE_CHECKING:
    from .alert import Alert


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class Incident(Base, TimestampMixin):
    """
    Represents a correlated security incident case.
    """
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(
        SQLEnum(IncidentSeverity),
        default=IncidentSeverity.HIGH,
        nullable=False,
        index=True,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        SQLEnum(IncidentStatus),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )

    assigned_analyst: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitigation_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert",
        back_populates="incident",
    )
