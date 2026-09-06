"""
prediction_log.py - SQLAlchemy Model for ML Model Predictions.

Why this model exists:
Provides an immutable audit log of every ML inference decision executed
by the SENTINELX detection engine, tracking model versions, classification labels,
confidence scores, full probability distributions, and inference latencies.
"""

from typing import Optional, Dict, Any, TYPE_CHECKING
from sqlalchemy import String, Float, Integer, Boolean, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

if TYPE_CHECKING:
    from .network_event import NetworkEvent


class PredictionLog(Base, TimestampMixin):
    """
    Represents an ML inference record associated with a network event.
    """
    __tablename__ = "prediction_logs"

    # Foreign Key to Network Event
    network_event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("network_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ML Inference Results
    model_version: Mapped[str] = mapped_column(String(50), default="0.1.0", nullable=False)
    predicted_class_id: Mapped[int] = mapped_column(Integer, nullable=False)
    predicted_label: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    is_intrusion: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    probabilities: Mapped[Optional[Dict[str, float]]] = mapped_column(JSON, nullable=True)
    inference_time_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Relationship
    network_event: Mapped["NetworkEvent"] = relationship(
        "NetworkEvent",
        back_populates="predictions",
    )
