"""
detection.py - Pydantic Schemas for Detection & Prediction Responses.

Why this module exists:
Standardizes the structure of ML detection responses returned to API clients,
including intrusion status flags, confidence levels, class probabilities, and linked event IDs.
"""

from datetime import datetime
from typing import Dict, Optional, List
from pydantic import BaseModel, ConfigDict, Field


class DetectionResult(BaseModel):
    """
    Detailed ML prediction result for a single network flow record.
    """
    model_config = ConfigDict(from_attributes=True)

    event_id: Optional[int] = Field(None, description="Database ID of the persisted network event")
    prediction_id: Optional[int] = Field(None, description="Database ID of the prediction audit log")
    alert_id: Optional[int] = Field(None, description="Database ID of the generated security alert (if any)")
    
    is_intrusion: bool = Field(..., description="True if classified as malicious/attack, False if benign")
    predicted_label: str = Field(..., description="Human-readable classification label (e.g. Normal, Attack)")
    predicted_class_id: int = Field(..., description="Integer class index from model")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score of predicted class")
    probabilities: Dict[str, float] = Field(default_factory=dict, description="Class-wise probability distribution")
    inference_time_ms: float = Field(..., description="Execution latency in milliseconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="UTC timestamp of inspection")


class BatchDetectionResponse(BaseModel):
    """
    Response schema for batch flow inspection requests.
    """
    total_processed: int
    intrusions_detected: int
    benign_count: int
    alerts_generated: int
    total_time_ms: float
    results: List[DetectionResult]
