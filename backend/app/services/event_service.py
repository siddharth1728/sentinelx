"""
event_service.py - Event Ingestion, Persistence, and Threat Escalation Service.

Why this module exists:
Implements the core backend workflow:
  1. Ingests validated network telemetry.
  2. Executes ML classification via MLService.
  3. Persists the NetworkEvent in PostgreSQL.
  4. Records the immutable PredictionLog audit entry.
  5. If confidence exceeds threshold and is_intrusion is True, creates an actionable Alert.
"""

from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from ..config import settings
from ..models.network_event import NetworkEvent
from ..models.prediction_log import PredictionLog
from ..models.alert import Alert, AlertSeverity, AlertStatus
from ..schemas.network_flow import NetworkFlowInput
from ..schemas.detection import DetectionResult, BatchDetectionResponse
from .ml_service import ml_service, MLService
from ..utils.logger import get_logger

logger = get_logger("event_service")


class EventService:
    """
    EventService coordinates database persistence for network events,
    prediction audit logs, and automated alert triggering.
    """

    @staticmethod
    def _determine_severity(confidence: float, threat_type: str) -> AlertSeverity:
        """Assign alert severity based on confidence and threat category."""
        if confidence >= 0.95 or "DoS" in threat_type or "Brute Force" in threat_type:
            return AlertSeverity.CRITICAL
        elif confidence >= 0.85:
            return AlertSeverity.HIGH
        elif confidence >= 0.70:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def process_and_store_event(
        self,
        db: Session,
        flow: NetworkFlowInput,
        source_type: str = "api_ingest",
    ) -> DetectionResult:
        """
        Process a single network flow: run inference, store event, store prediction, and alert if threat.

        Args:
            db: Active database session.
            flow: Validated network flow input.
            source_type: Origin of flow record.

        Returns:
            DetectionResult: Comprehensive detection result containing DB entity IDs.
        """
        # 1. Run ML inference
        detection = ml_service.predict_flow(flow)

        # 2. Persist NetworkEvent
        event = NetworkEvent(
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            source_port=flow.source_port,
            destination_port=flow.destination_port,
            duration=flow.duration,
            protocol_type=flow.protocol_type,
            service=flow.service,
            flag=flow.flag,
            src_bytes=flow.src_bytes,
            dst_bytes=flow.dst_bytes,
            count=flow.count,
            srv_count=flow.srv_count,
            same_srv_rate=flow.same_srv_rate,
            diff_srv_rate=flow.diff_srv_rate,
            dst_host_count=flow.dst_host_count,
            dst_host_srv_count=flow.dst_host_srv_count,
            dst_host_same_srv_rate=flow.dst_host_same_srv_rate,
            dst_host_diff_srv_rate=flow.dst_host_diff_srv_rate,
            source_type=source_type,
        )
        db.add(event)
        db.flush()  # Generates event.id without full commit

        # 3. Persist PredictionLog
        pred_log = PredictionLog(
            network_event_id=event.id,
            model_version=settings.APP_VERSION,
            predicted_class_id=detection.predicted_class_id,
            predicted_label=detection.predicted_label,
            is_intrusion=detection.is_intrusion,
            confidence=detection.confidence,
            probabilities=detection.probabilities,
            inference_time_ms=detection.inference_time_ms,
        )
        db.add(pred_log)
        db.flush()

        # 4. Conditionally generate Alert if intrusion detected
        alert_id = None
        if detection.is_intrusion and settings.ENABLE_AUTO_ALERT_CREATION:
            if detection.confidence >= settings.INTRUSION_CONFIDENCE_THRESHOLD:
                threat_type = MLService.infer_threat_type(flow, detection.is_intrusion)
                severity = self._determine_severity(detection.confidence, threat_type)

                alert = Alert(
                    network_event_id=event.id,
                    title=f"Intrusion Alert: {threat_type}",
                    description=(
                        f"Detected malicious network flow activity ({threat_type}) from "
                        f"{flow.source_ip or 'unknown'} to {flow.destination_ip or 'internal'} "
                        f"with confidence {detection.confidence * 100:.1f}%."
                    ),
                    threat_type=threat_type,
                    severity=severity,
                    status=AlertStatus.NEW,
                    confidence=detection.confidence,
                )
                db.add(alert)
                db.flush()
                alert_id = alert.id
                logger.warning(
                    f"SECURITY ALERT [{severity.value}] generated for event #{event.id} ({threat_type})"
                )

        db.commit()

        # Update detection result with database identifiers
        detection.event_id = event.id
        detection.prediction_id = pred_log.id
        detection.alert_id = alert_id

        return detection

    def process_and_store_batch(
        self,
        db: Session,
        flows: List[NetworkFlowInput],
        source_type: str = "batch_api_ingest",
    ) -> BatchDetectionResponse:
        """
        Process a batch of network flows with bulk ML prediction and database persistence.

        Args:
            db: Active database session.
            flows: List of validated network flow inputs.
            source_type: Origin tag.

        Returns:
            BatchDetectionResponse: Summary metrics and itemized detection results.
        """
        import time

        start_time = time.perf_counter()
        detections = ml_service.predict_flows_batch(flows)

        intrusions = 0
        alerts_count = 0
        populated_results = []

        for flow, detection in zip(flows, detections):
            event = NetworkEvent(
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                duration=flow.duration,
                protocol_type=flow.protocol_type,
                service=flow.service,
                flag=flow.flag,
                src_bytes=flow.src_bytes,
                dst_bytes=flow.dst_bytes,
                count=flow.count,
                srv_count=flow.srv_count,
                same_srv_rate=flow.same_srv_rate,
                diff_srv_rate=flow.diff_srv_rate,
                dst_host_count=flow.dst_host_count,
                dst_host_srv_count=flow.dst_host_srv_count,
                dst_host_same_srv_rate=flow.dst_host_same_srv_rate,
                dst_host_diff_srv_rate=flow.dst_host_diff_srv_rate,
                source_type=source_type,
            )
            db.add(event)
            db.flush()

            pred_log = PredictionLog(
                network_event_id=event.id,
                model_version=settings.APP_VERSION,
                predicted_class_id=detection.predicted_class_id,
                predicted_label=detection.predicted_label,
                is_intrusion=detection.is_intrusion,
                confidence=detection.confidence,
                probabilities=detection.probabilities,
                inference_time_ms=detection.inference_time_ms,
            )
            db.add(pred_log)
            db.flush()

            alert_id = None
            if detection.is_intrusion:
                intrusions += 1
                if settings.ENABLE_AUTO_ALERT_CREATION and detection.confidence >= settings.INTRUSION_CONFIDENCE_THRESHOLD:
                    threat_type = MLService.infer_threat_type(flow, detection.is_intrusion)
                    severity = self._determine_severity(detection.confidence, threat_type)

                    alert = Alert(
                        network_event_id=event.id,
                        title=f"Intrusion Alert: {threat_type}",
                        description=f"Batch inspection flagged {threat_type} with confidence {detection.confidence*100:.1f}%.",
                        threat_type=threat_type,
                        severity=severity,
                        status=AlertStatus.NEW,
                        confidence=detection.confidence,
                    )
                    db.add(alert)
                    db.flush()
                    alert_id = alert.id
                    alerts_count += 1

            detection.event_id = event.id
            detection.prediction_id = pred_log.id
            detection.alert_id = alert_id
            populated_results.append(detection)

        db.commit()

        total_elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return BatchDetectionResponse(
            total_processed=len(flows),
            intrusions_detected=intrusions,
            benign_count=len(flows) - intrusions,
            alerts_generated=alerts_count,
            total_time_ms=round(total_elapsed_ms, 2),
            results=populated_results,
        )

    def get_events(
        self,
        db: Session,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[NetworkEvent], int]:
        """Query paginated network events."""
        from sqlalchemy import func
        total = db.scalar(select(func.count()).select_from(NetworkEvent)) or 0
        stmt = select(NetworkEvent).order_by(desc(NetworkEvent.created_at)).offset(skip).limit(limit)
        items = list(db.scalars(stmt).all())
        return items, total


# Default instance
event_service = EventService()
