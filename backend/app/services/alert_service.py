"""
alert_service.py - Alert Triage and Lifecycle Management Service.

Why this module exists:
Provides SOC workflow operations: querying alerts with severity/status filters,
assigning alerts to security analysts, recording triage notes, and updating resolution states.
"""

from typing import List, Optional, Tuple
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import select, desc, func

from ..models.alert import Alert, AlertSeverity, AlertStatus
from ..schemas.alert import AlertCreate, AlertUpdate
from ..utils.logger import get_logger

logger = get_logger("alert_service")


class AlertService:
    """
    AlertService handles alert retrieval, updates, and lifecycle operations.
    """

    def get_alerts(
        self,
        db: Session,
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Alert], int]:
        """
        Query alerts with optional filtering and pagination.
        """
        query = select(Alert).options(joinedload(Alert.network_event))

        if status:
            query = query.where(Alert.status == status)
        if severity:
            query = query.where(Alert.severity == severity)

        # Count total
        count_query = select(func.count()).select_from(Alert)
        if status:
            count_query = count_query.where(Alert.status == status)
        if severity:
            count_query = count_query.where(Alert.severity == severity)
        total = db.scalar(count_query) or 0

        # Paginate
        stmt = query.order_by(desc(Alert.created_at)).offset(skip).limit(limit)
        items = list(db.scalars(stmt).unique().all())

        return items, total

    def get_alert_by_id(self, db: Session, alert_id: int) -> Optional[Alert]:
        """Fetch single alert by ID with network event relationship."""
        stmt = (
            select(Alert)
            .options(joinedload(Alert.network_event))
            .where(Alert.id == alert_id)
        )
        return db.scalar(stmt)

    def create_alert(self, db: Session, alert_in: AlertCreate) -> Alert:
        """Create a new alert record manually or from external sensor."""
        alert = Alert(
            network_event_id=alert_in.network_event_id,
            incident_id=alert_in.incident_id,
            title=alert_in.title,
            description=alert_in.description,
            threat_type=alert_in.threat_type,
            severity=alert_in.severity,
            status=AlertStatus.NEW,
            confidence=alert_in.confidence,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        logger.info(f"Created manual alert #{alert.id}: {alert.title}")
        return alert

    def update_alert(
        self,
        db: Session,
        alert_id: int,
        alert_update: AlertUpdate,
    ) -> Optional[Alert]:
        """Update alert status, assignment, severity, or notes."""
        alert = self.get_alert_by_id(db, alert_id)
        if not alert:
            return None

        update_data = alert_update.model_dump(exclude_unset=True)
        for field, val in update_data.items():
            setattr(alert, field, val)

        db.commit()
        db.refresh(alert)
        logger.info(f"Updated alert #{alert_id} - status: {alert.status.value}")
        return alert


# Default instance
alert_service = AlertService()
