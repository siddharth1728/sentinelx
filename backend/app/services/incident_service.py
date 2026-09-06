"""
incident_service.py - Security Incident Management Service for SENTINELX.

Why this module exists:
Correlates individual intrusion alerts into broader incident cases, tracks assigned
analysts, records containment & mitigation steps, and updates incident lifecycle states.
"""

from typing import List, Optional, Tuple
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import select, desc, func

from ..models.incident import Incident, IncidentSeverity, IncidentStatus
from ..models.alert import Alert
from ..schemas.incident import IncidentCreate, IncidentUpdate
from ..utils.logger import get_logger

logger = get_logger("incident_service")


class IncidentService:
    """
    IncidentService handles incident creation, alert correlation, and lifecycle tracking.
    """

    def get_incidents(
        self,
        db: Session,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Incident], int]:
        """Query incidents with optional filters and pagination."""
        query = select(Incident).options(joinedload(Incident.alerts))

        if status:
            query = query.where(Incident.status == status)
        if severity:
            query = query.where(Incident.severity == severity)

        count_query = select(func.count()).select_from(Incident)
        if status:
            count_query = count_query.where(Incident.status == status)
        if severity:
            count_query = count_query.where(Incident.severity == severity)
        total = db.scalar(count_query) or 0

        stmt = query.order_by(desc(Incident.created_at)).offset(skip).limit(limit)
        items = list(db.scalars(stmt).unique().all())

        return items, total

    def get_incident_by_id(self, db: Session, incident_id: int) -> Optional[Incident]:
        """Fetch single incident by ID with linked alerts."""
        stmt = (
            select(Incident)
            .options(joinedload(Incident.alerts))
            .where(Incident.id == incident_id)
        )
        return db.scalar(stmt)

    def create_incident(self, db: Session, inc_in: IncidentCreate) -> Incident:
        """Create new incident case and link specified alerts."""
        incident = Incident(
            title=inc_in.title,
            summary=inc_in.summary,
            severity=inc_in.severity,
            status=IncidentStatus.OPEN,
            assigned_analyst=inc_in.assigned_analyst,
            mitigation_steps=inc_in.mitigation_steps,
        )
        db.add(incident)
        db.flush()

        # Link alerts if provided
        if inc_in.alert_ids:
            stmt = select(Alert).where(Alert.id.in_(inc_in.alert_ids))
            alerts = list(db.scalars(stmt).all())
            for a in alerts:
                a.incident_id = incident.id

        db.commit()
        db.refresh(incident)
        logger.info(f"Opened new security incident #{incident.id}: {incident.title}")
        return incident

    def update_incident(
        self,
        db: Session,
        incident_id: int,
        inc_update: IncidentUpdate,
    ) -> Optional[Incident]:
        """Update incident details, assignment, mitigation steps, or status."""
        incident = self.get_incident_by_id(db, incident_id)
        if not incident:
            return None

        update_data = inc_update.model_dump(exclude_unset=True)
        for field, val in update_data.items():
            setattr(incident, field, val)

        db.commit()
        db.refresh(incident)
        logger.info(f"Updated incident #{incident_id} - status: {incident.status.value}")
        return incident


# Default instance
incident_service = IncidentService()
