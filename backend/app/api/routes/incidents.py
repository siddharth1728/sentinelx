"""
incidents.py - Security Incident Management & Case Tracking Endpoints.

Why this route exists:
Provides capabilities to create investigation cases, correlate multiple alerts,
assign lead investigators, and record containment and mitigation steps.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...database.session import get_db
from ...models.incident import IncidentSeverity, IncidentStatus
from ...schemas.incident import IncidentCreate, IncidentUpdate, IncidentResponse
from ...schemas.common import PaginatedResponse
from ...services.incident_service import incident_service, IncidentService
from ...api.dependencies import get_incident_service

router = APIRouter(prefix="/incidents", tags=["Incident Response & Case Management"])


@router.get(
    "",
    response_model=PaginatedResponse[IncidentResponse],
    status_code=status.HTTP_200_OK,
    summary="List Security Incidents",
    description="Retrieves a paginated list of security incidents with optional filtering by status and severity.",
)
def list_incidents(
    status: Optional[IncidentStatus] = Query(None, description="Filter by status (OPEN, INVESTIGATING, RESOLVED, etc.)"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    db: Session = Depends(get_db),
    svc: IncidentService = Depends(get_incident_service),
) -> PaginatedResponse[IncidentResponse]:
    """List security incidents."""
    skip = (page - 1) * page_size
    items, total = svc.get_incidents(
        db=db, status=status, severity=severity, skip=skip, limit=page_size
    )

    results = []
    for inc in items:
        resp = IncidentResponse.model_validate(inc)
        resp.alert_count = len(inc.alerts) if hasattr(inc, "alerts") and inc.alerts else 0
        results.append(resp)

    return PaginatedResponse[IncidentResponse](
        total=total,
        page=page,
        page_size=page_size,
        items=results,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Incident Details",
    description="Retrieves comprehensive details for a specific incident case.",
)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    svc: IncidentService = Depends(get_incident_service),
) -> IncidentResponse:
    """Fetch single incident by ID."""
    incident = svc.get_incident_by_id(db=db, incident_id=incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident #{incident_id} not found.",
        )
    resp = IncidentResponse.model_validate(incident)
    resp.alert_count = len(incident.alerts) if hasattr(incident, "alerts") and incident.alerts else 0
    return resp


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Security Incident",
    description="Opens a new security incident case and optionally links related alert IDs.",
)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
    svc: IncidentService = Depends(get_incident_service),
) -> IncidentResponse:
    """Create a new incident case."""
    incident = svc.create_incident(db=db, inc_in=incident_in)
    resp = IncidentResponse.model_validate(incident)
    resp.alert_count = len(incident.alerts) if hasattr(incident, "alerts") and incident.alerts else 0
    return resp


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Incident Case",
    description="Updates investigation status, mitigation steps, or assignee for an incident.",
)
def update_incident(
    incident_id: int,
    incident_in: IncidentUpdate,
    db: Session = Depends(get_db),
    svc: IncidentService = Depends(get_incident_service),
) -> IncidentResponse:
    """Update incident metadata or status."""
    incident = svc.update_incident(db=db, incident_id=incident_id, inc_update=incident_in)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident #{incident_id} not found.",
        )
    resp = IncidentResponse.model_validate(incident)
    resp.alert_count = len(incident.alerts) if hasattr(incident, "alerts") and incident.alerts else 0
    return resp
