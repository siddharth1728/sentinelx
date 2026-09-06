"""
detection.py - Real-Time ML Intrusion Detection & Flow Ingestion Endpoints.

Why this route exists:
Primary API interface for network packet sniffers, firewall log forwarders,
and SIEM integrations to stream network connection telemetry for instant ML classification.
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ...database.session import get_db
from ...schemas.network_flow import NetworkFlowInput, BatchFlowInput, NetworkEventResponse
from ...schemas.detection import DetectionResult, BatchDetectionResponse
from ...schemas.common import PaginatedResponse
from ...services.event_service import event_service, EventService
from ...api.dependencies import get_event_service

router = APIRouter(prefix="/detect", tags=["Intrusion Detection & Telemetry"])


@router.post(
    "",
    response_model=DetectionResult,
    status_code=status.HTTP_200_OK,
    summary="Inspect Single Network Flow",
    description="Submits a single network flow record for real-time ML classification, logs the event, and triggers an alert if malicious.",
)
def detect_single_flow(
    flow: NetworkFlowInput,
    db: Session = Depends(get_db),
    svc: EventService = Depends(get_event_service),
) -> DetectionResult:
    """Inspect single network flow and persist detection."""
    return svc.process_and_store_event(db=db, flow=flow, source_type="api_detect_single")


@router.post(
    "/batch",
    response_model=BatchDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect Batch of Network Flows",
    description="Bulk-inspects up to 1,000 network flows in a single request with high-throughput vector processing.",
)
def detect_batch_flows(
    payload: BatchFlowInput,
    db: Session = Depends(get_db),
    svc: EventService = Depends(get_event_service),
) -> BatchDetectionResponse:
    """Inspect multiple network flows in batch mode."""
    return svc.process_and_store_batch(db=db, flows=payload.flows, source_type="api_detect_batch")


@router.get(
    "/events",
    response_model=PaginatedResponse[NetworkEventResponse],
    status_code=status.HTTP_200_OK,
    summary="Query Ingested Network Events",
    description="Retrieves a paginated historical log of ingested network flow records.",
)
def list_network_events(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    db: Session = Depends(get_db),
    svc: EventService = Depends(get_event_service),
) -> PaginatedResponse[NetworkEventResponse]:
    """Query paginated network events."""
    skip = (page - 1) * page_size
    items, total = svc.get_events(db=db, skip=skip, limit=page_size)
    
    return PaginatedResponse[NetworkEventResponse](
        total=total,
        page=page,
        page_size=page_size,
        items=[NetworkEventResponse.model_validate(i) for i in items],
    )
