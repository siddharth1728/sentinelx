"""
statistics.py - Security Analytics & SOC Metrics Endpoints.

Why this route exists:
Provides aggregated security telemetry and threat classification breakdowns
for dashboard visualizations and executive reporting.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from ...database.session import get_db
from ...schemas.stats import SecurityStatsResponse
from ...services.stats_service import stats_service, StatsService
from ...api.dependencies import get_stats_service

router = APIRouter(prefix="/stats", tags=["Security Analytics & Statistics"])


@router.get(
    "/overview",
    response_model=SecurityStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Security Dashboard Overview",
    description="Returns aggregate counts of processed events, intrusions, alerts by severity, and threat type distributions.",
)
def get_security_overview(
    db: Session = Depends(get_db),
    svc: StatsService = Depends(get_stats_service),
) -> SecurityStatsResponse:
    """Fetch security overview KPIs and threat breakdowns."""
    return svc.get_security_overview(db=db)
