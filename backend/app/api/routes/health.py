"""
health.py - System Health & Diagnostic Endpoints.

Why this route exists:
Provides kubernetes/docker liveness and readiness probes, verifying database connectivity
and ML model availability.
"""

from fastapi import APIRouter, status
from ...config import settings
from ...schemas.common import HealthResponse
from ...database.init_db import check_db_health
from ...ml.model_loader import is_model_ready

router = APIRouter(prefix="/health", tags=["System & Diagnostics"])


@router.get(
    "",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="System Health Check",
    description="Returns connectivity status of the database and operational readiness of the ML detection model.",
)
def get_health() -> HealthResponse:
    """Check database and ML engine health."""
    db_ok = check_db_health()
    model_ok = is_model_ready()

    overall_status = "HEALTHY" if (db_ok and model_ok) else "DEGRADED"

    return HealthResponse(
        status=overall_status,
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database_connected=db_ok,
        ml_model_loaded=model_ok,
        model_version=settings.APP_VERSION if model_ok else None,
    )
