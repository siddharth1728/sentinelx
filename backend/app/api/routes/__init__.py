"""
Routes package for SENTINELX backend.
Consolidates all API routers into a single root router.
"""

from fastapi import APIRouter
from .health import router as health_router
from .detection import router as detection_router
from .alerts import router as alerts_router
from .incidents import router as incidents_router
from .statistics import router as stats_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(detection_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(stats_router)

__all__ = ["api_router"]
