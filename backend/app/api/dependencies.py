"""
dependencies.py - Common FastAPI Route Dependencies.

Why this module exists:
Centralizes dependency injection for database sessions, authentication headers,
and service locators across all route handlers.
"""

from typing import Generator
from fastapi import Depends
from sqlalchemy.orm import Session

from ..database.session import get_db
from ..services.event_service import event_service, EventService
from ..services.alert_service import alert_service, AlertService
from ..services.incident_service import incident_service, IncidentService
from ..services.stats_service import stats_service, StatsService


def get_event_service() -> EventService:
    return event_service


def get_alert_service() -> AlertService:
    return alert_service


def get_incident_service() -> IncidentService:
    return incident_service


def get_stats_service() -> StatsService:
    return stats_service
