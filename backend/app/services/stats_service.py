"""
stats_service.py - Security Analytics & SOC Dashboard Aggregation Service.

Why this module exists:
Aggregates relational metrics across network events, prediction audit logs,
alerts, and incidents to power real-time security dashboard charts and KPIs.
"""

from sqlalchemy.orm import Session
from sqlalchemy import select, func

from ..models.network_event import NetworkEvent
from ..models.prediction_log import PredictionLog
from ..models.alert import Alert, AlertStatus, AlertSeverity
from ..models.incident import Incident, IncidentStatus
from ..schemas.stats import SecurityStatsResponse, ThreatBreakdownItem, SeverityBreakdownItem


class StatsService:
    """
    StatsService computes security telemetry statistics and threat distributions.
    """

    def get_security_overview(self, db: Session) -> SecurityStatsResponse:
        """
        Compute high-level security overview metrics.
        """
        # Event & Intrusion totals
        total_events = db.scalar(select(func.count()).select_from(NetworkEvent)) or 0
        total_intrusions = db.scalar(
            select(func.count()).select_from(PredictionLog).where(PredictionLog.is_intrusion == True)
        ) or 0
        total_benign = max(0, total_events - total_intrusions)

        # Alerts
        total_alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
        active_alerts = db.scalar(
            select(func.count()).select_from(Alert).where(
                Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS])
            )
        ) or 0

        # Incidents
        total_incidents = db.scalar(select(func.count()).select_from(Incident)) or 0

        # Average latency
        avg_latency = db.scalar(select(func.avg(PredictionLog.inference_time_ms))) or 0.0

        # Threat breakdown
        threat_stmt = (
            select(Alert.threat_type, func.count(Alert.id))
            .group_by(Alert.threat_type)
        )
        threat_rows = db.execute(threat_stmt).all()
        threat_breakdown = []
        for threat_type, count in threat_rows:
            pct = round((count / total_alerts * 100.0) if total_alerts > 0 else 0.0, 2)
            threat_breakdown.append(
                ThreatBreakdownItem(threat_type=threat_type, count=count, percentage=pct)
            )

        # Severity breakdown
        sev_stmt = (
            select(Alert.severity, func.count(Alert.id))
            .group_by(Alert.severity)
        )
        sev_rows = db.execute(sev_stmt).all()
        severity_breakdown = []
        for sev, count in sev_rows:
            severity_breakdown.append(
                SeverityBreakdownItem(severity=sev.value if hasattr(sev, 'value') else str(sev), count=count)
            )

        return SecurityStatsResponse(
            total_events_processed=total_events,
            total_intrusions_detected=total_intrusions,
            total_benign_events=total_benign,
            total_alerts_generated=total_alerts,
            active_alerts_count=active_alerts,
            total_incidents_opened=total_incidents,
            average_inference_latency_ms=round(float(avg_latency), 3),
            threat_distribution=threat_breakdown,
            alert_severity_distribution=severity_breakdown,
            recent_activity_summary={
                "system_status": "OPERATIONAL",
                "detection_engine": "ACTIVE",
            },
        )


# Default instance
stats_service = StatsService()
