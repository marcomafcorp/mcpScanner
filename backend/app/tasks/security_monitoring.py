import asyncio
from typing import Dict, List, Any
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.db.base import AsyncSessionLocal
from app.core.log_monitoring import security_monitor, log_aggregator
from app.models import AuditLog
from app.core.config import settings


logger = logging.getLogger(__name__)


@shared_task
def run_security_checks_task() -> Dict[str, List[Dict[str, Any]]]:
    """
    Run all security monitoring checks.
    
    Returns:
        Dictionary of security check results
    """
    async def _run_checks():
        async with AsyncSessionLocal() as db:
            try:
                results = await security_monitor.run_all_checks(db)
                
                # Log results
                total_alerts = sum(len(alerts) for alerts in results.values())
                logger.info(
                    f"Security checks completed. Total alerts: {total_alerts}"
                )
                
                # If there are critical alerts, log them
                for check_type, alerts in results.items():
                    for alert in alerts:
                        if alert.get("severity") == "high":
                            logger.warning(
                                f"HIGH SEVERITY ALERT: {alert['type']} - "
                                f"{alert.get('user_id') or alert.get('ip_address')} "
                                f"({alert['count']} occurrences in {alert['time_window']} minutes)"
                            )
                
                return results
                
            except Exception as e:
                logger.error(f"Security monitoring failed: {e}")
                raise
    
    return asyncio.run(_run_checks())


@shared_task
def generate_activity_report_task(hours: int = 24) -> Dict[str, Any]:
    """
    Generate activity report for the specified time period.
    
    Args:
        hours: Number of hours to analyze
        
    Returns:
        Activity report
    """
    async def _generate_report():
        async with AsyncSessionLocal() as db:
            try:
                # Get activity summary
                activity = await log_aggregator.get_activity_summary(db, hours)
                
                # Get error summary
                errors = await log_aggregator.get_error_summary(db, hours)
                
                report = {
                    "activity_summary": activity,
                    "error_summary": errors,
                    "report_generated_at": datetime.utcnow().isoformat(),
                }
                
                logger.info(
                    f"Activity report generated for last {hours} hours. "
                    f"Total requests: {activity['total_requests']}"
                )
                
                return report
                
            except Exception as e:
                logger.error(f"Failed to generate activity report: {e}")
                raise
    
    from datetime import datetime
    return asyncio.run(_generate_report())


@shared_task
def alert_on_critical_events_task() -> None:
    """
    Check for critical security events and send alerts.
    """
    async def _check_critical():
        async with AsyncSessionLocal() as db:
            try:
                # Check for recent critical events
                from datetime import datetime, timedelta
                cutoff_time = datetime.utcnow() - timedelta(minutes=5)
                
                # Check for admin actions by non-admins
                suspicious_admin_query = select(AuditLog).where(
                    and_(
                        AuditLog.created_at >= cutoff_time,
                        AuditLog.action.like("admin.%"),
                        AuditLog.actor_role != "admin"
                    )
                )
                
                result = await db.execute(suspicious_admin_query)
                suspicious = result.scalars().all()
                
                if suspicious:
                    logger.critical(
                        f"SECURITY ALERT: Non-admin users performing admin actions! "
                        f"Found {len(suspicious)} instances"
                    )
                    # Here you would send alerts (email, Slack, etc.)
                
                # Check for data deletions
                deletion_query = select(AuditLog).where(
                    and_(
                        AuditLog.created_at >= cutoff_time,
                        AuditLog.action.in_([
                            "user.data_deletion",
                            "scan.deleted",
                            "user.deleted"
                        ])
                    )
                )
                
                result = await db.execute(deletion_query)
                deletions = result.scalars().all()
                
                if deletions:
                    logger.warning(
                        f"Data deletion activity detected: {len(deletions)} deletions "
                        f"in the last 5 minutes"
                    )
                
            except Exception as e:
                logger.error(f"Critical event monitoring failed: {e}")
                raise
    
    from sqlalchemy import select, and_
    asyncio.run(_check_critical())


# Alert handler for sending notifications
async def send_security_alerts(alerts: List[Dict[str, Any]]) -> None:
    """
    Send security alerts via configured channels.
    
    Args:
        alerts: List of security alerts
    """
    # Group alerts by severity
    high_severity = [a for a in alerts if a.get("severity") == "high"]
    medium_severity = [a for a in alerts if a.get("severity") == "medium"]
    
    if high_severity:
        # Send immediate alerts for high severity
        logger.critical(f"HIGH SEVERITY ALERTS: {len(high_severity)} alerts")
        
        # Here you would integrate with notification services:
        # - Email
        # - Slack/Discord
        # - PagerDuty
        # - SMS
        
        # Example (would need actual implementation):
        # await send_email_alert(high_severity)
        # await send_slack_alert(high_severity)
    
    if medium_severity:
        # Log medium severity alerts
        logger.warning(f"Medium severity alerts: {len(medium_severity)} alerts")


# Register alert handler
security_monitor.add_alert_handler(send_security_alerts)