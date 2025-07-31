import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
import logging

from app.models import AuditLog
from app.core.rate_limiter import RateLimiter


logger = logging.getLogger(__name__)


class SecurityMonitor:
    """Monitor for security-related events and anomalies."""
    
    def __init__(self):
        """Initialize security monitor."""
        # Thresholds for alerting
        self.thresholds = {
            "failed_logins_per_user": 5,  # Failed logins per user in time window
            "failed_logins_per_ip": 10,   # Failed logins per IP in time window
            "rate_limit_violations": 20,   # Rate limit violations in time window
            "unauthorized_access": 3,      # 401/403 responses in time window
            "scan_rate_per_user": 50,      # Scans per user in time window
        }
        
        # Time windows for monitoring (in minutes)
        self.time_windows = {
            "failed_logins": 15,
            "rate_limit": 5,
            "unauthorized": 10,
            "scan_rate": 60,
        }
        
        # Alert callbacks
        self.alert_handlers = []
    
    def add_alert_handler(self, handler):
        """Add an alert handler callback."""
        self.alert_handlers.append(handler)
    
    async def check_failed_logins(
        self,
        db: AsyncSession,
        time_window_minutes: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Check for excessive failed login attempts.
        
        Args:
            db: Database session
            time_window_minutes: Time window to check
            
        Returns:
            List of alerts
        """
        time_window = time_window_minutes or self.time_windows["failed_logins"]
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window)
        alerts = []
        
        # Check by user
        user_query = select(
            AuditLog.actor_id,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.action == "user.login_failed",
                AuditLog.created_at >= cutoff_time,
                AuditLog.actor_id.isnot(None)
            )
        ).group_by(AuditLog.actor_id)
        
        result = await db.execute(user_query)
        for row in result:
            if row.count >= self.thresholds["failed_logins_per_user"]:
                alerts.append({
                    "type": "excessive_failed_logins_user",
                    "severity": "high",
                    "user_id": row.actor_id,
                    "count": row.count,
                    "time_window": time_window,
                    "threshold": self.thresholds["failed_logins_per_user"],
                })
        
        # Check by IP
        ip_query = select(
            AuditLog.ip_address,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.action == "user.login_failed",
                AuditLog.created_at >= cutoff_time
            )
        ).group_by(AuditLog.ip_address)
        
        result = await db.execute(ip_query)
        for row in result:
            if row.count >= self.thresholds["failed_logins_per_ip"]:
                alerts.append({
                    "type": "excessive_failed_logins_ip",
                    "severity": "high",
                    "ip_address": row.ip_address,
                    "count": row.count,
                    "time_window": time_window,
                    "threshold": self.thresholds["failed_logins_per_ip"],
                })
        
        return alerts
    
    async def check_rate_limit_violations(
        self,
        db: AsyncSession,
        time_window_minutes: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Check for excessive rate limit violations.
        
        Args:
            db: Database session
            time_window_minutes: Time window to check
            
        Returns:
            List of alerts
        """
        time_window = time_window_minutes or self.time_windows["rate_limit"]
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window)
        alerts = []
        
        query = select(
            AuditLog.ip_address,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.status_code == 429,
                AuditLog.created_at >= cutoff_time
            )
        ).group_by(AuditLog.ip_address)
        
        result = await db.execute(query)
        for row in result:
            if row.count >= self.thresholds["rate_limit_violations"]:
                alerts.append({
                    "type": "excessive_rate_limit_violations",
                    "severity": "medium",
                    "ip_address": row.ip_address,
                    "count": row.count,
                    "time_window": time_window,
                    "threshold": self.thresholds["rate_limit_violations"],
                })
        
        return alerts
    
    async def check_unauthorized_access(
        self,
        db: AsyncSession,
        time_window_minutes: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Check for patterns of unauthorized access attempts.
        
        Args:
            db: Database session
            time_window_minutes: Time window to check
            
        Returns:
            List of alerts
        """
        time_window = time_window_minutes or self.time_windows["unauthorized"]
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window)
        alerts = []
        
        # Check by user
        user_query = select(
            AuditLog.actor_id,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.status_code.in_([401, 403]),
                AuditLog.created_at >= cutoff_time,
                AuditLog.actor_id.isnot(None)
            )
        ).group_by(AuditLog.actor_id)
        
        result = await db.execute(user_query)
        for row in result:
            if row.count >= self.thresholds["unauthorized_access"]:
                alerts.append({
                    "type": "unauthorized_access_pattern",
                    "severity": "high",
                    "user_id": row.actor_id,
                    "count": row.count,
                    "time_window": time_window,
                    "threshold": self.thresholds["unauthorized_access"],
                })
        
        return alerts
    
    async def check_scan_rate(
        self,
        db: AsyncSession,
        time_window_minutes: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Check for excessive scanning activity.
        
        Args:
            db: Database session
            time_window_minutes: Time window to check
            
        Returns:
            List of alerts
        """
        time_window = time_window_minutes or self.time_windows["scan_rate"]
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window)
        alerts = []
        
        query = select(
            AuditLog.actor_id,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.action == "scan.created",
                AuditLog.created_at >= cutoff_time,
                AuditLog.actor_id.isnot(None)
            )
        ).group_by(AuditLog.actor_id)
        
        result = await db.execute(query)
        for row in result:
            if row.count >= self.thresholds["scan_rate_per_user"]:
                alerts.append({
                    "type": "excessive_scanning",
                    "severity": "medium",
                    "user_id": row.actor_id,
                    "count": row.count,
                    "time_window": time_window,
                    "threshold": self.thresholds["scan_rate_per_user"],
                })
        
        return alerts
    
    async def run_all_checks(self, db: AsyncSession) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run all security checks.
        
        Args:
            db: Database session
            
        Returns:
            Dictionary of check results
        """
        results = {
            "failed_logins": await self.check_failed_logins(db),
            "rate_limit_violations": await self.check_rate_limit_violations(db),
            "unauthorized_access": await self.check_unauthorized_access(db),
            "scan_rate": await self.check_scan_rate(db),
        }
        
        # Trigger alerts
        all_alerts = []
        for check_type, alerts in results.items():
            all_alerts.extend(alerts)
        
        if all_alerts:
            await self._trigger_alerts(all_alerts)
        
        return results
    
    async def _trigger_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """
        Trigger alert handlers.
        
        Args:
            alerts: List of alerts
        """
        for handler in self.alert_handlers:
            try:
                await handler(alerts)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")


class LogAggregator:
    """Aggregate and analyze audit logs."""
    
    async def get_activity_summary(
        self,
        db: AsyncSession,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get activity summary for the specified time period.
        
        Args:
            db: Database session
            hours: Number of hours to look back
            
        Returns:
            Activity summary
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Total requests
        total_query = select(func.count(AuditLog.id)).where(
            AuditLog.created_at >= cutoff_time
        )
        total_result = await db.execute(total_query)
        total_requests = total_result.scalar()
        
        # Requests by action
        action_query = select(
            AuditLog.action,
            func.count(AuditLog.id).label("count")
        ).where(
            AuditLog.created_at >= cutoff_time
        ).group_by(AuditLog.action)
        
        action_result = await db.execute(action_query)
        actions = {row.action: row.count for row in action_result}
        
        # Requests by status code
        status_query = select(
            AuditLog.status_code,
            func.count(AuditLog.id).label("count")
        ).where(
            AuditLog.created_at >= cutoff_time
        ).group_by(AuditLog.status_code)
        
        status_result = await db.execute(status_query)
        status_codes = {row.status_code: row.count for row in status_result}
        
        # Active users
        user_query = select(
            func.count(func.distinct(AuditLog.actor_id))
        ).where(
            and_(
                AuditLog.created_at >= cutoff_time,
                AuditLog.actor_id.isnot(None)
            )
        )
        user_result = await db.execute(user_query)
        active_users = user_result.scalar()
        
        # Average response time
        response_time_query = select(
            func.avg(AuditLog.response_time_ms)
        ).where(
            and_(
                AuditLog.created_at >= cutoff_time,
                AuditLog.response_time_ms.isnot(None)
            )
        )
        response_time_result = await db.execute(response_time_query)
        avg_response_time = response_time_result.scalar()
        
        return {
            "time_period_hours": hours,
            "total_requests": total_requests,
            "actions": actions,
            "status_codes": status_codes,
            "active_users": active_users,
            "avg_response_time_ms": float(avg_response_time) if avg_response_time else 0,
        }
    
    async def get_error_summary(
        self,
        db: AsyncSession,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get error summary for the specified time period.
        
        Args:
            db: Database session
            hours: Number of hours to look back
            
        Returns:
            Error summary
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Errors by status code
        error_query = select(
            AuditLog.status_code,
            AuditLog.action,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.created_at >= cutoff_time,
                AuditLog.status_code >= 400
            )
        ).group_by(AuditLog.status_code, AuditLog.action)
        
        error_result = await db.execute(error_query)
        errors = []
        for row in error_result:
            errors.append({
                "status_code": row.status_code,
                "action": row.action,
                "count": row.count,
            })
        
        # Most common error messages
        message_query = select(
            AuditLog.error_message,
            func.count(AuditLog.id).label("count")
        ).where(
            and_(
                AuditLog.created_at >= cutoff_time,
                AuditLog.error_message.isnot(None)
            )
        ).group_by(AuditLog.error_message).order_by(
            func.count(AuditLog.id).desc()
        ).limit(10)
        
        message_result = await db.execute(message_query)
        error_messages = [
            {"message": row.error_message, "count": row.count}
            for row in message_result
        ]
        
        return {
            "time_period_hours": hours,
            "errors_by_type": errors,
            "top_error_messages": error_messages,
        }


# Global instances
security_monitor = SecurityMonitor()
log_aggregator = LogAggregator()