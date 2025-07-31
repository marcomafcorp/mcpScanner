from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


class AuditLogger:
    """Helper class for audit logging operations."""
    
    async def log_user_data_deletion(
        self,
        db: AsyncSession,
        user_id: str,
        deletion_type: str,
        deletion_counts: Dict[str, int]
    ) -> None:
        """Log user data deletion event."""
        audit_log = AuditLog(
            actor_id=user_id,
            actor_name="Self",
            action="user.data_deletion",
            resource_type="user_data",
            resource_id=user_id,
            changes={
                "deletion_type": deletion_type,
                "deletion_counts": deletion_counts
            },
            ip_address="system",
            user_agent="system",
            status_code=200
        )
        db.add(audit_log)
    
    async def log_admin_data_export(
        self,
        db: AsyncSession,
        admin_id: str,
        target_user_id: str,
        format: str
    ) -> None:
        """Log admin data export event."""
        audit_log = AuditLog(
            actor_id=admin_id,
            actor_name="Admin",
            action="admin.data_export",
            resource_type="user_data",
            resource_id=target_user_id,
            changes={
                "format": format,
                "target_user_id": target_user_id
            },
            ip_address="system",
            user_agent="system",
            status_code=200
        )
        db.add(audit_log)


# Global instance
audit_logger = AuditLogger()