from datetime import datetime
from typing import Dict
from celery import shared_task
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio

from app.db.base import AsyncSessionLocal
from contextlib import asynccontextmanager
from app.core.data_retention import retention_service
from app.core.audit import audit_logger
import logging

logger = logging.getLogger(__name__)


@shared_task
def cleanup_old_data_task(dry_run: bool = False) -> Dict[str, int]:
    """
    Scheduled task to clean up old data based on retention policies.
    
    Args:
        dry_run: If True, only report what would be deleted
        
    Returns:
        Dictionary with deletion counts
    """
    async def _cleanup():
        async with AsyncSessionLocal() as db:
            try:
                # Run cleanup
                deletion_counts = await retention_service.cleanup_old_data(
                    db=db,
                    dry_run=dry_run,
                    batch_size=100
                )
                
                # Log the cleanup action
                if not dry_run and any(deletion_counts.values()):
                    audit_log = AuditLog(
                        actor_id="system",
                        actor_name="Data Retention Service",
                        action="system.data_cleanup",
                        resource_type="system",
                        resource_id="data_retention",
                        changes={
                            "deletion_counts": deletion_counts,
                            "cleanup_time": datetime.utcnow().isoformat()
                        },
                        ip_address="system",
                        user_agent="celery",
                        status_code=200
                    )
                    db.add(audit_log)
                    await db.commit()
                
                logger.info(
                    f"Data retention cleanup completed. "
                    f"{'DRY RUN - Would delete' if dry_run else 'Deleted'}: {deletion_counts}"
                )
                
                return deletion_counts
                
            except Exception as e:
                logger.error(f"Data retention cleanup failed: {e}")
                raise
    
    # Run async function
    return asyncio.run(_cleanup())


@shared_task
def generate_retention_report_task() -> Dict[str, Dict[str, int]]:
    """
    Generate a report of data subject to retention policies.
    
    Returns:
        Report dictionary
    """
    async def _generate_report():
        async with AsyncSessionLocal() as db:
            try:
                report = await retention_service.get_retention_report(db)
                
                logger.info(
                    f"Data retention report generated: {len(report)} models tracked"
                )
                
                return report
                
            except Exception as e:
                logger.error(f"Failed to generate retention report: {e}")
                raise
    
    # Run async function
    return asyncio.run(_generate_report())


# Import AuditLog model
from app.models import AuditLog