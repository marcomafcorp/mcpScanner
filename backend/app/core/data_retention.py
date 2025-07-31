from datetime import datetime, timedelta
from typing import Dict, List, Optional, Type
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, and_
from enum import Enum

from app.models.base import BaseModel
from app.models import AuditLog, Scan, Finding, User


class RetentionPeriod(str, Enum):
    """Standard retention periods."""
    DAYS_7 = "7_days"
    DAYS_30 = "30_days"
    DAYS_90 = "90_days"
    DAYS_180 = "180_days"
    YEAR_1 = "1_year"
    YEARS_2 = "2_years"
    YEARS_7 = "7_years"
    FOREVER = "forever"
    
    def to_timedelta(self) -> Optional[timedelta]:
        """Convert to timedelta."""
        mapping = {
            self.DAYS_7: timedelta(days=7),
            self.DAYS_30: timedelta(days=30),
            self.DAYS_90: timedelta(days=90),
            self.DAYS_180: timedelta(days=180),
            self.YEAR_1: timedelta(days=365),
            self.YEARS_2: timedelta(days=730),
            self.YEARS_7: timedelta(days=2555),
            self.FOREVER: None,
        }
        return mapping.get(self)


class DataRetentionPolicy:
    """Data retention policy configuration."""
    
    def __init__(self):
        """Initialize retention policies."""
        # Default retention periods by model
        self.policies: Dict[Type[BaseModel], RetentionPeriod] = {
            AuditLog: RetentionPeriod.DAYS_90,  # 90 days for audit logs
            Scan: RetentionPeriod.DAYS_180,     # 180 days for scans
            Finding: RetentionPeriod.YEAR_1,    # 1 year for findings
            User: RetentionPeriod.FOREVER,      # Never auto-delete users
        }
        
        # Override policies for specific conditions
        self.conditional_policies = {
            # Keep critical findings for 2 years
            (Finding, "severity", "critical"): RetentionPeriod.YEARS_2,
            # Keep security events for 1 year
            (AuditLog, "action", "security.*"): RetentionPeriod.YEAR_1,
            # Keep failed logins for 180 days
            (AuditLog, "action", "user.login_failed"): RetentionPeriod.DAYS_180,
        }
        
        # Exclusions - data that should never be auto-deleted
        self.exclusions = {
            # Never delete users with admin role
            (User, "role", "admin"),
            # Never delete scans with legal hold
            (Scan, "metadata", {"legal_hold": True}),
        }
    
    def get_retention_period(
        self,
        model: Type[BaseModel],
        record: Optional[BaseModel] = None
    ) -> RetentionPeriod:
        """
        Get retention period for a model/record.
        
        Args:
            model: Model class
            record: Optional specific record
            
        Returns:
            Retention period
        """
        # Check conditional policies if record provided
        if record:
            for (cond_model, field, value), period in self.conditional_policies.items():
                if model == cond_model and hasattr(record, field):
                    record_value = getattr(record, field)
                    if isinstance(value, str) and value.endswith("*"):
                        # Wildcard matching
                        if str(record_value).startswith(value[:-1]):
                            return period
                    elif record_value == value:
                        return period
        
        # Return default policy
        return self.policies.get(model, RetentionPeriod.FOREVER)
    
    def should_delete(
        self,
        model: Type[BaseModel],
        record: BaseModel,
        current_time: Optional[datetime] = None
    ) -> bool:
        """
        Check if a record should be deleted based on retention policy.
        
        Args:
            model: Model class
            record: Record to check
            current_time: Current time (for testing)
            
        Returns:
            True if should be deleted
        """
        current_time = current_time or datetime.utcnow()
        
        # Check exclusions
        for (excl_model, field, value) in self.exclusions:
            if model == excl_model and hasattr(record, field):
                record_value = getattr(record, field)
                if record_value == value:
                    return False
        
        # Get retention period
        retention_period = self.get_retention_period(model, record)
        if retention_period == RetentionPeriod.FOREVER:
            return False
        
        # Check age
        retention_delta = retention_period.to_timedelta()
        if retention_delta and hasattr(record, "created_at"):
            cutoff_date = current_time - retention_delta
            return record.created_at < cutoff_date
        
        return False


class DataRetentionService:
    """Service for enforcing data retention policies."""
    
    def __init__(self, policy: Optional[DataRetentionPolicy] = None):
        """
        Initialize retention service.
        
        Args:
            policy: Retention policy to use
        """
        self.policy = policy or DataRetentionPolicy()
    
    async def cleanup_old_data(
        self,
        db: AsyncSession,
        dry_run: bool = True,
        batch_size: int = 100
    ) -> Dict[str, int]:
        """
        Clean up old data based on retention policies.
        
        Args:
            db: Database session
            dry_run: If True, only report what would be deleted
            batch_size: Number of records to process at once
            
        Returns:
            Dictionary with deletion counts by model
        """
        deletion_counts = {}
        current_time = datetime.utcnow()
        
        # Process each model with a retention policy
        for model, retention_period in self.policy.policies.items():
            if retention_period == RetentionPeriod.FOREVER:
                continue
            
            count = await self._cleanup_model(
                db, model, retention_period, current_time, dry_run, batch_size
            )
            deletion_counts[model.__name__] = count
        
        if not dry_run:
            await db.commit()
        
        return deletion_counts
    
    async def _cleanup_model(
        self,
        db: AsyncSession,
        model: Type[BaseModel],
        retention_period: RetentionPeriod,
        current_time: datetime,
        dry_run: bool,
        batch_size: int
    ) -> int:
        """
        Clean up old records for a specific model.
        
        Args:
            db: Database session
            model: Model class
            retention_period: Retention period
            current_time: Current time
            dry_run: If True, only count records
            batch_size: Batch size for deletion
            
        Returns:
            Number of records deleted/would be deleted
        """
        retention_delta = retention_period.to_timedelta()
        if not retention_delta:
            return 0
        
        cutoff_date = current_time - retention_delta
        total_deleted = 0
        
        while True:
            # Get batch of old records
            query = select(model).where(
                model.created_at < cutoff_date
            ).limit(batch_size)
            
            result = await db.execute(query)
            records = result.scalars().all()
            
            if not records:
                break
            
            # Check each record against exclusions
            records_to_delete = []
            for record in records:
                if not self._is_excluded(model, record):
                    records_to_delete.append(record)
            
            if dry_run:
                total_deleted += len(records_to_delete)
            else:
                # Delete records
                for record in records_to_delete:
                    await db.delete(record)
                    total_deleted += 1
                
                # Commit batch
                await db.commit()
            
            # If we got less than batch_size, we're done
            if len(records) < batch_size:
                break
        
        return total_deleted
    
    def _is_excluded(self, model: Type[BaseModel], record: BaseModel) -> bool:
        """
        Check if a record is excluded from deletion.
        
        Args:
            model: Model class
            record: Record to check
            
        Returns:
            True if excluded
        """
        for (excl_model, field, value) in self.policy.exclusions:
            if model == excl_model and hasattr(record, field):
                record_value = getattr(record, field)
                if isinstance(value, dict):
                    # Check nested values
                    if isinstance(record_value, dict):
                        for k, v in value.items():
                            if record_value.get(k) == v:
                                return True
                elif record_value == value:
                    return True
        
        return False
    
    async def get_retention_report(
        self,
        db: AsyncSession
    ) -> Dict[str, Dict[str, int]]:
        """
        Get report of data subject to retention policies.
        
        Args:
            db: Database session
            
        Returns:
            Report dictionary
        """
        report = {}
        current_time = datetime.utcnow()
        
        for model, retention_period in self.policy.policies.items():
            if retention_period == RetentionPeriod.FOREVER:
                continue
            
            retention_delta = retention_period.to_timedelta()
            if not retention_delta:
                continue
            
            cutoff_date = current_time - retention_delta
            
            # Count total records
            total_result = await db.execute(
                select(func.count()).select_from(model)
            )
            total_count = total_result.scalar()
            
            # Count old records
            old_result = await db.execute(
                select(func.count()).select_from(model).where(
                    model.created_at < cutoff_date
                )
            )
            old_count = old_result.scalar()
            
            report[model.__name__] = {
                "total_records": total_count,
                "records_to_delete": old_count,
                "retention_period": retention_period.value,
                "cutoff_date": cutoff_date.isoformat(),
            }
        
        return report


# Global retention service
from sqlalchemy import func
retention_service = DataRetentionService()