from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.target import Target
    from app.models.user import User


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(BaseModel):
    """Scan model for tracking security scans."""
    
    __tablename__ = "scans"
    
    # Basic fields
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        String(20),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    
    # Scan configuration
    depth: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    active_tests: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scan_config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Progress tracking
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_module: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Foreign keys
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="SET NULL"),
        nullable=True,
    )
    
    # Task tracking
    task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, unique=True)
    
    # Relationships
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    target: Mapped[Optional["Target"]] = relationship(
        "Target",
        back_populates="scans",
        lazy="joined",
    )
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="scans",
        lazy="joined",
    )
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @property
    def is_active(self) -> bool:
        """Check if scan is currently active."""
        return self.status in [ScanStatus.RUNNING, ScanStatus.PAUSED]
    
    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, target_url='{self.target_url}', status={self.status})>"