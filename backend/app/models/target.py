from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.scan import Scan


class Target(BaseModel):
    """Target model for scan targets."""
    
    __tablename__ = "targets"
    
    # Target identification
    url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # Supports IPv6
    
    # Service information
    ports: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    services: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Additional metadata
    target_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Relationships
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="target",
        lazy="dynamic",
    )
    
    def __repr__(self) -> str:
        return f"<Target(id={self.id}, url='{self.url}', hostname='{self.hostname}')>"