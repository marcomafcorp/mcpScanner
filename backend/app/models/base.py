from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column, declared_attr

from app.db.base import Base


class TimestampMixin:
    """Mixin that adds timestamp fields to models."""
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class BaseModel(Base, TimestampMixin):
    """Base model with common fields."""
    
    __abstract__ = True
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    
    @declared_attr
    def __tablename__(cls) -> str:
        """Generate table name from class name."""
        return cls.__name__.lower() + "s"