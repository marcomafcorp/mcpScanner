from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.settings import settings

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Import all models here to ensure they are registered with SQLAlchemy
# This will be populated as we create models
from app.models import *  # noqa