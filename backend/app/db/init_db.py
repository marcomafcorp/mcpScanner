import asyncio
import logging
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base, engine
from app.db.session import AsyncSessionLocal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def init_db() -> None:
    """Initialize database by creating all tables."""
    logger.info("Creating database tables...")
    
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Database tables created successfully!")
    
    # You can add initial data seeding here if needed
    async with AsyncSessionLocal() as session:
        # Example: Create default admin user, settings, etc.
        pass


async def drop_db() -> None:
    """Drop all database tables."""
    logger.warning("Dropping all database tables...")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    logger.info("All database tables dropped!")


if __name__ == "__main__":
    # Run database initialization
    asyncio.run(init_db())