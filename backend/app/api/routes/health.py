from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings import settings
from app.db.session import get_db

router = APIRouter()


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/health/db")
async def database_health_check(
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Database health check endpoint."""
    try:
        # Test database connection
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        
        return {
            "status": "healthy",
            "database": "connected",
            "database_url": settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else "local",
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
        }


@router.get("/health/detailed")
async def detailed_health_check(
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Detailed health check with all service statuses."""
    health_status = {
        "status": "healthy",
        "app": {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "debug": settings.DEBUG,
        },
        "services": {
            "api": "healthy",
            "database": "unknown",
            "redis": "unknown",
        },
        "configuration": {
            "max_scan_depth": settings.MAX_SCAN_DEPTH,
            "scan_timeout": settings.SCAN_TIMEOUT_SECONDS,
            "max_concurrent_scans": settings.MAX_CONCURRENT_SCANS,
        }
    }
    
    # Check database
    try:
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        health_status["services"]["database"] = "healthy"
    except Exception:
        health_status["services"]["database"] = "unhealthy"
        health_status["status"] = "degraded"
    
    # Redis check would go here when implemented
    # For now, we'll leave it as "unknown"
    
    return health_status