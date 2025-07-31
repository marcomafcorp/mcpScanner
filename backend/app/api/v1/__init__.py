from fastapi import APIRouter

from app.api.v1 import health, users, scans, audit_logs, user_data, monitoring

api_router = APIRouter(prefix="/api/v1")

# Include all routers
api_router.include_router(health.router)
api_router.include_router(users.router)
api_router.include_router(scans.router)
api_router.include_router(audit_logs.router)
api_router.include_router(user_data.router)
api_router.include_router(monitoring.router)