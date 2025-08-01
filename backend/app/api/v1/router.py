from fastapi import APIRouter

from app.api.v1 import auth, users, audit_logs


# Create v1 router
v1_router = APIRouter(prefix="/v1")

# Include all v1 routers
v1_router.include_router(auth.router)
v1_router.include_router(users.router)
v1_router.include_router(audit_logs.router)