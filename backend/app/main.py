from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import health
from app.api.v1.router import v1_router
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.validation import RequestValidationMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown events."""
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    yield
    # Shutdown
    print("Shutting down...")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs" if settings.DEBUG else None,
    redoc_url=f"{settings.API_PREFIX}/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Request Validation (should be before rate limiting)
app.add_middleware(
    RequestValidationMiddleware,
    max_content_length=10 * 1024 * 1024,  # 10MB max request size
    sanitize_inputs=True
)

# Configure Rate Limiting
app.add_middleware(
    RateLimitMiddleware,
    calls=100,  # Default: 100 calls
    period=60,  # Per 60 seconds
    calls_per_user=200,  # Authenticated users get more
    calls_per_ip=100,  # Per IP address
    exclude_paths=["/api/v1/health", "/docs", "/redoc", "/openapi.json"],
    custom_limits={
        "/api/v1/auth/login": (5, 60),  # 5 login attempts per minute
        "/api/v1/auth/register": (3, 300),  # 3 registrations per 5 minutes
        "/api/v1/scans": (10, 60),  # 10 scan creations per minute
    }
)

# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """Root endpoint."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "environment": settings.ENVIRONMENT,
    }

# Include routers
app.include_router(health.router, prefix=settings.API_PREFIX, tags=["Health"])
app.include_router(v1_router, prefix="/api")