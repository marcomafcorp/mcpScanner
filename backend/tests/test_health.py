import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.core.settings import settings


def test_root_endpoint(client: TestClient):
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    
    data = response.json()
    assert data["app"] == settings.APP_NAME
    assert data["version"] == settings.APP_VERSION
    assert data["status"] == "running"
    assert data["environment"] == settings.ENVIRONMENT


def test_health_check(client: TestClient):
    """Test the basic health check endpoint."""
    response = client.get(f"{settings.API_PREFIX}/health")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == settings.APP_NAME
    assert data["version"] == settings.APP_VERSION
    assert data["environment"] == settings.ENVIRONMENT


@pytest.mark.asyncio
async def test_database_health_check(async_client: AsyncClient):
    """Test the database health check endpoint."""
    response = await async_client.get(f"{settings.API_PREFIX}/health/db")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert "database_url" in data


@pytest.mark.asyncio
async def test_detailed_health_check(async_client: AsyncClient):
    """Test the detailed health check endpoint."""
    response = await async_client.get(f"{settings.API_PREFIX}/health/detailed")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    
    # Check app information
    assert data["app"]["name"] == settings.APP_NAME
    assert data["app"]["version"] == settings.APP_VERSION
    assert data["app"]["environment"] == settings.ENVIRONMENT
    assert data["app"]["debug"] == settings.DEBUG
    
    # Check services
    assert "api" in data["services"]
    assert "database" in data["services"]
    assert "redis" in data["services"]
    
    # Check configuration
    assert data["configuration"]["max_scan_depth"] == settings.MAX_SCAN_DEPTH
    assert data["configuration"]["scan_timeout"] == settings.SCAN_TIMEOUT_SECONDS
    assert data["configuration"]["max_concurrent_scans"] == settings.MAX_CONCURRENT_SCANS