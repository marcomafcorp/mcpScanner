import pytest

from app.core.config import Settings


def test_settings_defaults():
    """Test that settings have correct default values."""
    settings = Settings()
    
    assert settings.APP_NAME == "MCP Security Scanner"
    assert settings.APP_VERSION == "1.0.0"
    assert settings.API_PREFIX == "/api/v1"
    assert settings.ALGORITHM == "HS256"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 30
    assert settings.MAX_SCAN_DEPTH == 3
    assert settings.SCAN_TIMEOUT_SECONDS == 300
    assert settings.MAX_CONCURRENT_SCANS == 5


def test_settings_cors_origins_parsing():
    """Test CORS origins parsing from different formats."""
    # Test JSON format
    settings = Settings(CORS_ORIGINS='["http://localhost:3000", "http://localhost:5173"]')
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://localhost:5173"]
    
    # Test comma-separated format
    settings = Settings(CORS_ORIGINS="http://localhost:3000,http://localhost:5173")
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://localhost:5173"]
    
    # Test list format
    settings = Settings(CORS_ORIGINS=["http://localhost:3000"])
    assert settings.CORS_ORIGINS == ["http://localhost:3000"]


def test_settings_environment_properties():
    """Test environment property methods."""
    # Test development environment
    settings = Settings(ENVIRONMENT="development")
    assert settings.is_development is True
    assert settings.is_production is False
    assert settings.is_testing is False
    
    # Test production environment
    settings = Settings(ENVIRONMENT="production")
    assert settings.is_development is False
    assert settings.is_production is True
    assert settings.is_testing is False
    
    # Test testing environment
    settings = Settings(ENVIRONMENT="testing")
    assert settings.is_development is False
    assert settings.is_production is False
    assert settings.is_testing is True