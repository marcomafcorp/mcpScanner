from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Application Settings
    APP_NAME: str = Field(default="MCP Security Scanner")
    APP_VERSION: str = Field(default="1.0.0")
    DEBUG: bool = Field(default=False)
    ENVIRONMENT: str = Field(default="production")

    # API Settings
    API_PREFIX: str = Field(default="/api/v1")
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:5173"])

    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./mcp_scanner.db",
        description="Database connection URL"
    )

    # Security
    SECRET_KEY: str = Field(
        default="your-secret-key-here-change-in-production",
        description="Secret key for JWT encoding"
    )
    REFRESH_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Separate secret key for refresh tokens"
    )
    JWT_ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)

    # Redis Configuration
    REDIS_URL: str = Field(default="redis://localhost:6379/0")

    # Celery Configuration
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/0")

    # Scanner Configuration
    MAX_SCAN_DEPTH: int = Field(default=3)
    SCAN_TIMEOUT_SECONDS: int = Field(default=300)
    MAX_CONCURRENT_SCANS: int = Field(default=5)

    # OWASP Dependency Check
    DEPENDENCY_CHECK_PATH: Optional[str] = Field(
        default="/usr/local/bin/dependency-check"
    )

    # Logging
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = Field(default="json")

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            import json
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",")]
        return v

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == "testing"


settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings