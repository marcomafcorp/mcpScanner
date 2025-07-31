from datetime import datetime
from typing import Dict, List, Optional

from pydantic import Field, HttpUrl, field_validator

from app.models.scan import ScanStatus
from app.schemas.base import BaseSchema, IdTimestampSchema
from app.schemas.finding import FindingResponse
from app.schemas.target import TargetResponse


class ScanConfigSchema(BaseSchema):
    """Schema for scan configuration."""
    
    user_agent: Optional[str] = Field(None, description="User agent for HTTP requests")
    timeout: Optional[int] = Field(30, description="Timeout in seconds for each test")
    follow_redirects: Optional[bool] = Field(True, description="Follow HTTP redirects")
    max_redirects: Optional[int] = Field(5, description="Maximum number of redirects to follow")
    authentication: Optional[Dict[str, str]] = Field(None, description="Authentication details")
    headers: Optional[Dict[str, str]] = Field(None, description="Additional HTTP headers")
    excluded_paths: Optional[List[str]] = Field(default_factory=list, description="Paths to exclude from scanning")


class ScanCreateRequest(BaseSchema):
    """Request schema for creating a scan."""
    
    target_url: HttpUrl = Field(..., description="Target URL to scan")
    depth: int = Field(3, ge=1, le=10, description="Scan depth (1-10)")
    active_tests: bool = Field(True, description="Enable active security tests")
    scan_config: Optional[ScanConfigSchema] = Field(None, description="Additional scan configuration")


class ScanUpdateRequest(BaseSchema):
    """Request schema for updating a scan."""
    
    status: Optional[ScanStatus] = Field(None, description="Scan status")


class ScanResponse(IdTimestampSchema):
    """Response schema for scan."""
    
    target_url: str
    status: ScanStatus
    depth: int
    active_tests: bool
    scan_config: Optional[dict]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    progress: int = Field(..., ge=0, le=100)
    current_module: Optional[str]
    error_message: Optional[str]
    user_id: Optional[int]
    target_id: Optional[int]
    task_id: Optional[str]
    
    # Computed fields
    duration: Optional[float] = Field(None, description="Scan duration in seconds")
    is_active: bool = Field(False, description="Whether scan is currently active")
    
    # Related data (optional)
    target: Optional[TargetResponse] = None
    findings_count: Optional[int] = None
    findings_by_severity: Optional[Dict[str, int]] = None


class ScanListResponse(BaseSchema):
    """Response schema for scan list."""
    
    items: List[ScanResponse]
    total: int
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)
    pages: int = Field(1, ge=1)


class ScanWithFindingsResponse(ScanResponse):
    """Response schema for scan with findings."""
    
    findings: List[FindingResponse] = Field(default_factory=list)


class ScanFilters(BaseSchema):
    """Filters for scan queries."""
    
    status: Optional[ScanStatus] = None
    user_id: Optional[int] = None
    target_url: Optional[str] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    
    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: Optional[str]) -> Optional[str]:
        """Allow partial URL matching."""
        return v