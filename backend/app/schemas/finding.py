from datetime import datetime
from typing import List, Optional

from pydantic import Field

from app.models.finding import FindingCategory, FindingStatus, SeverityLevel
from app.schemas.base import BaseSchema, IdTimestampSchema
from app.schemas.vulnerability import VulnerabilityResponse


class FindingBaseSchema(BaseSchema):
    """Base schema for finding."""
    
    category: FindingCategory
    severity: SeverityLevel
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1)
    evidence: Optional[str] = None
    location: Optional[str] = Field(None, max_length=1000)
    file_path: Optional[str] = Field(None, max_length=500)
    line_number: Optional[int] = Field(None, ge=1)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    scanner_module: str = Field(..., min_length=1, max_length=100)


class FindingCreateRequest(FindingBaseSchema):
    """Request schema for creating a finding."""
    
    scan_id: int = Field(..., description="Associated scan ID")


class FindingUpdateRequest(BaseSchema):
    """Request schema for updating a finding."""
    
    status: Optional[FindingStatus] = None
    false_positive: Optional[bool] = None


class FindingResponse(FindingBaseSchema, IdTimestampSchema):
    """Response schema for finding."""
    
    scan_id: int
    status: FindingStatus
    false_positive: bool
    confirmed_at: Optional[datetime]
    dismissed_at: Optional[datetime]
    resolved_at: Optional[datetime]
    
    # Computed field
    severity_score: int = Field(..., ge=1, le=5, description="Numeric severity score")
    
    # Related data (optional)
    vulnerability: Optional[VulnerabilityResponse] = None


class FindingListResponse(BaseSchema):
    """Response schema for finding list."""
    
    items: List[FindingResponse]
    total: int
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)
    pages: int = Field(1, ge=1)


class FindingFilters(BaseSchema):
    """Filters for finding queries."""
    
    scan_id: Optional[int] = None
    category: Optional[FindingCategory] = None
    severity: Optional[SeverityLevel] = None
    status: Optional[FindingStatus] = None
    scanner_module: Optional[str] = None
    false_positive: Optional[bool] = None


class FindingActionRequest(BaseSchema):
    """Request schema for finding actions."""
    
    reason: Optional[str] = Field(None, max_length=500, description="Reason for action")


class FindingSummary(BaseSchema):
    """Summary of findings by severity."""
    
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0