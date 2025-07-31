from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import Field, HttpUrl

from app.schemas.base import BaseSchema, IdTimestampSchema


class PortInfo(BaseSchema):
    """Schema for port information."""
    
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., description="Protocol (tcp/udp)")
    state: str = Field(..., description="Port state (open/closed/filtered)")
    service: Optional[str] = Field(None, description="Service name")
    version: Optional[str] = Field(None, description="Service version")


class ServiceInfo(BaseSchema):
    """Schema for service information."""
    
    name: str = Field(..., description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    product: Optional[str] = Field(None, description="Product name")
    vendor: Optional[str] = Field(None, description="Vendor name")
    cpe: Optional[str] = Field(None, description="CPE identifier")


class TargetBaseSchema(BaseSchema):
    """Base schema for target."""
    
    url: HttpUrl = Field(..., description="Target URL")
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$")
    target_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class TargetCreateRequest(TargetBaseSchema):
    """Request schema for creating a target."""
    pass


class TargetUpdateRequest(BaseSchema):
    """Request schema for updating a target."""
    
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$")
    ports: Optional[List[PortInfo]] = None
    services: Optional[List[ServiceInfo]] = None
    target_metadata: Optional[Dict[str, Any]] = None


class TargetResponse(TargetBaseSchema, IdTimestampSchema):
    """Response schema for target."""
    
    ports: Optional[Dict[str, PortInfo]] = Field(default_factory=dict)
    services: Optional[Dict[str, ServiceInfo]] = Field(default_factory=dict)
    
    # Statistics
    total_scans: Optional[int] = Field(None, description="Total number of scans for this target")
    last_scan_at: Optional[datetime] = Field(None, description="Timestamp of last scan")


class TargetListResponse(BaseSchema):
    """Response schema for target list."""
    
    items: List[TargetResponse]
    total: int
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)
    pages: int = Field(1, ge=1)