from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class AuditLogBase(BaseModel):
    """Base audit log schema."""
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    response_status: Optional[int] = None
    response_time_ms: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class AuditLogCreate(AuditLogBase):
    """Audit log creation schema."""
    pass


class AuditLogResponse(AuditLogBase):
    """Audit log response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    created_at: datetime
    is_error: bool = Field(default=False)
    is_authentication_event: bool = Field(default=False)


class AuditLogFilter(BaseModel):
    """Audit log filter schema."""
    actor_id: Optional[str] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    is_error: Optional[bool] = None
    actions: Optional[List[str]] = None


class AuditLogExport(BaseModel):
    """Audit log export request schema."""
    format: str = Field(default="json", pattern="^(json|csv)$")
    filter: Optional[AuditLogFilter] = None
    include_details: bool = Field(default=True)


class AuditLogSummary(BaseModel):
    """Audit log summary schema."""
    total_events: int
    unique_actors: int
    unique_ips: int
    error_count: int
    authentication_events: int
    action_breakdown: Dict[str, int]
    top_actors: List[Dict[str, Any]]
    top_ips: List[Dict[str, Any]]
    time_range: Dict[str, datetime]