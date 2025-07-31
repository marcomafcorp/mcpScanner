from app.schemas.base import BaseSchema, IdTimestampSchema, TimestampSchema
from app.schemas.finding import (
    FindingActionRequest,
    FindingCreateRequest,
    FindingFilters,
    FindingListResponse,
    FindingResponse,
    FindingSummary,
    FindingUpdateRequest,
)
from app.schemas.scan import (
    ScanConfigSchema,
    ScanCreateRequest,
    ScanFilters,
    ScanListResponse,
    ScanResponse,
    ScanUpdateRequest,
    ScanWithFindingsResponse,
)
from app.schemas.target import (
    PortInfo,
    ServiceInfo,
    TargetCreateRequest,
    TargetListResponse,
    TargetResponse,
    TargetUpdateRequest,
)
from app.schemas.user import (
    PasswordChangeRequest,
    UserCreateRequest,
    UserListResponse,
    UserResponse,
    UserUpdateRequest,
)
from app.schemas.vulnerability import (
    RemediationAdvice,
    VulnerabilityCreateRequest,
    VulnerabilityResponse,
    VulnerabilityUpdateRequest,
)

__all__ = [
    # Base schemas
    "BaseSchema",
    "TimestampSchema",
    "IdTimestampSchema",
    # Finding schemas
    "FindingCreateRequest",
    "FindingUpdateRequest",
    "FindingResponse",
    "FindingListResponse",
    "FindingFilters",
    "FindingActionRequest",
    "FindingSummary",
    # Scan schemas
    "ScanConfigSchema",
    "ScanCreateRequest",
    "ScanUpdateRequest",
    "ScanResponse",
    "ScanListResponse",
    "ScanWithFindingsResponse",
    "ScanFilters",
    # Target schemas
    "PortInfo",
    "ServiceInfo",
    "TargetCreateRequest",
    "TargetUpdateRequest",
    "TargetResponse",
    "TargetListResponse",
    # User schemas
    "UserCreateRequest",
    "UserUpdateRequest",
    "UserResponse",
    "UserListResponse",
    "PasswordChangeRequest",
    # Vulnerability schemas
    "VulnerabilityCreateRequest",
    "VulnerabilityUpdateRequest",
    "VulnerabilityResponse",
    "RemediationAdvice",
]