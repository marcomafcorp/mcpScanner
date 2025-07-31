from typing import List, Optional

from pydantic import EmailStr, Field

from app.schemas.base import BaseSchema, IdTimestampSchema


class UserBaseSchema(BaseSchema):
    """Base schema for user."""
    
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=255)


class UserCreateRequest(UserBaseSchema):
    """Request schema for creating a user."""
    
    password: str = Field(..., min_length=8, max_length=128)


class UserUpdateRequest(BaseSchema):
    """Request schema for updating a user."""
    
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, min_length=8, max_length=128)


class UserResponse(UserBaseSchema, IdTimestampSchema):
    """Response schema for user."""
    
    is_active: bool
    is_superuser: bool
    
    # Statistics
    total_scans: Optional[int] = Field(None, description="Total number of scans by user")


class UserListResponse(BaseSchema):
    """Response schema for user list."""
    
    items: List[UserResponse]
    total: int
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)
    pages: int = Field(1, ge=1)


class PasswordChangeRequest(BaseSchema):
    """Request schema for changing password."""
    
    current_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)