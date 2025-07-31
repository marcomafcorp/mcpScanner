from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.hybrid import hybrid_property

from app.models.base import BaseModel


class AuditLog(BaseModel):
    """Audit log model for tracking user actions and system events."""
    
    __tablename__ = "audit_logs"
    
    # Actor information
    actor_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="User ID who performed the action"
    )
    actor_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Email of the actor for reference"
    )
    actor_role: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="Role of the actor at time of action"
    )
    
    # Action information
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Action performed (e.g., 'user.login', 'scan.create')"
    )
    resource_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
        comment="Type of resource affected (e.g., 'user', 'scan', 'finding')"
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="ID of the affected resource"
    )
    
    # Request information
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # Supports IPv6
        nullable=True,
        index=True,
        comment="IP address of the request"
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="User agent string"
    )
    request_method: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
        comment="HTTP method (GET, POST, etc.)"
    )
    request_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Request path"
    )
    
    # Response information
    response_status: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="HTTP response status code"
    )
    response_time_ms: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Response time in milliseconds"
    )
    
    # Additional details
    details: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Additional details about the action"
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if action failed"
    )
    
    # Timestamp (using BaseModel's created_at)
    # created_at is already provided by BaseModel
    
    # Indexes for common queries
    __table_args__ = (
        Index("idx_audit_logs_actor_action", "actor_id", "action"),
        Index("idx_audit_logs_resource", "resource_type", "resource_id"),
        Index("idx_audit_logs_timestamp", "created_at"),
        Index("idx_audit_logs_ip_timestamp", "ip_address", "created_at"),
    )
    
    @hybrid_property
    def is_error(self) -> bool:
        """Check if this log entry represents an error."""
        return self.error_message is not None or (
            self.response_status is not None and self.response_status >= 400
        )
    
    @hybrid_property
    def is_authentication_event(self) -> bool:
        """Check if this is an authentication-related event."""
        auth_actions = ["user.login", "user.logout", "user.register", "token.refresh"]
        return self.action in auth_actions
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "actor_id": self.actor_id,
            "actor_email": self.actor_email,
            "actor_role": self.actor_role,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "response_status": self.response_status,
            "response_time_ms": self.response_time_ms,
            "details": self.details,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# Common audit log actions
class AuditAction:
    """Common audit log action constants."""
    
    # Authentication
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    USER_LOGIN_FAILED = "user.login_failed"
    TOKEN_REFRESH = "token.refresh"
    PASSWORD_CHANGE = "user.password_change"
    PASSWORD_RESET_REQUEST = "user.password_reset_request"
    PASSWORD_RESET_COMPLETE = "user.password_reset_complete"
    
    # User management
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_ACTIVATE = "user.activate"
    USER_DEACTIVATE = "user.deactivate"
    USER_ROLE_CHANGE = "user.role_change"
    
    # Scan operations
    SCAN_CREATE = "scan.create"
    SCAN_START = "scan.start"
    SCAN_COMPLETE = "scan.complete"
    SCAN_CANCEL = "scan.cancel"
    SCAN_DELETE = "scan.delete"
    SCAN_VIEW = "scan.view"
    
    # Finding operations
    FINDING_CREATE = "finding.create"
    FINDING_UPDATE = "finding.update"
    FINDING_DELETE = "finding.delete"
    FINDING_EXPORT = "finding.export"
    
    # Security events
    SECURITY_VIOLATION = "security.violation"
    RATE_LIMIT_EXCEEDED = "security.rate_limit"
    CSRF_FAILURE = "security.csrf_failure"
    SQL_INJECTION_ATTEMPT = "security.sql_injection"
    XSS_ATTEMPT = "security.xss_attempt"
    UNAUTHORIZED_ACCESS = "security.unauthorized"
    
    # System events
    SYSTEM_START = "system.start"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_CONFIG_CHANGE = "system.config_change"