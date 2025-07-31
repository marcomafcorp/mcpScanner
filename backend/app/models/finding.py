from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability


class SeverityLevel(str, Enum):
    """Severity level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status enumeration."""
    OPEN = "open"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"


class FindingCategory(str, Enum):
    """Finding category enumeration."""
    # Dependency vulnerabilities
    DEPENDENCY = "dependency"
    
    # Configuration issues
    CONFIG_INSECURE_DEFAULT = "config_insecure_default"
    CONFIG_HARDCODED_CREDS = "config_hardcoded_creds"
    CONFIG_PERMISSIVE_ACCESS = "config_permissive_access"
    
    # Code vulnerabilities
    CODE_INJECTION_SQL = "code_injection_sql"
    CODE_INJECTION_XSS = "code_injection_xss"
    CODE_INJECTION_CMD = "code_injection_cmd"
    
    # Network vulnerabilities
    NETWORK_OPEN_PORT = "network_open_port"
    NETWORK_WEAK_PROTOCOL = "network_weak_protocol"
    NETWORK_MISCONFIGURATION = "network_misconfiguration"
    
    # API/Web vulnerabilities
    WEB_AUTHENTICATION = "web_authentication"
    WEB_AUTHORIZATION = "web_authorization"
    WEB_INJECTION = "web_injection"
    WEB_EXPOSURE = "web_exposure"


class Finding(BaseModel):
    """Finding model for security vulnerabilities discovered during scans."""
    
    __tablename__ = "findings"
    
    # Foreign keys
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Basic information
    category: Mapped[FindingCategory] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    severity: Mapped[SeverityLevel] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    status: Mapped[FindingStatus] = mapped_column(
        String(20),
        default=FindingStatus.OPEN,
        nullable=False,
        index=True,
    )
    
    # Finding details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Location information
    location: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Risk scoring
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Scanner information
    scanner_module: Mapped[str] = mapped_column(String(100), nullable=False)
    
    # Status tracking
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    dismissed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Additional metadata
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="findings",
        lazy="joined",
    )
    vulnerability: Mapped[Optional["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="finding",
        cascade="all, delete-orphan",
        uselist=False,
    )
    
    @property
    def severity_score(self) -> int:
        """Get numeric severity score for sorting."""
        severity_map = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
        }
        return severity_map.get(self.severity, 0)
    
    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, title='{self.title}', severity={self.severity})>"