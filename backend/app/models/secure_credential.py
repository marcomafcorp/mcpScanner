from typing import Optional, Dict, Any
from sqlalchemy import String, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.core.encryption import EncryptedString, EncryptedJSON, hash_value


class SecureCredential(BaseModel):
    """Model for storing encrypted credentials and API keys."""
    
    __tablename__ = "secure_credentials"
    
    # Owner
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Credential metadata (not encrypted)
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Friendly name for the credential"
    )
    credential_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type: api_key, oauth_token, password, etc."
    )
    service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Service name (e.g., github, aws, etc.)"
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Description of what this credential is for"
    )
    
    # Encrypted fields
    credential_value: Mapped[str] = mapped_column(
        EncryptedString(500),
        nullable=False,
        comment="Encrypted credential value"
    )
    credential_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        EncryptedJSON,
        nullable=True,
        comment="Encrypted additional metadata (JSON)"
    )
    
    # Security fields
    credential_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        comment="SHA256 hash for duplicate detection"
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="When the credential expires"
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Last time credential was accessed"
    )
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="credentials")
    
    def __init__(self, **kwargs):
        """Initialize secure credential."""
        # Generate hash before saving
        if "credential_value" in kwargs and "credential_hash" not in kwargs:
            kwargs["credential_hash"] = hash_value(
                kwargs["credential_value"],
                salt=kwargs.get("user_id", "")
            )
        super().__init__(**kwargs)
    
    def verify_credential(self, value: str) -> bool:
        """
        Verify if a given value matches this credential.
        
        Args:
            value: Value to check
            
        Returns:
            True if matches
        """
        value_hash = hash_value(value, salt=self.user_id)
        return value_hash == self.credential_hash
    
    def is_expired(self) -> bool:
        """Check if credential is expired."""
        if not self.expires_at:
            return False
        
        from datetime import datetime
        return datetime.utcnow() > self.expires_at
    
    def mark_used(self) -> None:
        """Mark credential as used."""
        from datetime import datetime
        self.last_used_at = datetime.utcnow()
    
    def to_dict(self, include_value: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary.
        
        Args:
            include_value: Whether to include decrypted value
            
        Returns:
            Dictionary representation
        """
        data = {
            "id": str(self.id),
            "name": self.name,
            "credential_type": self.credential_type,
            "service": self.service,
            "description": self.description,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "is_expired": self.is_expired(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_value:
            # Only include actual value if explicitly requested
            data["credential_value"] = self.credential_value
            data["credential_metadata"] = self.credential_metadata
        else:
            # Mask the value
            from app.core.encryption import mask_sensitive_data
            data["credential_value_masked"] = mask_sensitive_data(self.credential_value)
        
        return data


# Import for datetime
from datetime import datetime