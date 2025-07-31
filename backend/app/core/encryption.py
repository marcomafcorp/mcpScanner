import base64
import os
from typing import Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.types import TypeDecorator, String
from pydantic import BaseModel, Field


class EncryptionConfig(BaseModel):
    """Encryption configuration."""
    master_key: str = Field(..., description="Master encryption key")
    salt: Optional[str] = Field(None, description="Salt for key derivation")
    iterations: int = Field(100000, description="PBKDF2 iterations")
    
    @classmethod
    def from_env(cls) -> "EncryptionConfig":
        """Create config from environment variables."""
        master_key = os.getenv("ENCRYPTION_MASTER_KEY")
        if not master_key:
            # Generate a new key if not provided (for development only)
            master_key = Fernet.generate_key().decode()
            print(f"WARNING: Generated encryption key: {master_key}")
            print("Set ENCRYPTION_MASTER_KEY environment variable in production!")
        
        return cls(
            master_key=master_key,
            salt=os.getenv("ENCRYPTION_SALT", "mcp-scanner-salt"),
            iterations=int(os.getenv("ENCRYPTION_ITERATIONS", "100000"))
        )


class FieldEncryption:
    """Field-level encryption for sensitive data."""
    
    def __init__(self, config: Optional[EncryptionConfig] = None):
        """
        Initialize field encryption.
        
        Args:
            config: Encryption configuration
        """
        self.config = config or EncryptionConfig.from_env()
        self._fernet = self._create_fernet()
    
    def _create_fernet(self) -> Fernet:
        """Create Fernet cipher from configuration."""
        # Derive key from master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.config.salt.encode() if self.config.salt else b'salt',
            iterations=self.config.iterations,
        )
        
        # Ensure master key is bytes
        master_key_bytes = self.config.master_key.encode() if isinstance(self.config.master_key, str) else self.config.master_key
        
        # Derive key
        key = base64.urlsafe_b64encode(kdf.derive(master_key_bytes))
        
        return Fernet(key)
    
    def encrypt(self, plaintext: Optional[Union[str, bytes]]) -> Optional[str]:
        """
        Encrypt plaintext.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Base64 encoded encrypted text or None
        """
        if plaintext is None:
            return None
        
        # Convert to bytes if string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Encrypt
        encrypted = self._fernet.encrypt(plaintext)
        
        # Return as base64 string
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: Optional[str]) -> Optional[str]:
        """
        Decrypt ciphertext.
        
        Args:
            ciphertext: Base64 encoded encrypted text
            
        Returns:
            Decrypted text or None
        """
        if ciphertext is None:
            return None
        
        try:
            # Decode from base64
            encrypted = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
            
            # Decrypt
            decrypted = self._fernet.decrypt(encrypted)
            
            # Return as string
            return decrypted.decode('utf-8')
        
        except Exception as e:
            # Log error but don't expose details
            print(f"Decryption error: {type(e).__name__}")
            return None
    
    def encrypt_dict(self, data: dict, fields: list[str]) -> dict:
        """
        Encrypt specific fields in a dictionary.
        
        Args:
            data: Dictionary with data
            fields: List of field names to encrypt
            
        Returns:
            Dictionary with encrypted fields
        """
        result = data.copy()
        
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.encrypt(str(result[field]))
        
        return result
    
    def decrypt_dict(self, data: dict, fields: list[str]) -> dict:
        """
        Decrypt specific fields in a dictionary.
        
        Args:
            data: Dictionary with encrypted data
            fields: List of field names to decrypt
            
        Returns:
            Dictionary with decrypted fields
        """
        result = data.copy()
        
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.decrypt(result[field])
        
        return result


# Global encryption instance
field_encryption = FieldEncryption()


class EncryptedString(TypeDecorator):
    """
    SQLAlchemy type for encrypted string fields.
    
    Usage:
        class MyModel(Base):
            encrypted_field = Column(EncryptedString(255))
    """
    
    impl = String
    cache_ok = True
    
    def __init__(self, length: Optional[int] = None, **kwargs):
        """
        Initialize encrypted string type.
        
        Args:
            length: Maximum length of encrypted data
        """
        # Encrypted data is longer than plaintext, so increase length
        if length:
            length = length * 2  # Base64 encoding increases size
        super().__init__(length=length, **kwargs)
        self._encryption = field_encryption
    
    def process_bind_param(self, value: Optional[str], dialect) -> Optional[str]:
        """
        Encrypt value before storing in database.
        
        Args:
            value: Plain text value
            dialect: SQL dialect
            
        Returns:
            Encrypted value
        """
        return self._encryption.encrypt(value)
    
    def process_result_value(self, value: Optional[str], dialect) -> Optional[str]:
        """
        Decrypt value when loading from database.
        
        Args:
            value: Encrypted value
            dialect: SQL dialect
            
        Returns:
            Decrypted value
        """
        return self._encryption.decrypt(value)


class EncryptedJSON(TypeDecorator):
    """
    SQLAlchemy type for encrypted JSON fields.
    
    Usage:
        class MyModel(Base):
            encrypted_data = Column(EncryptedJSON)
    """
    
    impl = String
    cache_ok = True
    
    def __init__(self, **kwargs):
        """Initialize encrypted JSON type."""
        super().__init__(**kwargs)
        self._encryption = field_encryption
    
    def process_bind_param(self, value: Optional[dict], dialect) -> Optional[str]:
        """
        Serialize and encrypt JSON before storing.
        
        Args:
            value: Dictionary to store
            dialect: SQL dialect
            
        Returns:
            Encrypted JSON string
        """
        if value is None:
            return None
        
        import json
        json_str = json.dumps(value)
        return self._encryption.encrypt(json_str)
    
    def process_result_value(self, value: Optional[str], dialect) -> Optional[dict]:
        """
        Decrypt and deserialize JSON when loading.
        
        Args:
            value: Encrypted JSON string
            dialect: SQL dialect
            
        Returns:
            Decrypted dictionary
        """
        if value is None:
            return None
        
        decrypted = self._encryption.decrypt(value)
        if decrypted is None:
            return None
        
        import json
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            return None


def hash_value(value: str, salt: Optional[str] = None) -> str:
    """
    Hash a value using SHA256.
    
    Args:
        value: Value to hash
        salt: Optional salt
        
    Returns:
        Hex digest of hash
    """
    import hashlib
    
    if salt:
        value = f"{salt}{value}"
    
    return hashlib.sha256(value.encode()).hexdigest()


def mask_sensitive_data(value: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data for display.
    
    Args:
        value: Value to mask
        visible_chars: Number of characters to show at start/end
        
    Returns:
        Masked value
    """
    if not value or len(value) <= visible_chars * 2:
        return "*" * 8
    
    start = value[:visible_chars]
    end = value[-visible_chars:]
    masked = "*" * (len(value) - visible_chars * 2)
    
    return f"{start}{masked}{end}"