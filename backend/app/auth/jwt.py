from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.core.config import get_settings


settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token blacklist (in production, use Redis)
token_blacklist = set()


class Token(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Token payload data."""
    sub: str  # Subject (user ID)
    email: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    jti: Optional[str] = None  # JWT ID for blacklisting


class JWTManager:
    """JWT token management."""
    
    def __init__(self):
        self.algorithm = settings.JWT_ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
        self.secret_key = settings.SECRET_KEY
        self.refresh_secret_key = settings.REFRESH_SECRET_KEY or settings.SECRET_KEY
    
    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.
        
        Args:
            data: Token payload data
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT token
        """
        to_encode = data.copy()
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.access_token_expire_minutes
            )
        
        # Add standard claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        })
        
        # Generate JWT ID for potential blacklisting
        import uuid
        to_encode["jti"] = str(uuid.uuid4())
        
        # Encode token
        encoded_jwt = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm
        )
        
        return encoded_jwt
    
    def create_refresh_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token.
        
        Args:
            data: Token payload data
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT refresh token
        """
        to_encode = data.copy()
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=self.refresh_token_expire_days
            )
        
        # Add standard claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh"
        })
        
        # Generate JWT ID
        import uuid
        to_encode["jti"] = str(uuid.uuid4())
        
        # Encode token with refresh secret
        encoded_jwt = jwt.encode(
            to_encode,
            self.refresh_secret_key,
            algorithm=self.algorithm
        )
        
        return encoded_jwt
    
    def create_tokens(self, user_id: str, email: str, role: str) -> Token:
        """
        Create both access and refresh tokens.
        
        Args:
            user_id: User ID
            email: User email
            role: User role
            
        Returns:
            Token object with both tokens
        """
        # Token payload
        data = {
            "sub": user_id,
            "email": email,
            "role": role
        }
        
        # Create tokens
        access_token = self.create_access_token(data)
        refresh_token = self.create_refresh_token(data)
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token
        )
    
    def decode_token(self, token: str, is_refresh: bool = False) -> TokenData:
        """
        Decode and validate JWT token.
        
        Args:
            token: JWT token to decode
            is_refresh: Whether this is a refresh token
            
        Returns:
            TokenData object
            
        Raises:
            jwt.ExpiredSignatureError: Token has expired
            jwt.InvalidTokenError: Token is invalid
        """
        # Use appropriate secret
        secret_key = self.refresh_secret_key if is_refresh else self.secret_key
        
        # Decode token
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[self.algorithm]
        )
        
        # Check if token is blacklisted
        jti = payload.get("jti")
        if jti and jti in token_blacklist:
            raise jwt.InvalidTokenError("Token has been revoked")
        
        # Verify token type
        token_type = payload.get("type")
        expected_type = "refresh" if is_refresh else "access"
        if token_type != expected_type:
            raise jwt.InvalidTokenError(f"Invalid token type: expected {expected_type}")
        
        # Create TokenData object
        return TokenData(
            sub=payload.get("sub"),
            email=payload.get("email"),
            role=payload.get("role"),
            exp=payload.get("exp"),
            iat=payload.get("iat"),
            jti=payload.get("jti")
        )
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Create new access token from refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New access token
            
        Raises:
            jwt.InvalidTokenError: Invalid refresh token
        """
        # Decode refresh token
        token_data = self.decode_token(refresh_token, is_refresh=True)
        
        # Create new access token with same user data
        data = {
            "sub": token_data.sub,
            "email": token_data.email,
            "role": token_data.role
        }
        
        return self.create_access_token(data)
    
    def revoke_token(self, token: str, is_refresh: bool = False) -> None:
        """
        Revoke a token by adding to blacklist.
        
        Args:
            token: Token to revoke
            is_refresh: Whether this is a refresh token
        """
        try:
            token_data = self.decode_token(token, is_refresh=is_refresh)
            if token_data.jti:
                token_blacklist.add(token_data.jti)
        except jwt.InvalidTokenError:
            # Token is already invalid, no need to blacklist
            pass
    
    def verify_token(self, token: str) -> Optional[TokenData]:
        """
        Verify token validity without raising exceptions.
        
        Args:
            token: Token to verify
            
        Returns:
            TokenData if valid, None otherwise
        """
        try:
            return self.decode_token(token)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            True if password matches
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        Hash a password.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return pwd_context.hash(password)


# Global JWT manager instance
jwt_manager = JWTManager()