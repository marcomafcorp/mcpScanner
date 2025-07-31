import secrets
import time
from typing import Optional, Set, Tuple
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF (Cross-Site Request Forgery) protection middleware.
    
    Uses double-submit cookie pattern with additional security measures.
    """
    
    def __init__(
        self,
        app,
        secret_key: str,
        cookie_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
        exclude_methods: Optional[Set[str]] = None,
        exclude_paths: Optional[Set[str]] = None,
        token_length: int = 32,
        max_age: int = 3600,  # 1 hour
        secure: bool = True,
        samesite: str = "strict"
    ):
        """
        Initialize CSRF protection middleware.
        
        Args:
            app: FastAPI application
            secret_key: Secret key for token generation
            cookie_name: Name of CSRF cookie
            header_name: Name of CSRF header
            exclude_methods: Methods to exclude from CSRF check
            exclude_paths: Paths to exclude from CSRF check
            token_length: Length of CSRF token
            max_age: Token expiration time in seconds
            secure: Whether to use secure cookies (HTTPS only)
            samesite: SameSite cookie attribute
        """
        super().__init__(app)
        self.secret_key = secret_key
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.exclude_methods = exclude_methods or {"GET", "HEAD", "OPTIONS", "TRACE"}
        self.exclude_paths = exclude_paths or set()
        self.token_length = token_length
        self.max_age = max_age
        self.secure = secure
        self.samesite = samesite
        
        # Token storage (in production, use Redis)
        self.tokens: dict[str, float] = {}
        
        # Cleanup interval
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request with CSRF protection.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response
            
        Raises:
            HTTPException: If CSRF validation fails
        """
        # Check if method requires CSRF protection
        if request.method in self.exclude_methods:
            return await call_next(request)
        
        # Check if path is excluded
        path = request.url.path
        if any(path.startswith(exclude) for exclude in self.exclude_paths):
            return await call_next(request)
        
        # Cleanup old tokens periodically
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_tokens(current_time)
            self.last_cleanup = current_time
        
        # Get CSRF token from cookie
        cookie_token = request.cookies.get(self.cookie_name)
        
        # Get CSRF token from header or form
        header_token = request.headers.get(self.header_name)
        
        # For form submissions, check form data
        if not header_token and request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            form = await request.form()
            header_token = form.get("csrf_token")
        
        # Validate CSRF tokens
        if not self._validate_csrf_token(cookie_token, header_token, current_time):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF validation failed"
            )
        
        # Process request
        response = await call_next(request)
        
        # Generate new token if needed
        if not cookie_token or not self._is_token_valid(cookie_token, current_time):
            new_token = self._generate_token()
            self.tokens[new_token] = current_time
            
            # Set cookie
            response.set_cookie(
                key=self.cookie_name,
                value=new_token,
                max_age=self.max_age,
                secure=self.secure,
                httponly=True,
                samesite=self.samesite
            )
            
            # Add token to response header for client access
            response.headers[self.header_name] = new_token
        
        return response
    
    def _generate_token(self) -> str:
        """
        Generate a new CSRF token.
        
        Returns:
            CSRF token
        """
        return secrets.token_urlsafe(self.token_length)
    
    def _validate_csrf_token(
        self,
        cookie_token: Optional[str],
        header_token: Optional[str],
        current_time: float
    ) -> bool:
        """
        Validate CSRF tokens.
        
        Args:
            cookie_token: Token from cookie
            header_token: Token from header/form
            current_time: Current timestamp
            
        Returns:
            True if valid
        """
        # Both tokens must be present
        if not cookie_token or not header_token:
            return False
        
        # Tokens must match
        if cookie_token != header_token:
            return False
        
        # Token must be valid (not expired)
        if not self._is_token_valid(cookie_token, current_time):
            return False
        
        return True
    
    def _is_token_valid(self, token: str, current_time: float) -> bool:
        """
        Check if token is valid and not expired.
        
        Args:
            token: CSRF token
            current_time: Current timestamp
            
        Returns:
            True if valid
        """
        if token not in self.tokens:
            return False
        
        token_time = self.tokens[token]
        if current_time - token_time > self.max_age:
            return False
        
        return True
    
    def _cleanup_tokens(self, current_time: float) -> None:
        """
        Clean up expired tokens.
        
        Args:
            current_time: Current timestamp
        """
        expired_tokens = [
            token for token, token_time in self.tokens.items()
            if current_time - token_time > self.max_age
        ]
        
        for token in expired_tokens:
            del self.tokens[token]


class CSRFTokenGenerator:
    """
    CSRF token generator for use in templates and forms.
    """
    
    def __init__(self, secret_key: str, token_length: int = 32):
        """
        Initialize token generator.
        
        Args:
            secret_key: Secret key for token generation
            token_length: Length of tokens
        """
        self.secret_key = secret_key
        self.token_length = token_length
    
    def generate_token(self) -> str:
        """
        Generate a new CSRF token.
        
        Returns:
            CSRF token
        """
        return secrets.token_urlsafe(self.token_length)
    
    def generate_token_field(self, token: str) -> str:
        """
        Generate hidden form field for CSRF token.
        
        Args:
            token: CSRF token
            
        Returns:
            HTML hidden input field
        """
        return f'<input type="hidden" name="csrf_token" value="{token}">'


async def get_csrf_token(request: Request) -> str:
    """
    Get CSRF token from request.
    
    Args:
        request: FastAPI request
        
    Returns:
        CSRF token
        
    Raises:
        HTTPException: If token not found
    """
    token = request.cookies.get("csrf_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token not found"
        )
    return token