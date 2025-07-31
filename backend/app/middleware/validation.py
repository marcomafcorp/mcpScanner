import json
import re
from typing import Optional, List, Dict, Any
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating and sanitizing incoming requests.
    
    Provides protection against:
    - Oversized payloads
    - Malicious input patterns
    - SQL injection attempts
    - XSS attempts
    - Path traversal
    """
    
    def __init__(
        self,
        app,
        max_content_length: int = 1024 * 1024,  # 1MB default
        blocked_patterns: Optional[List[str]] = None,
        allowed_content_types: Optional[List[str]] = None,
        sanitize_inputs: bool = True
    ):
        """
        Initialize validation middleware.
        
        Args:
            app: FastAPI application
            max_content_length: Maximum allowed request body size in bytes
            blocked_patterns: List of regex patterns to block
            allowed_content_types: List of allowed content types
            sanitize_inputs: Whether to sanitize input strings
        """
        super().__init__(app)
        self.max_content_length = max_content_length
        self.blocked_patterns = blocked_patterns or self._get_default_blocked_patterns()
        self.allowed_content_types = allowed_content_types or [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        ]
        self.sanitize_inputs = sanitize_inputs
        
        # Compile regex patterns
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.blocked_patterns
        ]
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request with validation.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response or validation error
        """
        # Check content length
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_content_length:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": f"Request body too large. Maximum size: {self.max_content_length} bytes"}
            )
        
        # Check content type for POST/PUT/PATCH requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            if content_type and content_type not in self.allowed_content_types:
                return JSONResponse(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    content={"detail": f"Unsupported content type: {content_type}"}
                )
        
        # Validate URL path
        if self._contains_malicious_pattern(request.url.path):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Invalid request path"}
            )
        
        # Validate query parameters
        for key, value in request.query_params.items():
            if self._contains_malicious_pattern(f"{key}={value}"):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid query parameters"}
                )
        
        # For JSON requests, validate and sanitize body
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                # Store original body for later use
                body = await request.body()
                if body:
                    # Parse and validate JSON
                    try:
                        json_body = json.loads(body)
                        
                        # Validate JSON content
                        if self._validate_json_content(json_body):
                            # Sanitize if enabled
                            if self.sanitize_inputs:
                                json_body = self._sanitize_json(json_body)
                            
                            # Create new request with sanitized body
                            async def receive():
                                return {
                                    "type": "http.request",
                                    "body": json.dumps(json_body).encode()
                                }
                            
                            request._receive = receive
                        else:
                            return JSONResponse(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                content={"detail": "Invalid request body content"}
                            )
                    except json.JSONDecodeError:
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={"detail": "Invalid JSON in request body"}
                        )
            except Exception as e:
                # Log error but continue
                pass
        
        # Process request
        response = await call_next(request)
        
        return response
    
    def _get_default_blocked_patterns(self) -> List[str]:
        """
        Get default list of blocked patterns.
        
        Returns:
            List of regex patterns
        """
        return [
            # SQL Injection patterns
            r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|where|table)\b)",
            r"(--|#|\/\*|\*\/|;)",  # SQL comments
            r"(\bor\b\s*\d+\s*=\s*\d+)",  # OR 1=1
            r"(\band\b\s*\d+\s*=\s*\d+)",  # AND 1=1
            
            # XSS patterns
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",  # Event handlers
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            
            # Path traversal
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[/\\]",
            r"%252e%252e[/\\]",
            
            # Command injection
            r"[;&|`]",  # Command separators
            r"\$\(",  # Command substitution
            r"\${",  # Variable expansion
            
            # LDAP injection
            r"[*()\\]",  # LDAP special characters
            
            # XML injection
            r"<!ENTITY",
            r"<!\[CDATA\[",
        ]
    
    def _contains_malicious_pattern(self, text: str) -> bool:
        """
        Check if text contains malicious patterns.
        
        Args:
            text: Text to check
            
        Returns:
            True if malicious pattern found
        """
        if not text:
            return False
        
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                return True
        
        return False
    
    def _validate_json_content(self, data: Any, depth: int = 0, max_depth: int = 10) -> bool:
        """
        Recursively validate JSON content.
        
        Args:
            data: JSON data to validate
            depth: Current recursion depth
            max_depth: Maximum allowed depth
            
        Returns:
            True if valid, False otherwise
        """
        # Check recursion depth
        if depth > max_depth:
            return False
        
        if isinstance(data, dict):
            for key, value in data.items():
                # Check key
                if isinstance(key, str) and self._contains_malicious_pattern(key):
                    return False
                
                # Recursively check value
                if not self._validate_json_content(value, depth + 1, max_depth):
                    return False
        
        elif isinstance(data, list):
            for item in data:
                if not self._validate_json_content(item, depth + 1, max_depth):
                    return False
        
        elif isinstance(data, str):
            # Check string values
            if self._contains_malicious_pattern(data):
                return False
        
        return True
    
    def _sanitize_json(self, data: Any) -> Any:
        """
        Recursively sanitize JSON data.
        
        Args:
            data: JSON data to sanitize
            
        Returns:
            Sanitized data
        """
        if isinstance(data, dict):
            return {
                self._sanitize_string(k) if isinstance(k, str) else k: self._sanitize_json(v)
                for k, v in data.items()
            }
        
        elif isinstance(data, list):
            return [self._sanitize_json(item) for item in data]
        
        elif isinstance(data, str):
            return self._sanitize_string(data)
        
        return data
    
    def _sanitize_string(self, text: str) -> str:
        """
        Sanitize string by escaping dangerous characters.
        
        Args:
            text: String to sanitize
            
        Returns:
            Sanitized string
        """
        # HTML encode dangerous characters
        replacements = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "&": "&amp;",
            "/": "&#x2F;",
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        # Remove null bytes
        text = text.replace("\x00", "")
        
        # Limit string length
        max_length = 10000
        if len(text) > max_length:
            text = text[:max_length]
        
        return text


class SQLInjectionProtection:
    """
    Dependency for SQL injection protection on specific endpoints.
    
    Usage:
        @router.get("/search", dependencies=[Depends(SQLInjectionProtection())])
    """
    
    def __init__(self, param_names: Optional[List[str]] = None):
        """
        Initialize SQL injection protection.
        
        Args:
            param_names: Specific parameter names to check (None = check all)
        """
        self.param_names = param_names
        self.sql_patterns = [
            re.compile(r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)", re.I),
            re.compile(r"(--|#|\/\*|\*\/)", re.I),
            re.compile(r"(\bor\b\s*\d+\s*=\s*\d+)", re.I),
            re.compile(r"(\band\b\s*\d+\s*=\s*\d+)", re.I),
            re.compile(r"[';]", re.I),
        ]
    
    async def __call__(self, request: Request) -> None:
        """
        Check for SQL injection attempts.
        
        Args:
            request: Incoming request
            
        Raises:
            HTTPException: If SQL injection detected
        """
        # Check query parameters
        params_to_check = self.param_names or list(request.query_params.keys())
        
        for param in params_to_check:
            value = request.query_params.get(param, "")
            if self._contains_sql_injection(value):
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid characters in parameter: {param}"
                )
    
    def _contains_sql_injection(self, text: str) -> bool:
        """Check if text contains SQL injection patterns."""
        for pattern in self.sql_patterns:
            if pattern.search(text):
                return True
        return False