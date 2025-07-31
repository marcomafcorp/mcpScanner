import json
import re
from typing import Optional, List, Dict, Any, Set
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import MutableHeaders


class ResponseSecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for securing API responses.
    
    Features:
    - Sensitive data filtering
    - Response sanitization
    - Error message sanitization
    - Stack trace removal in production
    """
    
    def __init__(
        self,
        app,
        debug: bool = False,
        sensitive_fields: Optional[Set[str]] = None,
        mask_char: str = "*",
        min_mask_length: int = 8
    ):
        """
        Initialize response security middleware.
        
        Args:
            app: FastAPI application
            debug: Whether in debug mode (show stack traces)
            sensitive_fields: Set of field names to mask
            mask_char: Character to use for masking
            min_mask_length: Minimum length of masked values
        """
        super().__init__(app)
        self.debug = debug
        self.mask_char = mask_char
        self.min_mask_length = min_mask_length
        
        # Default sensitive field names
        self.sensitive_fields = sensitive_fields or {
            "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
            "auth", "authorization", "cookie", "session", "credit_card", "card_number",
            "cvv", "ssn", "social_security", "tax_id", "driver_license",
            "passport", "bank_account", "routing_number", "private_key",
            "refresh_token", "access_token", "jwt", "bearer", "oauth",
            "database_url", "db_password", "db_pass", "connection_string"
        }
        
        # Patterns for sensitive data
        self.sensitive_patterns = [
            # Credit card numbers
            re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            # SSN
            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            # Email (partial masking)
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            # JWT tokens
            re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            # API keys (generic pattern)
            re.compile(r'\b[A-Za-z0-9]{32,}\b'),
            # Bearer tokens
            re.compile(r'Bearer\s+[A-Za-z0-9\-._~\+\/]+=*'),
        ]
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process response with security filtering.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Secured response
        """
        # Get response
        response = await call_next(request)
        
        # Process JSON responses
        if response.headers.get("content-type", "").startswith("application/json"):
            # Read response body
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            try:
                # Parse JSON
                data = json.loads(body.decode())
                
                # Sanitize response data
                sanitized_data = self._sanitize_response_data(data)
                
                # Handle error responses
                if response.status_code >= 400:
                    sanitized_data = self._sanitize_error_response(sanitized_data, response.status_code)
                
                # Create new response with sanitized data
                return Response(
                    content=json.dumps(sanitized_data),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type="application/json"
                )
            
            except json.JSONDecodeError:
                # If not valid JSON, return as-is
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers)
                )
        
        return response
    
    def _sanitize_response_data(self, data: Any, depth: int = 0, max_depth: int = 10) -> Any:
        """
        Recursively sanitize response data.
        
        Args:
            data: Data to sanitize
            depth: Current recursion depth
            max_depth: Maximum recursion depth
            
        Returns:
            Sanitized data
        """
        if depth > max_depth:
            return "[MAX_DEPTH_EXCEEDED]"
        
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Check if field is sensitive
                if self._is_sensitive_field(key):
                    sanitized[key] = self._mask_value(value)
                else:
                    sanitized[key] = self._sanitize_response_data(value, depth + 1, max_depth)
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_response_data(item, depth + 1, max_depth) for item in data]
        
        elif isinstance(data, str):
            # Check for sensitive patterns
            return self._mask_sensitive_patterns(data)
        
        return data
    
    def _sanitize_error_response(self, data: Dict[str, Any], status_code: int) -> Dict[str, Any]:
        """
        Sanitize error response.
        
        Args:
            data: Error response data
            status_code: HTTP status code
            
        Returns:
            Sanitized error response
        """
        # Remove stack traces in production
        if not self.debug:
            # Remove common stack trace fields
            stack_fields = ["traceback", "stack_trace", "stack", "exception", "exc_info"]
            for field in stack_fields:
                if field in data:
                    del data[field]
            
            # Sanitize detail message
            if "detail" in data and isinstance(data["detail"], str):
                # Remove file paths
                data["detail"] = re.sub(r'File "[^"]+", line \d+', 'File "[HIDDEN]"', data["detail"])
                # Remove system paths
                data["detail"] = re.sub(r'(/[^\s]+)+', '[PATH]', data["detail"])
        
        # Add generic messages for certain status codes
        if status_code == 500 and not self.debug:
            data = {
                "detail": "Internal server error occurred. Please try again later.",
                "status_code": 500
            }
        
        return data
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """
        Check if field name is sensitive.
        
        Args:
            field_name: Field name to check
            
        Returns:
            True if sensitive
        """
        field_lower = field_name.lower()
        
        # Direct match
        if field_lower in self.sensitive_fields:
            return True
        
        # Partial match
        for sensitive in self.sensitive_fields:
            if sensitive in field_lower or field_lower in sensitive:
                return True
        
        return False
    
    def _mask_value(self, value: Any) -> Any:
        """
        Mask sensitive value.
        
        Args:
            value: Value to mask
            
        Returns:
            Masked value
        """
        if value is None:
            return None
        
        if isinstance(value, str):
            if len(value) <= 4:
                return self.mask_char * self.min_mask_length
            else:
                # Show first and last 2 characters
                visible_start = value[:2]
                visible_end = value[-2:]
                mask_length = max(len(value) - 4, self.min_mask_length)
                return f"{visible_start}{self.mask_char * mask_length}{visible_end}"
        
        elif isinstance(value, (int, float)):
            # Mask numbers
            str_value = str(value)
            if len(str_value) > 4:
                return f"{str_value[0]}{self.mask_char * (len(str_value) - 2)}{str_value[-1]}"
            else:
                return self.mask_char * self.min_mask_length
        
        elif isinstance(value, list):
            return [self._mask_value(item) for item in value]
        
        elif isinstance(value, dict):
            return {k: self._mask_value(v) for k, v in value.items()}
        
        return self.mask_char * self.min_mask_length
    
    def _mask_sensitive_patterns(self, text: str) -> str:
        """
        Mask sensitive patterns in text.
        
        Args:
            text: Text to check
            
        Returns:
            Text with masked patterns
        """
        for pattern in self.sensitive_patterns:
            def replacer(match):
                matched = match.group(0)
                if "@" in matched:  # Email
                    parts = matched.split("@")
                    username = parts[0]
                    if len(username) > 2:
                        masked_username = username[0] + self.mask_char * (len(username) - 2) + username[-1]
                    else:
                        masked_username = self.mask_char * 3
                    return f"{masked_username}@{parts[1]}"
                elif len(matched) > 8:
                    # Show first and last 4 characters
                    return matched[:4] + self.mask_char * (len(matched) - 8) + matched[-4:]
                else:
                    return self.mask_char * len(matched)
            
            text = pattern.sub(replacer, text)
        
        return text


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """
    Middleware for consistent error handling.
    """
    
    def __init__(self, app, debug: bool = False):
        """
        Initialize error handler middleware.
        
        Args:
            app: FastAPI application
            debug: Whether in debug mode
        """
        super().__init__(app)
        self.debug = debug
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Handle errors consistently.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response or error response
        """
        try:
            response = await call_next(request)
            return response
        
        except Exception as e:
            # Log the error
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
            
            # Create error response
            if self.debug:
                import traceback
                return Response(
                    content=json.dumps({
                        "detail": str(e),
                        "type": type(e).__name__,
                        "traceback": traceback.format_exc()
                    }),
                    status_code=500,
                    media_type="application/json"
                )
            else:
                return Response(
                    content=json.dumps({
                        "detail": "An internal error occurred. Please try again later."
                    }),
                    status_code=500,
                    media_type="application/json"
                )