from typing import Optional, Dict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware for adding security headers to responses.
    
    Implements OWASP recommended security headers.
    """
    
    def __init__(
        self,
        app,
        content_security_policy: Optional[str] = None,
        strict_transport_security: Optional[str] = None,
        x_content_type_options: str = "nosniff",
        x_frame_options: str = "DENY",
        x_xss_protection: str = "1; mode=block",
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize security headers middleware.
        
        Args:
            app: FastAPI application
            content_security_policy: CSP header value
            strict_transport_security: HSTS header value
            x_content_type_options: X-Content-Type-Options value
            x_frame_options: X-Frame-Options value
            x_xss_protection: X-XSS-Protection value
            referrer_policy: Referrer-Policy value
            permissions_policy: Permissions-Policy value
            custom_headers: Additional custom headers
        """
        super().__init__(app)
        
        # Default CSP if not provided
        self.content_security_policy = content_security_policy or (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        
        # Default HSTS - 1 year
        self.strict_transport_security = strict_transport_security or (
            "max-age=31536000; includeSubDomains"
        )
        
        # Default Permissions Policy
        self.permissions_policy = permissions_policy or (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )
        
        self.x_content_type_options = x_content_type_options
        self.x_frame_options = x_frame_options
        self.x_xss_protection = x_xss_protection
        self.referrer_policy = referrer_policy
        self.custom_headers = custom_headers or {}
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Add security headers to response.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response with security headers
        """
        # Process request
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = self.x_content_type_options
        response.headers["X-Frame-Options"] = self.x_frame_options
        response.headers["X-XSS-Protection"] = self.x_xss_protection
        response.headers["Referrer-Policy"] = self.referrer_policy
        
        # Add CSP header
        if self.content_security_policy:
            response.headers["Content-Security-Policy"] = self.content_security_policy
        
        # Add HSTS header (only for HTTPS)
        if request.url.scheme == "https" and self.strict_transport_security:
            response.headers["Strict-Transport-Security"] = self.strict_transport_security
        
        # Add Permissions Policy
        if self.permissions_policy:
            response.headers["Permissions-Policy"] = self.permissions_policy
        
        # Remove potentially dangerous headers
        headers_to_remove = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in headers_to_remove:
            response.headers.pop(header, None)
        
        # Add custom headers
        for header, value in self.custom_headers.items():
            response.headers[header] = value
        
        return response


def get_security_headers(
    is_production: bool = True,
    enable_hsts: bool = True,
    csp_report_uri: Optional[str] = None
) -> Dict[str, str]:
    """
    Get recommended security headers.
    
    Args:
        is_production: Whether in production environment
        enable_hsts: Whether to enable HSTS
        csp_report_uri: URI for CSP violation reports
        
    Returns:
        Dictionary of security headers
    """
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        ),
    }
    
    # Content Security Policy
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'" if not is_production else "script-src 'self'",
        "style-src 'self' 'unsafe-inline'" if not is_production else "style-src 'self'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "upgrade-insecure-requests",
    ]
    
    if csp_report_uri:
        csp_directives.append(f"report-uri {csp_report_uri}")
    
    headers["Content-Security-Policy"] = "; ".join(csp_directives)
    
    # HSTS
    if enable_hsts:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    return headers


class CSPViolationReport:
    """
    Model for CSP violation reports.
    """
    
    def __init__(self, report_data: Dict[str, Any]):
        """
        Initialize CSP violation report.
        
        Args:
            report_data: CSP report data
        """
        self.document_uri = report_data.get("document-uri", "")
        self.referrer = report_data.get("referrer", "")
        self.violated_directive = report_data.get("violated-directive", "")
        self.effective_directive = report_data.get("effective-directive", "")
        self.original_policy = report_data.get("original-policy", "")
        self.blocked_uri = report_data.get("blocked-uri", "")
        self.line_number = report_data.get("line-number", 0)
        self.column_number = report_data.get("column-number", 0)
        self.source_file = report_data.get("source-file", "")
        self.status_code = report_data.get("status-code", 0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_uri": self.document_uri,
            "referrer": self.referrer,
            "violated_directive": self.violated_directive,
            "effective_directive": self.effective_directive,
            "original_policy": self.original_policy,
            "blocked_uri": self.blocked_uri,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "source_file": self.source_file,
            "status_code": self.status_code,
        }