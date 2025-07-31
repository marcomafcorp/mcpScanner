import time
import asyncio
from typing import Optional, Set, Dict, Any
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import SessionLocal
from app.models.audit_log import AuditLog, AuditAction
from app.auth.jwt import jwt_manager


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for automatic audit logging of API calls.
    
    Logs user actions, authentication events, and security violations.
    """
    
    def __init__(
        self,
        app,
        excluded_paths: Optional[Set[str]] = None,
        excluded_methods: Optional[Set[str]] = None,
        log_request_body: bool = False,
        log_response_body: bool = False,
        sensitive_paths: Optional[Set[str]] = None
    ):
        """
        Initialize audit logging middleware.
        
        Args:
            app: FastAPI application
            excluded_paths: Paths to exclude from logging
            excluded_methods: HTTP methods to exclude
            log_request_body: Whether to log request bodies
            log_response_body: Whether to log response bodies  
            sensitive_paths: Paths with sensitive data (mask bodies)
        """
        super().__init__(app)
        self.excluded_paths = excluded_paths or {
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/v1/health",
            "/favicon.ico",
            "/static",
        }
        self.excluded_methods = excluded_methods or {"OPTIONS", "HEAD"}
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.sensitive_paths = sensitive_paths or {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/change-password",
        }
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request with audit logging.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response
        """
        # Check if should log this request
        if not self._should_log(request):
            return await call_next(request)
        
        # Start timing
        start_time = time.time()
        
        # Extract actor information
        actor_info = await self._extract_actor_info(request)
        
        # Extract request details
        request_info = await self._extract_request_info(request)
        
        # Initialize audit log data
        audit_data = {
            **actor_info,
            **request_info,
            "action": self._determine_action(request),
        }
        
        # Process request
        response = None
        error_message = None
        
        try:
            response = await call_next(request)
            
            # Extract response details
            response_info = self._extract_response_info(response, start_time)
            audit_data.update(response_info)
            
            # Extract resource information from response
            resource_info = await self._extract_resource_info(request, response)
            audit_data.update(resource_info)
            
        except Exception as e:
            # Log error
            error_message = str(e)
            audit_data.update({
                "response_status": 500,
                "response_time_ms": int((time.time() - start_time) * 1000),
                "error_message": error_message,
            })
            raise
        
        finally:
            # Create audit log entry asynchronously
            asyncio.create_task(self._create_audit_log(audit_data))
        
        return response
    
    def _should_log(self, request: Request) -> bool:
        """
        Check if request should be logged.
        
        Args:
            request: Incoming request
            
        Returns:
            True if should log
        """
        # Check method
        if request.method in self.excluded_methods:
            return False
        
        # Check path
        path = request.url.path
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                return False
        
        return True
    
    async def _extract_actor_info(self, request: Request) -> Dict[str, Any]:
        """
        Extract actor information from request.
        
        Args:
            request: Incoming request
            
        Returns:
            Actor information
        """
        actor_info = {
            "actor_id": None,
            "actor_email": None,
            "actor_role": None,
        }
        
        # Try to get user from JWT token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                token = auth_header.split(" ")[1]
                token_data = jwt_manager.verify_token(token)
                if token_data:
                    actor_info.update({
                        "actor_id": token_data.sub,
                        "actor_email": token_data.email,
                        "actor_role": token_data.role,
                    })
            except Exception:
                pass
        
        return actor_info
    
    async def _extract_request_info(self, request: Request) -> Dict[str, Any]:
        """
        Extract request information.
        
        Args:
            request: Incoming request
            
        Returns:
            Request information
        """
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        request_info = {
            "ip_address": client_ip,
            "user_agent": request.headers.get("User-Agent", ""),
            "request_method": request.method,
            "request_path": request.url.path,
        }
        
        # Add request body if enabled and not sensitive
        if self.log_request_body and request.url.path not in self.sensitive_paths:
            try:
                if request.method in ["POST", "PUT", "PATCH"]:
                    # Note: This requires reading the body, which may affect performance
                    # In production, consider using a different approach
                    pass
            except Exception:
                pass
        
        return request_info
    
    def _extract_response_info(self, response: Response, start_time: float) -> Dict[str, Any]:
        """
        Extract response information.
        
        Args:
            response: Response object
            start_time: Request start time
            
        Returns:
            Response information
        """
        return {
            "response_status": response.status_code,
            "response_time_ms": int((time.time() - start_time) * 1000),
        }
    
    async def _extract_resource_info(self, request: Request, response: Response) -> Dict[str, Any]:
        """
        Extract resource information from request/response.
        
        Args:
            request: Request object
            response: Response object
            
        Returns:
            Resource information
        """
        resource_info = {
            "resource_type": None,
            "resource_id": None,
        }
        
        # Extract from path parameters
        path = request.url.path
        path_params = request.path_params
        
        # Determine resource type and ID based on path patterns
        if "/users/" in path and "user_id" in path_params:
            resource_info["resource_type"] = "user"
            resource_info["resource_id"] = path_params["user_id"]
        elif "/scans/" in path and "scan_id" in path_params:
            resource_info["resource_type"] = "scan"
            resource_info["resource_id"] = path_params["scan_id"]
        elif "/findings/" in path and "finding_id" in path_params:
            resource_info["resource_type"] = "finding"
            resource_info["resource_id"] = path_params["finding_id"]
        
        # Try to extract from response body for creation endpoints
        if response.status_code == 201 and request.method == "POST":
            try:
                # This would require parsing response body
                # Implement if needed
                pass
            except Exception:
                pass
        
        return resource_info
    
    def _determine_action(self, request: Request) -> str:
        """
        Determine audit action based on request.
        
        Args:
            request: Request object
            
        Returns:
            Audit action string
        """
        path = request.url.path
        method = request.method
        
        # Authentication actions
        if path == "/api/v1/auth/login":
            return AuditAction.USER_LOGIN
        elif path == "/api/v1/auth/logout":
            return AuditAction.USER_LOGOUT
        elif path == "/api/v1/auth/register":
            return AuditAction.USER_REGISTER
        elif path == "/api/v1/auth/refresh":
            return AuditAction.TOKEN_REFRESH
        elif path == "/api/v1/auth/change-password":
            return AuditAction.PASSWORD_CHANGE
        
        # User management actions
        elif path.startswith("/api/v1/users"):
            if method == "POST":
                return AuditAction.USER_CREATE
            elif method == "PATCH":
                return AuditAction.USER_UPDATE
            elif method == "DELETE":
                return AuditAction.USER_DELETE
            elif "/activate" in path:
                return AuditAction.USER_ACTIVATE
            elif "/deactivate" in path:
                return AuditAction.USER_DEACTIVATE
            elif "/change-role" in path:
                return AuditAction.USER_ROLE_CHANGE
        
        # Scan actions
        elif path.startswith("/api/v1/scans"):
            if method == "POST":
                return AuditAction.SCAN_CREATE
            elif method == "GET":
                return AuditAction.SCAN_VIEW
            elif method == "DELETE":
                return AuditAction.SCAN_DELETE
        
        # Default action based on method
        resource = path.split("/")[-2] if len(path.split("/")) > 2 else "unknown"
        return f"{resource}.{method.lower()}"
    
    async def _create_audit_log(self, audit_data: Dict[str, Any]) -> None:
        """
        Create audit log entry in database.
        
        Args:
            audit_data: Audit log data
        """
        try:
            async with SessionLocal() as db:
                audit_log = AuditLog(**audit_data)
                db.add(audit_log)
                await db.commit()
        except Exception as e:
            # Log error but don't fail the request
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to create audit log: {e}")


async def log_security_event(
    action: str,
    request: Request,
    details: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None
) -> None:
    """
    Log a security event.
    
    Args:
        action: Security action (from AuditAction)
        request: Request object
        details: Additional details
        error_message: Error message if applicable
    """
    try:
        # Extract actor info
        actor_info = {}
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                token = auth_header.split(" ")[1]
                token_data = jwt_manager.verify_token(token)
                if token_data:
                    actor_info = {
                        "actor_id": token_data.sub,
                        "actor_email": token_data.email,
                        "actor_role": token_data.role,
                    }
            except Exception:
                pass
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        # Create audit log
        async with SessionLocal() as db:
            audit_log = AuditLog(
                **actor_info,
                action=action,
                ip_address=client_ip,
                user_agent=request.headers.get("User-Agent", ""),
                request_method=request.method,
                request_path=request.url.path,
                details=details,
                error_message=error_message,
            )
            db.add(audit_log)
            await db.commit()
    
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to log security event: {e}")