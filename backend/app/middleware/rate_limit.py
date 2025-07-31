import time
from typing import Dict, Tuple, Optional, Callable
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using sliding window algorithm.
    
    Tracks requests per IP/user and enforces limits.
    """
    
    def __init__(
        self,
        app,
        calls: int = 100,
        period: int = 60,
        calls_per_user: Optional[int] = None,
        calls_per_ip: Optional[int] = None,
        exclude_paths: Optional[list] = None,
        custom_limits: Optional[Dict[str, Tuple[int, int]]] = None
    ):
        """
        Initialize rate limiter.
        
        Args:
            app: FastAPI application
            calls: Default number of calls allowed
            period: Time period in seconds
            calls_per_user: Calls allowed per authenticated user
            calls_per_ip: Calls allowed per IP address
            exclude_paths: Paths to exclude from rate limiting
            custom_limits: Custom limits for specific paths {path: (calls, period)}
        """
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.calls_per_user = calls_per_user or calls
        self.calls_per_ip = calls_per_ip or calls
        self.exclude_paths = exclude_paths or []
        self.custom_limits = custom_limits or {}
        
        # Storage for request timestamps
        self.requests: Dict[str, list] = defaultdict(list)
        
        # Cleanup old entries periodically
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with rate limiting.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response or rate limit error
        """
        # Check if path is excluded
        path = request.url.path
        if any(path.startswith(exclude) for exclude in self.exclude_paths):
            return await call_next(request)
        
        # Get identifier (user ID or IP)
        identifier = await self._get_identifier(request)
        
        # Get rate limit for this path
        limit, period = self._get_limit_for_path(path, identifier)
        
        # Check rate limit
        current_time = time.time()
        if not self._is_allowed(identifier, current_time, limit, period):
            return self._rate_limit_exceeded_response(identifier, limit, period)
        
        # Record request
        self._record_request(identifier, current_time)
        
        # Cleanup old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        self._add_rate_limit_headers(response, identifier, limit, period, current_time)
        
        return response
    
    async def _get_identifier(self, request: Request) -> str:
        """
        Get identifier for rate limiting (user ID or IP).
        
        Args:
            request: Incoming request
            
        Returns:
            Identifier string
        """
        # Try to get user ID from JWT token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from app.auth.jwt import jwt_manager
                token = auth_header.split(" ")[1]
                token_data = jwt_manager.verify_token(token)
                if token_data and token_data.sub:
                    return f"user:{token_data.sub}"
            except Exception:
                pass
        
        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        
        # Check for X-Forwarded-For header (proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        return f"ip:{client_ip}"
    
    def _get_limit_for_path(self, path: str, identifier: str) -> Tuple[int, int]:
        """
        Get rate limit for specific path.
        
        Args:
            path: Request path
            identifier: User/IP identifier
            
        Returns:
            Tuple of (calls, period)
        """
        # Check custom limits
        for custom_path, (calls, period) in self.custom_limits.items():
            if path.startswith(custom_path):
                return calls, period
        
        # Use user or IP limits
        if identifier.startswith("user:"):
            return self.calls_per_user, self.period
        else:
            return self.calls_per_ip, self.period
    
    def _is_allowed(self, identifier: str, current_time: float, limit: int, period: int) -> bool:
        """
        Check if request is allowed under rate limit.
        
        Args:
            identifier: User/IP identifier
            current_time: Current timestamp
            limit: Number of allowed calls
            period: Time period in seconds
            
        Returns:
            True if allowed, False otherwise
        """
        # Get request timestamps for identifier
        timestamps = self.requests[identifier]
        
        # Remove old timestamps outside the window
        cutoff_time = current_time - period
        self.requests[identifier] = [ts for ts in timestamps if ts > cutoff_time]
        
        # Check if under limit
        return len(self.requests[identifier]) < limit
    
    def _record_request(self, identifier: str, timestamp: float) -> None:
        """
        Record a request timestamp.
        
        Args:
            identifier: User/IP identifier
            timestamp: Request timestamp
        """
        self.requests[identifier].append(timestamp)
    
    def _cleanup_old_entries(self, current_time: float) -> None:
        """
        Clean up old request entries.
        
        Args:
            current_time: Current timestamp
        """
        # Remove entries older than the longest period
        max_period = max(self.period, max((p for _, p in self.custom_limits.values()), default=self.period))
        cutoff_time = current_time - max_period * 2
        
        # Clean up old identifiers
        identifiers_to_remove = []
        for identifier, timestamps in self.requests.items():
            # Remove old timestamps
            self.requests[identifier] = [ts for ts in timestamps if ts > cutoff_time]
            
            # Mark empty entries for removal
            if not self.requests[identifier]:
                identifiers_to_remove.append(identifier)
        
        # Remove empty entries
        for identifier in identifiers_to_remove:
            del self.requests[identifier]
    
    def _add_rate_limit_headers(
        self,
        response: Response,
        identifier: str,
        limit: int,
        period: int,
        current_time: float
    ) -> None:
        """
        Add rate limit headers to response.
        
        Args:
            response: Response object
            identifier: User/IP identifier
            limit: Rate limit
            period: Time period
            current_time: Current timestamp
        """
        # Calculate remaining calls
        cutoff_time = current_time - period
        recent_requests = [ts for ts in self.requests[identifier] if ts > cutoff_time]
        remaining = max(0, limit - len(recent_requests))
        
        # Calculate reset time
        if recent_requests:
            oldest_request = min(recent_requests)
            reset_time = int(oldest_request + period)
        else:
            reset_time = int(current_time + period)
        
        # Add headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        response.headers["X-RateLimit-Period"] = str(period)
    
    def _rate_limit_exceeded_response(self, identifier: str, limit: int, period: int) -> JSONResponse:
        """
        Create rate limit exceeded response.
        
        Args:
            identifier: User/IP identifier
            limit: Rate limit
            period: Time period
            
        Returns:
            JSON response with 429 status
        """
        # Calculate retry after
        current_time = time.time()
        cutoff_time = current_time - period
        recent_requests = [ts for ts in self.requests[identifier] if ts > cutoff_time]
        
        if recent_requests:
            oldest_request = min(recent_requests)
            retry_after = int(oldest_request + period - current_time)
        else:
            retry_after = period
        
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded",
                "limit": limit,
                "period": period,
                "retry_after": retry_after
            },
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(current_time + retry_after))
            }
        )


class IPRateLimiter:
    """
    Simple IP-based rate limiter for specific endpoints.
    
    Usage as dependency:
        @router.get("/", dependencies=[Depends(IPRateLimiter(calls=10, period=60))])
    """
    
    def __init__(self, calls: int = 100, period: int = 60):
        """
        Initialize IP rate limiter.
        
        Args:
            calls: Number of calls allowed
            period: Time period in seconds
        """
        self.calls = calls
        self.period = period
        self.requests: Dict[str, list] = defaultdict(list)
    
    async def __call__(self, request: Request) -> None:
        """
        Check rate limit for request.
        
        Args:
            request: Incoming request
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        # Check rate limit
        current_time = time.time()
        cutoff_time = current_time - self.period
        
        # Clean old requests
        self.requests[client_ip] = [
            ts for ts in self.requests[client_ip] if ts > cutoff_time
        ]
        
        # Check limit
        if len(self.requests[client_ip]) >= self.calls:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {self.calls} requests per {self.period} seconds.",
                headers={"Retry-After": str(self.period)}
            )
        
        # Record request
        self.requests[client_ip].append(current_time)