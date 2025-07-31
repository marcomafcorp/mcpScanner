from typing import Optional, Dict, Any
from enum import Enum


class ScannerErrorType(str, Enum):
    """Scanner error types."""
    CONFIGURATION = "configuration_error"
    CONNECTION = "connection_error"
    AUTHENTICATION = "authentication_error"
    TIMEOUT = "timeout_error"
    RESOURCE = "resource_error"
    PARSING = "parsing_error"
    VALIDATION = "validation_error"
    PERMISSION = "permission_error"
    RATE_LIMIT = "rate_limit_error"
    UNKNOWN = "unknown_error"


class ScannerError(Exception):
    """Base exception for scanner errors."""
    
    def __init__(
        self,
        message: str,
        error_type: ScannerErrorType = ScannerErrorType.UNKNOWN,
        details: Optional[Dict[str, Any]] = None,
        recoverable: bool = True,
    ):
        """
        Initialize scanner error.
        
        Args:
            message: Error message
            error_type: Type of error
            details: Additional error details
            recoverable: Whether the error is recoverable
        """
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.details = details or {}
        self.recoverable = recoverable
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary."""
        return {
            "message": self.message,
            "error_type": self.error_type,
            "details": self.details,
            "recoverable": self.recoverable,
        }


class ConfigurationError(ScannerError):
    """Raised when scanner configuration is invalid."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.CONFIGURATION,
            details=details,
            recoverable=False,
        )


class ConnectionError(ScannerError):
    """Raised when connection to target fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.CONNECTION,
            details=details,
            recoverable=True,
        )


class AuthenticationError(ScannerError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.AUTHENTICATION,
            details=details,
            recoverable=False,
        )


class TimeoutError(ScannerError):
    """Raised when scanner operation times out."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.TIMEOUT,
            details=details,
            recoverable=True,
        )


class ResourceError(ScannerError):
    """Raised when scanner runs out of resources."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.RESOURCE,
            details=details,
            recoverable=True,
        )


class ParsingError(ScannerError):
    """Raised when parsing scanner output fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.PARSING,
            details=details,
            recoverable=True,
        )


class ValidationError(ScannerError):
    """Raised when validation fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.VALIDATION,
            details=details,
            recoverable=False,
        )


class PermissionError(ScannerError):
    """Raised when scanner lacks permissions."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_type=ScannerErrorType.PERMISSION,
            details=details,
            recoverable=False,
        )


class RateLimitError(ScannerError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        details = details or {}
        if retry_after:
            details["retry_after"] = retry_after
        
        super().__init__(
            message=message,
            error_type=ScannerErrorType.RATE_LIMIT,
            details=details,
            recoverable=True,
        )


class ScannerErrorHandler:
    """Handler for scanner errors."""
    
    def __init__(self, logger=None):
        """Initialize error handler."""
        self.logger = logger
        self.error_counts: Dict[ScannerErrorType, int] = {}
        self.max_retries = 3
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Handle scanner error.
        
        Args:
            error: The error to handle
            context: Additional context
            
        Returns:
            True if error is recoverable, False otherwise
        """
        if not isinstance(error, ScannerError):
            # Convert to ScannerError
            error = ScannerError(
                message=str(error),
                error_type=ScannerErrorType.UNKNOWN,
                details={"original_error": type(error).__name__},
            )
        
        # Track error counts
        self.error_counts[error.error_type] = self.error_counts.get(error.error_type, 0) + 1
        
        # Log error
        if self.logger:
            self.logger.error(
                f"Scanner error: {error.message}",
                extra={
                    "error_type": error.error_type,
                    "error_details": error.details,
                    "context": context,
                    "error_count": self.error_counts[error.error_type],
                }
            )
        
        # Check if we should retry
        if error.recoverable and self.should_retry(error):
            return True
        
        return False
    
    def should_retry(self, error: ScannerError) -> bool:
        """
        Determine if operation should be retried.
        
        Args:
            error: The error that occurred
            
        Returns:
            True if should retry, False otherwise
        """
        error_count = self.error_counts.get(error.error_type, 0)
        
        # Don't retry if max retries exceeded
        if error_count >= self.max_retries:
            return False
        
        # Specific retry logic for different error types
        if error.error_type == ScannerErrorType.RATE_LIMIT:
            # Always retry rate limit errors if retry_after is provided
            return "retry_after" in error.details
        
        if error.error_type in [
            ScannerErrorType.CONNECTION,
            ScannerErrorType.TIMEOUT,
            ScannerErrorType.RESOURCE,
        ]:
            # Retry these transient errors
            return True
        
        # Don't retry other errors by default
        return False
    
    def get_retry_delay(self, error: ScannerError) -> int:
        """
        Get retry delay in seconds.
        
        Args:
            error: The error that occurred
            
        Returns:
            Delay in seconds
        """
        error_count = self.error_counts.get(error.error_type, 0)
        
        # Rate limit errors have specific retry delay
        if error.error_type == ScannerErrorType.RATE_LIMIT:
            return error.details.get("retry_after", 60)
        
        # Exponential backoff for other errors
        return min(2 ** error_count, 300)  # Max 5 minutes
    
    def reset_error_counts(self):
        """Reset error counts."""
        self.error_counts.clear()
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary."""
        return {
            "total_errors": sum(self.error_counts.values()),
            "error_breakdown": dict(self.error_counts),
            "max_retries": self.max_retries,
        }