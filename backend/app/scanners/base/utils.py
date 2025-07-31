import asyncio
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union
import time
from pathlib import Path

from app.scanners.base.logger import setup_scanner_logger, ScannerLogContext, log_scanner_error
from app.scanners.base.errors import ScannerError, ScannerErrorHandler, TimeoutError


T = TypeVar('T')


def with_scanner_context(
    scanner_name: str,
    scan_id: Optional[str] = None,
    log_dir: Optional[Path] = None
):
    """
    Decorator to add scanner context to methods.
    
    Args:
        scanner_name: Name of the scanner
        scan_id: Optional scan ID
        log_dir: Optional log directory
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(self, *args, **kwargs):
            # Set up logger if not already present
            if not hasattr(self, '_logger') or self._logger is None:
                self._logger = setup_scanner_logger(
                    name=f"scanner.{scanner_name}",
                    scanner_name=scanner_name,
                    scan_id=scan_id,
                    log_dir=log_dir
                )
            
            # Set up error handler if not present
            if not hasattr(self, '_error_handler') or self._error_handler is None:
                self._error_handler = ScannerErrorHandler(logger=self._logger)
            
            # Execute function with context
            with ScannerLogContext(self._logger, method=func.__name__):
                try:
                    self._logger.info(f"Starting {func.__name__}")
                    result = await func(self, *args, **kwargs)
                    self._logger.info(f"Completed {func.__name__}")
                    return result
                except Exception as e:
                    log_scanner_error(self._logger, e, {"method": func.__name__})
                    raise
        
        @wraps(func)
        def sync_wrapper(self, *args, **kwargs):
            # Set up logger if not already present
            if not hasattr(self, '_logger') or self._logger is None:
                self._logger = setup_scanner_logger(
                    name=f"scanner.{scanner_name}",
                    scanner_name=scanner_name,
                    scan_id=scan_id,
                    log_dir=log_dir
                )
            
            # Set up error handler if not present
            if not hasattr(self, '_error_handler') or self._error_handler is None:
                self._error_handler = ScannerErrorHandler(logger=self._logger)
            
            # Execute function with context
            with ScannerLogContext(self._logger, method=func.__name__):
                try:
                    self._logger.info(f"Starting {func.__name__}")
                    result = func(self, *args, **kwargs)
                    self._logger.info(f"Completed {func.__name__}")
                    return result
                except Exception as e:
                    log_scanner_error(self._logger, e, {"method": func.__name__})
                    raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    Decorator to retry failed operations.
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier for delay
        exceptions: Tuple of exceptions to catch
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise
            
            raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise
            
            raise last_exception
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_timeout(timeout_seconds: float):
    """
    Decorator to add timeout to async functions.
    
    Args:
        timeout_seconds: Timeout in seconds
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"Operation timed out after {timeout_seconds} seconds",
                    details={"timeout": timeout_seconds, "function": func.__name__}
                )
        
        return wrapper
    
    return decorator


def rate_limiter(calls_per_second: float):
    """
    Decorator to rate limit function calls.
    
    Args:
        calls_per_second: Maximum calls per second
    """
    min_interval = 1.0 / calls_per_second
    last_called = {}
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            key = id(args[0]) if args else 0  # Use instance ID as key
            current_time = time.time()
            
            if key in last_called:
                elapsed = current_time - last_called[key]
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
            
            last_called[key] = time.time()
            return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            key = id(args[0]) if args else 0  # Use instance ID as key
            current_time = time.time()
            
            if key in last_called:
                elapsed = current_time - last_called[key]
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
            
            last_called[key] = time.time()
            return func(*args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def sanitize_url(url: str) -> str:
    """
    Sanitize URL for logging/display.
    
    Args:
        url: URL to sanitize
        
    Returns:
        Sanitized URL
    """
    from urllib.parse import urlparse, urlunparse
    
    parsed = urlparse(url)
    
    # Hide credentials if present
    if parsed.username or parsed.password:
        netloc = parsed.hostname
        if parsed.port:
            netloc += f":{parsed.port}"
        
        sanitized = parsed._replace(netloc=netloc)
        return urlunparse(sanitized)
    
    return url


def extract_domain(url: str) -> str:
    """
    Extract domain from URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain name
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc or url


def normalize_severity(severity: str) -> str:
    """
    Normalize severity levels.
    
    Args:
        severity: Input severity
        
    Returns:
        Normalized severity
    """
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "warning": "medium",
        "error": "high",
    }
    
    return severity_map.get(severity.lower(), "info")


def calculate_confidence(
    has_evidence: bool = False,
    has_cve: bool = False,
    has_verified: bool = False,
    false_positive_indicators: int = 0
) -> float:
    """
    Calculate finding confidence score.
    
    Args:
        has_evidence: Whether evidence is present
        has_cve: Whether CVE is associated
        has_verified: Whether finding is verified
        false_positive_indicators: Number of false positive indicators
        
    Returns:
        Confidence score (0.0 - 1.0)
    """
    score = 0.5  # Base confidence
    
    if has_evidence:
        score += 0.2
    if has_cve:
        score += 0.2
    if has_verified:
        score += 0.1
    
    # Reduce confidence based on false positive indicators
    score -= (false_positive_indicators * 0.1)
    
    # Clamp between 0 and 1
    return max(0.0, min(1.0, score))


class ProgressTracker:
    """Track and report scanner progress."""
    
    def __init__(self, total_steps: int, callback: Optional[Callable] = None):
        """
        Initialize progress tracker.
        
        Args:
            total_steps: Total number of steps
            callback: Optional callback for progress updates
        """
        self.total_steps = total_steps
        self.completed_steps = 0
        self.current_step = ""
        self.callback = callback
        self.start_time = time.time()
    
    def update(self, step_name: str, increment: int = 1):
        """Update progress."""
        self.current_step = step_name
        self.completed_steps += increment
        
        if self.callback:
            from app.scanners.base.scanner import ScannerProgress
            progress = ScannerProgress(
                current_step=self.current_step,
                total_steps=self.total_steps,
                completed_steps=self.completed_steps,
                message=f"Processing: {step_name}"
            )
            self.callback(progress)
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return time.time() - self.start_time
    
    def get_eta(self) -> Optional[float]:
        """Get estimated time to completion in seconds."""
        if self.completed_steps == 0:
            return None
        
        elapsed = self.get_elapsed_time()
        rate = self.completed_steps / elapsed
        remaining = self.total_steps - self.completed_steps
        
        return remaining / rate if rate > 0 else None