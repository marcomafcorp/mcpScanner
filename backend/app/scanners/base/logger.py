import logging
import sys
from typing import Optional
from pathlib import Path
import json
from datetime import datetime
from pythonjsonlogger import jsonlogger


class ScannerLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter for adding scanner context to log records."""
    
    def process(self, msg, kwargs):
        """Process log record to add scanner context."""
        extra = kwargs.get('extra', {})
        extra.update(self.extra)
        kwargs['extra'] = extra
        return msg, kwargs


class ScannerFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for scanner logs."""
    
    def add_fields(self, log_record, record, message_dict):
        """Add custom fields to log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat()
        
        # Add scanner context if available
        if hasattr(record, 'scanner_name'):
            log_record['scanner_name'] = record.scanner_name
        if hasattr(record, 'scan_id'):
            log_record['scan_id'] = record.scan_id
        if hasattr(record, 'target'):
            log_record['target'] = record.target
        
        # Add error details if it's an error
        if record.levelname == 'ERROR' and hasattr(record, 'exc_info') and record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)


def setup_scanner_logger(
    name: str,
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    scanner_name: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> logging.Logger:
    """
    Set up a logger for scanner modules.
    
    Args:
        name: Logger name
        level: Log level
        log_dir: Directory for log files
        scanner_name: Name of the scanner
        scan_id: ID of the current scan
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with standard formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with JSON formatting if log_dir provided
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{scanner_name or 'scanner'}_{scan_id or 'general'}.json"
        
        file_handler = logging.FileHandler(log_file)
        json_formatter = ScannerFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
        file_handler.setFormatter(json_formatter)
        logger.addHandler(file_handler)
    
    # Create adapter with context
    extra = {}
    if scanner_name:
        extra['scanner_name'] = scanner_name
    if scan_id:
        extra['scan_id'] = scan_id
    
    if extra:
        return ScannerLoggerAdapter(logger, extra)
    
    return logger


class ScannerLogContext:
    """Context manager for scanner logging."""
    
    def __init__(self, logger: logging.Logger, **context):
        self.logger = logger
        self.context = context
        self.original_extra = {}
    
    def __enter__(self):
        """Enter context and add extra fields."""
        if isinstance(self.logger, ScannerLoggerAdapter):
            self.original_extra = self.logger.extra.copy()
            self.logger.extra.update(self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original extra fields."""
        if isinstance(self.logger, ScannerLoggerAdapter):
            self.logger.extra = self.original_extra
        
        # Log any exception that occurred
        if exc_type:
            self.logger.error(
                f"Exception in scanner context: {exc_type.__name__}",
                exc_info=True,
                extra={'exception_type': exc_type.__name__}
            )
        
        return False  # Don't suppress exceptions


def log_scanner_error(logger: logging.Logger, error: Exception, context: Optional[dict] = None):
    """
    Log scanner error with context.
    
    Args:
        logger: Logger instance
        error: Exception to log
        context: Additional context information
    """
    error_info = {
        'error_type': type(error).__name__,
        'error_message': str(error),
    }
    
    if context:
        error_info.update(context)
    
    logger.error(
        f"Scanner error: {error}",
        exc_info=True,
        extra=error_info
    )


def log_scanner_result(logger: logging.Logger, result: dict):
    """
    Log scanner result.
    
    Args:
        logger: Logger instance
        result: Scanner result to log
    """
    logger.info(
        f"Scanner found: {result.get('title', 'Unknown')}",
        extra={
            'result_severity': result.get('severity'),
            'result_category': result.get('category'),
            'result_confidence': result.get('confidence'),
        }
    )


def create_scan_summary(logger: logging.Logger, scan_id: str, results: list):
    """
    Create and log scan summary.
    
    Args:
        logger: Logger instance
        scan_id: Scan ID
        results: List of scan results
    """
    summary = {
        'scan_id': scan_id,
        'total_findings': len(results),
        'critical': sum(1 for r in results if r.get('severity') == 'critical'),
        'high': sum(1 for r in results if r.get('severity') == 'high'),
        'medium': sum(1 for r in results if r.get('severity') == 'medium'),
        'low': sum(1 for r in results if r.get('severity') == 'low'),
        'info': sum(1 for r in results if r.get('severity') == 'info'),
    }
    
    logger.info(
        f"Scan {scan_id} completed with {summary['total_findings']} findings",
        extra={'scan_summary': summary}
    )
    
    return summary