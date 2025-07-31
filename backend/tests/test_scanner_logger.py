import pytest
import asyncio
from pathlib import Path
import tempfile
import json

from app.scanners.base.logger import (
    setup_scanner_logger,
    ScannerLogContext,
    log_scanner_error,
    log_scanner_result,
    create_scan_summary,
)
from app.scanners.base.errors import (
    ScannerError,
    ScannerErrorHandler,
    ConfigurationError,
    ConnectionError,
    TimeoutError,
    RateLimitError,
)
from app.scanners.base.utils import (
    with_scanner_context,
    with_retry,
    with_timeout,
    rate_limiter,
)


class TestScannerLogger:
    """Test scanner logger functionality."""
    
    def test_setup_scanner_logger(self):
        """Test logger setup."""
        logger = setup_scanner_logger(
            name="test.scanner",
            level="DEBUG",
            scanner_name="TestScanner",
            scan_id="test-123",
        )
        
        assert logger is not None
        assert logger.name == "test.scanner"
    
    def test_scanner_log_context(self):
        """Test scanner log context."""
        logger = setup_scanner_logger(name="test.context")
        
        with ScannerLogContext(logger, test_field="test_value"):
            logger.info("Test message")
            # Context should be active here
        
        # Context should be cleared here
    
    def test_log_scanner_error(self):
        """Test error logging."""
        logger = setup_scanner_logger(name="test.error")
        
        try:
            raise ValueError("Test error")
        except Exception as e:
            log_scanner_error(logger, e, {"test_context": "value"})
    
    def test_log_scanner_result(self):
        """Test result logging."""
        logger = setup_scanner_logger(name="test.result")
        
        result = {
            "title": "Test Finding",
            "severity": "high",
            "category": "test",
            "confidence": 0.9,
        }
        
        log_scanner_result(logger, result)
    
    def test_create_scan_summary(self):
        """Test scan summary creation."""
        logger = setup_scanner_logger(name="test.summary")
        
        results = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        
        summary = create_scan_summary(logger, "test-scan", results)
        
        assert summary["scan_id"] == "test-scan"
        assert summary["total_findings"] == 6
        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["info"] == 1
    
    def test_json_log_formatting(self):
        """Test JSON log formatting."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            logger = setup_scanner_logger(
                name="test.json",
                scanner_name="JsonTest",
                scan_id="json-123",
                log_dir=log_dir,
            )
            
            logger.info("Test JSON log")
            
            # Check that log file was created
            log_file = log_dir / "JsonTest_json-123.json"
            assert log_file.exists()
            
            # Verify JSON format
            with open(log_file) as f:
                log_line = f.readline()
                log_data = json.loads(log_line)
                assert "timestamp" in log_data
                assert "message" in log_data
                assert log_data["scanner_name"] == "JsonTest"
                assert log_data["scan_id"] == "json-123"


class TestScannerErrors:
    """Test scanner error handling."""
    
    def test_scanner_error_creation(self):
        """Test scanner error creation."""
        error = ScannerError(
            message="Test error",
            details={"key": "value"},
            recoverable=True,
        )
        
        assert error.message == "Test error"
        assert error.details["key"] == "value"
        assert error.recoverable is True
    
    def test_specific_error_types(self):
        """Test specific error types."""
        config_error = ConfigurationError("Bad config")
        assert config_error.recoverable is False
        
        conn_error = ConnectionError("Connection failed")
        assert conn_error.recoverable is True
        
        timeout_error = TimeoutError("Timed out")
        assert timeout_error.recoverable is True
        
        rate_error = RateLimitError("Rate limited", retry_after=60)
        assert rate_error.recoverable is True
        assert rate_error.details["retry_after"] == 60
    
    def test_error_handler(self):
        """Test error handler."""
        handler = ScannerErrorHandler()
        
        # Test recoverable error
        error = ConnectionError("Connection failed")
        assert handler.handle_error(error) is True
        
        # Test non-recoverable error
        error = ConfigurationError("Bad config")
        assert handler.handle_error(error) is False
        
        # Test retry limit
        for _ in range(3):
            handler.handle_error(ConnectionError("Failed"))
        
        # Should not retry after max attempts
        assert handler.handle_error(ConnectionError("Failed")) is False
    
    def test_retry_delay(self):
        """Test retry delay calculation."""
        handler = ScannerErrorHandler()
        
        # Test rate limit delay
        rate_error = RateLimitError("Limited", retry_after=120)
        assert handler.get_retry_delay(rate_error) == 120
        
        # Test exponential backoff
        conn_error = ConnectionError("Failed")
        handler.handle_error(conn_error)
        assert handler.get_retry_delay(conn_error) == 2  # 2^1
        
        handler.handle_error(conn_error)
        assert handler.get_retry_delay(conn_error) == 4  # 2^2


class TestScannerUtils:
    """Test scanner utility functions."""
    
    @pytest.mark.asyncio
    async def test_with_scanner_context_decorator(self):
        """Test scanner context decorator."""
        
        class TestScanner:
            @with_scanner_context("TestScanner", "test-123")
            async def scan(self):
                return "scan_result"
        
        scanner = TestScanner()
        result = await scanner.scan()
        assert result == "scan_result"
        assert hasattr(scanner, "_logger")
        assert hasattr(scanner, "_error_handler")
    
    @pytest.mark.asyncio
    async def test_with_retry_decorator(self):
        """Test retry decorator."""
        call_count = 0
        
        @with_retry(max_attempts=3, delay=0.1)
        async def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Failed")
            return "success"
        
        result = await failing_function()
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_with_timeout_decorator(self):
        """Test timeout decorator."""
        
        @with_timeout(0.1)
        async def slow_function():
            await asyncio.sleep(1)
            return "should_not_reach"
        
        with pytest.raises(TimeoutError):
            await slow_function()
    
    @pytest.mark.asyncio
    async def test_rate_limiter_decorator(self):
        """Test rate limiter decorator."""
        calls = []
        
        @rate_limiter(calls_per_second=10)
        async def rate_limited_function():
            calls.append(asyncio.get_event_loop().time())
        
        # Make rapid calls
        for _ in range(3):
            await rate_limited_function()
        
        # Check that calls are spaced appropriately
        assert len(calls) == 3
        for i in range(1, len(calls)):
            assert calls[i] - calls[i-1] >= 0.09  # Allow small margin