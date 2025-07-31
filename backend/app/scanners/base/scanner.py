from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol
from pathlib import Path

from app.models.finding import FindingCategory, SeverityLevel
from app.scanners.base.logger import setup_scanner_logger, ScannerLogContext
from app.scanners.base.errors import ScannerError, ScannerErrorHandler


class ScannerType(str, Enum):
    """Scanner type enumeration."""
    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass
class ScannerResult:
    """Result from a scanner module."""
    
    category: FindingCategory
    severity: SeverityLevel
    title: str
    description: str
    evidence: Optional[str] = None
    location: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None
    scanner_module: str = ""
    
    # CVE/CWE information
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    
    # Remediation information
    remediation_summary: Optional[str] = None
    remediation_steps: Optional[str] = None
    patch_available: bool = False
    patch_url: Optional[str] = None
    workaround: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScannerProgress:
    """Progress information for a scanner."""
    
    current_step: str
    total_steps: int
    completed_steps: int
    message: Optional[str] = None
    
    @property
    def percentage(self) -> int:
        """Calculate progress percentage."""
        if self.total_steps == 0:
            return 0
        return int((self.completed_steps / self.total_steps) * 100)


class ProgressCallback(Protocol):
    """Protocol for progress callbacks."""
    
    def __call__(self, progress: ScannerProgress) -> None:
        """Called to report progress."""
        ...


class BaseScanner(ABC):
    """Base abstract class for all scanners."""
    
    # Scanner metadata
    name: str = "BaseScanner"
    description: str = "Base scanner implementation"
    scanner_type: ScannerType = ScannerType.PASSIVE
    version: str = "1.0.0"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner with configuration."""
        self.config = config or {}
        self.results: List[ScannerResult] = []
        self.errors: List[str] = []
        self._progress_callback: Optional[ProgressCallback] = None
        
        # Initialize logger and error handler
        self._logger = setup_scanner_logger(
            name=f"scanner.{self.name}",
            scanner_name=self.name,
            log_dir=Path(self.config.get("log_dir", "/tmp/mcp-scanner/logs")) if self.config.get("log_dir") else None
        )
        self._error_handler = ScannerErrorHandler(logger=self._logger)
    
    @abstractmethod
    async def scan(self, target: str, depth: int = 3) -> List[ScannerResult]:
        """
        Perform the scan on the target.
        
        Args:
            target: Target URL or resource to scan
            depth: Scan depth (1-10)
            
        Returns:
            List of scanner results
        """
        pass
    
    @abstractmethod
    def get_supported_categories(self) -> List[FindingCategory]:
        """Get the finding categories this scanner can detect."""
        pass
    
    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set progress callback function."""
        self._progress_callback = callback
    
    def report_progress(self, current_step: str, total_steps: int, completed_steps: int, message: Optional[str] = None) -> None:
        """Report scan progress."""
        if self._progress_callback:
            progress = ScannerProgress(
                current_step=current_step,
                total_steps=total_steps,
                completed_steps=completed_steps,
                message=message,
            )
            self._progress_callback(progress)
    
    def add_result(self, result: ScannerResult) -> None:
        """Add a result to the scanner results."""
        result.scanner_module = self.name
        self.results.append(result)
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(f"[{self.name}] {error}")
        self._logger.error(f"Scanner error: {error}")
    
    def clear_results(self) -> None:
        """Clear all results and errors."""
        self.results.clear()
        self.errors.clear()
    
    async def initialize(self) -> None:
        """Initialize scanner resources (override if needed)."""
        self._logger.info(f"Initializing {self.name} scanner")
        pass
    
    async def cleanup(self) -> None:
        """Cleanup scanner resources (override if needed)."""
        self._logger.info(f"Cleaning up {self.name} scanner")
        pass
    
    def validate_config(self) -> bool:
        """Validate scanner configuration (override if needed)."""
        self._logger.info(f"Validating configuration for {self.name} scanner")
        return True
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Handle scanner error.
        
        Args:
            error: The error that occurred
            context: Additional context
            
        Returns:
            True if error is recoverable
        """
        return self._error_handler.handle_error(error, context)
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}', type={self.scanner_type})>"