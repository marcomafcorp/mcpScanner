import logging
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanners.base.scanner import ScannerResult

logger = logging.getLogger(__name__)


class ResultProcessor:
    """Process scanner results and store them in the database."""
    
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
    
    async def process_results(
        self,
        scan: Scan,
        results: List[ScannerResult],
        deduplicate: bool = True
    ) -> List[Finding]:
        """
        Process scanner results and create findings.
        
        Args:
            scan: The scan object
            results: List of scanner results
            deduplicate: Whether to deduplicate findings
            
        Returns:
            List of created findings
        """
        findings = []
        
        # Group results by title and location for deduplication
        if deduplicate:
            results = self._deduplicate_results(results)
        
        for result in results:
            try:
                finding = await self._create_finding(scan, result)
                findings.append(finding)
            except Exception as e:
                logger.error(f"Failed to process result '{result.title}': {e}")
        
        return findings
    
    async def _create_finding(self, scan: Scan, result: ScannerResult) -> Finding:
        """Create a finding from a scanner result."""
        # Create finding
        finding = Finding(
            scan_id=scan.id,
            category=result.category,
            severity=result.severity,
            title=result.title,
            description=result.description,
            evidence=result.evidence,
            location=result.location,
            file_path=result.file_path,
            line_number=result.line_number,
            cvss_score=result.cvss_score,
            confidence=result.confidence,
            scanner_module=result.scanner_module,
        )
        
        self.db.add(finding)
        await self.db.flush()  # Get the finding ID
        
        # Create vulnerability details if present
        if any([
            result.cve_id,
            result.cwe_id,
            result.remediation_summary,
            result.remediation_steps,
            result.references,
        ]):
            vulnerability = Vulnerability(
                finding_id=finding.id,
                cve_id=result.cve_id,
                cwe_id=result.cwe_id,
                cvss_base_score=result.cvss_score,
                remediation_summary=result.remediation_summary,
                remediation_steps=result.remediation_steps,
                patch_available=result.patch_available,
                patch_url=result.patch_url,
                workaround=result.workaround,
                references="\n".join(result.references) if result.references else None,
            )
            self.db.add(vulnerability)
        
        await self.db.flush()
        return finding
    
    def _deduplicate_results(self, results: List[ScannerResult]) -> List[ScannerResult]:
        """Deduplicate scanner results based on title and location."""
        seen = set()
        deduplicated = []
        
        for result in results:
            # Create a unique key for the result
            key = (
                result.title,
                result.location or "",
                result.file_path or "",
                result.line_number or 0,
            )
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(result)
            else:
                # If we've seen this before, merge any additional information
                existing = next(
                    r for r in deduplicated
                    if (r.title, r.location or "", r.file_path or "", r.line_number or 0) == key
                )
                
                # Merge evidence
                if result.evidence and existing.evidence != result.evidence:
                    existing.evidence = f"{existing.evidence}\n\n{result.evidence}"
                
                # Take higher severity
                severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                if severity_map.get(result.severity, 0) > severity_map.get(existing.severity, 0):
                    existing.severity = result.severity
                
                # Take higher CVSS score
                if result.cvss_score and (not existing.cvss_score or result.cvss_score > existing.cvss_score):
                    existing.cvss_score = result.cvss_score
        
        return deduplicated
    
    async def update_scan_progress(
        self,
        scan: Scan,
        progress: int,
        current_module: Optional[str] = None
    ) -> None:
        """Update scan progress."""
        scan.progress = min(progress, 100)
        if current_module:
            scan.current_module = current_module
        
        await self.db.flush()
    
    async def mark_scan_complete(
        self,
        scan: Scan,
        status: str = "completed",
        error_message: Optional[str] = None
    ) -> None:
        """Mark a scan as complete."""
        from datetime import datetime
        
        scan.status = status
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        
        if error_message:
            scan.error_message = error_message
        
        await self.db.flush()