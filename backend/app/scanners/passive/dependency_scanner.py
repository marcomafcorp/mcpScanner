import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
import aiohttp
import asyncio
from packaging import version

from app.models.finding import FindingCategory, SeverityLevel
from app.scanners.base.scanner import BaseScanner, ScannerResult, ScannerType
from app.scanners.base.utils import with_scanner_context, with_retry, with_timeout
from app.scanners.base.errors import ParsingError, ConnectionError as ScannerConnectionError


class DependencyScanner(BaseScanner):
    """Scanner for detecting vulnerable dependencies."""
    
    name = "DependencyScanner"
    description = "Scans for vulnerable dependencies in various package managers"
    scanner_type = ScannerType.PASSIVE
    version = "1.0.0"
    
    # Package file patterns
    PACKAGE_FILES = {
        "npm": ["package.json", "package-lock.json", "yarn.lock"],
        "python": ["requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock"],
        "ruby": ["Gemfile", "Gemfile.lock"],
        "php": ["composer.json", "composer.lock"],
        "maven": ["pom.xml"],
        "gradle": ["build.gradle", "build.gradle.kts"],
        "go": ["go.mod", "go.sum"],
        "rust": ["Cargo.toml", "Cargo.lock"],
    }
    
    def get_supported_categories(self) -> List[FindingCategory]:
        """Get supported finding categories."""
        return [FindingCategory.DEPENDENCY]
    
    @with_scanner_context("DependencyScanner")
    async def scan(self, target: str, depth: int = 3) -> List[ScannerResult]:
        """
        Scan for vulnerable dependencies.
        
        Args:
            target: Target directory or repository URL
            depth: Scan depth (not used for dependency scanning)
            
        Returns:
            List of vulnerability findings
        """
        self.clear_results()
        self._logger.info(f"Starting dependency scan for: {target}")
        
        # Determine if target is a URL or directory
        if target.startswith(("http://", "https://", "git@")):
            # Clone repository temporarily
            target_path = await self._clone_repository(target)
        else:
            target_path = Path(target)
            if not target_path.exists():
                raise ValueError(f"Target path does not exist: {target}")
        
        # Find all package files
        package_files = await self._find_package_files(target_path)
        self._logger.info(f"Found {len(package_files)} package files")
        
        # Report progress
        total_steps = len(package_files)
        self.report_progress("Scanning dependencies", total_steps, 0)
        
        # Scan each package file
        for idx, (file_path, package_type) in enumerate(package_files):
            try:
                await self._scan_package_file(file_path, package_type)
                self.report_progress(
                    f"Scanned {file_path.name}",
                    total_steps,
                    idx + 1
                )
            except Exception as e:
                self.add_error(f"Failed to scan {file_path}: {str(e)}")
                self._logger.error(f"Error scanning {file_path}", exc_info=True)
        
        self._logger.info(f"Dependency scan completed with {len(self.results)} findings")
        return self.results
    
    async def _clone_repository(self, repo_url: str) -> Path:
        """Clone repository to temporary directory."""
        import tempfile
        temp_dir = Path(tempfile.mkdtemp(prefix="mcp_scanner_"))
        
        try:
            process = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo_url, str(temp_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"Failed to clone repository: {stderr.decode()}")
            
            return temp_dir
        except Exception as e:
            self._logger.error(f"Failed to clone repository: {e}")
            raise
    
    async def _find_package_files(self, target_path: Path) -> List[tuple[Path, str]]:
        """Find all package files in the target directory."""
        package_files = []
        
        for package_type, patterns in self.PACKAGE_FILES.items():
            for pattern in patterns:
                for file_path in target_path.rglob(pattern):
                    # Skip node_modules and other vendor directories
                    if any(part in file_path.parts for part in ["node_modules", "vendor", ".git"]):
                        continue
                    package_files.append((file_path, package_type))
        
        return package_files
    
    async def _scan_package_file(self, file_path: Path, package_type: str) -> None:
        """Scan a specific package file for vulnerabilities."""
        self._logger.debug(f"Scanning {package_type} file: {file_path}")
        
        if package_type == "npm":
            await self._scan_npm_dependencies(file_path)
        elif package_type == "python":
            await self._scan_python_dependencies(file_path)
        elif package_type == "ruby":
            await self._scan_ruby_dependencies(file_path)
        elif package_type == "php":
            await self._scan_php_dependencies(file_path)
        elif package_type == "go":
            await self._scan_go_dependencies(file_path)
        elif package_type == "rust":
            await self._scan_rust_dependencies(file_path)
        else:
            self._logger.warning(f"Unsupported package type: {package_type}")
    
    @with_retry(max_attempts=3)
    @with_timeout(30)
    async def _scan_npm_dependencies(self, file_path: Path) -> None:
        """Scan npm dependencies using npm audit."""
        if file_path.name == "package.json":
            # Run npm audit
            try:
                process = await asyncio.create_subprocess_exec(
                    "npm", "audit", "--json",
                    cwd=file_path.parent,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if stdout:
                    audit_data = json.loads(stdout.decode())
                    await self._process_npm_audit(audit_data, file_path)
            except Exception as e:
                self._logger.error(f"Failed to run npm audit: {e}")
                # Fallback to manual parsing
                await self._parse_npm_package_json(file_path)
        
        elif file_path.name in ["package-lock.json", "yarn.lock"]:
            # Parse lock files for exact versions
            await self._parse_npm_lock_file(file_path)
    
    async def _process_npm_audit(self, audit_data: Dict[str, Any], file_path: Path) -> None:
        """Process npm audit results."""
        vulnerabilities = audit_data.get("vulnerabilities", {})
        
        for pkg_name, vuln_info in vulnerabilities.items():
            severity = self._map_npm_severity(vuln_info.get("severity", "info"))
            
            for via in vuln_info.get("via", []):
                if isinstance(via, dict):
                    self.add_result(ScannerResult(
                        category=FindingCategory.DEPENDENCY,
                        severity=severity,
                        title=f"Vulnerable dependency: {pkg_name}",
                        description=via.get("title", "Vulnerability found in dependency"),
                        evidence=f"Version: {vuln_info.get('range', 'unknown')}\n"
                                f"Advisory: {via.get('url', 'N/A')}",
                        location=str(file_path),
                        cve_id=via.get("cve"),
                        cwe_id=f"CWE-{via.get('cwe', '').replace('CWE-', '')}" if via.get("cwe") else None,
                        cvss_score=via.get("cvss", {}).get("score"),
                        remediation_summary=f"Update {pkg_name} to version {vuln_info.get('fixAvailable', {}).get('version', 'latest')}",
                        patch_available=bool(vuln_info.get("fixAvailable")),
                        references=[via.get("url")] if via.get("url") else [],
                    ))
    
    async def _parse_npm_package_json(self, file_path: Path) -> None:
        """Parse package.json and check for outdated dependencies."""
        try:
            with open(file_path) as f:
                package_data = json.load(f)
            
            dependencies = {}
            dependencies.update(package_data.get("dependencies", {}))
            dependencies.update(package_data.get("devDependencies", {}))
            
            # Check each dependency
            async with aiohttp.ClientSession() as session:
                for pkg_name, version_spec in dependencies.items():
                    await self._check_npm_package(session, pkg_name, version_spec, file_path)
        
        except Exception as e:
            raise ParsingError(f"Failed to parse package.json: {e}")
    
    async def _check_npm_package(
        self,
        session: aiohttp.ClientSession,
        pkg_name: str,
        version_spec: str,
        file_path: Path
    ) -> None:
        """Check npm package for vulnerabilities."""
        try:
            # Query npm registry
            async with session.get(f"https://registry.npmjs.org/{pkg_name}") as resp:
                if resp.status != 200:
                    return
                
                data = await resp.json()
                
                # Check for security advisories
                if "security" in data:
                    for advisory in data["security"]:
                        self.add_result(ScannerResult(
                            category=FindingCategory.DEPENDENCY,
                            severity=self._map_npm_severity(advisory.get("severity", "info")),
                            title=f"Security advisory for {pkg_name}",
                            description=advisory.get("overview", "Security vulnerability found"),
                            evidence=f"Affected versions: {advisory.get('vulnerable_versions', 'unknown')}",
                            location=str(file_path),
                            cve_id=advisory.get("cve"),
                            cvss_score=advisory.get("cvss_score"),
                            remediation_summary=advisory.get("recommendation", "Update to latest version"),
                            references=[advisory.get("references", "")],
                        ))
        
        except Exception as e:
            self._logger.debug(f"Failed to check npm package {pkg_name}: {e}")
    
    async def _parse_npm_lock_file(self, file_path: Path) -> None:
        """Parse npm lock files."""
        # Implementation depends on specific lock file format
        pass
    
    @with_retry(max_attempts=3)
    async def _scan_python_dependencies(self, file_path: Path) -> None:
        """Scan Python dependencies."""
        if file_path.name == "requirements.txt":
            await self._scan_requirements_txt(file_path)
        elif file_path.name == "pyproject.toml":
            await self._scan_pyproject_toml(file_path)
        elif file_path.name in ["Pipfile", "Pipfile.lock", "poetry.lock"]:
            await self._scan_python_lock_file(file_path)
    
    async def _scan_requirements_txt(self, file_path: Path) -> None:
        """Scan requirements.txt file."""
        try:
            with open(file_path) as f:
                lines = f.readlines()
            
            async with aiohttp.ClientSession() as session:
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Parse package name and version
                    match = re.match(r"^([a-zA-Z0-9\-_]+)(.*?)$", line)
                    if match:
                        pkg_name = match.group(1)
                        version_spec = match.group(2).strip()
                        
                        await self._check_pypi_package(session, pkg_name, version_spec, file_path)
        
        except Exception as e:
            raise ParsingError(f"Failed to parse requirements.txt: {e}")
    
    async def _check_pypi_package(
        self,
        session: aiohttp.ClientSession,
        pkg_name: str,
        version_spec: str,
        file_path: Path
    ) -> None:
        """Check PyPI package for vulnerabilities."""
        try:
            # Query PyPI API
            async with session.get(f"https://pypi.org/pypi/{pkg_name}/json") as resp:
                if resp.status != 200:
                    return
                
                data = await resp.json()
                
                # Check against known vulnerable versions
                # In a real implementation, this would query a vulnerability database
                # For now, we'll check if the package is severely outdated
                latest_version = data["info"]["version"]
                
                if version_spec and "==" in version_spec:
                    current_version = version_spec.split("==")[1].strip()
                    
                    try:
                        if version.parse(current_version) < version.parse(latest_version):
                            # Check how outdated it is
                            major_diff = int(latest_version.split(".")[0]) - int(current_version.split(".")[0])
                            
                            if major_diff >= 2:
                                self.add_result(ScannerResult(
                                    category=FindingCategory.DEPENDENCY,
                                    severity=SeverityLevel.MEDIUM,
                                    title=f"Severely outdated dependency: {pkg_name}",
                                    description=f"{pkg_name} is {major_diff} major versions behind",
                                    evidence=f"Current: {current_version}, Latest: {latest_version}",
                                    location=str(file_path),
                                    remediation_summary=f"Update {pkg_name} to version {latest_version}",
                                    confidence=0.7,
                                ))
                    except Exception:
                        pass
        
        except Exception as e:
            self._logger.debug(f"Failed to check PyPI package {pkg_name}: {e}")
    
    async def _scan_pyproject_toml(self, file_path: Path) -> None:
        """Scan pyproject.toml file."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            
            # Extract dependencies
            dependencies = []
            
            # Poetry format
            if "tool" in data and "poetry" in data["tool"]:
                poetry_deps = data["tool"]["poetry"].get("dependencies", {})
                dependencies.extend(poetry_deps.items())
                
                dev_deps = data["tool"]["poetry"].get("group", {}).get("dev", {}).get("dependencies", {})
                dependencies.extend(dev_deps.items())
            
            # PEP 621 format
            if "project" in data:
                project_deps = data["project"].get("dependencies", [])
                for dep in project_deps:
                    # Parse dependency string
                    match = re.match(r"^([a-zA-Z0-9\-_]+)(.*?)$", dep)
                    if match:
                        dependencies.append((match.group(1), match.group(2)))
            
            # Check each dependency
            async with aiohttp.ClientSession() as session:
                for pkg_name, version_spec in dependencies:
                    if pkg_name == "python":
                        continue
                    await self._check_pypi_package(session, pkg_name, str(version_spec), file_path)
        
        except Exception as e:
            self._logger.error(f"Failed to parse pyproject.toml: {e}")
    
    async def _scan_python_lock_file(self, file_path: Path) -> None:
        """Scan Python lock files."""
        # Implementation for Pipfile.lock and poetry.lock
        pass
    
    async def _scan_ruby_dependencies(self, file_path: Path) -> None:
        """Scan Ruby dependencies."""
        if file_path.name == "Gemfile":
            await self._scan_gemfile(file_path)
        elif file_path.name == "Gemfile.lock":
            await self._scan_gemfile_lock(file_path)
    
    async def _scan_gemfile(self, file_path: Path) -> None:
        """Scan Gemfile."""
        # Basic implementation - in production would use bundler-audit
        try:
            with open(file_path) as f:
                content = f.read()
            
            # Find gem declarations
            gem_pattern = re.compile(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?")
            
            for match in gem_pattern.finditer(content):
                gem_name = match.group(1)
                gem_version = match.group(2) or "any"
                
                # Check for known vulnerable gems
                vulnerable_gems = {
                    "rails": {"<5.2.6": SeverityLevel.HIGH},
                    "nokogiri": {"<1.13.0": SeverityLevel.MEDIUM},
                    "rack": {"<2.2.3": SeverityLevel.HIGH},
                }
                
                if gem_name in vulnerable_gems:
                    for vuln_version, severity in vulnerable_gems[gem_name].items():
                        self.add_result(ScannerResult(
                            category=FindingCategory.DEPENDENCY,
                            severity=severity,
                            title=f"Potentially vulnerable gem: {gem_name}",
                            description=f"Known vulnerabilities exist in {gem_name} versions {vuln_version}",
                            evidence=f"Current constraint: {gem_version}",
                            location=str(file_path),
                            remediation_summary=f"Update {gem_name} to latest secure version",
                            confidence=0.6,
                        ))
        
        except Exception as e:
            self._logger.error(f"Failed to scan Gemfile: {e}")
    
    async def _scan_gemfile_lock(self, file_path: Path) -> None:
        """Scan Gemfile.lock."""
        # Would parse exact versions from lock file
        pass
    
    async def _scan_php_dependencies(self, file_path: Path) -> None:
        """Scan PHP dependencies."""
        if file_path.name == "composer.json":
            await self._scan_composer_json(file_path)
        elif file_path.name == "composer.lock":
            await self._scan_composer_lock(file_path)
    
    async def _scan_composer_json(self, file_path: Path) -> None:
        """Scan composer.json."""
        try:
            with open(file_path) as f:
                data = json.load(f)
            
            dependencies = {}
            dependencies.update(data.get("require", {}))
            dependencies.update(data.get("require-dev", {}))
            
            # Check for known vulnerable packages
            vulnerable_packages = {
                "symfony/symfony": {"<4.4.0": SeverityLevel.HIGH},
                "laravel/framework": {"<8.0.0": SeverityLevel.MEDIUM},
                "monolog/monolog": {"<2.0.0": SeverityLevel.LOW},
            }
            
            for pkg_name, version_constraint in dependencies.items():
                if pkg_name in vulnerable_packages:
                    for vuln_version, severity in vulnerable_packages[pkg_name].items():
                        self.add_result(ScannerResult(
                            category=FindingCategory.DEPENDENCY,
                            severity=severity,
                            title=f"Potentially vulnerable PHP package: {pkg_name}",
                            description=f"Known vulnerabilities in {pkg_name} versions {vuln_version}",
                            evidence=f"Current constraint: {version_constraint}",
                            location=str(file_path),
                            remediation_summary=f"Update {pkg_name} to latest secure version",
                            confidence=0.6,
                        ))
        
        except Exception as e:
            self._logger.error(f"Failed to scan composer.json: {e}")
    
    async def _scan_composer_lock(self, file_path: Path) -> None:
        """Scan composer.lock."""
        # Would check exact versions from lock file
        pass
    
    async def _scan_go_dependencies(self, file_path: Path) -> None:
        """Scan Go dependencies."""
        if file_path.name == "go.mod":
            await self._scan_go_mod(file_path)
    
    async def _scan_go_mod(self, file_path: Path) -> None:
        """Scan go.mod file."""
        try:
            # Run go list to check for vulnerabilities
            process = await asyncio.create_subprocess_exec(
                "go", "list", "-json", "-m", "all",
                cwd=file_path.parent,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout and process.returncode == 0:
                # Parse module information
                for line in stdout.decode().split("\n"):
                    if line.strip():
                        try:
                            module_info = json.loads(line)
                            # Check against known vulnerabilities
                            # In production, would use govulncheck
                        except json.JSONDecodeError:
                            pass
        
        except Exception as e:
            self._logger.debug(f"Failed to scan go.mod: {e}")
    
    async def _scan_rust_dependencies(self, file_path: Path) -> None:
        """Scan Rust dependencies."""
        if file_path.name == "Cargo.toml":
            await self._scan_cargo_toml(file_path)
    
    async def _scan_cargo_toml(self, file_path: Path) -> None:
        """Scan Cargo.toml."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            
            dependencies = data.get("dependencies", {})
            
            # Check for known vulnerable crates
            vulnerable_crates = {
                "openssl": {"<0.10.38": SeverityLevel.HIGH},
                "tokio": {"<1.0.0": SeverityLevel.MEDIUM},
            }
            
            for crate_name, version_info in dependencies.items():
                if isinstance(version_info, str):
                    version_spec = version_info
                elif isinstance(version_info, dict):
                    version_spec = version_info.get("version", "")
                else:
                    continue
                
                if crate_name in vulnerable_crates:
                    for vuln_version, severity in vulnerable_crates[crate_name].items():
                        self.add_result(ScannerResult(
                            category=FindingCategory.DEPENDENCY,
                            severity=severity,
                            title=f"Potentially vulnerable Rust crate: {crate_name}",
                            description=f"Known vulnerabilities in {crate_name} versions {vuln_version}",
                            evidence=f"Current version: {version_spec}",
                            location=str(file_path),
                            remediation_summary=f"Update {crate_name} to latest secure version",
                            confidence=0.6,
                        ))
        
        except Exception as e:
            self._logger.error(f"Failed to scan Cargo.toml: {e}")
    
    def _map_npm_severity(self, npm_severity: str) -> SeverityLevel:
        """Map npm severity to our severity levels."""
        mapping = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "moderate": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        return mapping.get(npm_severity.lower(), SeverityLevel.INFO)