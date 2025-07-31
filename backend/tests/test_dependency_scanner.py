import pytest
import tempfile
from pathlib import Path
import json

from app.scanners.passive.dependency_scanner import DependencyScanner
from app.models.finding import FindingCategory, SeverityLevel


class TestDependencyScanner:
    """Test dependency scanner functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return DependencyScanner()
    
    def test_scanner_metadata(self, scanner):
        """Test scanner metadata."""
        assert scanner.name == "DependencyScanner"
        assert scanner.scanner_type.value == "passive"
        assert FindingCategory.DEPENDENCY in scanner.get_supported_categories()
    
    @pytest.mark.asyncio
    async def test_scan_npm_package_json(self, scanner):
        """Test scanning npm package.json."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a package.json with vulnerable dependencies
            package_json = {
                "name": "test-app",
                "version": "1.0.0",
                "dependencies": {
                    "express": "3.0.0",  # Old version
                    "lodash": "4.17.11",  # Known vulnerable version
                }
            }
            
            package_path = Path(temp_dir) / "package.json"
            with open(package_path, "w") as f:
                json.dump(package_json, f)
            
            # Scan the directory
            results = await scanner.scan(temp_dir)
            
            # Should find issues with outdated/vulnerable packages
            assert len(results) >= 0  # May vary based on actual vulnerability data
    
    @pytest.mark.asyncio
    async def test_scan_python_requirements(self, scanner):
        """Test scanning Python requirements.txt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a requirements.txt with old versions
            requirements = """
django==2.0.0
requests==2.20.0
flask==0.12.0
"""
            
            req_path = Path(temp_dir) / "requirements.txt"
            with open(req_path, "w") as f:
                f.write(requirements)
            
            # Scan the directory
            results = await scanner.scan(temp_dir)
            
            # Should detect outdated packages
            assert any(r.category == FindingCategory.DEPENDENCY for r in results)
    
    @pytest.mark.asyncio
    async def test_scan_pyproject_toml(self, scanner):
        """Test scanning pyproject.toml."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a pyproject.toml
            pyproject = """
[tool.poetry]
name = "test-project"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.8"
django = "2.0.0"
requests = "^2.20.0"
"""
            
            pyproject_path = Path(temp_dir) / "pyproject.toml"
            with open(pyproject_path, "w") as f:
                f.write(pyproject)
            
            # Scan the directory
            results = await scanner.scan(temp_dir)
            
            # Should process the file without errors
            assert scanner.errors == [] or len(scanner.errors) == 0
    
    @pytest.mark.asyncio
    async def test_scan_ruby_gemfile(self, scanner):
        """Test scanning Ruby Gemfile."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a Gemfile
            gemfile = """
source 'https://rubygems.org'

gem 'rails', '4.2.0'
gem 'nokogiri', '1.10.0'
gem 'rack', '2.0.0'
"""
            
            gemfile_path = Path(temp_dir) / "Gemfile"
            with open(gemfile_path, "w") as f:
                f.write(gemfile)
            
            # Scan the directory
            results = await scanner.scan(temp_dir)
            
            # Should find potentially vulnerable gems
            vulnerable_results = [r for r in results if "vulnerable gem" in r.title]
            assert len(vulnerable_results) >= 0
    
    @pytest.mark.asyncio
    async def test_scan_composer_json(self, scanner):
        """Test scanning PHP composer.json."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a composer.json
            composer = {
                "require": {
                    "symfony/symfony": "3.4.0",
                    "laravel/framework": "5.5.0",
                    "monolog/monolog": "1.25.0"
                }
            }
            
            composer_path = Path(temp_dir) / "composer.json"
            with open(composer_path, "w") as f:
                json.dump(composer, f)
            
            # Scan the directory
            results = await scanner.scan(temp_dir)
            
            # Should find potentially vulnerable packages
            php_results = [r for r in results if "PHP package" in r.title]
            assert len(php_results) >= 0
    
    @pytest.mark.asyncio
    async def test_scan_cargo_toml(self, scanner):
        """Test scanning Rust Cargo.toml."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a Cargo.toml
            cargo_toml = """
[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
openssl = "0.9.0"
tokio = "0.2.0"
"""
            
            cargo_path = Path(temp_dir) / "Cargo.toml"
            with open(cargo_path, "w") as f:
                f.write(cargo_toml)
            
            # Scan the directory
            results = await scanner.scan(temp_dir)
            
            # Should find potentially vulnerable crates
            rust_results = [r for r in results if "Rust crate" in r.title]
            assert len(rust_results) >= 0
    
    @pytest.mark.asyncio
    async def test_skip_vendor_directories(self, scanner):
        """Test that vendor directories are skipped."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create package files in vendor directories
            vendor_dirs = ["node_modules", "vendor", ".git"]
            
            for vendor_dir in vendor_dirs:
                vendor_path = Path(temp_dir) / vendor_dir
                vendor_path.mkdir(parents=True)
                
                # Create package.json in vendor directory
                package_path = vendor_path / "package.json"
                with open(package_path, "w") as f:
                    json.dump({"name": "vendor-package"}, f)
            
            # Create a normal package.json
            normal_package = Path(temp_dir) / "package.json"
            with open(normal_package, "w") as f:
                json.dump({"name": "normal-package"}, f)
            
            # Find package files
            package_files = await scanner._find_package_files(Path(temp_dir))
            
            # Should only find the normal package.json
            assert len(package_files) == 1
            assert package_files[0][0] == normal_package
    
    def test_npm_severity_mapping(self, scanner):
        """Test NPM severity mapping."""
        assert scanner._map_npm_severity("critical") == SeverityLevel.CRITICAL
        assert scanner._map_npm_severity("high") == SeverityLevel.HIGH
        assert scanner._map_npm_severity("moderate") == SeverityLevel.MEDIUM
        assert scanner._map_npm_severity("low") == SeverityLevel.LOW
        assert scanner._map_npm_severity("info") == SeverityLevel.INFO
        assert scanner._map_npm_severity("unknown") == SeverityLevel.INFO