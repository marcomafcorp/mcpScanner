import json
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import configparser
from xml.etree import ElementTree as ET

from app.models.finding import FindingCategory, SeverityLevel
from app.scanners.base.scanner import BaseScanner, ScannerResult, ScannerType
from app.scanners.base.utils import with_scanner_context
from app.scanners.base.errors import ParsingError


class ConfigScanner(BaseScanner):
    """Scanner for detecting configuration security issues."""
    
    name = "ConfigScanner"
    description = "Scans for insecure configurations and hardcoded secrets"
    scanner_type = ScannerType.PASSIVE
    version = "1.0.0"
    
    # Configuration file patterns
    CONFIG_FILES = {
        "yaml": ["*.yml", "*.yaml"],
        "json": ["*.json"],
        "ini": ["*.ini", "*.cfg", "*.conf"],
        "xml": ["*.xml"],
        "env": [".env", "*.env", ".env.*"],
        "properties": ["*.properties"],
        "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
        "kubernetes": ["*.k8s.yml", "*.k8s.yaml", "deployment.yml", "deployment.yaml"],
        "terraform": ["*.tf", "*.tfvars"],
        "ansible": ["playbook.yml", "playbook.yaml", "*.ansible.yml"],
        "nginx": ["nginx.conf", "*.nginx"],
        "apache": ["httpd.conf", ".htaccess", "apache2.conf"],
    }
    
    # Patterns for detecting secrets
    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}", re.I),
        "aws_secret_key": re.compile(r"[0-9a-zA-Z/+=]{40}"),
        "api_key": re.compile(r"(api[_\-]?key|apikey)\s*[:=]\s*[\"']?([a-zA-Z0-9\-_]{20,})[\"']?", re.I),
        "password": re.compile(r"(password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"']+)[\"']?", re.I),
        "token": re.compile(r"(token|auth[_\-]?token)\s*[:=]\s*[\"']?([a-zA-Z0-9\-_.]{20,})[\"']?", re.I),
        "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "stripe_key": re.compile(r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}"),
        "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z-]+"),
        "database_url": re.compile(r"(mysql|postgres|postgresql|mongodb)://[^@\s]+@[^\s]+", re.I),
    }
    
    # Insecure configuration patterns
    INSECURE_CONFIGS = {
        "debug_enabled": re.compile(r"(debug|DEBUG)\s*[:=]\s*(true|True|1|on|yes)", re.I),
        "ssl_disabled": re.compile(r"(ssl|tls|https).*\s*[:=]\s*(false|False|0|off|no|disabled)", re.I),
        "allow_all": re.compile(r"(allow|permit|access).*\s*[:=]\s*[\"\']?(all|\*|any|0\.0\.0\.0)[\"']?", re.I),
        "weak_cipher": re.compile(r"(cipher|encryption).*\s*[:=]\s*[\"\']?(des|rc4|md5)[\"']?", re.I),
        "no_auth": re.compile(r"(auth|authentication).*\s*[:=]\s*(false|False|0|off|no|disabled|none)", re.I),
        "permissive_cors": re.compile(r"(cors|origin).*\s*[:=]\s*[\"\']?\*[\"']?", re.I),
        "public_bind": re.compile(r"(bind|listen).*\s*[:=]\s*[\"\']?0\.0\.0\.0[\"']?", re.I),
    }
    
    def get_supported_categories(self) -> List[FindingCategory]:
        """Get supported finding categories."""
        return [
            FindingCategory.CONFIG_INSECURE_DEFAULT,
            FindingCategory.CONFIG_HARDCODED_CREDS,
            FindingCategory.CONFIG_PERMISSIVE_ACCESS,
        ]
    
    @with_scanner_context("ConfigScanner")
    async def scan(self, target: str, depth: int = 3) -> List[ScannerResult]:
        """
        Scan for configuration security issues.
        
        Args:
            target: Target directory or repository URL
            depth: Scan depth (not used for config scanning)
            
        Returns:
            List of configuration findings
        """
        self.clear_results()
        self._logger.info(f"Starting configuration scan for: {target}")
        
        # Determine target path
        if target.startswith(("http://", "https://", "git@")):
            # Would clone repository - for now, skip
            self.add_error("Repository cloning not implemented in this example")
            return self.results
        
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        # Find all configuration files
        config_files = await self._find_config_files(target_path)
        self._logger.info(f"Found {len(config_files)} configuration files")
        
        # Report progress
        total_steps = len(config_files)
        self.report_progress("Scanning configurations", total_steps, 0)
        
        # Scan each configuration file
        for idx, (file_path, config_type) in enumerate(config_files):
            try:
                await self._scan_config_file(file_path, config_type)
                self.report_progress(
                    f"Scanned {file_path.name}",
                    total_steps,
                    idx + 1
                )
            except Exception as e:
                self.add_error(f"Failed to scan {file_path}: {str(e)}")
                self._logger.error(f"Error scanning {file_path}", exc_info=True)
        
        self._logger.info(f"Configuration scan completed with {len(self.results)} findings")
        return self.results
    
    async def _find_config_files(self, target_path: Path) -> List[tuple[Path, str]]:
        """Find all configuration files in the target directory."""
        config_files = []
        
        # Skip certain directories
        skip_dirs = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__"}
        
        for config_type, patterns in self.CONFIG_FILES.items():
            for pattern in patterns:
                for file_path in target_path.rglob(pattern):
                    # Skip if in excluded directory
                    if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                        continue
                    
                    # Skip very large files
                    if file_path.stat().st_size > 1024 * 1024:  # 1MB
                        continue
                    
                    config_files.append((file_path, config_type))
        
        return config_files
    
    async def _scan_config_file(self, file_path: Path, config_type: str) -> None:
        """Scan a specific configuration file."""
        self._logger.debug(f"Scanning {config_type} file: {file_path}")
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Scan for hardcoded secrets
            await self._scan_for_secrets(content, file_path)
            
            # Scan for insecure configurations
            await self._scan_for_insecure_configs(content, file_path)
            
            # Type-specific scanning
            if config_type == "yaml":
                await self._scan_yaml_config(content, file_path)
            elif config_type == "json":
                await self._scan_json_config(content, file_path)
            elif config_type == "ini":
                await self._scan_ini_config(content, file_path)
            elif config_type == "xml":
                await self._scan_xml_config(content, file_path)
            elif config_type == "env":
                await self._scan_env_file(content, file_path)
            elif config_type == "docker":
                await self._scan_docker_config(content, file_path)
            elif config_type == "kubernetes":
                await self._scan_k8s_config(content, file_path)
            elif config_type == "terraform":
                await self._scan_terraform_config(content, file_path)
            elif config_type == "nginx":
                await self._scan_nginx_config(content, file_path)
            elif config_type == "apache":
                await self._scan_apache_config(content, file_path)
        
        except Exception as e:
            self._logger.error(f"Error scanning {file_path}: {e}")
    
    async def _scan_for_secrets(self, content: str, file_path: Path) -> None:
        """Scan content for hardcoded secrets."""
        # Split content into lines for line number tracking
        lines = content.split('\n')
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    # Extract the actual secret value
                    if match.groups():
                        secret_value = match.group(len(match.groups()))
                    else:
                        secret_value = match.group(0)
                    
                    # Mask the secret for evidence
                    masked_value = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:]
                    
                    self.add_result(ScannerResult(
                        category=FindingCategory.CONFIG_HARDCODED_CREDS,
                        severity=SeverityLevel.HIGH,
                        title=f"Hardcoded {secret_type.replace('_', ' ').title()} found",
                        description=f"A hardcoded {secret_type.replace('_', ' ')} was found in the configuration file",
                        evidence=f"Line {line_num}: {line.strip()[:50]}...\nFound: {masked_value}",
                        location=str(file_path),
                        file_path=str(file_path),
                        line_number=line_num,
                        confidence=0.9,
                        remediation_summary="Remove hardcoded secrets and use environment variables or secret management systems",
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                            "https://12factor.net/config"
                        ],
                    ))
    
    async def _scan_for_insecure_configs(self, content: str, file_path: Path) -> None:
        """Scan content for insecure configurations."""
        lines = content.split('\n')
        
        for config_type, pattern in self.INSECURE_CONFIGS.items():
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    severity = self._get_config_severity(config_type)
                    
                    self.add_result(ScannerResult(
                        category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                        severity=severity,
                        title=f"Insecure configuration: {config_type.replace('_', ' ').title()}",
                        description=self._get_config_description(config_type),
                        evidence=f"Line {line_num}: {line.strip()}",
                        location=str(file_path),
                        file_path=str(file_path),
                        line_number=line_num,
                        confidence=0.8,
                        remediation_summary=self._get_config_remediation(config_type),
                    ))
    
    async def _scan_yaml_config(self, content: str, file_path: Path) -> None:
        """Scan YAML configuration files."""
        try:
            data = yaml.safe_load(content)
            if data:
                await self._analyze_structured_config(data, file_path, "yaml")
        except yaml.YAMLError as e:
            self._logger.debug(f"Failed to parse YAML {file_path}: {e}")
    
    async def _scan_json_config(self, content: str, file_path: Path) -> None:
        """Scan JSON configuration files."""
        try:
            data = json.loads(content)
            await self._analyze_structured_config(data, file_path, "json")
        except json.JSONDecodeError as e:
            self._logger.debug(f"Failed to parse JSON {file_path}: {e}")
    
    async def _scan_ini_config(self, content: str, file_path: Path) -> None:
        """Scan INI configuration files."""
        try:
            parser = configparser.ConfigParser()
            parser.read_string(content)
            
            # Check for insecure settings
            for section in parser.sections():
                for key, value in parser.items(section):
                    # Check for exposed credentials
                    if any(cred in key.lower() for cred in ["password", "secret", "key", "token"]):
                        if value and not value.startswith("${") and not value.startswith("%("):
                            self.add_result(ScannerResult(
                                category=FindingCategory.CONFIG_HARDCODED_CREDS,
                                severity=SeverityLevel.HIGH,
                                title=f"Potential hardcoded credential in INI file",
                                description=f"Found potential credential in section [{section}]",
                                evidence=f"[{section}]\n{key} = {'*' * len(value)}",
                                location=str(file_path),
                                file_path=str(file_path),
                                confidence=0.7,
                                remediation_summary="Use environment variables or external configuration",
                            ))
        
        except Exception as e:
            self._logger.debug(f"Failed to parse INI {file_path}: {e}")
    
    async def _scan_xml_config(self, content: str, file_path: Path) -> None:
        """Scan XML configuration files."""
        try:
            root = ET.fromstring(content)
            
            # Look for security-related elements
            for elem in root.iter():
                # Check for passwords in attributes
                for attr, value in elem.attrib.items():
                    if "password" in attr.lower() and value:
                        self.add_result(ScannerResult(
                            category=FindingCategory.CONFIG_HARDCODED_CREDS,
                            severity=SeverityLevel.HIGH,
                            title="Hardcoded password in XML attribute",
                            description=f"Found password in XML element <{elem.tag}>",
                            evidence=f"<{elem.tag} {attr}=\"***\">",
                            location=str(file_path),
                            file_path=str(file_path),
                            confidence=0.8,
                            remediation_summary="Store passwords securely outside of configuration files",
                        ))
                
                # Check for security misconfigurations
                if elem.tag.lower() in ["security", "authentication", "authorization"]:
                    if elem.text and elem.text.lower() in ["false", "disabled", "none"]:
                        self.add_result(ScannerResult(
                            category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                            severity=SeverityLevel.MEDIUM,
                            title=f"Security feature disabled in XML",
                            description=f"Security feature <{elem.tag}> is disabled",
                            evidence=f"<{elem.tag}>{elem.text}</{elem.tag}>",
                            location=str(file_path),
                            file_path=str(file_path),
                            confidence=0.7,
                            remediation_summary="Enable security features in production",
                        ))
        
        except ET.ParseError as e:
            self._logger.debug(f"Failed to parse XML {file_path}: {e}")
    
    async def _scan_env_file(self, content: str, file_path: Path) -> None:
        """Scan .env files."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse key=value
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                
                # Check for sensitive keys
                sensitive_keys = ["password", "secret", "key", "token", "api", "database_url", "db_"]
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    if value and not value.startswith("${"):
                        self.add_result(ScannerResult(
                            category=FindingCategory.CONFIG_HARDCODED_CREDS,
                            severity=SeverityLevel.HIGH,
                            title=f"Hardcoded credential in .env file",
                            description=f"Found hardcoded {key} in environment file",
                            evidence=f"Line {line_num}: {key}={'*' * min(len(value), 10)}",
                            location=str(file_path),
                            file_path=str(file_path),
                            line_number=line_num,
                            confidence=0.9,
                            remediation_summary="Use secure secret management systems in production",
                            references=["https://12factor.net/config"],
                        ))
    
    async def _scan_docker_config(self, content: str, file_path: Path) -> None:
        """Scan Docker configuration files."""
        lines = content.split('\n')
        
        if file_path.name == "Dockerfile":
            for line_num, line in enumerate(lines, 1):
                # Check for hardcoded secrets in ENV
                if line.strip().startswith("ENV") and any(secret in line.lower() for secret in ["password", "secret", "key"]):
                    self.add_result(ScannerResult(
                        category=FindingCategory.CONFIG_HARDCODED_CREDS,
                        severity=SeverityLevel.HIGH,
                        title="Hardcoded secret in Dockerfile",
                        description="Secrets should not be hardcoded in Dockerfiles",
                        evidence=f"Line {line_num}: {line.strip()}",
                        location=str(file_path),
                        file_path=str(file_path),
                        line_number=line_num,
                        remediation_summary="Use Docker secrets or build arguments",
                    ))
                
                # Check for running as root
                if line.strip() == "USER root" or (not any("USER" in l for l in lines)):
                    if line_num == len(lines):  # Only report once at end if no USER directive
                        self.add_result(ScannerResult(
                            category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                            severity=SeverityLevel.MEDIUM,
                            title="Container running as root",
                            description="Container runs as root user by default",
                            evidence="No USER directive found or explicitly set to root",
                            location=str(file_path),
                            file_path=str(file_path),
                            remediation_summary="Add 'USER' directive to run as non-root",
                        ))
        
        elif "docker-compose" in file_path.name:
            try:
                data = yaml.safe_load(content)
                if data and "services" in data:
                    for service_name, service_config in data["services"].items():
                        # Check for privileged mode
                        if service_config.get("privileged", False):
                            self.add_result(ScannerResult(
                                category=FindingCategory.CONFIG_PERMISSIVE_ACCESS,
                                severity=SeverityLevel.HIGH,
                                title=f"Privileged container: {service_name}",
                                description="Container runs in privileged mode",
                                evidence=f"Service '{service_name}' has privileged: true",
                                location=str(file_path),
                                file_path=str(file_path),
                                remediation_summary="Avoid privileged mode unless absolutely necessary",
                            ))
                        
                        # Check for exposed sensitive ports
                        ports = service_config.get("ports", [])
                        sensitive_ports = {"3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB"}
                        for port in ports:
                            port_str = str(port)
                            for sensitive_port, service in sensitive_ports.items():
                                if sensitive_port in port_str and "127.0.0.1" not in port_str:
                                    self.add_result(ScannerResult(
                                        category=FindingCategory.CONFIG_PERMISSIVE_ACCESS,
                                        severity=SeverityLevel.MEDIUM,
                                        title=f"{service} port exposed: {service_name}",
                                        description=f"{service} port is exposed to all interfaces",
                                        evidence=f"Port mapping: {port}",
                                        location=str(file_path),
                                        file_path=str(file_path),
                                        remediation_summary="Bind to localhost only or use internal networks",
                                    ))
            
            except yaml.YAMLError:
                pass
    
    async def _scan_k8s_config(self, content: str, file_path: Path) -> None:
        """Scan Kubernetes configuration files."""
        try:
            docs = yaml.safe_load_all(content)
            for doc in docs:
                if not doc:
                    continue
                
                kind = doc.get("kind", "")
                
                # Check for security contexts
                if kind in ["Deployment", "Pod", "DaemonSet", "StatefulSet"]:
                    spec = doc.get("spec", {})
                    
                    # Check pod spec
                    pod_spec = spec
                    if "template" in spec:
                        pod_spec = spec["template"].get("spec", {})
                    
                    # Check if running as root
                    security_context = pod_spec.get("securityContext", {})
                    if not security_context.get("runAsNonRoot", False):
                        self.add_result(ScannerResult(
                            category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                            severity=SeverityLevel.MEDIUM,
                            title=f"K8s {kind} may run as root",
                            description=f"{kind} does not enforce non-root user",
                            evidence="No securityContext.runAsNonRoot: true",
                            location=str(file_path),
                            file_path=str(file_path),
                            remediation_summary="Set securityContext.runAsNonRoot: true",
                        ))
                    
                    # Check for privileged containers
                    containers = pod_spec.get("containers", [])
                    for container in containers:
                        container_sc = container.get("securityContext", {})
                        if container_sc.get("privileged", False):
                            self.add_result(ScannerResult(
                                category=FindingCategory.CONFIG_PERMISSIVE_ACCESS,
                                severity=SeverityLevel.HIGH,
                                title=f"Privileged container: {container.get('name', 'unnamed')}",
                                description="Container runs in privileged mode",
                                evidence=f"Container '{container.get('name')}' has privileged: true",
                                location=str(file_path),
                                file_path=str(file_path),
                                remediation_summary="Avoid privileged containers",
                            ))
                
                # Check for exposed secrets
                if kind == "Secret" and doc.get("type") != "Opaque":
                    self.add_result(ScannerResult(
                        category=FindingCategory.CONFIG_HARDCODED_CREDS,
                        severity=SeverityLevel.HIGH,
                        title="Kubernetes Secret in plain text",
                        description="Secret object contains unencrypted data",
                        evidence=f"Secret: {doc.get('metadata', {}).get('name', 'unnamed')}",
                        location=str(file_path),
                        file_path=str(file_path),
                        remediation_summary="Use sealed secrets or external secret management",
                    ))
        
        except yaml.YAMLError:
            pass
    
    async def _scan_terraform_config(self, content: str, file_path: Path) -> None:
        """Scan Terraform configuration files."""
        # Look for hardcoded credentials in variables
        if re.search(r'default\s*=\s*"[^"]*password[^"]*"', content, re.I):
            self.add_result(ScannerResult(
                category=FindingCategory.CONFIG_HARDCODED_CREDS,
                severity=SeverityLevel.HIGH,
                title="Hardcoded password in Terraform",
                description="Default password value found in Terraform configuration",
                location=str(file_path),
                file_path=str(file_path),
                remediation_summary="Use Terraform variables without defaults for secrets",
            ))
        
        # Check for public cloud resources
        if re.search(r'ingress.*cidr_blocks.*\["0\.0\.0\.0/0"\]', content):
            self.add_result(ScannerResult(
                category=FindingCategory.CONFIG_PERMISSIVE_ACCESS,
                severity=SeverityLevel.HIGH,
                title="Security group allows access from anywhere",
                description="Security group ingress rule allows 0.0.0.0/0",
                location=str(file_path),
                file_path=str(file_path),
                remediation_summary="Restrict security group rules to specific IP ranges",
            ))
    
    async def _scan_nginx_config(self, content: str, file_path: Path) -> None:
        """Scan Nginx configuration files."""
        # Check for missing security headers
        security_headers = [
            "add_header X-Frame-Options",
            "add_header X-Content-Type-Options",
            "add_header X-XSS-Protection",
            "add_header Strict-Transport-Security",
        ]
        
        missing_headers = []
        for header in security_headers:
            if header not in content:
                missing_headers.append(header.split()[-1])
        
        if missing_headers:
            self.add_result(ScannerResult(
                category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                severity=SeverityLevel.MEDIUM,
                title="Missing security headers in Nginx",
                description=f"Missing headers: {', '.join(missing_headers)}",
                location=str(file_path),
                file_path=str(file_path),
                remediation_summary="Add security headers to Nginx configuration",
                references=["https://securityheaders.com/"],
            ))
        
        # Check for SSL/TLS configuration
        if "ssl_protocols" in content:
            if any(proto in content for proto in ["SSLv2", "SSLv3", "TLSv1 ", "TLSv1.0"]):
                self.add_result(ScannerResult(
                    category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                    severity=SeverityLevel.HIGH,
                    title="Weak SSL/TLS protocols enabled",
                    description="Nginx allows weak SSL/TLS protocols",
                    location=str(file_path),
                    file_path=str(file_path),
                    remediation_summary="Use only TLS 1.2 and above",
                ))
    
    async def _scan_apache_config(self, content: str, file_path: Path) -> None:
        """Scan Apache configuration files."""
        # Check for directory listing
        if "Options" in content and "Indexes" in content and "Options -Indexes" not in content:
            self.add_result(ScannerResult(
                category=FindingCategory.CONFIG_PERMISSIVE_ACCESS,
                severity=SeverityLevel.MEDIUM,
                title="Directory listing enabled",
                description="Apache allows directory listing",
                location=str(file_path),
                file_path=str(file_path),
                remediation_summary="Add 'Options -Indexes' to disable directory listing",
            ))
        
        # Check for ServerSignature
        if "ServerSignature On" in content:
            self.add_result(ScannerResult(
                category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                severity=SeverityLevel.LOW,
                title="Server signature enabled",
                description="Apache reveals version information",
                location=str(file_path),
                file_path=str(file_path),
                remediation_summary="Set 'ServerSignature Off' and 'ServerTokens Prod'",
            ))
    
    async def _analyze_structured_config(self, data: Any, file_path: Path, format_type: str) -> None:
        """Analyze structured configuration data (JSON/YAML)."""
        if isinstance(data, dict):
            for key, value in data.items():
                # Check for sensitive keys
                if isinstance(key, str):
                    key_lower = key.lower()
                    
                    # Database connection strings
                    if any(db in key_lower for db in ["database_url", "db_url", "connection_string"]):
                        if isinstance(value, str) and "@" in value and not value.startswith("${"):
                            self.add_result(ScannerResult(
                                category=FindingCategory.CONFIG_HARDCODED_CREDS,
                                severity=SeverityLevel.CRITICAL,
                                title="Database connection string with credentials",
                                description="Database URL contains embedded credentials",
                                evidence=f"{key}: {self._mask_connection_string(value)}",
                                location=str(file_path),
                                file_path=str(file_path),
                                confidence=0.95,
                                remediation_summary="Use environment variables for database URLs",
                            ))
                    
                    # AWS credentials
                    if key_lower in ["aws_access_key_id", "aws_secret_access_key"]:
                        if isinstance(value, str) and value and not value.startswith("${"):
                            self.add_result(ScannerResult(
                                category=FindingCategory.CONFIG_HARDCODED_CREDS,
                                severity=SeverityLevel.CRITICAL,
                                title="AWS credentials in configuration",
                                description="AWS access keys found in configuration file",
                                evidence=f"{key}: {'*' * 10}",
                                location=str(file_path),
                                file_path=str(file_path),
                                confidence=0.95,
                                remediation_summary="Use IAM roles or AWS credentials file",
                            ))
                    
                    # Debug mode
                    if key_lower in ["debug", "debug_mode", "development_mode"]:
                        if value is True or str(value).lower() in ["true", "on", "yes", "1"]:
                            self.add_result(ScannerResult(
                                category=FindingCategory.CONFIG_INSECURE_DEFAULT,
                                severity=SeverityLevel.MEDIUM,
                                title="Debug mode enabled",
                                description="Application is running in debug mode",
                                evidence=f"{key}: {value}",
                                location=str(file_path),
                                file_path=str(file_path),
                                confidence=0.9,
                                remediation_summary="Disable debug mode in production",
                            ))
                
                # Recurse into nested structures
                if isinstance(value, (dict, list)):
                    await self._analyze_structured_config(value, file_path, format_type)
        
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    await self._analyze_structured_config(item, file_path, format_type)
    
    def _mask_connection_string(self, conn_str: str) -> str:
        """Mask credentials in connection string."""
        # Pattern: protocol://user:pass@host:port/db
        if "@" in conn_str:
            parts = conn_str.split("@")
            if len(parts) >= 2:
                proto_creds = parts[0]
                if "://" in proto_creds:
                    proto, creds = proto_creds.split("://", 1)
                    return f"{proto}://***:***@{parts[1]}"
        return conn_str
    
    def _get_config_severity(self, config_type: str) -> SeverityLevel:
        """Get severity level for configuration type."""
        severity_map = {
            "debug_enabled": SeverityLevel.MEDIUM,
            "ssl_disabled": SeverityLevel.HIGH,
            "allow_all": SeverityLevel.HIGH,
            "weak_cipher": SeverityLevel.HIGH,
            "no_auth": SeverityLevel.CRITICAL,
            "permissive_cors": SeverityLevel.MEDIUM,
            "public_bind": SeverityLevel.MEDIUM,
        }
        return severity_map.get(config_type, SeverityLevel.MEDIUM)
    
    def _get_config_description(self, config_type: str) -> str:
        """Get description for configuration issue."""
        descriptions = {
            "debug_enabled": "Debug mode is enabled, which may expose sensitive information",
            "ssl_disabled": "SSL/TLS is disabled, allowing unencrypted communication",
            "allow_all": "Permissive access control allows unrestricted access",
            "weak_cipher": "Weak encryption ciphers are configured",
            "no_auth": "Authentication is disabled or set to none",
            "permissive_cors": "CORS policy allows requests from any origin",
            "public_bind": "Service is bound to all network interfaces (0.0.0.0)",
        }
        return descriptions.get(config_type, "Insecure configuration detected")
    
    def _get_config_remediation(self, config_type: str) -> str:
        """Get remediation advice for configuration issue."""
        remediations = {
            "debug_enabled": "Disable debug mode in production environments",
            "ssl_disabled": "Enable SSL/TLS for all communications",
            "allow_all": "Implement proper access controls with specific allow lists",
            "weak_cipher": "Use strong encryption ciphers (AES, ChaCha20)",
            "no_auth": "Enable and properly configure authentication",
            "permissive_cors": "Configure CORS with specific allowed origins",
            "public_bind": "Bind services to specific interfaces or use 127.0.0.1 for local only",
        }
        return remediations.get(config_type, "Review and secure the configuration")