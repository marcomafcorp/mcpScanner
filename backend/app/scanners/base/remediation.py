from dataclasses import dataclass
from typing import Dict, List, Optional

from app.models.finding import FindingCategory, SeverityLevel


@dataclass
class RemediationStep:
    """A single remediation step."""
    order: int
    description: str
    command: Optional[str] = None
    references: List[str] = None


@dataclass
class RemediationPlan:
    """Complete remediation plan for a vulnerability."""
    priority: str  # critical, high, medium, low
    summary: str
    steps: List[RemediationStep]
    effort_estimate: str
    prerequisites: List[str]
    references: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "priority": self.priority,
            "summary": self.summary,
            "steps": [
                {
                    "order": step.order,
                    "description": step.description,
                    "command": step.command,
                    "references": step.references or [],
                }
                for step in self.steps
            ],
            "effort_estimate": self.effort_estimate,
            "prerequisites": self.prerequisites,
            "references": self.references,
        }


class RemediationEngine:
    """Engine for generating remediation recommendations."""
    
    def __init__(self):
        self._remediation_db = self._build_remediation_database()
    
    def _build_remediation_database(self) -> Dict[FindingCategory, Dict]:
        """Build the remediation database."""
        return {
            # Dependency vulnerabilities
            FindingCategory.DEPENDENCY: {
                "summary": "Update vulnerable dependencies",
                "steps": [
                    RemediationStep(1, "Review the vulnerability details and affected versions"),
                    RemediationStep(2, "Check if a patched version is available", "npm audit"),
                    RemediationStep(3, "Update to the latest secure version", "npm update <package>"),
                    RemediationStep(4, "Run tests to ensure compatibility"),
                    RemediationStep(5, "Deploy the updated application"),
                ],
                "effort": "1-2 hours",
                "prerequisites": ["Access to source code", "Deployment permissions"],
            },
            
            # Configuration issues
            FindingCategory.CONFIG_INSECURE_DEFAULT: {
                "summary": "Secure default configurations",
                "steps": [
                    RemediationStep(1, "Identify all insecure default settings"),
                    RemediationStep(2, "Create secure configuration templates"),
                    RemediationStep(3, "Update configuration files with secure values"),
                    RemediationStep(4, "Implement configuration validation"),
                    RemediationStep(5, "Test application with new configurations"),
                ],
                "effort": "2-4 hours",
                "prerequisites": ["Configuration file access", "Understanding of secure defaults"],
            },
            
            FindingCategory.CONFIG_HARDCODED_CREDS: {
                "summary": "Remove hardcoded credentials",
                "steps": [
                    RemediationStep(1, "Identify all hardcoded credentials"),
                    RemediationStep(2, "Set up secure credential storage (e.g., environment variables, secrets manager)"),
                    RemediationStep(3, "Replace hardcoded values with secure references"),
                    RemediationStep(4, "Rotate all exposed credentials"),
                    RemediationStep(5, "Implement credential scanning in CI/CD"),
                ],
                "effort": "4-8 hours",
                "prerequisites": ["Secrets management system", "CI/CD pipeline access"],
            },
            
            FindingCategory.CONFIG_PERMISSIVE_ACCESS: {
                "summary": "Implement proper access controls",
                "steps": [
                    RemediationStep(1, "Review current access control policies"),
                    RemediationStep(2, "Define principle of least privilege access"),
                    RemediationStep(3, "Implement role-based access control (RBAC)"),
                    RemediationStep(4, "Configure proper file and directory permissions"),
                    RemediationStep(5, "Test access controls thoroughly"),
                ],
                "effort": "1-2 days",
                "prerequisites": ["Access control system", "User role definitions"],
            },
            
            # Code vulnerabilities
            FindingCategory.CODE_INJECTION_SQL: {
                "summary": "Fix SQL injection vulnerabilities",
                "steps": [
                    RemediationStep(1, "Identify all dynamic SQL queries"),
                    RemediationStep(2, "Replace with parameterized queries or prepared statements"),
                    RemediationStep(3, "Implement input validation and sanitization"),
                    RemediationStep(4, "Use ORM/query builder where possible"),
                    RemediationStep(5, "Add SQL injection testing to QA process"),
                ],
                "effort": "1-3 days",
                "prerequisites": ["Database access", "Code deployment permissions"],
            },
            
            FindingCategory.CODE_INJECTION_XSS: {
                "summary": "Fix XSS vulnerabilities",
                "steps": [
                    RemediationStep(1, "Identify all user input reflection points"),
                    RemediationStep(2, "Implement proper output encoding/escaping"),
                    RemediationStep(3, "Use Content Security Policy (CSP) headers"),
                    RemediationStep(4, "Validate and sanitize all user inputs"),
                    RemediationStep(5, "Use secure templating engines with auto-escaping"),
                ],
                "effort": "1-2 days",
                "prerequisites": ["Frontend framework knowledge", "CSP understanding"],
            },
            
            FindingCategory.CODE_INJECTION_CMD: {
                "summary": "Fix command injection vulnerabilities",
                "steps": [
                    RemediationStep(1, "Identify all system command executions"),
                    RemediationStep(2, "Avoid shell command execution where possible"),
                    RemediationStep(3, "Use language-specific APIs instead of shell commands"),
                    RemediationStep(4, "If shell required, use proper escaping and whitelisting"),
                    RemediationStep(5, "Implement strict input validation"),
                ],
                "effort": "1-2 days",
                "prerequisites": ["System command knowledge", "Alternative API awareness"],
            },
            
            # Network vulnerabilities
            FindingCategory.NETWORK_OPEN_PORT: {
                "summary": "Secure open ports",
                "steps": [
                    RemediationStep(1, "Review all open ports and their purposes"),
                    RemediationStep(2, "Close unnecessary ports", "sudo ufw deny <port>"),
                    RemediationStep(3, "Implement firewall rules for required ports"),
                    RemediationStep(4, "Use VPN or SSH tunneling for administrative access"),
                    RemediationStep(5, "Monitor port access logs"),
                ],
                "effort": "2-4 hours",
                "prerequisites": ["Firewall access", "Network configuration permissions"],
            },
            
            FindingCategory.NETWORK_WEAK_PROTOCOL: {
                "summary": "Upgrade to secure protocols",
                "steps": [
                    RemediationStep(1, "Identify all weak protocol usage"),
                    RemediationStep(2, "Plan migration to secure alternatives (e.g., HTTPS, SSH)"),
                    RemediationStep(3, "Update server configurations"),
                    RemediationStep(4, "Update client applications"),
                    RemediationStep(5, "Disable weak protocols completely"),
                ],
                "effort": "1-2 days",
                "prerequisites": ["SSL/TLS certificates", "Server configuration access"],
            },
            
            # Web vulnerabilities
            FindingCategory.WEB_AUTHENTICATION: {
                "summary": "Strengthen authentication mechanisms",
                "steps": [
                    RemediationStep(1, "Review current authentication implementation"),
                    RemediationStep(2, "Implement secure password policies"),
                    RemediationStep(3, "Add multi-factor authentication (MFA)"),
                    RemediationStep(4, "Use secure session management"),
                    RemediationStep(5, "Implement account lockout policies"),
                ],
                "effort": "3-5 days",
                "prerequisites": ["MFA system", "Session storage infrastructure"],
            },
            
            FindingCategory.WEB_AUTHORIZATION: {
                "summary": "Fix authorization vulnerabilities",
                "steps": [
                    RemediationStep(1, "Map all authorization points"),
                    RemediationStep(2, "Implement consistent authorization checks"),
                    RemediationStep(3, "Use centralized authorization service"),
                    RemediationStep(4, "Implement proper RBAC/ABAC"),
                    RemediationStep(5, "Add authorization testing to QA"),
                ],
                "effort": "2-4 days",
                "prerequisites": ["Authorization framework", "User role mappings"],
            },
        }
    
    def get_remediation_plan(
        self,
        category: FindingCategory,
        severity: SeverityLevel,
        cve_id: Optional[str] = None,
        custom_info: Optional[Dict] = None,
    ) -> RemediationPlan:
        """Generate a remediation plan for a finding."""
        # Get base remediation from database
        base_remediation = self._remediation_db.get(
            category,
            {
                "summary": "Apply security best practices",
                "steps": [
                    RemediationStep(1, "Review the vulnerability details"),
                    RemediationStep(2, "Research appropriate fixes"),
                    RemediationStep(3, "Implement and test the fix"),
                    RemediationStep(4, "Deploy the fix to production"),
                ],
                "effort": "Varies",
                "prerequisites": ["Technical knowledge of the issue"],
            }
        )
        
        # Determine priority based on severity
        priority_map = {
            SeverityLevel.CRITICAL: "critical",
            SeverityLevel.HIGH: "high",
            SeverityLevel.MEDIUM: "medium",
            SeverityLevel.LOW: "low",
            SeverityLevel.INFO: "low",
        }
        
        # Build references
        references = []
        if cve_id:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
            references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
        
        # Add category-specific references
        category_refs = {
            FindingCategory.CODE_INJECTION_SQL: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            FindingCategory.CODE_INJECTION_XSS: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            FindingCategory.WEB_AUTHENTICATION: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
            ],
        }
        
        if category in category_refs:
            references.extend(category_refs[category])
        
        return RemediationPlan(
            priority=priority_map[severity],
            summary=base_remediation["summary"],
            steps=base_remediation["steps"],
            effort_estimate=base_remediation["effort"],
            prerequisites=base_remediation["prerequisites"],
            references=references,
        )
    
    def get_quick_fix(self, category: FindingCategory) -> Optional[str]:
        """Get a quick fix command or snippet if available."""
        quick_fixes = {
            FindingCategory.DEPENDENCY: "npm audit fix",
            FindingCategory.NETWORK_OPEN_PORT: "sudo ufw deny {port}",
            FindingCategory.CONFIG_PERMISSIVE_ACCESS: "chmod 600 {file}",
        }
        return quick_fixes.get(category)