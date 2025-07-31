import re
import ipaddress
from typing import Set, List, Optional, Dict
from urllib.parse import urlparse


class DomainWhitelist:
    """
    Domain whitelisting for scanner restrictions.
    
    Ensures scanners only target approved domains/IPs.
    """
    
    def __init__(
        self,
        allowed_domains: Optional[Set[str]] = None,
        allowed_ips: Optional[Set[str]] = None,
        allowed_networks: Optional[List[str]] = None,
        blocked_domains: Optional[Set[str]] = None,
        blocked_ips: Optional[Set[str]] = None,
        allow_localhost: bool = False,
        allow_private_ips: bool = False
    ):
        """
        Initialize domain whitelist.
        
        Args:
            allowed_domains: Set of allowed domain patterns
            allowed_ips: Set of allowed IP addresses
            allowed_networks: List of allowed CIDR networks
            blocked_domains: Set of explicitly blocked domains
            blocked_ips: Set of explicitly blocked IPs
            allow_localhost: Whether to allow localhost/127.0.0.1
            allow_private_ips: Whether to allow private IP ranges
        """
        self.allowed_domains = allowed_domains or set()
        self.allowed_ips = allowed_ips or set()
        self.blocked_domains = blocked_domains or set()
        self.blocked_ips = blocked_ips or set()
        self.allow_localhost = allow_localhost
        self.allow_private_ips = allow_private_ips
        
        # Parse allowed networks
        self.allowed_networks = []
        for network in (allowed_networks or []):
            try:
                self.allowed_networks.append(ipaddress.ip_network(network))
            except ValueError:
                pass
        
        # Compile domain patterns
        self.domain_patterns = []
        for domain in self.allowed_domains:
            # Convert wildcard patterns to regex
            pattern = domain.replace(".", r"\.")
            pattern = pattern.replace("*", ".*")
            pattern = f"^{pattern}$"
            self.domain_patterns.append(re.compile(pattern, re.IGNORECASE))
        
        # Default blocked patterns (sensitive services)
        self.sensitive_patterns = [
            re.compile(r".*\.gov$", re.I),  # Government sites
            re.compile(r".*\.mil$", re.I),  # Military sites
            re.compile(r".*\.bank$", re.I),  # Banking sites
            re.compile(r".*localhost.*", re.I),  # Localhost variants
            re.compile(r".*\.local$", re.I),  # Local network
            re.compile(r".*\.internal$", re.I),  # Internal network
        ]
    
    def is_allowed(self, target: str) -> bool:
        """
        Check if target is allowed for scanning.
        
        Args:
            target: Target URL or domain
            
        Returns:
            True if allowed, False otherwise
        """
        # Parse URL
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        # Check if explicitly blocked
        if self._is_blocked(hostname):
            return False
        
        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            return self._is_ip_allowed(ip)
        except ValueError:
            # Not an IP, check domain
            return self._is_domain_allowed(hostname)
    
    def _is_blocked(self, hostname: str) -> bool:
        """
        Check if hostname is explicitly blocked.
        
        Args:
            hostname: Hostname to check
            
        Returns:
            True if blocked
        """
        # Check blocked domains
        if hostname in self.blocked_domains:
            return True
        
        # Check blocked IPs
        if hostname in self.blocked_ips:
            return True
        
        # Check sensitive patterns
        for pattern in self.sensitive_patterns:
            if pattern.match(hostname):
                return True
        
        return False
    
    def _is_ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """
        Check if IP address is allowed.
        
        Args:
            ip: IP address object
            
        Returns:
            True if allowed
        """
        ip_str = str(ip)
        
        # Check localhost
        if ip.is_loopback:
            return self.allow_localhost
        
        # Check private IPs
        if ip.is_private:
            return self.allow_private_ips
        
        # Check if explicitly allowed
        if ip_str in self.allowed_ips:
            return True
        
        # Check allowed networks
        for network in self.allowed_networks:
            if ip in network:
                return True
        
        # If we have a whitelist, IP must be in it
        if self.allowed_ips or self.allowed_networks:
            return False
        
        # Otherwise allow public IPs
        return not (ip.is_multicast or ip.is_reserved)
    
    def _is_domain_allowed(self, domain: str) -> bool:
        """
        Check if domain is allowed.
        
        Args:
            domain: Domain name
            
        Returns:
            True if allowed
        """
        # Normalize domain
        domain = domain.lower().strip()
        
        # Check exact match
        if domain in self.allowed_domains:
            return True
        
        # Check patterns
        for pattern in self.domain_patterns:
            if pattern.match(domain):
                return True
        
        # Check subdomain matches
        for allowed in self.allowed_domains:
            if allowed.startswith("*.") and domain.endswith(allowed[2:]):
                return True
            if domain.endswith(f".{allowed}"):
                return True
        
        # If we have a whitelist, domain must be in it
        if self.allowed_domains:
            return False
        
        # Otherwise allow if not sensitive
        return not any(pattern.match(domain) for pattern in self.sensitive_patterns)
    
    def get_blocked_reason(self, target: str) -> Optional[str]:
        """
        Get reason why target is blocked.
        
        Args:
            target: Target URL or domain
            
        Returns:
            Reason string or None if allowed
        """
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        # Check explicit blocks
        if hostname in self.blocked_domains:
            return f"Domain {hostname} is explicitly blocked"
        
        if hostname in self.blocked_ips:
            return f"IP {hostname} is explicitly blocked"
        
        # Check IP restrictions
        try:
            ip = ipaddress.ip_address(hostname)
            
            if ip.is_loopback and not self.allow_localhost:
                return "Localhost scanning is not allowed"
            
            if ip.is_private and not self.allow_private_ips:
                return "Private IP scanning is not allowed"
            
            if ip.is_multicast:
                return "Multicast addresses cannot be scanned"
            
            if ip.is_reserved:
                return "Reserved IP addresses cannot be scanned"
            
        except ValueError:
            # Check domain restrictions
            for pattern in self.sensitive_patterns:
                if pattern.match(hostname):
                    return f"Domain {hostname} matches sensitive pattern"
        
        # Check whitelist
        if not self.is_allowed(target):
            if self.allowed_domains or self.allowed_ips:
                return f"Target {hostname} is not in the whitelist"
            else:
                return f"Target {hostname} is not allowed"
        
        return None


class ScanThrottler:
    """
    Throttling for scan operations.
    
    Limits concurrent scans and scan frequency.
    """
    
    def __init__(
        self,
        max_concurrent_scans: int = 5,
        max_scans_per_user: int = 10,
        scan_cooldown: int = 60,  # seconds
        max_scans_per_target: int = 3,
        target_cooldown: int = 300  # seconds
    ):
        """
        Initialize scan throttler.
        
        Args:
            max_concurrent_scans: Maximum concurrent scans globally
            max_scans_per_user: Maximum concurrent scans per user
            scan_cooldown: Cooldown between scans for same user
            max_scans_per_target: Maximum scans per target
            target_cooldown: Cooldown between scans for same target
        """
        self.max_concurrent_scans = max_concurrent_scans
        self.max_scans_per_user = max_scans_per_user
        self.scan_cooldown = scan_cooldown
        self.max_scans_per_target = max_scans_per_target
        self.target_cooldown = target_cooldown
        
        # Tracking
        self.active_scans: Set[str] = set()
        self.user_scans: Dict[str, List[float]] = {}
        self.target_scans: Dict[str, List[float]] = {}
    
    def can_start_scan(
        self,
        user_id: str,
        target: str,
        current_time: Optional[float] = None
    ) -> bool:
        """
        Check if scan can be started.
        
        Args:
            user_id: User ID
            target: Target URL
            current_time: Current timestamp
            
        Returns:
            True if scan can start
        """
        import time
        current_time = current_time or time.time()
        
        # Check global limit
        if len(self.active_scans) >= self.max_concurrent_scans:
            return False
        
        # Check user limits
        user_scan_times = self.user_scans.get(user_id, [])
        
        # Clean old entries
        user_scan_times = [t for t in user_scan_times if current_time - t < self.scan_cooldown]
        
        if len(user_scan_times) >= self.max_scans_per_user:
            return False
        
        # Check target limits
        target_scan_times = self.target_scans.get(target, [])
        
        # Clean old entries
        target_scan_times = [t for t in target_scan_times if current_time - t < self.target_cooldown]
        
        if len(target_scan_times) >= self.max_scans_per_target:
            return False
        
        return True
    
    def register_scan(self, scan_id: str, user_id: str, target: str) -> None:
        """
        Register a new scan.
        
        Args:
            scan_id: Unique scan ID
            user_id: User ID
            target: Target URL
        """
        import time
        current_time = time.time()
        
        self.active_scans.add(scan_id)
        
        if user_id not in self.user_scans:
            self.user_scans[user_id] = []
        self.user_scans[user_id].append(current_time)
        
        if target not in self.target_scans:
            self.target_scans[target] = []
        self.target_scans[target].append(current_time)
    
    def unregister_scan(self, scan_id: str) -> None:
        """
        Unregister a completed scan.
        
        Args:
            scan_id: Scan ID
        """
        self.active_scans.discard(scan_id)
    
    def get_throttle_info(self, user_id: str, target: str) -> Dict[str, any]:
        """
        Get throttling information.
        
        Args:
            user_id: User ID
            target: Target URL
            
        Returns:
            Throttle status information
        """
        import time
        current_time = time.time()
        
        # User info
        user_scan_times = self.user_scans.get(user_id, [])
        user_scan_times = [t for t in user_scan_times if current_time - t < self.scan_cooldown]
        
        # Target info
        target_scan_times = self.target_scans.get(target, [])
        target_scan_times = [t for t in target_scan_times if current_time - t < self.target_cooldown]
        
        return {
            "global_active_scans": len(self.active_scans),
            "global_limit": self.max_concurrent_scans,
            "user_active_scans": len(user_scan_times),
            "user_limit": self.max_scans_per_user,
            "target_recent_scans": len(target_scan_times),
            "target_limit": self.max_scans_per_target,
            "can_scan": self.can_start_scan(user_id, target, current_time),
        }


class EthicalScanningPolicy:
    """
    Ethical scanning policy enforcement.
    """
    
    def __init__(
        self,
        respect_robots_txt: bool = True,
        max_requests_per_second: float = 10.0,
        user_agent: str = "MCP Security Scanner",
        non_destructive_only: bool = True
    ):
        """
        Initialize ethical scanning policy.
        
        Args:
            respect_robots_txt: Whether to respect robots.txt
            max_requests_per_second: Maximum requests per second to target
            user_agent: User agent string
            non_destructive_only: Only allow non-destructive scans
        """
        self.respect_robots_txt = respect_robots_txt
        self.max_requests_per_second = max_requests_per_second
        self.user_agent = user_agent
        self.non_destructive_only = non_destructive_only
    
    async def check_robots_txt(self, target_url: str) -> bool:
        """
        Check if scanning is allowed by robots.txt.
        
        Args:
            target_url: Target URL
            
        Returns:
            True if allowed
        """
        if not self.respect_robots_txt:
            return True
        
        try:
            from urllib.robotparser import RobotFileParser
            from urllib.parse import urlparse
            
            parsed = urlparse(target_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            
            return rp.can_fetch(self.user_agent, target_url)
        
        except Exception:
            # If we can't check, assume it's allowed
            return True
    
    def get_scan_headers(self) -> Dict[str, str]:
        """
        Get headers for ethical scanning.
        
        Returns:
            Dictionary of headers
        """
        return {
            "User-Agent": self.user_agent,
            "X-Scanner": "MCP Security Scanner",
            "X-Scanner-Contact": "security@example.com",  # Update with real contact
            "X-Scanner-Purpose": "Security Assessment",
        }