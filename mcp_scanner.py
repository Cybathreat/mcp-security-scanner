"""
MCP Security Scanner - Main Scanner Class
Scans MCP (Model Context Protocol) servers for security misconfigurations,
authentication flaws, exposed secrets, and insecure network bindings.
"""

import re
import socket
import json
import time
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

from config import ScannerConfig, ScanTarget, load_config, DEFAULT_SECRETS_PATTERNS
from report import Finding, ScanResult, ReportGenerator, create_scan_result


@dataclass
class MCPServiceInfo:
    """Discovered MCP service information."""
    host: str
    port: int
    protocol: str
    server_type: Optional[str] = None
    auth_required: bool = False
    auth_header: Optional[str] = None
    endpoints: List[str] = None
    config_exposed: bool = False


class MCPScanner:
    """
    Main security scanner for MCP servers.
    
    Performs:
    - Authentication misconfiguration detection
    - Hardcoded secret discovery
    - Insecure network binding audit
    - Admin endpoint exposure check
    - Configuration file exposure
    """
    
    VERSION = "1.0.0"
    
    # Known MCP admin/debug endpoints that should not be public
    ADMIN_ENDPOINTS = [
        '/admin', '/admin/config', '/admin/debug', '/admin/logs',
        '/debug', '/debug/vars', '/debug/pprof', '/health', '/metrics',
        '/config', '/.env', '/.git/config', '/backup', '/dump'
    ]
    
    # Common insecure binding patterns
    INSECURE_BINDINGS = ['0.0.0.0', '127.0.0.1', '::', '*']
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or load_config()
        self.report_generator = ReportGenerator(self.config.output_dir)
        self.findings: List[Finding] = []
        self.scanned_targets = 0
        self.start_time: Optional[float] = None
    
    async def scan_target(self, target: ScanTarget) -> List[Finding]:
        """Scan a single MCP target for security issues."""
        findings = []
        
        try:
            # Check network binding
            if self.config.check_insecure_bindings:
                network_findings = await self._check_network_binding(target)
                findings.extend(network_findings)
            
            # Check authentication
            if self.config.auth_check_enabled:
                auth_findings = await self._check_authentication(target)
                findings.extend(auth_findings)
            
            # Check for exposed secrets in responses
            if self.config.check_hardcoded_secrets:
                secret_findings = await self._check_exposed_secrets(target)
                findings.extend(secret_findings)
            
            # Check admin endpoint exposure
            if self.config.check_exposed_admin_endpoints:
                admin_findings = await self._check_admin_endpoints(target)
                findings.extend(admin_findings)
            
            # Check config file exposure
            if self.config.config_check_enabled:
                config_findings = await self._check_config_exposure(target)
                findings.extend(config_findings)
            
            # Check rate limiting
            rate_findings = await self._check_rate_limiting(target)
            findings.extend(rate_findings)
            
            self.scanned_targets += 1
            
        except Exception as e:
            findings.append(Finding(
                id=f"ERR-{target.host}-{target.port}",
                severity="INFO",
                category="network",
                title="Scan Error",
                description=f"Failed to scan target: {str(e)}",
                target_host=target.host,
                target_port=target.port
            ))
        
        return findings
    
    async def _check_network_binding(self, target: ScanTarget) -> List[Finding]:
        """Check if MCP server is bound to insecure network interfaces."""
        findings = []
        
        # Check if bound to all interfaces (0.0.0.0)
        if target.host in self.INSECURE_BINDINGS:
            findings.append(Finding(
                id=f"NET-{target.host}-{target.port}-001",
                severity="HIGH",
                category="network",
                title="Insecure Network Binding",
                description=f"MCP server is bound to {target.host}, making it accessible from all network interfaces. This exposes the service to potential unauthorized access from external networks.",
                target_host=target.host,
                target_port=target.port,
                evidence=f"Binding address: {target.host}",
                remediation="Bind the MCP server to localhost (127.0.0.1) or a specific internal interface unless external access is explicitly required. Implement firewall rules to restrict access.",
                cwe_id="CWE-284",
                cvss_score=7.5
            ))
        
        # Try to connect and check response headers for binding info
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{target.protocol}://{target.host}:{target.port}"
                async with session.get(url, timeout=target.timeout) as resp:
                    server_header = resp.headers.get('Server', '')
                    if '0.0.0.0' in server_header or '*' in server_header:
                        findings.append(Finding(
                            id=f"NET-{target.host}-{target.port}-002",
                            severity="MEDIUM",
                            category="network",
                            title="Server Header Reveals Insecure Binding",
                            description="Server HTTP header indicates binding to all interfaces.",
                            target_host=target.host,
                            target_port=target.port,
                            evidence=f"Server header: {server_header}",
                            remediation="Configure server to not expose binding information in headers.",
                            cwe_id="CWE-200"
                        ))
        except:
            pass  # Connection failed, that's ok
        
        return findings
    
    async def _check_authentication(self, target: ScanTarget) -> List[Finding]:
        """Check for authentication misconfigurations."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}"
                
                # Test without auth
                async with session.get(f"{base_url}/", timeout=target.timeout) as resp:
                    if resp.status == 200:
                        # Check if auth is missing when it should be required
                        auth_header = resp.headers.get('WWW-Authenticate')
                        if not auth_header and not target.auth_token:
                            findings.append(Finding(
                                id=f"AUTH-{target.host}-{target.port}-001",
                                severity="CRITICAL",
                                category="auth",
                                title="Missing Authentication",
                                description="MCP server responds successfully without any authentication. This allows unauthorized access to the service.",
                                target_host=target.host,
                                target_port=target.port,
                                evidence="HTTP 200 response without authentication",
                                remediation="Implement authentication (API keys, OAuth, JWT, or HTTP Basic Auth) for all MCP server endpoints.",
                                cwe_id="CWE-306",
                                cvss_score=9.8
                            ))
                
                # Test common admin endpoints without auth
                for endpoint in self.ADMIN_ENDPOINTS[:5]:  # Limit to first 5
                    try:
                        async with session.get(f"{base_url}{endpoint}", timeout=5) as resp:
                            if resp.status == 200:
                                findings.append(Finding(
                                    id=f"AUTH-{target.host}-{target.port}-002",
                                    severity="HIGH",
                                    category="auth",
                                    title="Admin Endpoint Accessible Without Auth",
                                    description=f"Admin/debug endpoint {endpoint} is accessible without authentication.",
                                    target_host=target.host,
                                    target_port=target.port,
                                    evidence=f"GET {endpoint} returned HTTP {resp.status}",
                                    remediation="Require authentication for all admin and debug endpoints. Consider removing debug endpoints in production.",
                                    cwe_id="CWE-306",
                                    cvss_score=8.6
                                ))
                    except:
                        pass
                
                # Check for rate limiting on auth endpoints (enhancement)
                rate_limit_findings = await self._check_rate_limiting(session, base_url)
                findings.extend(rate_limit_findings)
        
        except Exception as e:
            pass  # Connection issues handled gracefully
        
        return findings
    
    async def _check_rate_limiting(self, session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
        """Check if authentication endpoints implement rate limiting."""
        findings = []
        auth_endpoints = ['/auth', '/login', '/api/auth', '/authenticate']
        
        for endpoint in auth_endpoints:
            try:
                # Send rapid requests to detect rate limiting
                responses = []
                for _ in range(5):
                    async with session.post(f"{base_url}{endpoint}", json={}, timeout=3) as resp:
                        responses.append(resp.status)
                
                # If all requests succeed without 429, rate limiting may be missing
                if all(r == 200 for r in responses):
                    findings.append(Finding(
                        id=f"RATE-{base_url.split('://')[1].split(':')[0]}-001",
                        severity="MEDIUM",
                        category="auth",
                        title="No Rate Limiting Detected",
                        description=f"Authentication endpoint {endpoint} does not appear to implement rate limiting, making it vulnerable to brute force attacks.",
                        target_host=base_url,
                        target_port=0,
                        evidence="5 rapid requests all returned HTTP 200",
                        remediation="Implement rate limiting (e.g., max 5 attempts per minute per IP) on authentication endpoints.",
                        cwe_id="CWE-307",
                        cvss_score=5.3
                    ))
                    break
            except:
                pass
        
        return findings
    
    async def _check_exposed_secrets(self, target: ScanTarget) -> List[Finding]:
        """Check for exposed secrets in server responses."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}"
                
                # Fetch main endpoint
                async with session.get(base_url, timeout=target.timeout) as resp:
                    try:
                        content = await resp.text()
                        
                        # Check against secrets patterns
                        for pattern in self.config.secrets_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                findings.append(Finding(
                                    id=f"SEC-{target.host}-{target.port}-001",
                                    severity="CRITICAL",
                                    category="secrets",
                                    title="Hardcoded Secret Exposed",
                                    description="Server response contains hardcoded secrets or credentials that should not be exposed.",
                                    target_host=target.host,
                                    target_port=target.port,
                                    evidence=f"Pattern matched: {pattern[:50]}... Found: {matches[0][:100]}",
                                    remediation="Remove hardcoded secrets from responses. Use environment variables or secure secret management.",
                                    cwe_id="CWE-798",
                                    cvss_score=9.1
                                ))
                                break  # One finding per target for secrets
                    
                    except:
                        pass  # Binary or non-text response
                
                # Check config endpoint
                try:
                    async with session.get(f"{base_url}/config", timeout=5) as resp:
                        if resp.status == 200:
                            try:
                                config_data = await resp.json()
                                config_str = json.dumps(config_data)
                                
                                for pattern in self.config.secrets_patterns:
                                    if re.search(pattern, config_str):
                                        findings.append(Finding(
                                            id=f"SEC-{target.host}-{target.port}-002",
                                            severity="CRITICAL",
                                            category="secrets",
                                            title="Secrets in Config Endpoint",
                                            description="MCP /config endpoint exposes secrets in configuration.",
                                            target_host=target.host,
                                            target_port=target.port,
                                            evidence="Secrets found in /config JSON response",
                                            remediation="Sanitize config endpoint to exclude secrets. Use separate internal config for sensitive values.",
                                            cwe_id="CWE-200",
                                            cvss_score=8.6
                                        ))
                                        break
                            except:
                                pass
                except:
                    pass
        
        except Exception as e:
            pass
        
        return findings
    
    async def _check_admin_endpoints(self, target: ScanTarget) -> List[Finding]:
        """Check for exposed admin and debug endpoints."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}"
                
                for endpoint in self.ADMIN_ENDPOINTS:
                    try:
                        async with session.get(f"{base_url}{endpoint}", timeout=5) as resp:
                            if resp.status == 200:
                                # Check if it's an actual admin page
                                content = await resp.text()
                                if any(kw in content.lower() for kw in ['admin', 'debug', 'config', 'internal']):
                                    findings.append(Finding(
                                        id=f"ADM-{target.host}-{target.port}-001",
                                        severity="MEDIUM",
                                        category="config",
                                        title="Admin/Debug Endpoint Exposed",
                                        description=f"Internal endpoint {endpoint} is publicly accessible.",
                                        target_host=target.host,
                                        target_port=target.port,
                                        evidence=f"Accessible: {base_url}{endpoint}",
                                        remediation="Remove or restrict access to admin/debug endpoints in production. Use IP allowlists or authentication.",
                                        cwe_id="CWE-489",
                                        cvss_score=5.3
                                    ))
                                    break  # One finding per target
                    except:
                        pass
        
        except Exception as e:
            pass
        
        return findings
    
    async def _check_rate_limiting(self, target: ScanTarget) -> List[Finding]:
        """Check if target implements rate limiting by sending rapid requests."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}"
                endpoint = f"{base_url}/health"
                
                status_codes = []
                response_times = []
                
                # Send 10 rapid requests
                for i in range(10):
                    start = time.time()
                    try:
                        async with session.get(endpoint, timeout=5) as resp:
                            status_codes.append(resp.status)
                            response_times.append(time.time() - start)
                    except Exception as e:
                        status_codes.append(429 if "429" in str(e) else 503)
                        response_times.append(time.time() - start)
                
                # Check for 429 Too Many Requests
                if 429 in status_codes:
                    findings.append(Finding(
                        id=f"RATE-{target.host}-{target.port}-001",
                        severity="INFO",
                        category="security",
                        title="Rate Limiting Detected",
                        description="Target implements rate limiting (429 responses observed).",
                        target_host=target.host,
                        target_port=target.port,
                        evidence=f"429 response after {status_codes.index(429) + 1} requests",
                        remediation="N/A - Rate limiting is properly configured.",
                        cwe_id="CWE-770",
                        cvss_score=0.0
                    ))
                else:
                    # No rate limiting detected
                    avg_response_time = sum(response_times) / len(response_times)
                    if avg_response_time < 0.5:  # Fast responses, no throttling
                        findings.append(Finding(
                            id=f"RATE-{target.host}-{target.port}-001",
                            severity="MEDIUM",
                            category="security",
                            title="No Rate Limiting Detected",
                            description="Target does not appear to implement rate limiting. All 10 rapid requests succeeded without throttling.",
                            target_host=target.host,
                            target_port=target.port,
                            evidence=f"All requests returned 200, avg response time: {avg_response_time:.3f}s",
                            remediation="Implement rate limiting to prevent abuse and DoS attacks. Use token bucket or sliding window algorithms.",
                            cwe_id="CWE-770",
                            cvss_score=5.3
                        ))
        
        except Exception as e:
            pass
        
        return findings
    
    async def _check_config_exposure(self, target: ScanTarget) -> List[Finding]:
        """Check for exposed configuration files."""
        findings = []
        
        config_paths = ['/config', '/config.json', '/settings', '/.env', '/config.yaml']
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}"
                
                for path in config_paths:
                    try:
                        async with session.get(f"{base_url}{path}", timeout=5) as resp:
                            if resp.status == 200:
                                content_type = resp.headers.get('Content-Type', '')
                                if 'json' in content_type or 'yaml' in content_type or 'text' in content_type:
                                    findings.append(Finding(
                                        id=f"CFG-{target.host}-{target.port}-001",
                                        severity="HIGH",
                                        category="config",
                                        title="Configuration File Exposed",
                                        description=f"Configuration file at {path} is publicly accessible.",
                                        target_host=target.host,
                                        target_port=target.port,
                                        evidence=f"GET {path} returned {resp.headers.get('Content-Type')}",
                                        remediation="Block public access to configuration files. Serve configs from non-web-accessible locations.",
                                        cwe_id="CWE-538",
                                        cvss_score=7.5
                                    ))
                                    break
                    except:
                        pass
        
        except Exception as e:
            pass
        
        return findings
    
    async def scan_all(self) -> ScanResult:
        """Scan all configured targets and generate results."""
        self.start_time = time.time()
        self.findings = []
        self.scanned_targets = 0
        
        for target in self.config.targets:
            target_findings = await self.scan_target(target)
            self.findings.extend(target_findings)
        
        duration = time.time() - (self.start_time or time.time())
        
        result = create_scan_result(
            findings=self.findings,
            targets_scanned=self.scanned_targets,
            duration=duration
        )
        
        return result
    
    def generate_reports(self, result: ScanResult) -> Dict[str, str]:
        """Generate all report formats."""
        return self.report_generator.generate_all_reports(result)
    
    def run(self) -> Tuple[ScanResult, Dict[str, str]]:
        """Synchronous wrapper for scan execution."""
        result = asyncio.run(self.scan_all())
        reports = self.generate_reports(result)
        return result, reports


def run_scan(config_path: Optional[str] = None) -> Tuple[ScanResult, Dict[str, str]]:
    """Convenience function to run a full scan."""
    config = load_config(config_path)
    scanner = MCPScanner(config)
    return scanner.run()


if __name__ == "__main__":
    import sys
    
    config_file = sys.argv[1] if len(sys.argv) > 1 else None
    result, reports = run_scan(config_file)
    
    print(f"\n{'='*60}")
    print(f"MCP Security Scan Complete")
    print(f"{'='*60}")
    print(f"Scan ID: {result.scan_id}")
    print(f"Targets scanned: {result.targets_scanned}")
    print(f"Duration: {result.duration_seconds:.2f}s")
    print(f"Total findings: {len(result.findings)}")
    print(f"\nSeverity breakdown:")
    for sev, count in result.summary.items():
        print(f"  {sev}: {count}")
    print(f"\nReports generated:")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")
