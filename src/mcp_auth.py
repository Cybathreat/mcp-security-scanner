#!/usr/bin/env python3
"""
MCP Authentication/Authorization Scanner

Scans MCP (Model Context Protocol) servers for authentication and authorization
misconfigurations, weak credentials, and privilege escalation vectors.
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class AuthRiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuthFinding:
    finding_id: str
    title: str
    description: str
    risk_level: str
    affected_endpoint: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


class MCPAuthScanner:
    """
    Scanner for MCP authentication and authorization vulnerabilities.
    
    Checks for:
    - Missing authentication on sensitive endpoints
    - Weak token validation
    - Hardcoded credentials
    - Insecure token storage
    - Privilege escalation paths
    - Session fixation vulnerabilities
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.findings: List[AuthFinding] = []
        self.scanned_endpoints: List[str] = []
        
    def scan_auth_config(self, config_data: Dict) -> List[AuthFinding]:
        """Scan MCP server configuration for auth weaknesses."""
        findings = []
        
        # Check for missing auth requirements
        if "authentication" in config_data:
            auth_config = config_data["authentication"]
            
            # Check if auth is disabled
            if auth_config.get("enabled") is False:
                findings.append(AuthFinding(
                    finding_id="MCP-Auth-001",
                    title="Authentication Disabled",
                    description="MCP server has authentication completely disabled",
                    risk_level=AuthRiskLevel.CRITICAL.value,
                    affected_endpoint="global",
                    remediation="Enable authentication with strong token validation",
                    cwe_id="CWE-306",
                    cvss_score=9.8
                ))
            
            # Check for weak token algorithms
            token_alg = auth_config.get("token_algorithm", "")
            if token_alg.lower() in ["none", "plain", "md5", "sha1"]:
                findings.append(AuthFinding(
                    finding_id="MCP-Auth-002",
                    title="Weak Token Algorithm",
                    description=f"Using weak/insecure token algorithm: {token_alg}",
                    risk_level=AuthRiskLevel.HIGH.value,
                    affected_endpoint="auth/token",
                    remediation="Use HS256, RS256, or EdDSA for token signing",
                    cwe_id="CWE-327",
                    cvss_score=7.5
                ))
            
            # Check for hardcoded secrets
            if "secret" in auth_config and len(str(auth_config["secret"])) < 32:
                findings.append(AuthFinding(
                    finding_id="MCP-Auth-003",
                    title="Weak Secret Key",
                    description="Secret key is too short (< 32 characters)",
                    risk_level=AuthRiskLevel.HIGH.value,
                    affected_endpoint="auth/config",
                    remediation="Use a cryptographically secure random secret of at least 256 bits",
                    cwe_id="CWE-326",
                    cvss_score=7.0
                ))
        
        # Check for exposed credentials in config
        self._scan_hardcoded_creds(config_data, findings)
        
        # Check for insecure session settings
        self._scan_session_config(config_data, findings)
        
        self.findings.extend(findings)
        return findings
    
    def _scan_hardcoded_creds(self, config_data: Dict, findings: List[AuthFinding]):
        """Detect hardcoded credentials in configuration."""
        cred_patterns = [
            (r"['\"]?password['\"]?\s*[=:]\s*['\"]([^'\"]+)['\"]", "Hardcoded Password"),
            (r"['\"]?api_key['\"]?\s*[=:]\s*['\"]([^'\"]+)['\"]", "Hardcoded API Key"),
            (r"['\"]?secret['\"]?\s*[=:]\s*['\"]([^'\"]+)['\"]", "Hardcoded Secret"),
            (r"['\"]?token['\"]?\s*[=:]\s*['\"]([^'\"]+)['\"]", "Hardcoded Token"),
        ]
        
        config_str = json.dumps(config_data)
        
        for pattern, cred_type in cred_patterns:
            matches = re.findall(pattern, config_str, re.IGNORECASE)
            if matches:
                findings.append(AuthFinding(
                    finding_id="MCP-Auth-004",
                    title=cred_type,
                    description=f"Found hardcoded {cred_type} in configuration",
                    risk_level=AuthRiskLevel.HIGH.value,
                    affected_endpoint="config",
                    remediation="Use environment variables or secure vault for credentials",
                    cwe_id="CWE-798",
                    cvss_score=7.5
                ))
                break
    
    def _scan_session_config(self, config_data: Dict, findings: List[AuthFinding]):
        """Check session security settings."""
        session = config_data.get("session", {})
        
        # Check for insecure cookie settings
        if session.get("secure_cookie") is False:
            findings.append(AuthFinding(
                finding_id="MCP-Auth-005",
                title="Insecure Cookie Flag",
                description="Session cookies not marked as secure",
                risk_level=AuthRiskLevel.MEDIUM.value,
                affected_endpoint="session",
                remediation="Set secure flag on all session cookies",
                cwe_id="CWE-614",
                cvss_score=5.3
            ))
        
        # Check for missing HTTP-only flag
        if session.get("http_only") is False:
            findings.append(AuthFinding(
                finding_id="MCP-Auth-006",
                title="Missing HttpOnly Flag",
                description="Session cookies accessible via JavaScript",
                risk_level=AuthRiskLevel.MEDIUM.value,
                affected_endpoint="session",
                remediation="Set HttpOnly flag on session cookies",
                cwe_id="CWE-1004",
                cvss_score=5.0
            ))
        
        # Check for excessive session timeout
        timeout = session.get("timeout_seconds", 0)
        if timeout > 86400:  # > 24 hours
            findings.append(AuthFinding(
                finding_id="MCP-Auth-007",
                title="Excessive Session Timeout",
                description=f"Session timeout too long: {timeout} seconds",
                risk_level=AuthRiskLevel.LOW.value,
                affected_endpoint="session",
                remediation="Reduce session timeout to 1-4 hours for sensitive operations",
                cwe_id="CWE-613",
                cvss_score=3.5
            ))
    
    def scan_endpoint_auth(self, endpoint: str, auth_config: Dict) -> List[AuthFinding]:
        """Scan individual endpoint for auth weaknesses."""
        findings = []
        self.scanned_endpoints.append(endpoint)
        
        # Check if sensitive endpoint lacks auth
        sensitive_patterns = [
            r"/admin", r"/config", r"/secret", r"/internal",
            r"/debug", r"/metrics", r"/health", r"/.well-known"
        ]
        
        is_sensitive = any(re.search(p, endpoint) for p in sensitive_patterns)
        
        if is_sensitive and not auth_config.get("requires_auth", True):
            findings.append(AuthFinding(
                finding_id="MCP-Auth-008",
                title="Unauthenticated Sensitive Endpoint",
                description=f"Sensitive endpoint {endpoint} does not require authentication",
                risk_level=AuthRiskLevel.HIGH.value,
                affected_endpoint=endpoint,
                remediation="Require authentication for all sensitive endpoints",
                cwe_id="CWE-306",
                cvss_score=7.5
            ))
        
        # Check for missing rate limiting on auth endpoints
        if "/auth" in endpoint or "/login" in endpoint:
            if not auth_config.get("rate_limit"):
                findings.append(AuthFinding(
                    finding_id="MCP-Auth-009",
                    title="No Rate Limiting on Auth Endpoint",
                    description=f"Auth endpoint {endpoint} has no rate limiting",
                    risk_level=AuthRiskLevel.MEDIUM.value,
                    affected_endpoint=endpoint,
                    remediation="Implement rate limiting to prevent brute force attacks",
                    cwe_id="CWE-307",
                    cvss_score=5.5
                ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_tool_permissions(self, tools: List[Dict]) -> List[AuthFinding]:
        """Check tool permission configurations for privilege escalation."""
        findings = []
        
        dangerous_tools = ["shell", "exec", "file_write", "config_modify", "user_manage"]
        
        for tool in tools:
            tool_name = tool.get("name", "")
            
            # Check if dangerous tools are unrestricted
            if any(d in tool_name.lower() for d in dangerous_tools):
                if tool.get("requires_auth") is False:
                    findings.append(AuthFinding(
                        finding_id="MCP-Auth-010",
                        title="Unrestricted Dangerous Tool",
                        description=f"Dangerous tool '{tool_name}' does not require authentication",
                        risk_level=AuthRiskLevel.CRITICAL.value,
                        affected_endpoint=f"tool/{tool_name}",
                        remediation="Require authentication and authorization for dangerous tools",
                        cwe_id="CWE-284",
                        cvss_score=9.0
                    ))
        
        self.findings.extend(findings)
        return findings
    
    def get_all_findings(self) -> List[Dict]:
        """Return all findings as serializable dicts."""
        return [asdict(f) for f in self.findings]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary statistics."""
        summary = {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.risk_level == "critical"),
            "high": sum(1 for f in self.findings if f.risk_level == "high"),
            "medium": sum(1 for f in self.findings if f.risk_level == "medium"),
            "low": sum(1 for f in self.findings if f.risk_level == "low"),
            "info": sum(1 for f in self.findings if f.risk_level == "info"),
            "endpoints_scanned": len(self.scanned_endpoints)
        }
        return summary


def scan_mcp_auth(config_path: str) -> Dict[str, Any]:
    """
    Main entry point for MCP auth scanning.
    
    Args:
        config_path: Path to MCP server configuration file
        
    Returns:
        Dictionary with findings and summary
    """
    import yaml
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    scanner = MCPAuthScanner()
    scanner.scan_auth_config(config)
    
    tools = config.get("tools", [])
    if tools:
        scanner.scan_tool_permissions(tools)
    
    endpoints = config.get("endpoints", [])
    for endpoint in endpoints:
        auth_config = endpoint.get("auth", {})
        scanner.scan_endpoint_auth(endpoint.get("path", ""), auth_config)
    
    return {
        "findings": scanner.get_all_findings(),
        "summary": scanner.get_summary(),
        "endpoints_scanned": scanner.scanned_endpoints
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mcp_auth.py <config_path>")
        sys.exit(1)
    
    result = scan_mcp_auth(sys.argv[1])
    print(json.dumps(result, indent=2))
