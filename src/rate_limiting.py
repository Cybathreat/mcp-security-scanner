#!/usr/bin/env python3
"""
Rate Limiting / Rate Abuse Detector

Detects missing rate limits, misconfigured throttling, and rate abuse
vulnerabilities in MCP servers.
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class RateRiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RateFinding:
    finding_id: str
    title: str
    description: str
    risk_level: str
    affected_component: str
    abuse_vector: str
    impact: str
    remediation: str
    cwe_id: Optional[str] = None


class RateLimitDetector:
    """
    Detector for MCP rate limiting vulnerabilities.
    
    Checks for:
    - Missing rate limits on sensitive endpoints
    - Ineffective rate limit configurations
    - Bypass vectors
    - Resource exhaustion risks
    - DDoS amplification
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.findings: List[RateFinding] = []
        self.scanned_components: List[str] = []
        
    def scan_global_rate_limits(self, config: Dict) -> List[RateFinding]:
        """Check global rate limiting configuration."""
        findings = []
        self.scanned_components.append("global")
        
        rate_config = config.get("rate_limiting", {})
        
        # Check if rate limiting is disabled globally
        if rate_config.get("enabled") is False:
            findings.append(RateFinding(
                finding_id="MCP-Rate-001",
                title="Global Rate Limiting Disabled",
                description="Rate limiting is completely disabled",
                risk_level=RateRiskLevel.CRITICAL.value,
                affected_component="global",
                abuse_vector="Unlimited requests → resource exhaustion/DoS",
                impact="Service disruption, brute force attacks",
                remediation="Enable rate limiting with appropriate thresholds",
                cwe_id="CWE-400"
            ))
        
        # Check for excessive global limits
        requests_per_minute = rate_config.get("requests_per_minute", 0)
        if requests_per_minute == 0 or requests_per_minute > 10000:
            findings.append(RateFinding(
                finding_id="MCP-Rate-002",
                title="Excessive Global Rate Limit",
                description=f"Global limit: {requests_per_minute} req/min (too high or unlimited)",
                risk_level=RateRiskLevel.HIGH.value,
                affected_component="global",
                abuse_vector="High limit → volumetric attacks",
                impact="Resource exhaustion, service degradation",
                remediation="Set reasonable limits (100-1000 req/min typical)",
                cwe_id="CWE-400"
            ))
        
        # Check for missing burst handling
        if not rate_config.get("burst_limit"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-003",
                title="No Burst Limit",
                description="No burst/capacity limit configured",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="global",
                abuse_vector="Burst traffic → sudden resource spike",
                impact="Service instability, cascading failures",
                remediation="Configure burst limits and backpressure",
                cwe_id="CWE-400"
            ))
        
        # Check for missing rate limit headers
        if rate_config.get("include_headers") is False:
            findings.append(RateFinding(
                finding_id="MCP-Rate-004",
                title="Missing Rate Limit Headers",
                description="Rate limit headers not included in responses",
                risk_level=RateRiskLevel.LOW.value,
                affected_component="global",
                abuse_vector="No visibility → clients can't self-regulate",
                impact="Poor client behavior, accidental abuse",
                remediation="Include X-RateLimit-* headers in responses",
                cwe_id="CWE-200"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_endpoint_rate_limits(self, endpoints: List[Dict]) -> List[RateFinding]:
        """Check rate limits on individual endpoints."""
        findings = []
        
        # Sensitive endpoints that MUST have rate limits
        sensitive_endpoints = [
            ("/auth", "authentication"),
            ("/login", "authentication"),
            ("/register", "authentication"),
            ("/password", "credential reset"),
            ("/token", "token generation"),
            ("/api", "API access"),
            ("/graphql", "query execution"),
            ("/search", "resource enumeration"),
            ("/export", "data extraction"),
            ("/download", "data extraction"),
        ]
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            self.scanned_components.append(f"endpoint/{path}")
            
            # Check if sensitive endpoint lacks rate limit
            is_sensitive = any(path.startswith(s[0]) for s in sensitive_endpoints)
            
            if is_sensitive and not endpoint.get("rate_limit"):
                endpoint_type = next((s[1] for s in sensitive_endpoints if path.startswith(s[0])), "sensitive")
                findings.append(RateFinding(
                    finding_id="MCP-Rate-005",
                    title=f"No Rate Limit on {endpoint_type.title()} Endpoint",
                    description=f"Sensitive endpoint '{path}' has no rate limiting",
                    risk_level=RateRiskLevel.HIGH.value,
                    affected_component=path,
                    abuse_vector=f"Unlimited {endpoint_type} → brute force/enumeration",
                    impact=f"Credential compromise, {endpoint_type} abuse",
                    remediation=f"Implement rate limiting on {path}",
                    cwe_id="CWE-307"
                ))
            
            # Check for permissive rate limits on data endpoints
            if "data" in path or "bulk" in path or "export" in path:
                rate_limit = endpoint.get("rate_limit", {})
                limit = rate_limit.get("requests_per_minute", 0)
                if limit == 0 or limit > 100:
                    findings.append(RateFinding(
                        finding_id="MCP-Rate-006",
                        title="Permissive Rate Limit on Data Endpoint",
                        description=f"Data endpoint '{path}' allows {limit} req/min",
                        risk_level=RateRiskLevel.MEDIUM.value,
                        affected_component=path,
                        abuse_vector="High limit on data endpoint → scraping",
                        impact="Data exfiltration, competitive scraping",
                        remediation="Reduce limit to 10-50 req/min for data endpoints",
                        cwe_id="CWE-307"
                    ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_auth_rate_limits(self, config: Dict) -> List[RateFinding]:
        """Check authentication-specific rate limits."""
        findings = []
        self.scanned_components.append("auth")
        
        auth_config = config.get("authentication", {})
        rate_config = auth_config.get("rate_limiting", {})
        
        # Check for missing login rate limit
        if not rate_config.get("login_attempts"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-007",
                title="No Login Attempt Limit",
                description="No limit on login attempts per account/IP",
                risk_level=RateRiskLevel.HIGH.value,
                affected_component="auth/login",
                abuse_vector="Unlimited logins → credential stuffing",
                impact="Account compromise",
                remediation="Limit to 5-10 attempts per minute per account",
                cwe_id="CWE-307"
            ))
        
        # Check for missing password reset rate limit
        if not rate_config.get("password_reset"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-008",
                title="No Password Reset Limit",
                description="No limit on password reset requests",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="auth/reset",
                abuse_vector="Unlimited resets → DoS/email spam",
                impact="User harassment, email reputation damage",
                remediation="Limit to 3-5 resets per hour per account",
                cwe_id="CWE-307"
            ))
        
        # Check for missing token generation rate limit
        if not rate_config.get("token_generation"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-009",
                title="No Token Generation Limit",
                description="No limit on API token/session creation",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="auth/token",
                abuse_vector="Unlimited tokens → resource exhaustion",
                impact="Session table exhaustion, memory pressure",
                remediation="Limit token generation per user/IP",
                cwe_id="CWE-400"
            ))
        
        # Check for missing account enumeration protection
        if rate_config.get("uniform_response", True) is False:
            findings.append(RateFinding(
                finding_id="MCP-Rate-010",
                title="Account Enumeration via Timing",
                description="Different response times for valid/invalid accounts",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="auth",
                abuse_vector="Timing differences → user enumeration",
                impact="User list disclosure, targeted attacks",
                remediation="Use constant-time responses for auth attempts",
                cwe_id="CWE-208"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_api_rate_limits(self, config: Dict) -> List[RateFinding]:
        """Check API-specific rate limits."""
        findings = []
        self.scanned_components.append("api")
        
        api_config = config.get("api", {})
        rate_config = api_config.get("rate_limiting", {})
        
        # Check for missing API key rate limits
        if not rate_config.get("per_api_key"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-011",
                title="No Per-API-Key Rate Limit",
                description="Rate limits not enforced per API key",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="api",
                abuse_vector="Single key can exhaust resources",
                impact="Service disruption, unfair resource usage",
                remediation="Implement per-API-key rate limiting",
                cwe_id="CWE-400"
            ))
        
        # Check for missing tier-based limits
        if not rate_config.get("tier_limits"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-012",
                title="No Tier-Based Rate Limits",
                description="All users have same rate limits regardless of tier",
                risk_level=RateRiskLevel.LOW.value,
                affected_component="api",
                abuse_vector="Free tier can abuse resources",
                impact="Resource imbalance, paid tier devaluation",
                remediation="Implement tiered rate limits",
                cwe_id="CWE-284"
            ))
        
        # Check for missing rate limit bypass protection
        if rate_config.get("header_override") is True:
            findings.append(RateFinding(
                finding_id="MCP-Rate-013",
                title="Rate Limit Header Override",
                description="X-Forwarded-For or similar headers can override rate limits",
                risk_level=RateRiskLevel.HIGH.value,
                affected_component="api",
                abuse_vector="Header spoofing → rate limit bypass",
                impact="Complete rate limit circumvention",
                remediation="Ignore or validate forwarding headers",
                cwe_id="CWE-284"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_resource_limits(self, config: Dict) -> List[RateFinding]:
        """Check resource consumption limits."""
        findings = []
        self.scanned_components.append("resources")
        
        resource_config = config.get("resources", {})
        
        # Check for missing request size limit
        if not resource_config.get("max_request_size"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-014",
                title="No Request Size Limit",
                description="No maximum request body size configured",
                risk_level=RateRiskLevel.HIGH.value,
                affected_component="resources",
                abuse_vector="Large requests → memory exhaustion",
                impact="DoS via memory consumption",
                remediation="Set max request size (e.g., 10MB)",
                cwe_id="CWE-400"
            ))
        
        # Check for missing query complexity limit
        if "graphql" in config or resource_config.get("max_query_depth", 0) == 0:
            findings.append(RateFinding(
                finding_id="MCP-Rate-015",
                title="No Query Complexity Limit",
                description="No limit on query depth/complexity",
                risk_level=RateRiskLevel.HIGH.value,
                affected_component="resources",
                abuse_vector="Complex queries → CPU exhaustion",
                impact="DoS via computational overload",
                remediation="Set max query depth and complexity limits",
                cwe_id="CWE-400"
            ))
        
        # Check for missing concurrent connection limit
        if not resource_config.get("max_connections"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-016",
                title="No Connection Limit",
                description="No maximum concurrent connections configured",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="resources",
                abuse_vector="Connection flood → socket exhaustion",
                impact="Service unavailability",
                remediation="Set max concurrent connections",
                cwe_id="CWE-400"
            ))
        
        # Check for missing timeout
        if not resource_config.get("request_timeout"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-017",
                title="No Request Timeout",
                description="No timeout configured for requests",
                risk_level=RateRiskLevel.MEDIUM.value,
                affected_component="resources",
                abuse_vector="Slow requests → connection exhaustion",
                impact="Slowloris-style DoS",
                remediation="Set request timeout (30-60 seconds)",
                cwe_id="CWE-400"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_ddos_amplification(self, config: Dict) -> List[RateFinding]:
        """Check for DDoS amplification vectors."""
        findings = []
        self.scanned_components.append("ddos")
        
        # Check for expensive operations without limits
        expensive_ops = ["search", "aggregate", "report", "export", "analyze"]
        
        endpoints = config.get("endpoints", [])
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            op_type = endpoint.get("operation", "")
            
            if any(op in op_type.lower() or op in path.lower() for op in expensive_ops):
                if not endpoint.get("rate_limit"):
                    findings.append(RateFinding(
                        finding_id="MCP-Rate-018",
                        title="Expensive Operation Unlimited",
                        description=f"Expensive operation '{path}' has no rate limit",
                        risk_level=RateRiskLevel.HIGH.value,
                        affected_component=path,
                        abuse_vector="Expensive ops → amplification attack",
                        impact="Resource amplification, DDoS",
                        remediation="Rate limit expensive operations",
                        cwe_id="CWE-400"
                    ))
        
        # Check for missing geographic rate limiting
        if not config.get("rate_limiting", {}).get("geo_limits"):
            findings.append(RateFinding(
                finding_id="MCP-Rate-019",
                title="No Geographic Rate Limiting",
                description="No rate limits based on geographic origin",
                risk_level=RateRiskLevel.LOW.value,
                affected_component="global",
                abuse_vector="Single region can flood service",
                impact="Regional DDoS",
                remediation="Implement geo-based rate limiting",
                cwe_id="CWE-400"
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
            "components_scanned": len(self.scanned_components)
        }
        return summary


def detect_rate_limit_issues(config_path: str) -> Dict[str, Any]:
    """
    Main entry point for rate limit detection.
    
    Args:
        config_path: Path to MCP server configuration file
        
    Returns:
        Dictionary with findings and summary
    """
    import yaml
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    detector = RateLimitDetector()
    
    detector.scan_global_rate_limits(config)
    
    endpoints = config.get("endpoints", [])
    if endpoints:
        detector.scan_endpoint_rate_limits(endpoints)
    
    detector.scan_auth_rate_limits(config)
    detector.scan_api_rate_limits(config)
    detector.scan_resource_limits(config)
    detector.scan_ddos_amplification(config)
    
    return {
        "findings": detector.get_all_findings(),
        "summary": detector.get_summary(),
        "components_scanned": detector.scanned_components
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python rate_limiting.py <config_path>")
        sys.exit(1)
    
    result = detect_rate_limit_issues(sys.argv[1])
    print(json.dumps(result, indent=2))
