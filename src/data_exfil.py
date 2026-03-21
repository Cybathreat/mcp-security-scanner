#!/usr/bin/env python3
"""
Data Exfiltration Vector Detector

Detects potential data exfiltration paths in MCP servers including
unauthorized data access, insecure data transmission, and leakage vectors.
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class ExfilRiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ExfilFinding:
    finding_id: str
    title: str
    description: str
    risk_level: str
    affected_component: str
    exfil_vector: str
    data_at_risk: str
    remediation: str
    cwe_id: Optional[str] = None


class DataExfilDetector:
    """
    Detector for MCP data exfiltration vulnerabilities.
    
    Checks for:
    - Unrestricted data access
    - Insecure data transmission
    - Logging of sensitive data
    - Missing data classification
    - Unvalidated data exports
    - Side-channel leakage
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.findings: List[ExfilFinding] = []
        self.scanned_components: List[str] = []
        
    def scan_data_handlers(self, handlers: List[Dict]) -> List[ExfilFinding]:
        """Scan data handlers for exfiltration risks."""
        findings = []
        
        for handler in handlers:
            handler_name = handler.get("name", "unknown")
            self.scanned_components.append(f"handler/{handler_name}")
            
            # Check for unrestricted data access
            if handler.get("access_level") == "unrestricted":
                findings.append(ExfilFinding(
                    finding_id="MCP-Exfil-001",
                    title="Unrestricted Data Access",
                    description=f"Handler '{handler_name}' has unrestricted data access",
                    risk_level=ExfilRiskLevel.CRITICAL.value,
                    affected_component=handler_name,
                    exfil_vector="Unrestricted read → full data dump",
                    data_at_risk="All accessible data",
                    remediation="Implement role-based access control",
                    cwe_id="CWE-284"
                ))
            
            # Check for missing output validation
            if not handler.get("output_validation", False):
                findings.append(ExfilFinding(
                    finding_id="MCP-Exfil-002",
                    title="Missing Output Validation",
                    description=f"Handler '{handler_name}' does not validate output",
                    risk_level=ExfilRiskLevel.HIGH.value,
                    affected_component=handler_name,
                    exfil_vector="Unvalidated output → data leakage",
                    data_at_risk="Response data",
                    remediation="Implement output filtering and validation",
                    cwe_id="CWE-200"
                ))
            
            # Check for dangerous data operations
            ops = handler.get("operations", [])
            dangerous_ops = ["export", "dump", "download", "bulk_read", "replicate"]
            
            for op in ops:
                if op.lower() in dangerous_ops and not handler.get("requires_approval"):
                    findings.append(ExfilFinding(
                        finding_id="MCP-Exfil-003",
                        title="Unapproved Data Export",
                        description=f"Handler '{handler_name}' allows '{op}' without approval",
                        risk_level=ExfilRiskLevel.HIGH.value,
                        affected_component=handler_name,
                        exfil_vector=f"{op} operation → bulk data exfiltration",
                        data_at_risk="Exported data",
                        remediation="Require approval for bulk data operations",
                        cwe_id="CWE-284"
                    ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_data_transmission(self, config: Dict) -> List[ExfilFinding]:
        """Check data transmission security."""
        findings = []
        self.scanned_components.append("transmission")
        
        network = config.get("network", {})
        
        # Check for unencrypted transmission
        if network.get("encrypt_data") is False:
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-004",
                title="Unencrypted Data Transmission",
                description="Data transmission is not encrypted",
                risk_level=ExfilRiskLevel.CRITICAL.value,
                affected_component="network/transmission",
                exfil_vector="Cleartext → network sniffing",
                data_at_risk="All transmitted data",
                remediation="Enable TLS 1.3 for all data transmission",
                cwe_id="CWE-311"
            ))
        
        # Check for weak TLS configuration
        tls_config = network.get("tls", {})
        if tls_config.get("min_version") in ["1.0", "1.1"]:
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-005",
                title="Weak TLS Version",
                description=f"Minimum TLS version: {tls_config.get('min_version')}",
                risk_level=ExfilRiskLevel.HIGH.value,
                affected_component="network/tls",
                exfil_vector="Weak TLS → cryptographic attacks",
                data_at_risk="Encrypted data",
                remediation="Set minimum TLS version to 1.2 or 1.3",
                cwe_id="CWE-327"
            ))
        
        # Check for missing certificate validation
        if network.get("verify_certs") is False:
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-006",
                title="Certificate Validation Disabled",
                description="TLS certificate validation is disabled",
                risk_level=ExfilRiskLevel.HIGH.value,
                affected_component="network/tls",
                exfil_vector="No cert validation → MITM attacks",
                data_at_risk="All transmitted data",
                remediation="Enable strict certificate validation",
                cwe_id="CWE-295"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_logging_config(self, config: Dict) -> List[ExfilFinding]:
        """Check logging for sensitive data leakage."""
        findings = []
        self.scanned_components.append("logging")
        
        logging_config = config.get("logging", {})
        
        # Check for sensitive data in logs
        if logging_config.get("log_sensitive", True):
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-007",
                title="Sensitive Data Logging",
                description="Logging configured to include sensitive data",
                risk_level=ExfilRiskLevel.HIGH.value,
                affected_component="logging",
                exfil_vector="Log files → credential/PII exposure",
                data_at_risk="Credentials, PII, secrets",
                remediation="Disable logging of sensitive fields",
                cwe_id="CWE-532"
            ))
        
        # Check for missing log redaction
        sensitive_fields = ["password", "token", "secret", "api_key", "credential"]
        redact_fields = logging_config.get("redact_fields", [])
        
        for field in sensitive_fields:
            if field not in redact_fields:
                findings.append(ExfilFinding(
                    finding_id="MCP-Exfil-008",
                    title="Unredacted Sensitive Field",
                    description=f"Field '{field}' not in redaction list",
                    risk_level=ExfilRiskLevel.MEDIUM.value,
                    affected_component="logging",
                    exfil_vector="Log output → credential leakage",
                    data_at_risk=field,
                    remediation=f"Add '{field}' to redact_fields",
                    cwe_id="CWE-532"
                ))
                break  # Only report once
        
        # Check for verbose debug logging in production
        if logging_config.get("level") in ["DEBUG", "TRACE"]:
            if not config.get("development", False):
                findings.append(ExfilFinding(
                    finding_id="MCP-Exfil-009",
                    title="Verbose Logging in Production",
                    description="Debug/trace logging enabled in production",
                    risk_level=ExfilRiskLevel.MEDIUM.value,
                    affected_component="logging",
                    exfil_vector="Debug logs → internal state exposure",
                    data_at_risk="Application state, stack traces",
                    remediation="Set log level to INFO or WARN in production",
                    cwe_id="CWE-532"
                ))
        
        # Check for world-readable log files
        if logging_config.get("file_mode", 0o644) > 0o600:
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-010",
                title="World-Readable Log Files",
                description=f"Log file mode: {oct(logging_config.get('file_mode'))}",
                risk_level=ExfilRiskLevel.MEDIUM.value,
                affected_component="logging",
                exfil_vector="Readable logs → data exposure",
                data_at_risk="All logged data",
                remediation="Set log file mode to 0600",
                cwe_id="CWE-732"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_data_classification(self, config: Dict) -> List[ExfilFinding]:
        """Check data classification and handling."""
        findings = []
        self.scanned_components.append("classification")
        
        data_config = config.get("data", {})
        
        # Check for missing data classification
        if not data_config.get("classification_enabled", False):
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-011",
                title="No Data Classification",
                description="Data classification is not enabled",
                risk_level=ExfilRiskLevel.MEDIUM.value,
                affected_component="data",
                exfil_vector="Unclassified data → inappropriate handling",
                data_at_risk="All data",
                remediation="Enable data classification with sensitivity levels",
                cwe_id="CWE-284"
            ))
        
        # Check for missing PII detection
        if data_config.get("pii_detection") is False:
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-012",
                title="PII Detection Disabled",
                description="Personally identifiable information detection is disabled",
                risk_level=ExfilRiskLevel.HIGH.value,
                affected_component="data",
                exfil_vector="Undetected PII → privacy violation",
                data_at_risk="Personal data",
                remediation="Enable PII detection and masking",
                cwe_id="CWE-359"
            ))
        
        # Check for missing data retention policy
        if not data_config.get("retention_policy"):
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-013",
                title="No Data Retention Policy",
                description="No data retention/deletion policy configured",
                risk_level=ExfilRiskLevel.LOW.value,
                affected_component="data",
                exfil_vector="Indefinite retention → increased exposure window",
                data_at_risk="Stored data",
                remediation="Implement data retention and automatic deletion",
                cwe_id="CWE-284"
            ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_api_endpoints(self, endpoints: List[Dict]) -> List[ExfilFinding]:
        """Scan API endpoints for data exfiltration risks."""
        findings = []
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            self.scanned_components.append(f"endpoint/{path}")
            
            # Check for bulk data endpoints without auth
            if endpoint.get("bulk", False) and not endpoint.get("requires_auth", True):
                findings.append(ExfilFinding(
                    finding_id="MCP-Exfil-014",
                    title="Unauthenticated Bulk Data Endpoint",
                    description=f"Bulk endpoint '{path}' does not require authentication",
                    risk_level=ExfilRiskLevel.CRITICAL.value,
                    affected_component=path,
                    exfil_vector="Bulk read → mass data exfiltration",
                    data_at_risk="All accessible data",
                    remediation="Require authentication for bulk endpoints",
                    cwe_id="CWE-306"
                ))
            
            # Check for missing rate limiting on data endpoints
            if "data" in path or "export" in path or "download" in path:
                if not endpoint.get("rate_limit"):
                    findings.append(ExfilFinding(
                        finding_id="MCP-Exfil-015",
                        title="No Rate Limit on Data Endpoint",
                        description=f"Data endpoint '{path}' has no rate limiting",
                        risk_level=ExfilRiskLevel.HIGH.value,
                        affected_component=path,
                        exfil_vector="No rate limit → automated scraping",
                        data_at_risk="Endpoint data",
                        remediation="Implement rate limiting",
                        cwe_id="CWE-307"
                    ))
            
            # Check for pagination bypass
            if endpoint.get("pagination") is False and endpoint.get("max_results", 0) > 1000:
                findings.append(ExfilFinding(
                    finding_id="MCP-Exfil-016",
                    title="Pagination Bypass",
                    description=f"Endpoint '{path}' allows large result sets",
                    risk_level=ExfilRiskLevel.MEDIUM.value,
                    affected_component=path,
                    exfil_vector="Large result set → bulk data extraction",
                    data_at_risk="Query results",
                    remediation="Enforce pagination with reasonable limits",
                    cwe_id="CWE-284"
                ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_side_channels(self, config: Dict) -> List[ExfilFinding]:
        """Check for side-channel leakage."""
        findings = []
        self.scanned_components.append("side_channels")
        
        # Check for timing oracle
        if config.get("timing_safe_compare") is False:
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-017",
                title="Timing Oracle Vulnerability",
                description="String comparisons not timing-safe",
                risk_level=ExfilRiskLevel.MEDIUM.value,
                affected_component="auth/compare",
                exfil_vector="Timing differences → information leakage",
                data_at_risk="Comparison results",
                remediation="Use constant-time comparison functions",
                cwe_id="CWE-208"
            ))
        
        # Check for error message leakage
        error_config = config.get("errors", {})
        if error_config.get("verbose", False):
            findings.append(ExfilFinding(
                finding_id="MCP-Exfil-018",
                title="Verbose Error Messages",
                description="Error messages include internal details",
                risk_level=ExfilRiskLevel.MEDIUM.value,
                affected_component="errors",
                exfil_vector="Error messages → stack traces/internal state",
                data_at_risk="Application internals",
                remediation="Use generic error messages in production",
                cwe_id="CWE-209"
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


def detect_data_exfil_vectors(config_path: str) -> Dict[str, Any]:
    """
    Main entry point for data exfiltration detection.
    
    Args:
        config_path: Path to MCP server configuration file
        
    Returns:
        Dictionary with findings and summary
    """
    import yaml
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    detector = DataExfilDetector()
    
    handlers = config.get("handlers", [])
    if handlers:
        detector.scan_data_handlers(handlers)
    
    detector.scan_data_transmission(config)
    detector.scan_logging_config(config)
    detector.scan_data_classification(config)
    
    endpoints = config.get("endpoints", [])
    if endpoints:
        detector.scan_api_endpoints(endpoints)
    
    detector.scan_side_channels(config)
    
    return {
        "findings": detector.get_all_findings(),
        "summary": detector.get_summary(),
        "components_scanned": detector.scanned_components
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python data_exfil.py <config_path>")
        sys.exit(1)
    
    result = detect_data_exfil_vectors(sys.argv[1])
    print(json.dumps(result, indent=2))
