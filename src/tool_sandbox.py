#!/usr/bin/env python3
"""
Tool Sandboxing Validator

Validates MCP tool sandboxing configurations to detect escape vectors,
unsafe command execution, and insufficient isolation.
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class SandboxRiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SandboxFinding:
    finding_id: str
    title: str
    description: str
    risk_level: str
    affected_tool: str
    vector: str
    remediation: str
    cwe_id: Optional[str] = None
    exploit_likelihood: str = "unknown"


class ToolSandboxValidator:
    """
    Validator for MCP tool sandboxing security.
    
    Checks for:
    - Command injection vectors
    - Path traversal vulnerabilities
    - Unsafe subprocess configurations
    - Missing input validation
    - Dangerous tool permissions
    - Container escape vectors
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.findings: List[SandboxFinding] = []
        self.validated_tools: List[str] = []
        
    def validate_tool_config(self, tool_config: Dict) -> List[SandboxFinding]:
        """Validate a single tool's sandbox configuration."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        self.validated_tools.append(tool_name)
        
        # Check command execution tools
        if tool_config.get("type") in ["shell", "exec", "command", "process"]:
            findings.extend(self._check_command_injection(tool_config))
            findings.extend(self._check_shell_escape(tool_config))
        
        # Check file system tools
        if tool_config.get("type") in ["file_read", "file_write", "fs"]:
            findings.extend(self._check_path_traversal(tool_config))
            findings.extend(self._check_file_permissions(tool_config))
        
        # Check network tools
        if tool_config.get("type") in ["http", "request", "network", "fetch"]:
            findings.extend(self._check_ssrf(tool_config))
            findings.extend(self._check_unsafe_protocols(tool_config))
        
        # Check for missing sandbox settings
        findings.extend(self._check_sandbox_config(tool_config))
        
        self.findings.extend(findings)
        return findings
    
    def _check_command_injection(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check for command injection vulnerabilities."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        # Check if tool accepts user input without sanitization
        params = tool_config.get("parameters", {})
        
        # Dangerous parameter patterns
        dangerous_params = ["cmd", "command", "shell", "exec", "run", "script"]
        
        for param_name, param_config in params.items():
            if any(d in param_name.lower() for d in dangerous_params):
                if not param_config.get("sanitize", False) and not param_config.get("allowlist"):
                    findings.append(SandboxFinding(
                        finding_id="MCP-Sandbox-001",
                        title="Command Injection Vector",
                        description=f"Parameter '{param_name}' accepts shell commands without sanitization",
                        risk_level=SandboxRiskLevel.CRITICAL.value,
                        affected_tool=tool_name,
                        vector=f"User input → {param_name} → shell execution",
                        remediation="Implement strict allowlist validation or use parameterized commands",
                        cwe_id="CWE-78",
                        exploit_likelihood="high"
                    ))
        
        # Check for direct shell access
        if tool_config.get("shell", False) and not tool_config.get("restricted_shell"):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-002",
                title="Unrestricted Shell Access",
                description="Tool provides direct shell access without restrictions",
                risk_level=SandboxRiskLevel.CRITICAL.value,
                affected_tool=tool_name,
                vector="Direct shell → arbitrary command execution",
                remediation="Use restricted shell or implement command allowlist",
                cwe_id="CWE-78",
                exploit_likelihood="high"
            ))
        
        return findings
    
    def _check_shell_escape(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check for shell escape vectors."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        # Check if subprocess allows shell=True
        exec_config = tool_config.get("execution", {})
        if exec_config.get("shell", False):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-003",
                title="Shell=True in Subprocess",
                description="Subprocess execution uses shell=True enabling shell expansion",
                risk_level=SandboxRiskLevel.HIGH.value,
                affected_tool=tool_name,
                vector="shell=True → command chaining via ; | &",
                remediation="Use shell=False with argument arrays",
                cwe_id="CWE-78",
                exploit_likelihood="medium"
            ))
        
        # Check for dangerous environment variable inheritance
        if exec_config.get("inherit_env", True):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-004",
                title="Environment Variable Inheritance",
                description="Tool inherits parent environment variables",
                risk_level=SandboxRiskLevel.MEDIUM.value,
                affected_tool=tool_name,
                vector="Inherited env vars → potential credential leakage",
                remediation="Explicitly set minimal environment variables",
                cwe_id="CWE-213",
                exploit_likelihood="medium"
            ))
        
        return findings
    
    def _check_path_traversal(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check for path traversal vulnerabilities."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        params = tool_config.get("parameters", {})
        
        for param_name, param_config in params.items():
            if "path" in param_name.lower() or "file" in param_name.lower():
                if not param_config.get("restrict_base_dir"):
                    findings.append(SandboxFinding(
                        finding_id="MCP-Sandbox-005",
                        title="Path Traversal Vector",
                        description=f"Parameter '{param_name}' allows path traversal",
                        risk_level=SandboxRiskLevel.HIGH.value,
                        affected_tool=tool_name,
                        vector="../ sequences → arbitrary file access",
                        remediation="Implement base directory restriction and path normalization",
                        cwe_id="CWE-22",
                        exploit_likelihood="high"
                    ))
        
        # Check for world-writable directories
        fs_config = tool_config.get("filesystem", {})
        if fs_config.get("allow_world_writable", False):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-006",
                title="World-Writable Directory Access",
                description="Tool can write to world-writable directories",
                risk_level=SandboxRiskLevel.MEDIUM.value,
                affected_tool=tool_name,
                vector="/tmp, /var/tmp → symlink attacks",
                remediation="Restrict to application-owned directories",
                cwe_id="CWE-377",
                exploit_likelihood="medium"
            ))
        
        return findings
    
    def _check_file_permissions(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check file permission configurations."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        fs_config = tool_config.get("filesystem", {})
        
        # Check for overly permissive file creation
        file_mode = fs_config.get("file_mode", 0o777)
        if file_mode and file_mode > 0o644:
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-007",
                title="Overly Permissive File Mode",
                description=f"Files created with mode {oct(file_mode)}",
                risk_level=SandboxRiskLevel.MEDIUM.value,
                affected_tool=tool_name,
                vector="World-readable/writable files → data exposure",
                remediation="Use restrictive file modes (0600 or 0640)",
                cwe_id="CWE-732",
                exploit_likelihood="medium"
            ))
        
        # Check if tool can read sensitive system files
        allowed_paths = fs_config.get("allowed_paths", [])
        sensitive_patterns = ["/etc/passwd", "/etc/shadow", "/proc", "/sys"]
        
        for path in allowed_paths:
            if any(s in path for s in sensitive_patterns):
                findings.append(SandboxFinding(
                    finding_id="MCP-Sandbox-008",
                    title="Sensitive File Access",
                    description=f"Tool can access sensitive system path: {path}",
                    risk_level=SandboxRiskLevel.HIGH.value,
                    affected_tool=tool_name,
                    vector="System file read → credential/information disclosure",
                    remediation="Remove sensitive paths from allowed list",
                    cwe_id="CWE-200",
                    exploit_likelihood="medium"
                ))
        
        return findings
    
    def _check_ssrf(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check for SSRF vulnerabilities."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        net_config = tool_config.get("network", {})
        
        # Check if internal networks are accessible
        if not net_config.get("block_internal", True):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-009",
                title="Internal Network Access",
                description="Tool can access internal/private IP ranges",
                risk_level=SandboxRiskLevel.HIGH.value,
                affected_tool=tool_name,
                vector="SSRF → internal service enumeration/exploitation",
                remediation="Block access to 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x",
                cwe_id="CWE-918",
                exploit_likelihood="high"
            ))
        
        # Check for missing URL validation
        if not net_config.get("url_allowlist"):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-010",
                title="No URL Allowlist",
                description="Network tool has no URL allowlist configured",
                risk_level=SandboxRiskLevel.MEDIUM.value,
                affected_tool=tool_name,
                vector="Arbitrary URL → SSRF/data exfiltration",
                remediation="Implement strict URL allowlist",
                cwe_id="CWE-918",
                exploit_likelihood="medium"
            ))
        
        return findings
    
    def _check_unsafe_protocols(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check for unsafe protocol usage."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        net_config = tool_config.get("network", {})
        allowed_protocols = net_config.get("allowed_protocols", ["http", "https"])
        
        unsafe_protocols = ["file", "gopher", "dict", "ftp", "ldap", "tftp"]
        
        for protocol in allowed_protocols:
            if protocol.lower() in unsafe_protocols:
                findings.append(SandboxFinding(
                    finding_id="MCP-Sandbox-011",
                    title="Unsafe Protocol Allowed",
                    description=f"Protocol '{protocol}' is allowed (SSRF vector)",
                    risk_level=SandboxRiskLevel.HIGH.value,
                    affected_tool=tool_name,
                    vector=f"{protocol}:// → file read/port scan/service probe",
                    remediation=f"Remove {protocol} from allowed protocols",
                    cwe_id="CWE-918",
                    exploit_likelihood="high"
                ))
        
        return findings
    
    def _check_sandbox_config(self, tool_config: Dict) -> List[SandboxFinding]:
        """Check overall sandbox configuration."""
        findings = []
        tool_name = tool_config.get("name", "unknown")
        
        sandbox = tool_config.get("sandbox", {})
        
        # Check if sandboxing is disabled
        if sandbox.get("enabled") is False:
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-012",
                title="Sandboxing Disabled",
                description="Tool sandboxing is completely disabled",
                risk_level=SandboxRiskLevel.CRITICAL.value,
                affected_tool=tool_name,
                vector="No isolation → full system access",
                remediation="Enable sandboxing with appropriate isolation",
                cwe_id="CWE-284",
                exploit_likelihood="high"
            ))
        
        # Check for missing resource limits
        if not sandbox.get("resource_limits"):
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-013",
                title="No Resource Limits",
                description="Tool has no CPU/memory/resource limits",
                risk_level=SandboxRiskLevel.MEDIUM.value,
                affected_tool=tool_name,
                vector="Unbounded resources → DoS/resource exhaustion",
                remediation="Set CPU, memory, and timeout limits",
                cwe_id="CWE-400",
                exploit_likelihood="medium"
            ))
        
        # Check for missing timeout
        timeout = sandbox.get("timeout_seconds", 0)
        if timeout == 0 or timeout > 300:
            findings.append(SandboxFinding(
                finding_id="MCP-Sandbox-014",
                title="Missing/Excessive Timeout",
                description=f"Tool timeout: {timeout}s (should be < 300s)",
                risk_level=SandboxRiskLevel.LOW.value,
                affected_tool=tool_name,
                vector="Long-running processes → resource exhaustion",
                remediation="Set timeout to 30-300 seconds",
                cwe_id="CWE-400",
                exploit_likelihood="low"
            ))
        
        # Check for container escape vectors
        if sandbox.get("container"):
            container = sandbox["container"]
            if container.get("privileged", False):
                findings.append(SandboxFinding(
                    finding_id="MCP-Sandbox-015",
                    title="Privileged Container",
                    description="Tool runs in privileged container mode",
                    risk_level=SandboxRiskLevel.CRITICAL.value,
                    affected_tool=tool_name,
                    vector="Privileged container → host escape",
                    remediation="Disable privileged mode, use seccomp/AppArmor",
                    cwe_id="CWE-284",
                    exploit_likelihood="high"
                ))
            
            if not container.get("read_only_root", True):
                findings.append(SandboxFinding(
                    finding_id="MCP-Sandbox-016",
                    title="Writable Container Root",
                    description="Container root filesystem is writable",
                    risk_level=SandboxRiskLevel.MEDIUM.value,
                    affected_tool=tool_name,
                    vector="Writable root → persistence/backdoor installation",
                    remediation="Use read-only root filesystem",
                    cwe_id="CWE-732",
                    exploit_likelihood="medium"
                ))
        
        return findings
    
    def validate_all_tools(self, tools_config: List[Dict]) -> List[SandboxFinding]:
        """Validate all tools in configuration."""
        all_findings = []
        for tool in tools_config:
            findings = self.validate_tool_config(tool)
            all_findings.extend(findings)
        return all_findings
    
    def get_all_findings(self) -> List[Dict]:
        """Return all findings as serializable dicts."""
        return [asdict(f) for f in self.findings]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary statistics."""
        summary = {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.risk_level == "critical"),
            "high": sum(1 for f in self.findings if f.risk_level == "high"),
            "medium": sum(1 for f in self.findings if f.risk_level == "medium"),
            "low": sum(1 for f in self.findings if f.risk_level == "low"),
            "info": sum(1 for f in self.findings if f.risk_level == "info"),
            "tools_validated": len(self.validated_tools)
        }
        return summary


def validate_tool_sandbox(config_path: str) -> Dict[str, Any]:
    """
    Main entry point for tool sandbox validation.
    
    Args:
        config_path: Path to MCP server configuration file
        
    Returns:
        Dictionary with findings and summary
    """
    import yaml
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    validator = ToolSandboxValidator()
    
    tools = config.get("tools", [])
    if tools:
        validator.validate_all_tools(tools)
    
    return {
        "findings": validator.get_all_findings(),
        "summary": validator.get_summary(),
        "tools_validated": validator.validated_tools
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python tool_sandbox.py <config_path>")
        sys.exit(1)
    
    result = validate_tool_sandbox(sys.argv[1])
    print(json.dumps(result, indent=2))
