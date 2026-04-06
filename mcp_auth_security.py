"""
MCP Server Authentication & Authorization Security Scanner
Detects authentication and authorization vulnerabilities in MCP server configurations.
"""

import re
import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path


class MCPAuthSecurityScanner:
    """Scanner for MCP authentication and authorization security issues."""
    
    # Known weak authentication patterns
    WEAK_AUTH_PATTERNS = [
        r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']?test["\']?',
        r'["\']?password["\']?\s*[=:]\s*["\']?admin["\']?',
        r'["\']?token["\']?\s*[=:]\s*["\']?123456["\']?',
        r'["\']?auth["\']?\s*[=:]\s*["\']?none["\']?',
        r'["\']?authentication["\']?\s*[=:]\s*["\']?disabled["\']?',
    ]
    
    # Credential exposure patterns
    CREDENTIAL_PATTERNS = [
        r'["\']?(api[_-]?key|apikey)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        r'["\']?(secret[_-]?key|secretkey)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        r'["\']?(access[_-]?token|accesstoken)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        r'[Bb]earer\s+([a-zA-Z0-9_\-\.]{50,})',
        r'["\']?password["\']?\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
    ]
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
    
    def scan_config_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scan a single MCP config file for auth/security issues."""
        findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except (IOError, UnicodeDecodeError) as e:
            return [{
                'file': filepath,
                'severity': 'error',
                'type': 'read_error',
                'message': f'Could not read file: {str(e)}'
            }]
        
        # Check for missing authentication
        if self._check_missing_auth(content):
            findings.append({
                'file': filepath,
                'severity': 'critical',
                'type': 'missing_authentication',
                'message': 'MCP server configured without authentication',
                'line': self._find_line_number(content, 'auth')
            })
        
        # Check for weak authentication
        weak_auth = self._check_weak_auth(content)
        if weak_auth:
            findings.append({
                'file': filepath,
                'severity': 'high',
                'type': 'weak_authentication',
                'message': f'Weak authentication detected: {weak_auth}',
                'line': self._find_line_number(content, weak_auth)
            })
        
        # Check for credential exposure
        exposed_creds = self._check_credential_exposure(content)
        findings.extend(exposed_creds)
        
        # Check for authorization bypass patterns
        auth_bypass = self._check_auth_bypass(content)
        if auth_bypass:
            findings.append({
                'file': filepath,
                'severity': 'high',
                'type': 'authorization_bypass',
                'message': 'Potential authorization bypass vulnerability',
                'details': auth_bypass,
                'line': self._find_line_number(content, auth_bypass[0:30])
            })
        
        return findings
    
    def _check_missing_auth(self, content: str) -> bool:
        """Check if authentication is missing or disabled."""
        # Look for auth-related fields that are missing or disabled
        auth_disabled_patterns = [
            r'"?auth"?\s*:\s*["\']?(none|disabled|false)["\']?',
            r'"?authentication"?\s*:\s*["\']?(none|disabled|false)["\']?',
            r'"?security"?\s*:\s*["\']?(none|disabled)["\']?',
        ]
        
        for pattern in auth_disabled_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # Check if auth section exists at all in JSON configs
        try:
            # Try to parse as JSON
            data = json.loads(content)
            if isinstance(data, dict):
                # Check common auth field names
                auth_fields = ['auth', 'authentication', 'security', 'authorization']
                has_auth = any(field in data for field in auth_fields)
                if not has_auth:
                    return True
        except json.JSONDecodeError:
            pass
        
        return False
    
    def _check_weak_auth(self, content: str) -> Optional[str]:
        """Check for weak authentication patterns."""
        for pattern in self.WEAK_AUTH_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _check_credential_exposure(self, content: str) -> List[Dict[str, Any]]:
        """Check for exposed credentials/tokens in config."""
        findings = []
        
        for pattern in self.CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'file': match.string,
                    'severity': 'critical',
                    'type': 'credential_exposure',
                    'message': f'Potential credential exposed: {match.group(1)}',
                    'line': self._find_line_number(content, match.group(0))
                })
        
        return findings
    
    def _check_auth_bypass(self, content: str) -> Optional[str]:
        """Check for authorization bypass patterns."""
        bypass_patterns = [
            r'"?admin"?\s*[=:]\s*true',
            r'"?role"?\s*[=:]\s*["\']?admin["\']?',
            r'"?permissions"?\s*[=:]\s*["\']?\*["\']?',
            r'"?allow_all"?\s*[=:]\s*true',
            r'"?skip_auth"?\s*[=:]\s*true',
            r'"?bypass"?\s*[=:]\s*true',
        ]
        
        for pattern in bypass_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return pattern
        return None
    
    def _find_line_number(self, content: str, search_text: str) -> int:
        """Find line number for a given text."""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if search_text and search_text in line:
                return i
        return 0
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict[str, Any]]:
        """Scan a directory for MCP config files."""
        all_findings = []
        path = Path(directory)
        
        # Common MCP config file patterns
        config_patterns = [
            '*.json', '*.yaml', '*.yml', '*.toml', '*.config',
            'mcp*', '*mcp*', 'config*', '*config*'
        ]
        
        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')
        
        for filepath in files:
            if filepath.is_file():
                # Check if it matches config patterns
                name = filepath.name.lower()
                is_config = any(
                    pattern.replace('*', '') in name 
                    for pattern in config_patterns
                )
                
                if is_config or filepath.suffix in ['.json', '.yaml', '.yml', '.toml']:
                    findings = self.scan_config_file(str(filepath))
                    all_findings.extend(findings)
        
        return all_findings
    
    def generate_report(self, findings: List[Dict[str, Any]]) -> str:
        """Generate a security report from findings."""
        if not findings:
            return "✅ No authentication/authorization issues detected."
        
        report = []
        report.append("🔒 MCP Authentication & Authorization Security Report")
        report.append("=" * 60)
        report.append(f"Total issues found: {len(findings)}")
        report.append("")
        
        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'error': []}
        for finding in findings:
            severity = finding.get('severity', 'low')
            by_severity[severity].append(finding)
        
        for severity in ['critical', 'high', 'medium', 'low', 'error']:
            issues = by_severity[severity]
            if issues:
                report.append(f"\n[{severity.upper()}] {len(issues)} issue(s):")
                for issue in issues:
                    report.append(f"  - {issue['type']}: {issue['message']}")
                    if 'file' in issue:
                        report.append(f"    File: {issue['file']}")
                    if 'line' in issue and issue['line']:
                        report.append(f"    Line: {issue['line']}")
        
        return '\n'.join(report)


def scan_mcp_auth(target: str, recursive: bool = True) -> str:
    """Convenience function to scan a target (file or directory)."""
    scanner = MCPAuthSecurityScanner()
    
    if os.path.isfile(target):
        findings = scanner.scan_config_file(target)
    elif os.path.isdir(target):
        findings = scanner.scan_directory(target, recursive)
    else:
        return f"Error: Target not found: {target}"
    
    return scanner.generate_report(findings)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mcp_auth_security.py <target_file_or_directory>")
        sys.exit(1)
    
    target = sys.argv[1]
    recursive = '--no-recursive' not in sys.argv
    
    report = scan_mcp_auth(target, recursive)
    print(report)
