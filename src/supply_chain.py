#!/usr/bin/env python3
"""
MCP Supply Chain Security Scanner

Detects supply chain vulnerabilities in MCP server dependencies,
package configurations, and third-party integrations.
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class SupplyChainRiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SupplyChainFinding:
    finding_id: str
    title: str
    description: str
    risk_level: str
    affected_package: str
    vector: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


class SupplyChainScanner:
    """
    Scanner for MCP supply chain security.
    
    Checks for:
    - Known vulnerable dependencies (CVE matching)
    - Typosquatting in package names
    - Unpinned/floating versions
    - Suspicious package metadata
    - Dependency confusion vectors
    - Compromised maintainer detection
    """
    
    # Known typosquatting patterns for common packages
    TYPOSQUAT_PATTERNS = {
        'requests': ['requets', 'reqeusts', 'request', 'reqests'],
        'flask': ['flaask', 'flaskk', 'falsk'],
        'django': ['djang0', 'djnago', 'dango'],
        'numpy': ['numpi', 'nunpy', 'numy'],
        'pandas': ['panda', 'pandass', 'pandad'],
        'aiohttp': ['aiohttplib', 'aiohtp', 'aiohttp-client'],
    }
    
    # Packages with history of compromises
    HIGH_RISK_PACKAGES = [
        'event-stream', 'ua-parser-js', 'colors', 'node-ipc',
        'api6', 'coa', 'rc'
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.findings: List[SupplyChainFinding] = []
        self.scanned_packages: List[str] = []
        
    def scan_requirements_file(self, requirements_path: str) -> List[SupplyChainFinding]:
        """Scan Python requirements.txt for supply chain issues."""
        findings = []
        path = Path(requirements_path)
        
        if not path.exists():
            return findings
        
        with open(path, 'r') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse package specification
            match = re.match(r'^([a-zA-Z0-9_-]+)([<>=!]+)?(.+)?$', line)
            if not match:
                continue
            
            package_name = match.group(1).lower()
            version_op = match.group(2) or ''
            version = match.group(3) or ''
            
            self.scanned_packages.append(package_name)
            
            # Check for typosquatting
            for legit, typos in self.TYPOSQUAT_PATTERNS.items():
                if package_name in typos:
                    findings.append(SupplyChainFinding(
                        finding_id=f"SC-TYPO-{package_name}-{line_num}",
                        title="Potential Typosquatting Package",
                        description=f"Package '{package_name}' appears to be a typosquat of '{legit}'",
                        risk_level=SupplyChainRiskLevel.CRITICAL.value,
                        affected_package=package_name,
                        vector=f"Typo in dependency → malicious package installation",
                        remediation=f"Replace '{package_name}' with '{legit}' in requirements.txt",
                        cwe_id="CWE-1321",
                        cvss_score=9.1
                    ))
            
            # Check for unpinned versions
            if not version_op or version_op in ['>=', '>']:
                findings.append(SupplyChainFinding(
                    finding_id=f"SC-UNPIN-{package_name}-{line_num}",
                    title="Unpinned Dependency Version",
                    description=f"Package '{package_name}' has no upper version bound",
                    risk_level=SupplyChainRiskLevel.MEDIUM.value,
                    affected_package=package_name,
                    vector="Floating version → potential introduction of vulnerable/malicious updates",
                    remediation=f"Pin to specific version: {package_name}==X.Y.Z or use {package_name}<NextMajor",
                    cwe_id="CWE-1391",
                    cvss_score=5.5
                ))
            
            # Check for known high-risk packages
            if package_name in self.HIGH_RISK_PACKAGES:
                findings.append(SupplyChainFinding(
                    finding_id=f"SC-RISK-{package_name}-{line_num}",
                    title="High-Risk Package with Compromise History",
                    description=f"Package '{package_name}' has been compromised in the past",
                    risk_level=SupplyChainRiskLevel.HIGH.value,
                    affected_package=package_name,
                    vector="Historical compromise → potential for future attacks",
                    remediation="Consider alternative packages or implement strict version pinning with integrity checks",
                    cwe_id="CWE-1321",
                    cvss_score=7.5
                ))
        
        self.findings.extend(findings)
        return findings
    
    def scan_package_json(self, package_json_path: str) -> List[SupplyChainFinding]:
        """Scan Node.js package.json for supply chain issues."""
        findings = []
        path = Path(package_json_path)
        
        if not path.exists():
            return findings
        
        try:
            with open(path, 'r') as f:
                pkg_data = json.load(f)
        except json.JSONDecodeError:
            return findings
        
        # Check dependencies
        deps = pkg_data.get('dependencies', {})
        dev_deps = pkg_data.get('devDependencies', {})
        
        for dep_name, version in {**deps, **dev_deps}.items():
            self.scanned_packages.append(dep_name)
            dep_name_lower = dep_name.lower()
            
            # Check for typosquatting
            for legit, typos in self.TYPOSQUAT_PATTERNS.items():
                if dep_name_lower in typos:
                    findings.append(SupplyChainFinding(
                        finding_id=f"SC-TYPO-{dep_name_lower}",
                        title="Potential Typosquatting Package",
                        description=f"Package '{dep_name}' appears to be a typosquat of '{legit}'",
                        risk_level=SupplyChainRiskLevel.CRITICAL.value,
                        affected_package=dep_name,
                        vector="Typo in dependency → malicious package installation",
                        remediation=f"Replace '{dep_name}' with '{legit}'",
                        cwe_id="CWE-1321",
                        cvss_score=9.1
                    ))
            
            # Check for wildcard versions
            if version in ['*', 'latest', 'x', 'X']:
                findings.append(SupplyChainFinding(
                    finding_id=f"SC-WILD-{dep_name}",
                    title="Wildcard Dependency Version",
                    description=f"Package '{dep_name}' uses wildcard version '{version}'",
                    risk_level=SupplyChainRiskLevel.HIGH.value,
                    affected_package=dep_name,
                    vector="Wildcard version → unpredictable dependency resolution",
                    remediation=f"Pin to specific version: {dep_name}@X.Y.Z",
                    cwe_id="CWE-1391",
                    cvss_score=6.5
                ))
        
        # Check for suspicious scripts
        scripts = pkg_data.get('scripts', {})
        dangerous_scripts = ['preinstall', 'postinstall', 'install']
        
        for script_name in dangerous_scripts:
            if script_name in scripts:
                script_content = scripts[script_name]
                # Check for suspicious patterns
                suspicious_patterns = [
                    r'curl\s+.*\|\s*sh',
                    r'wget\s+.*\|\s*sh',
                    r'base64\s+-d',
                    r'eval\s*\(',
                    r'\$\(',
                ]
                for pattern in suspicious_patterns:
                    if re.search(pattern, script_content):
                        findings.append(SupplyChainFinding(
                            finding_id=f"SC-SCRIPT-{script_name}",
                            title="Suspicious Install Script",
                            description=f"Package.json {script_name} script contains potentially dangerous commands",
                            risk_level=SupplyChainRiskLevel.CRITICAL.value,
                            affected_package=pkg_data.get('name', 'unknown'),
                            vector=f"{script_name} script → arbitrary code execution during install",
                            remediation="Review and remove suspicious install scripts",
                            cwe_id="CWE-1321",
                            cvss_score=9.0
                        ))
                        break
        
        self.findings.extend(findings)
        return findings
    
    def check_dependency_confusion(self, package_names: List[str]) -> List[SupplyChainFinding]:
        """Check for dependency confusion attack vectors."""
        findings = []
        
        # Internal package naming patterns that could be confused
        internal_patterns = [
            r'^@internal/',
            r'^@company/',
            r'^@private/',
            r'^internal-',
            r'^corp-',
        ]
        
        for pkg in package_names:
            for pattern in internal_patterns:
                if re.match(pattern, pkg):
                    # Check if public package with same name exists
                    # In production, would query npm/PyPI APIs
                    findings.append(SupplyChainFinding(
                        finding_id=f"SC-CONFUS-{pkg}",
                        title="Potential Dependency Confusion",
                        description=f"Package '{pkg}' follows internal naming pattern",
                        risk_level=SupplyChainRiskLevel.MEDIUM.value,
                        affected_package=pkg,
                        vector="Internal package name → could be confused with public package",
                        remediation="Use scoped packages with organization prefix and private registry",
                        cwe_id="CWE-1321",
                        cvss_score=6.0
                    ))
                    break
        
        self.findings.extend(findings)
        return findings
    
    def scan_for_cve(self, packages: List[Dict[str, str]]) -> List[SupplyChainFinding]:
        """
        Check packages against known CVEs.
        
        Args:
            packages: List of dicts with 'name' and 'version' keys
        
        In production, this would query NVD API or use local CVE database.
        """
        findings = []
        
        # Simulated CVE database (in production, use real CVE API)
        known_vulns = {
            'requests': {'2.25.0': 'CVE-2023-32681', '2.25.1': 'CVE-2023-32681'},
            'flask': {'2.0.0': 'CVE-2023-30861'},
            'django': {'3.2.0': 'CVE-2023-36053', '4.0.0': 'CVE-2023-36053'},
            'aiohttp': {'3.8.0': 'CVE-2023-37920'},
        }
        
        for pkg in packages:
            name = pkg.get('name', '').lower()
            version = pkg.get('version', '')
            
            if name in known_vulns and version in known_vulns[name]:
                cve = known_vulns[name][version]
                findings.append(SupplyChainFinding(
                    finding_id=f"SC-CVE-{name}-{version}",
                    title=f"Known CVE in Dependency: {cve}",
                    description=f"Package '{name}' version {version} is affected by {cve}",
                    risk_level=SupplyChainRiskLevel.HIGH.value,
                    affected_package=name,
                    vector=f"Known vulnerability {cve} → potential exploitation",
                    remediation=f"Upgrade {name} to latest secure version",
                    cwe_id="CWE-1391",
                    cvss_score=7.5
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
            "packages_scanned": len(self.scanned_packages)
        }
        return summary


def scan_supply_chain(requirements_path: Optional[str] = None, 
                      package_json_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Main entry point for supply chain scanning.
    
    Args:
        requirements_path: Path to Python requirements.txt
        package_json_path: Path to Node.js package.json
        
    Returns:
        Dictionary with findings and summary
    """
    scanner = SupplyChainScanner()
    
    if requirements_path:
        scanner.scan_requirements_file(requirements_path)
    
    if package_json_path:
        scanner.scan_package_json(package_json_path)
    
    return {
        "findings": scanner.get_all_findings(),
        "summary": scanner.get_summary(),
        "packages_scanned": scanner.scanned_packages
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python supply_chain.py <requirements.txt|package.json>")
        sys.exit(1)
    
    path = sys.argv[1]
    
    if path.endswith('requirements.txt'):
        result = scan_supply_chain(requirements_path=path)
    elif path.endswith('package.json'):
        result = scan_supply_chain(package_json_path=path)
    else:
        print("Error: Unsupported file type. Use requirements.txt or package.json")
        sys.exit(1)
    
    print(json.dumps(result, indent=2))
