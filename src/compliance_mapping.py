#!/usr/bin/env python3
"""
Compliance Mapping Module

Maps security findings to compliance frameworks:
- ISO 27001:2022 (Information Security Management)
- SOC 2 Type II (Service Organization Control)
- NIST AI RMF (AI Risk Management Framework)
- OWASP Top 10 (Web Application Security)
"""

import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict, field
from enum import Enum


class ComplianceFramework(Enum):
    ISO27001 = "ISO 27001:2022"
    SOC2 = "SOC 2 Type II"
    NIST_AI_RMF = "NIST AI RMF"
    OWASP_TOP10 = "OWASP Top 10 2021"


@dataclass
class ControlMapping:
    """Mapping of a finding to compliance controls."""
    framework: str
    control_id: str
    control_name: str
    control_description: str
    category: str
    relevance_score: float  # 0.0 to 1.0


@dataclass
class ComplianceFinding:
    """Security finding with compliance mappings."""
    finding_id: str
    title: str
    description: str
    severity: str
    category: str
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    compliance_mappings: List[ControlMapping] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Complete compliance mapping report."""
    total_findings: int
    findings_by_severity: Dict[str, int]
    framework_coverage: Dict[str, Dict[str, int]]
    unmapped_findings: int
    high_risk_gaps: List[str]
    remediation_priority: List[Dict[str, Any]]
    generated_at: str


class ComplianceMapper:
    """
    Maps security findings to compliance framework controls.
    
    Supports:
    - ISO 27001:2022 Annex A controls
    - SOC 2 Trust Services Criteria
    - NIST AI RMF Core Functions
    - OWASP Top 10 2021
    """
    
    # ISO 27001:2022 Annex A Controls (selected relevant ones)
    ISO27001_CONTROLS = {
        "A.5.7": ("Threat intelligence", "Information security threat intelligence collection and analysis"),
        "A.5.15": ("Access control", "Logical access control to information systems"),
        "A.5.18": ("Authentication information", "Management of authentication credentials"),
        "A.5.23": ("Cloud services", "Security of cloud services"),
        "A.8.2": ("Data classification", "Classification of information"),
        "A.8.3": ("Media handling", "Handling of storage media"),
        "A.8.9": ("Configuration management", "Secure configuration of IT systems"),
        "A.8.12": ("Data leakage prevention", "Prevention of data exfiltration"),
        "A.8.16": ("Monitoring activities", "Monitoring of information systems"),
        "A.8.20": ("Network security", "Network security controls"),
        "A.8.21": ("Web filtering", "Management of web access"),
        "A.8.22": ("Segregation of networks", "Segregation of networks"),
        "A.8.23": ("Secure coding", "Secure development practices"),
        "A.8.25": ("Secure development lifecycle", "SDLC security requirements"),
        "A.8.27": ("Secure system engineering", "Secure system architecture"),
        "A.8.28": ("Secure coding practices", "Secure coding standards"),
        "A.8.33": ("Logging", "Event logging for security monitoring"),
        "A.8.34": ("Protection of logs", "Protection of log information"),
        "A.12.4": ("Event logging", "Logging and monitoring"),
        "A.12.6": ("Technical vulnerability management", "Vulnerability scanning"),
        "A.14.2": ("Security in development", "Secure development environment"),
        "A.16.1": ("Incident management", "Incident response procedures"),
        "A.17.1": ("Backup", "Data backup and recovery"),
        "A.18.1": ("Compliance", "Compliance with legal requirements"),
    }
    
    # SOC 2 Trust Services Criteria
    SOC2_CONTROLS = {
        "CC6.1": ("Logical access security", "Logical and physical access controls"),
        "CC6.2": ("Access authorization", "Access authorization mechanisms"),
        "CC6.3": ("Access removal", "Access removal procedures"),
        "CC6.6": ("External threats", "Protection against external threats"),
        "CC6.7": ("Transmission integrity", "Data transmission integrity"),
        "CC6.8": ("Transmission confidentiality", "Data transmission confidentiality"),
        "CC7.1": ("Intrusion detection", "Detection of unauthorized activities"),
        "CC7.2": ("System monitoring", "System monitoring for anomalies"),
        "CC7.3": ("Security incident evaluation", "Security incident evaluation"),
        "CC7.4": ("Incident response", "Incident response procedures"),
        "CC8.1": ("Change management", "Change management procedures"),
        "CC9.1": ("Risk mitigation", "Risk mitigation strategies"),
        "CC9.2": ("Vendor management", "Third-party vendor management"),
        "PI1.1": ("Privacy notice", "Privacy notice and consent"),
        "PI2.1": ("Choice and consent", "Individual choice and consent"),
        "PI3.1": ("Data collection", "Data collection limitations"),
        "PI4.1": ("Data usage", "Data usage and retention"),
        "PI5.1": ("Data access", "Individual data access rights"),
        "PI6.1": ("Data disclosure", "Data disclosure to third parties"),
        "PI7.1": ("Data quality", "Data quality and integrity"),
        "PI8.1": ("Monitoring", "Privacy compliance monitoring"),
    }
    
    # NIST AI RMF Core Functions (Govern, Map, Measure, Manage)
    NIST_AI_RMF_CONTROLS = {
        "GOV.1": ("AI risk policies", "Establish AI risk management policies"),
        "GOV.2": ("AI risk culture", "Foster organizational AI risk culture"),
        "GOV.3": ("AI risk roles", "Define AI risk management roles"),
        "GOV.4": ("AI risk assessment", "Conduct AI risk assessments"),
        "GOV.5": ("AI risk monitoring", "Monitor AI risks continuously"),
        "GOV.6": ("AI risk communication", "Communicate AI risks to stakeholders"),
        "MAP.1": ("AI system context", "Understand AI system context"),
        "MAP.2": ("AI system capabilities", "Identify AI system capabilities"),
        "MAP.3": ("AI system risks", "Identify AI system risks"),
        "MAP.4": ("AI system impacts", "Assess AI system impacts"),
        "MEAS.1": ("AI risk metrics", "Define AI risk metrics"),
        "MEAS.2": ("AI risk testing", "Test AI system for risks"),
        "MEAS.3": ("AI risk tracking", "Track AI risk indicators"),
        "MEAS.4": ("AI risk reporting", "Report AI risk findings"),
        "MGMT.1": ("AI risk treatment", "Treat identified AI risks"),
        "MGMT.2": ("AI risk response", "Respond to AI risk events"),
        "MGMT.3": ("AI risk recovery", "Recover from AI risk incidents"),
        "MGMT.4": ("AI risk improvement", "Improve AI risk management"),
    }
    
    # OWASP Top 10 2021
    OWASP_TOP10 = {
        "A01:2021": ("Broken Access Control", "Access control weaknesses"),
        "A02:2021": ("Cryptographic Failures", "Weak or broken cryptography"),
        "A03:2021": ("Injection", "SQL, NoSQL, OS, LDAP injection"),
        "A04:2021": ("Insecure Design", "Security design flaws"),
        "A05:2021": ("Security Misconfiguration", "Insecure default configurations"),
        "A06:2021": ("Vulnerable Components", "Using vulnerable libraries"),
        "A07:2021": ("Auth Failures", "Authentication and session flaws"),
        "A08:2021": ("Data Integrity", "Data integrity failures"),
        "A09:2021": ("Logging Failures", "Insufficient logging and monitoring"),
        "A10:2021": ("SSRF", "Server-side request forgery"),
    }
    
    # Category to control mappings
    CATEGORY_MAPPINGS = {
        "auth": {
            "iso": ["A.5.15", "A.5.18"],
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist": ["GOV.2", "GOV.3", "MGMT.1"],
            "owasp": ["A01:2021", "A07:2021"]
        },
        "secrets": {
            "iso": ["A.5.18", "A.8.9"],
            "soc2": ["CC6.1", "CC6.8"],
            "nist": ["GOV.1", "MGMT.1"],
            "owasp": ["A02:2021", "A07:2021"]
        },
        "sandbox": {
            "iso": ["A.8.27", "A.8.28", "A.14.2"],
            "soc2": ["CC6.6", "CC9.1"],
            "nist": ["MAP.3", "MEAS.2", "MGMT.1"],
            "owasp": ["A03:2021", "A04:2021"]
        },
        "exfil": {
            "iso": ["A.8.12", "A.8.2", "A.8.3"],
            "soc2": ["CC6.7", "CC6.8", "PI4.1"],
            "nist": ["MAP.4", "MEAS.1", "MGMT.2"],
            "owasp": ["A08:2021"]
        },
        "rate": {
            "iso": ["A.8.16", "A.8.20"],
            "soc2": ["CC7.1", "CC7.2"],
            "nist": ["MEAS.3", "MGMT.2"],
            "owasp": ["A05:2021"]
        },
        "network": {
            "iso": ["A.8.20", "A.8.22"],
            "soc2": ["CC6.6", "CC6.8"],
            "nist": ["MAP.2", "MEAS.2"],
            "owasp": ["A10:2021"]
        },
        "config": {
            "iso": ["A.8.9", "A.8.33", "A.8.34"],
            "soc2": ["CC8.1", "CC7.2"],
            "nist": ["MAP.1", "MEAS.1"],
            "owasp": ["A05:2021"]
        },
        "supply_chain": {
            "iso": ["A.8.9", "A.12.6", "A.14.2"],
            "soc2": ["CC9.2", "CC8.1"],
            "nist": ["MAP.3", "MGMT.1"],
            "owasp": ["A06:2021"]
        },
        "fingerprint": {
            "iso": ["A.8.20", "A.8.21"],
            "soc2": ["CC6.6", "CC7.1"],
            "nist": ["MAP.2", "MEAS.3"],
            "owasp": ["A05:2021"]
        }
    }
    
    def __init__(self):
        self.mapped_findings: List[ComplianceFinding] = []
        self.unmapped_count = 0
    
    def map_finding(self, finding: Dict[str, Any]) -> ComplianceFinding:
        """Map a single finding to compliance controls."""
        category = finding.get("category", "").lower()
        severity = finding.get("severity", finding.get("risk_level", "MEDIUM"))
        
        # Get category mappings
        cat_maps = self.CATEGORY_MAPPINGS.get(category, {})
        
        # If no category match, try to match by CWE
        cwe_id = finding.get("cwe_id", "")
        if not cat_maps and cwe_id:
            cat_maps = self._get_cwe_mappings(cwe_id)
        
        compliance_mappings = []
        
        # Map to ISO 27001
        for control_id in cat_maps.get("iso", []):
            if control_id in self.ISO27001_CONTROLS:
                ctrl_name, ctrl_desc = self.ISO27001_CONTROLS[control_id]
                compliance_mappings.append(ControlMapping(
                    framework=ComplianceFramework.ISO27001.value,
                    control_id=control_id,
                    control_name=ctrl_name,
                    control_description=ctrl_desc,
                    category="Access Control" if "access" in ctrl_name.lower() else "Technical Controls",
                    relevance_score=self._calculate_relevance(finding, "iso", control_id)
                ))
        
        # Map to SOC 2
        for control_id in cat_maps.get("soc2", []):
            if control_id in self.SOC2_CONTROLS:
                ctrl_name, ctrl_desc = self.SOC2_CONTROLS[control_id]
                compliance_mappings.append(ControlMapping(
                    framework=ComplianceFramework.SOC2.value,
                    control_id=control_id,
                    control_name=ctrl_name,
                    control_description=ctrl_desc,
                    category="Security",
                    relevance_score=self._calculate_relevance(finding, "soc2", control_id)
                ))
        
        # Map to NIST AI RMF
        for control_id in cat_maps.get("nist", []):
            if control_id in self.NIST_AI_RMF_CONTROLS:
                ctrl_name, ctrl_desc = self.NIST_AI_RMF_CONTROLS[control_id]
                compliance_mappings.append(ControlMapping(
                    framework=ComplianceFramework.NIST_AI_RMF.value,
                    control_id=control_id,
                    control_name=ctrl_name,
                    control_description=ctrl_desc,
                    category="Govern" if ctrl_id.startswith("GOV") else 
                              "Map" if ctrl_id.startswith("MAP") else
                              "Measure" if ctrl_id.startswith("MEAS") else "Manage",
                    relevance_score=self._calculate_relevance(finding, "nist", control_id)
                ))
        
        # Map to OWASP Top 10
        for owasp_id in cat_maps.get("owasp", []):
            if owasp_id in self.OWASP_TOP10:
                ctrl_name, ctrl_desc = self.OWASP_TOP10[owasp_id]
                compliance_mappings.append(ControlMapping(
                    framework=ComplianceFramework.OWASP_TOP10.value,
                    control_id=owasp_id,
                    control_name=ctrl_name,
                    control_description=ctrl_desc,
                    category="Application Security",
                    relevance_score=self._calculate_relevance(finding, "owasp", owasp_id)
                ))
        
        compliance_finding = ComplianceFinding(
            finding_id=finding.get("id", finding.get("finding_id", "UNKNOWN")),
            title=finding.get("title", "Unknown Finding"),
            description=finding.get("description", ""),
            severity=severity.upper() if severity else "MEDIUM",
            category=category,
            cwe_id=finding.get("cwe_id"),
            cvss_score=finding.get("cvss_score"),
            compliance_mappings=compliance_mappings
        )
        
        if not compliance_mappings:
            self.unmapped_count += 1
        
        return compliance_finding
    
    def _get_cwe_mappings(self, cwe_id: str) -> Dict[str, List[str]]:
        """Get category mappings based on CWE ID."""
        cwe_categories = {
            "CWE-306": {"iso": ["A.5.15"], "soc2": ["CC6.1"], "nist": ["GOV.2"], "owasp": ["A07:2021"]},
            "CWE-327": {"iso": ["A.5.18"], "soc2": ["CC6.8"], "nist": ["MGMT.1"], "owasp": ["A02:2021"]},
            "CWE-78": {"iso": ["A.8.28"], "soc2": ["CC6.6"], "nist": ["MEAS.2"], "owasp": ["A03:2021"]},
            "CWE-22": {"iso": ["A.8.9"], "soc2": ["CC6.1"], "nist": ["MAP.3"], "owasp": ["A01:2021"]},
            "CWE-918": {"iso": ["A.8.20"], "soc2": ["CC6.6"], "nist": ["MEAS.2"], "owasp": ["A10:2021"]},
            "CWE-798": {"iso": ["A.5.18"], "soc2": ["CC6.1"], "nist": ["GOV.1"], "owasp": ["A07:2021"]},
            "CWE-311": {"iso": ["A.8.20"], "soc2": ["CC6.8"], "nist": ["MGMT.1"], "owasp": ["A02:2021"]},
            "CWE-400": {"iso": ["A.8.16"], "soc2": ["CC7.2"], "nist": ["MEAS.3"], "owasp": ["A05:2021"]},
            "CWE-284": {"iso": ["A.5.15"], "soc2": ["CC6.1"], "nist": ["GOV.2"], "owasp": ["A01:2021"]},
            "CWE-200": {"iso": ["A.8.16"], "soc2": ["CC7.2"], "nist": ["MEAS.3"], "owasp": ["A05:2021"]},
        }
        return cwe_categories.get(cwe_id, {})
    
    def _calculate_relevance(self, finding: Dict[str, Any], framework: str, 
                             control_id: str) -> float:
        """Calculate relevance score (0.0 to 1.0) for a mapping."""
        severity = finding.get("severity", finding.get("risk_level", "MEDIUM"))
        
        # Base score by severity
        severity_scores = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.6,
            "LOW": 0.4,
            "INFO": 0.2
        }
        base_score = severity_scores.get(severity.upper(), 0.5)
        
        # Boost for specific control matches
        if framework == "iso" and control_id.startswith("A.8"):
            base_score = min(1.0, base_score + 0.1)
        elif framework == "soc2" and control_id.startswith("CC6"):
            base_score = min(1.0, base_score + 0.1)
        elif framework == "nist" and control_id.startswith("MGMT"):
            base_score = min(1.0, base_score + 0.1)
        
        return round(base_score, 2)
    
    def map_all_findings(self, findings: List[Dict[str, Any]]) -> List[ComplianceFinding]:
        """Map a list of findings to compliance controls."""
        self.mapped_findings = []
        self.unmapped_count = 0
        
        for finding in findings:
            mapped = self.map_finding(finding)
            self.mapped_findings.append(mapped)
        
        return self.mapped_findings
    
    def generate_compliance_report(self, findings: List[ComplianceFinding]) -> ComplianceReport:
        """Generate a comprehensive compliance report."""
        # Count findings by severity
        severity_counts = {}
        for f in findings:
            sev = f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Count framework coverage
        framework_coverage = {
            ComplianceFramework.ISO27001.value: {"total": 0, "mapped": 0, "controls": set()},
            ComplianceFramework.SOC2.value: {"total": 0, "mapped": 0, "controls": set()},
            ComplianceFramework.NIST_AI_RMF.value: {"total": 0, "mapped": 0, "controls": set()},
            ComplianceFramework.OWASP_TOP10.value: {"total": 0, "mapped": 0, "controls": set()},
        }
        
        high_risk_gaps = []
        remediation_priority = []
        
        for finding in findings:
            for mapping in finding.compliance_mappings:
                fw = mapping.framework
                if fw in framework_coverage:
                    framework_coverage[fw]["total"] += 1
                    framework_coverage[fw]["controls"].add(mapping.control_id)
                    
                    if mapping.relevance_score >= 0.8:
                        framework_coverage[fw]["mapped"] += 1
            
            # Identify high-risk gaps
            if finding.severity in ["CRITICAL", "HIGH"] and not finding.compliance_mappings:
                high_risk_gaps.append(f"{finding.finding_id}: {finding.title}")
            
            # Build remediation priority list
            if finding.compliance_mappings:
                for mapping in finding.compliance_mappings:
                    if mapping.relevance_score >= 0.7:
                        remediation_priority.append({
                            "finding_id": finding.finding_id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "framework": mapping.framework,
                            "control": f"{mapping.control_id}: {mapping.control_name}",
                            "relevance": mapping.relevance_score,
                            "remediation": finding.description
                        })
        
        # Sort remediation by severity and relevance
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        remediation_priority.sort(key=lambda x: (
            severity_order.get(x["severity"], 5),
            -x["relevance"]
        ))
        
        # Convert sets to counts for JSON serialization
        for fw in framework_coverage:
            framework_coverage[fw]["controls_mapped"] = len(framework_coverage[fw]["controls"])
            del framework_coverage[fw]["controls"]
        
        from datetime import datetime
        return ComplianceReport(
            total_findings=len(findings),
            findings_by_severity=severity_counts,
            framework_coverage=framework_coverage,
            unmapped_findings=self.unmapped_count,
            high_risk_gaps=high_risk_gaps,
            remediation_priority=remediation_priority[:20],  # Top 20 priorities
            generated_at=datetime.utcnow().isoformat()
        )


def map_findings_to_compliance(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convenience function to map findings to compliance frameworks.
    
    Args:
        findings: List of security findings
    
    Returns:
        Dictionary with mapped findings and compliance report
    """
    mapper = ComplianceMapper()
    mapped = mapper.map_all_findings(findings)
    report = mapper.generate_compliance_report(mapped)
    
    return {
        "mapped_findings": [asdict(f) for f in mapped],
        "compliance_report": asdict(report)
    }


if __name__ == "__main__":
    import sys
    
    # Demo with sample findings
    sample_findings = [
        {
            "id": "AUTH-001",
            "title": "Missing Authentication",
            "description": "MCP server responds without authentication",
            "severity": "CRITICAL",
            "category": "auth",
            "cwe_id": "CWE-306",
            "cvss_score": 9.8
        },
        {
            "id": "SANDBOX-001",
            "title": "Command Injection Vector",
            "description": "Tool accepts unsanitized shell commands",
            "severity": "CRITICAL",
            "category": "sandbox",
            "cwe_id": "CWE-78",
            "cvss_score": 9.0
        },
        {
            "id": "EXFIL-001",
            "title": "Unencrypted Data Transmission",
            "description": "Data transmitted without encryption",
            "severity": "HIGH",
            "category": "exfil",
            "cwe_id": "CWE-311",
            "cvss_score": 7.5
        }
    ]
    
    result = map_findings_to_compliance(sample_findings)
    print(json.dumps(result, indent=2))
