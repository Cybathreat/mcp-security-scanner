#!/usr/bin/env python3
"""
Report Generator

Generates JSON and Markdown security reports from scan results.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path


def generate_json_report(results: Dict[str, Any]) -> str:
    """Generate JSON report content."""
    report = {
        "report_metadata": {
            "tool": "MCP Security Scanner",
            "version": "0.1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "config_scanned": results.get("config_path", "unknown")
        },
        "executive_summary": generate_executive_summary(results),
        "scan_results": {
            "modules_run": results.get("modules_run", []),
            "findings": results.get("findings", {}),
            "summaries": results.get("summaries", {})
        },
        "recommendations": generate_recommendations(results)
    }
    
    return json.dumps(report, indent=2, default=str)


def generate_executive_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate executive summary from results."""
    summaries = results.get("summaries", {})
    
    total_findings = 0
    critical = 0
    high = 0
    medium = 0
    low = 0
    
    for mod_summary in summaries.values():
        if isinstance(mod_summary, dict):
            total_findings += mod_summary.get("total_findings", 0)
            critical += mod_summary.get("critical", 0)
            high += mod_summary.get("high", 0)
            medium += mod_summary.get("medium", 0)
            low += mod_summary.get("low", 0)
    
    # Determine overall risk
    if critical > 0:
        risk_level = "CRITICAL"
    elif high > 0:
        risk_level = "HIGH"
    elif medium > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "total_findings": total_findings,
        "by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "overall_risk_level": risk_level,
        "modules_scanned": len(results.get("modules_run", [])),
        "immediate_actions_required": critical + high
    }


def generate_recommendations(results: Dict[str, Any]) -> List[Dict[str, str]]:
    """Generate prioritized recommendations."""
    recommendations = []
    findings = results.get("findings", {})
    
    # Collect all findings
    all_findings = []
    for mod_findings in findings.values():
        if isinstance(mod_findings, list):
            all_findings.extend(mod_findings)
    
    # Group by remediation
    remediation_map = {}
    for finding in all_findings:
        rem = finding.get("remediation", "Review and fix")
        if rem not in remediation_map:
            remediation_map[rem] = {
                "count": 0,
                "severity": "low",
                "finding_ids": []
            }
        remediation_map[rem]["count"] += 1
        remediation_map[rem]["finding_ids"].append(finding.get("finding_id"))
        
        # Track highest severity
        severity_order = ["critical", "high", "medium", "low"]
        finding_sev = finding.get("risk_level", "low")
        if severity_order.index(finding_sev) < severity_order.index(remediation_map[rem]["severity"]):
            remediation_map[rem]["severity"] = finding_sev
    
    # Build recommendations sorted by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    for rem, data in sorted(remediation_map.items(), key=lambda x: severity_order.get(x[1]["severity"], 4)):
        recommendations.append({
            "priority": data["severity"].upper(),
            "action": rem,
            "affected_findings": data["count"],
            "finding_ids": data["finding_ids"][:5]  # Limit to first 5
        })
    
    return recommendations[:20]  # Top 20 recommendations


def generate_markdown_report(results: Dict[str, Any]) -> str:
    """Generate Markdown report content."""
    md = []
    
    # Header
    md.append("# MCP Security Scan Report")
    md.append("")
    md.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    md.append(f"**Config:** {results.get('config_path', 'unknown')}")
    md.append(f"**Tool:** MCP Security Scanner v0.1.0")
    md.append("")
    
    # Executive Summary
    summary = generate_executive_summary(results)
    md.append("## Executive Summary")
    md.append("")
    md.append(f"**Overall Risk Level:** {summary['overall_risk_level']}")
    md.append("")
    md.append(f"- **Total Findings:** {summary['total_findings']}")
    md.append(f"- **Critical:** {summary['by_severity']['critical']}")
    md.append(f"- **High:** {summary['by_severity']['high']}")
    md.append(f"- **Medium:** {summary['by_severity']['medium']}")
    md.append(f"- **Low:** {summary['by_severity']['low']}")
    md.append("")
    
    if summary['overall_risk_level'] in ["CRITICAL", "HIGH"]:
        md.append("> ⚠️ **Immediate action required.** Address critical and high findings before deployment.")
        md.append("")
    
    # Modules Run
    md.append("## Scan Modules")
    md.append("")
    for mod in results.get("modules_run", []):
        md.append(f"- {mod}")
    md.append("")
    
    # Findings by Module
    findings = results.get("findings", {})
    summaries = results.get("summaries", {})
    
    md.append("## Detailed Findings")
    md.append("")
    
    module_names = {
        "auth": "Authentication & Authorization",
        "sandbox": "Tool Sandboxing",
        "exfil": "Data Exfiltration",
        "rate": "Rate Limiting"
    }
    
    for mod_key in results.get("modules_run", []):
        mod_findings = findings.get(mod_key, [])
        mod_summary = summaries.get(mod_key, {})
        mod_name = module_names.get(mod_key, mod_key)
        
        if not isinstance(mod_findings, list):
            md.append(f"### {mod_name}")
            md.append("")
            md.append(f"*Error during scan: {mod_findings}*")
            md.append("")
            continue
        
        md.append(f"### {mod_name}")
        md.append("")
        md.append(f"**Findings:** {mod_summary.get('total_findings', len(mod_findings))}")
        md.append("")
        
        if not mod_findings:
            md.append("*No findings.*")
            md.append("")
            continue
        
        # Group by severity
        by_severity = {}
        for f in mod_findings:
            sev = f.get("risk_level", "info")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)
        
        for severity in ["critical", "high", "medium", "low"]:
            if severity not in by_severity:
                continue
            
            md.append(f"#### {severity.upper()}")
            md.append("")
            
            for finding in by_severity[severity]:
                md.append(f"**{finding.get('finding_id')}**: {finding.get('title')}")
                md.append("")
                md.append(f"- **Description:** {finding.get('description')}")
                md.append(f"- **Component:** {finding.get('affected_component', finding.get('affected_endpoint', 'N/A'))}")
                md.append(f"- **Remediation:** {finding.get('remediation')}")
                if finding.get("cwe_id"):
                    md.append(f"- **CWE:** {finding.get('cwe_id')}")
                md.append("")
    
    # Recommendations
    recommendations = generate_recommendations(results)
    
    md.append("## Prioritized Recommendations")
    md.append("")
    
    if recommendations:
        md.append("| Priority | Action | Affected Findings |")
        md.append("|----------|--------|---------------------|")
        for rec in recommendations:
            md.append(f"| {rec['priority']} | {rec['action']} | {rec['affected_findings']} |")
        md.append("")
    else:
        md.append("*No specific recommendations.*")
        md.append("")
    
    # Footer
    md.append("---")
    md.append("")
    md.append("*Report generated by MCP Security Scanner. Review all findings before production deployment.*")
    
    return "\n".join(md)


def write_report_files(results: Dict[str, Any], output_dir: str, format_type: str) -> str:
    """
    Write report files to disk.
    
    Args:
        results: Scan results dictionary
        output_dir: Output directory path
        format_type: 'json', 'markdown', or 'both'
        
    Returns:
        Path to written file(s), or last file path
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"mcp_scan_{timestamp}"
    
    paths = []
    
    if format_type in ["json", "both"]:
        json_content = generate_json_report(results)
        json_path = os.path.join(output_dir, f"{base_name}.json")
        with open(json_path, 'w') as f:
            f.write(json_content)
        paths.append(json_path)
    
    if format_type in ["markdown", "both"]:
        md_content = generate_markdown_report(results)
        md_path = os.path.join(output_dir, f"{base_name}.md")
        with open(md_path, 'w') as f:
            f.write(md_content)
        paths.append(md_path)
    
    return paths[-1] if paths else ""


def generate_report(results: Dict[str, Any], format_type: str = "json") -> str:
    """
    Generate report content (without writing to disk).
    
    Args:
        results: Scan results dictionary
        format_type: 'json' or 'markdown'
        
    Returns:
        Report content as string
    """
    if format_type == "json":
        return generate_json_report(results)
    elif format_type == "markdown":
        return generate_markdown_report(results)
    else:
        raise ValueError(f"Unknown format: {format_type}")


if __name__ == "__main__":
    # Test with sample data
    sample_results = {
        "config_path": "test_config.yaml",
        "modules_run": ["auth", "sandbox"],
        "findings": {
            "auth": [
                {
                    "finding_id": "MCP-Auth-001",
                    "title": "Test Finding",
                    "description": "Test description",
                    "risk_level": "high",
                    "affected_endpoint": "/test",
                    "remediation": "Fix it"
                }
            ]
        },
        "summaries": {
            "auth": {"total_findings": 1, "critical": 0, "high": 1, "medium": 0, "low": 0}
        }
    }
    
    print("JSON Report:")
    print(generate_report(sample_results, "json"))
    print("\n" + "=" * 50 + "\n")
    print("Markdown Report:")
    print(generate_report(sample_results, "markdown"))
