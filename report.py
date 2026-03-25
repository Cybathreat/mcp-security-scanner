"""
MCP Security Scanner - Report Generation
Generates HTML and JSON security audit reports.
"""

import os
import json
import html
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    """Represents a single security finding."""
    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # auth, secrets, network, config
    title: str
    description: str
    target_host: str
    target_port: int
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class ScanResult:
    """Container for complete scan results."""
    scan_id: str
    timestamp: str
    targets_scanned: int
    findings: List[Finding]
    summary: Dict[str, int]  # severity counts
    duration_seconds: float
    scanner_version: str = "1.0.0"


class ReportGenerator:
    """Generates security reports in HTML and JSON formats."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_json_report(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate JSON format report."""
        if filename is None:
            filename = f"scan_{result.scan_id}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        report_data = {
            "report_metadata": {
                "generator": "MCP Security Scanner",
                "version": result.scanner_version,
                "generated_at": result.timestamp,
                "scan_id": result.scan_id
            },
            "scan_summary": {
                "targets_scanned": result.targets_scanned,
                "duration_seconds": result.duration_seconds,
                "findings_by_severity": result.summary
            },
            "findings": [asdict(f) for f in result.findings]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return filepath
    
    def generate_html_report(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate HTML format report with styling."""
        if filename is None:
            filename = f"scan_{result.scan_id}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
            'INFO': '#17a2b8'
        }
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Security Scan Report - {result.scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 6px; text-align: center; color: white; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}
        .finding {{ border: 1px solid #ddd; border-left: 4px solid; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; font-size: 12px; }}
        .evidence {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; overflow-x: auto; }}
        .remediation {{ background: #d4edda; padding: 10px; border-radius: 4px; margin-top: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .meta {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 MCP Security Scan Report</h1>
        <p class="meta">
            <strong>Scan ID:</strong> {result.scan_id}<br>
            <strong>Generated:</strong> {result.timestamp}<br>
            <strong>Scanner Version:</strong> {result.scanner_version}<br>
            <strong>Duration:</strong> {result.duration_seconds:.2f}s
        </p>
        
        <h2>Executive Summary</h2>
        <p>Scanned <strong>{result.targets_scanned}</strong> MCP server target(s). Found <strong>{len(result.findings)}</strong> security finding(s).</p>
        
        <div class="summary">
            <div class="summary-card critical">
                <div style="font-size: 24px; font-weight: bold;">{result.summary.get('CRITICAL', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div style="font-size: 24px; font-weight: bold;">{result.summary.get('HIGH', 0)}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div style="font-size: 24px; font-weight: bold;">{result.summary.get('MEDIUM', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div style="font-size: 24px; font-weight: bold;">{result.summary.get('LOW', 0)}</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div style="font-size: 24px; font-weight: bold;">{result.summary.get('INFO', 0)}</div>
                <div>Info</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        for finding in result.findings:
            color = severity_colors.get(finding.severity, '#666')
            html_content += f"""
        <div class="finding" style="border-left-color: {color};">
            <div class="finding-header">
                <span><strong>{html.escape(finding.title)}</strong></span>
                <span class="severity-badge" style="background: {color};">{finding.severity}</span>
            </div>
            <p><strong>Category:</strong> {finding.category} | <strong>Target:</strong> {finding.target_host}:{finding.target_port}</p>
            <p>{html.escape(finding.description)}</p>
"""
            if finding.evidence:
                html_content += f"""
            <div class="evidence"><strong>Evidence:</strong><br>{html.escape(finding.evidence)}</div>
"""
            if finding.remediation:
                html_content += f"""
            <div class="remediation"><strong>💡 Remediation:</strong> {html.escape(finding.remediation)}</div>
"""
            if finding.cwe_id:
                html_content += f"""
            <p class="meta"><strong>CWE:</strong> {finding.cwe_id}</p>
"""
            html_content += """
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def generate_all_reports(self, result: ScanResult, base_filename: Optional[str] = None) -> Dict[str, str]:
        """Generate both JSON and HTML reports."""
        return {
            'json': self.generate_json_report(result, base_filename),
            'html': self.generate_html_report(result, base_filename)
        }


def create_scan_result(
    findings: List[Finding],
    targets_scanned: int,
    duration: float,
    scan_id: Optional[str] = None
) -> ScanResult:
    """Helper to create a ScanResult with computed summary."""
    if scan_id is None:
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1
    
    return ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        targets_scanned=targets_scanned,
        findings=findings,
        summary=summary,
        duration_seconds=duration
    )
