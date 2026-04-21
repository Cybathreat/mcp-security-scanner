#!/usr/bin/env python3
"""
MCP Security Scanner CLI v2.0

Enhanced command-line interface with interactive mode, progress bars,
and improved user experience.
"""

import argparse
import sys
import os
import json
import yaml
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

# Try to import rich for progress bars (optional dependency)
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from mcp_auth import scan_mcp_auth
from tool_sandbox import validate_tool_sandbox
from data_exfil import detect_data_exfil_vectors
from rate_limiting import detect_rate_limit_issues
from server_fingerprint import fingerprint_mcp_server
from compliance_mapping import map_findings_to_compliance
from output import generate_report, write_report_files
from secrets_detection import scan_mcp_secrets


class MCPScannerCLI:
    """Enhanced CLI for MCP Security Scanner v2.0."""
    
    VERSION = "2.0.0"
    
    def __init__(self, use_rich: bool = True):
        self.use_rich = use_rich and RICH_AVAILABLE
        self.console = Console() if self.use_rich else None
        self.findings_count = 0
        self.modules_run = []
    
    def print_header(self):
        """Print scanner header."""
        if self.use_rich:
            self.console.print(Panel.fit(
                f"[bold blue]MCP Security Scanner v{self.VERSION}[/bold blue]\n"
                "[dim]Model Context Protocol Security Assessment Tool[/dim]",
                border_style="blue"
            ))
        else:
            print(f"\n{'='*60}")
            print(f"MCP Security Scanner v{self.VERSION}")
            print(f"{'='*60}\n")
    
    def print_module_start(self, module_name: str):
        """Print module start message."""
        if self.use_rich:
            self.console.print(f"\n[bold cyan]▶[/bold cyan] Running [green]{module_name}[/green]...")
        else:
            print(f"\n[*] Running {module_name}...")
    
    def print_module_complete(self, module_name: str, findings: int, critical: int, high: int):
        """Print module completion message."""
        if self.use_rich:
            status = "[red]CRITICAL[/red]" if critical > 0 else "[yellow]WARNINGS[/yellow]" if high > 0 else "[green]OK[/green]"
            self.console.print(f"  [dim]→ {findings} findings ({status})[/dim]")
        else:
            print(f"  → {findings} findings ({critical} critical, {high} high)")
    
    def print_summary(self, results: Dict[str, Any]):
        """Print scan summary."""
        total = sum(len(f) for f in results.get("findings", {}).values() if isinstance(f, list))
        critical = sum(
            sum(1 for f in findings if f.get("risk_level") == "critical")
            for findings in results.get("findings", {}).values()
            if isinstance(findings, list)
        )
        high = sum(
            sum(1 for f in findings if f.get("risk_level") == "high")
            for findings in results.get("findings", {}).values()
            if isinstance(findings, list)
        )
        
        if self.use_rich:
            table = Table(box=box.ROUNDED, title="Scan Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="bold")
            
            table.add_row("Modules Run", ", ".join(results.get("modules_run", [])))
            table.add_row("Total Findings", str(total))
            table.add_row("Critical", f"[red]{critical}[/red]" if critical > 0 else str(critical))
            table.add_row("High", f"[yellow]{high}[/yellow]" if high > 0 else str(high))
            
            self.console.print("\n")
            self.console.print(table)
        else:
            print("\n" + "="*50)
            print("SCAN SUMMARY")
            print("="*50)
            print(f"Modules Run: {', '.join(results.get('modules_run', []))}")
            print(f"Total Findings: {total}")
            print(f"Critical: {critical}")
            print(f"High: {high}")
    
    def run_interactive_scan(self, config_path: str, modules: List[str], 
                             output_format: str, output_dir: str,
                             min_severity: str) -> Dict[str, Any]:
        """Run scan with interactive progress."""
        results = {
            "config_path": config_path,
            "modules_run": [],
            "findings": {},
            "summaries": {},
            "compliance": None,
            "fingerprints": []
        }
        
        # Load config
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Module runners
        module_runners = {
            "auth": ("MCP Auth Scanner", scan_mcp_auth),
            "sandbox": ("Tool Sandbox Validator", validate_tool_sandbox),
            "exfil": ("Data Exfil Detector", detect_data_exfil_vectors),
            "rate": ("Rate Limit Detector", detect_rate_limit_issues),
            "secrets": ("Secrets Detection", scan_mcp_secrets),
        }
        
        self.print_header()
        
        if self.use_rich and not RICH_AVAILABLE:
            self.console.print("[yellow]Note: Install 'rich' for enhanced output: pip install rich[/yellow]\n")
        
        # Run modules with progress
        if self.use_rich:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                for module in modules:
                    if module == "all":
                        modules_to_run = ["auth", "sandbox", "exfil", "rate", "secrets"]
                    else:
                        modules_to_run = [module]
                    
                    for mod_key in modules_to_run:
                        if mod_key in module_runners:
                            mod_name, mod_func = module_runners[mod_key]
                            
                            task = progress.add_task(f"[cyan]{mod_name}", total=1)
                            self.print_module_start(mod_name)
                            
                            try:
                                result = mod_func(config_path)
                                results["modules_run"].append(mod_key)
                                results["findings"][mod_key] = result.get("findings", [])
                                results["summaries"][mod_key] = result.get("summary", {})
                                
                                summary = result.get("summary", {})
                                total_f = summary.get("total_findings", 0)
                                critical = summary.get("critical", 0)
                                high = summary.get("high", 0)
                                
                                progress.update(task, completed=1)
                                self.print_module_complete(mod_name, total_f, critical, high)
                            
                            except Exception as e:
                                progress.update(task, completed=1)
                                if self.use_rich:
                                    self.console.print(f"  [red]Error: {e}[/red]")
                                else:
                                    print(f"  [ERROR] {e}")
                                results["findings"][mod_key] = {"error": str(e)}
        else:
            # Simple progress without rich
            for module in modules:
                if module == "all":
                    modules_to_run = ["auth", "sandbox", "exfil", "rate", "secrets"]
                else:
                    modules_to_run = [module]
                
                for mod_key in modules_to_run:
                    if mod_key in module_runners:
                        mod_name, mod_func = module_runners[mod_key]
                        self.print_module_start(mod_name)
                        
                        try:
                            result = mod_func(config_path)
                            results["modules_run"].append(mod_key)
                            results["findings"][mod_key] = result.get("findings", [])
                            results["summaries"][mod_key] = result.get("summary", {})
                            
                            summary = result.get("summary", {})
                            total_f = summary.get("total_findings", 0)
                            critical = summary.get("critical", 0)
                            high = summary.get("high", 0)
                            
                            self.print_module_complete(mod_name, total_f, critical, high)
                        
                        except Exception as e:
                            print(f"  [ERROR] {e}")
                            results["findings"][mod_key] = {"error": str(e)}
        
        # Generate compliance mapping if requested
        all_findings = []
        for findings in results["findings"].values():
            if isinstance(findings, list):
                all_findings.extend(findings)
        
        if all_findings:
            if self.use_rich:
                self.console.print("\n[bold cyan]▶[/bold cyan] Generating compliance mappings...")
            else:
                print("\n[*] Generating compliance mappings...")
            
            compliance_result = map_findings_to_compliance(all_findings)
            results["compliance"] = compliance_result
            
            if self.use_rich:
                report = compliance_result.get("compliance_report", {})
                self.console.print(f"  [dim]→ Mapped to {len(report.get('framework_coverage', {}))} frameworks[/dim]")
            else:
                print(f"  → Mapped to compliance frameworks")
        
        # Filter by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 4
        
        filtered_findings = {}
        for mod_key, findings in results["findings"].items():
            if isinstance(findings, list):
                filtered = [
                    f for f in findings
                    if f.get("risk_level") in severity_order[min_idx:]
                ]
                filtered_findings[mod_key] = filtered
            else:
                filtered_findings[mod_key] = findings
        
        results["findings"] = filtered_findings
        
        # Generate reports
        if output_format in ["json", "both"]:
            json_path = write_report_files(results, output_dir, "json")
            if self.use_rich:
                self.console.print(f"\n[green]✓[/green] JSON report: [dim]{json_path}[/dim]")
            else:
                print(f"\n[+] JSON report: {json_path}")
        
        if output_format in ["markdown", "both"]:
            md_path = write_report_files(results, output_dir, "markdown")
            if self.use_rich:
                self.console.print(f"[green]✓[/green] Markdown report: [dim]{md_path}[/dim]")
            else:
                print(f"[+] Markdown report: {md_path}")
        
        self.print_summary(results)
        
        return results


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="mcp-security-scanner",
        description="MCP Security Scanner v2.0 - Comprehensive security assessment for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan config.yaml                    # Run all scans
  %(prog)s scan config.yaml -m auth sandbox    # Run specific modules
  %(prog)s scan config.yaml --interactive      # Interactive mode with progress
  %(prog)s fingerprint localhost 8080          # Fingerprint a server
  %(prog)s compliance findings.json            # Map findings to compliance
  %(prog)s validate config.yaml                # Validate config syntax
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scans")
    scan_parser.add_argument("config_path", help="Path to MCP server configuration file (YAML)")
    scan_parser.add_argument(
        "-m", "--modules",
        nargs="+",
        choices=["auth", "sandbox", "exfil", "rate", "secrets", "all"],
        default=["all"],
        help="Security modules to run (default: all)"
    )
    scan_parser.add_argument(
        "-o", "--output",
        choices=["json", "markdown", "both", "none"],
        default="both",
        help="Output format (default: both)"
    )
    scan_parser.add_argument(
        "-d", "--output-dir",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output"
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to report (default: info)"
    )
    scan_parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Enable interactive mode with progress bars"
    )
    
    # Fingerprint command
    fp_parser = subparsers.add_parser("fingerprint", help="Fingerprint an MCP server")
    fp_parser.add_argument("host", help="Server hostname or IP")
    fp_parser.add_argument("port", type=int, help="Server port")
    fp_parser.add_argument(
        "--protocol",
        choices=["http", "https"],
        default="http",
        help="Protocol (default: http)"
    )
    fp_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    fp_parser.add_argument(
        "-o", "--output",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)"
    )
    
    # Compliance command
    comp_parser = subparsers.add_parser("compliance", help="Map findings to compliance frameworks")
    comp_parser.add_argument("findings_file", help="JSON file with findings")
    comp_parser.add_argument(
        "-f", "--framework",
        choices=["iso27001", "soc2", "nist-ai", "owasp", "all"],
        default="all",
        help="Compliance framework (default: all)"
    )
    comp_parser.add_argument(
        "-o", "--output",
        default="-",
        help="Output file (default: stdout)"
    )
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate config syntax")
    validate_parser.add_argument("config_path", help="Path to configuration file")
    
    # Version command
    subparsers.add_parser("version", help="Show version")
    
    return parser.parse_args()


def validate_config(config_path: str) -> bool:
    """Validate YAML configuration syntax."""
    try:
        with open(config_path, 'r') as f:
            yaml.safe_load(f)
        print(f"[OK] Valid YAML: {config_path}")
        return True
    except yaml.YAMLError as e:
        print(f"[ERROR] Invalid YAML: {e}")
        return False
    except FileNotFoundError:
        print(f"[ERROR] File not found: {config_path}")
        return False


def run_fingerprint(host: str, port: int, protocol: str, timeout: int, 
                    output_format: str) -> Dict[str, Any]:
    """Run server fingerprinting."""
    print(f"\nFingerprinting {host}:{port} ({protocol.upper()})...")
    
    result = fingerprint_mcp_server(host, port, protocol, timeout)
    
    if output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        summary = result.get("summary", {})
        print(f"\n{'='*50}")
        print("SERVER FINGERPRINT")
        print(f"{'='*50}")
        print(f"Server Type: {summary.get('server_type', 'unknown')}")
        print(f"Version: {summary.get('version', 'unknown')}")
        print(f"Protocol Version: {summary.get('protocol_version', 'unknown')}")
        print(f"Capabilities: {', '.join(summary.get('capabilities', [])) or 'None'}")
        print(f"Transport: {summary.get('transport', 'unknown')}")
        print(f"TLS Enabled: {summary.get('tls_enabled', False)}")
        print(f"Auth Methods: {', '.join(summary.get('auth_methods', [])) or 'None'}")
        print(f"Tools: {summary.get('tools_count', 0)}")
        print(f"Resources: {summary.get('resources_count', 0)}")
        print(f"Prompts: {summary.get('prompts_count', 0)}")
        
        findings = result.get("findings", [])
        if findings:
            print(f"\nSecurity Findings: {len(findings)}")
            for f in findings:
                print(f"  [{f.get('risk_level')}] {f.get('title')}")
    
    return result


def run_compliance_mapping(findings_file: str, framework: str, output: str) -> Dict[str, Any]:
    """Run compliance mapping on findings."""
    if not os.path.exists(findings_file):
        print(f"[ERROR] File not found: {findings_file}")
        return {}
    
    with open(findings_file, 'r') as f:
        findings = json.load(f)
    
    # Extract findings list if nested
    if isinstance(findings, dict) and "findings" in findings:
        findings_list = []
        for mod_findings in findings["findings"].values():
            if isinstance(mod_findings, list):
                findings_list.extend(mod_findings)
        findings = findings_list
    
    result = map_findings_to_compliance(findings)
    
    if output == "-":
        print(json.dumps(result, indent=2))
    else:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[OK] Compliance report written to: {output}")
    
    return result


def main():
    """Main entry point."""
    args = parse_args()
    
    if args.command == "version":
        print(f"MCP Security Scanner v{MCPScannerCLI.VERSION}")
        return
    
    if args.command == "validate":
        success = validate_config(args.config_path)
        sys.exit(0 if success else 1)
    
    if args.command == "fingerprint":
        result = run_fingerprint(
            host=args.host,
            port=args.port,
            protocol=args.protocol,
            timeout=args.timeout,
            output_format=args.output
        )
        sys.exit(0 if result.get("findings", []) == [] else 2)
    
    if args.command == "compliance":
        result = run_compliance_mapping(
            findings_file=args.findings_file,
            framework=args.framework,
            output=args.output
        )
        sys.exit(0 if result else 1)
    
    if args.command == "scan":
        if not os.path.exists(args.config_path):
            print(f"[ERROR] Config file not found: {args.config_path}")
            sys.exit(1)
        
        # Determine modules to run
        if "all" in args.modules:
            modules = ["auth", "sandbox", "exfil", "rate"]
        else:
            modules = args.modules
        
        # Use interactive mode if requested or if rich is available
        use_interactive = args.interactive or (RICH_AVAILABLE and not args.quiet)
        cli = MCPScannerCLI(use_rich=use_interactive)
        
        if use_interactive:
            results = cli.run_interactive_scan(
                config_path=args.config_path,
                modules=modules,
                output_format=args.output,
                output_dir=args.output_dir,
                min_severity=args.min_severity
            )
        else:
            # Fall back to simple mode
            results = cli.run_interactive_scan(
                config_path=args.config_path,
                modules=modules,
                output_format=args.output,
                output_dir=args.output_dir,
                min_severity=args.min_severity
            )
        
        # Exit with error if critical findings
        critical_count = 0
        for mod_findings in results["findings"].values():
            if isinstance(mod_findings, list):
                critical_count += sum(1 for f in mod_findings if f.get("risk_level") == "critical")
        
        if critical_count > 0:
            print(f"\n[!] CRITICAL FINDINGS: {critical_count}")
            sys.exit(2)
        
        sys.exit(0)
    
    # Default: show help
    parse_args()


if __name__ == "__main__":
    main()
