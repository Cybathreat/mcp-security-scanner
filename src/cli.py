#!/usr/bin/env python3
"""
MCP Security Scanner CLI

Command-line interface for running MCP security scans.
"""

import argparse
import sys
import os
import json
import yaml
from pathlib import Path
from typing import Optional

from mcp_auth import scan_mcp_auth
from tool_sandbox import validate_tool_sandbox
from data_exfil import detect_data_exfil_vectors
from rate_limiting import detect_rate_limit_issues
from output import generate_report, write_report_files


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="mcp-security-scanner",
        description="MCP Security Scanner - Scan MCP servers for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan config.yaml                    # Run all scans
  %(prog)s scan config.yaml --modules auth     # Run only auth scan
  %(prog)s scan config.yaml --output report    # Generate reports
  %(prog)s validate config.yaml                # Validate config syntax
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scans")
    scan_parser.add_argument(
        "config_path",
        help="Path to MCP server configuration file (YAML)"
    )
    scan_parser.add_argument(
        "-m", "--modules",
        nargs="+",
        choices=["auth", "sandbox", "exfil", "rate", "all"],
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
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate config syntax")
    validate_parser.add_argument(
        "config_path",
        help="Path to configuration file"
    )
    
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


def run_scan(config_path: str, modules: list, output_format: str, 
             output_dir: str, quiet: bool, min_severity: str) -> dict:
    """Run security scans and generate reports."""
    
    results = {
        "config_path": config_path,
        "modules_run": [],
        "findings": {},
        "summaries": {}
    }
    
    # Load config once
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Module runners
    module_runners = {
        "auth": ("MCP Auth Scanner", scan_mcp_auth),
        "sandbox": ("Tool Sandbox Validator", validate_tool_sandbox),
        "exfil": ("Data Exfil Detector", detect_data_exfil_vectors),
        "rate": ("Rate Limit Detector", detect_rate_limit_issues),
    }
    
    if not quiet:
        print(f"\nMCP Security Scanner")
        print(f"Config: {config_path}")
        print(f"Modules: {', '.join(modules)}")
        print("-" * 50)
    
    for module in modules:
        if module == "all":
            modules_to_run = ["auth", "sandbox", "exfil", "rate"]
        else:
            modules_to_run = [module]
        
        for mod_key in modules_to_run:
            if mod_key in module_runners:
                mod_name, mod_func = module_runners[mod_key]
                
                if not quiet:
                    print(f"\n[*] Running {mod_name}...")
                
                try:
                    result = mod_func(config_path)
                    results["modules_run"].append(mod_key)
                    results["findings"][mod_key] = result.get("findings", [])
                    results["summaries"][mod_key] = result.get("summary", {})
                    
                    if not quiet:
                        summary = result.get("summary", {})
                        total = summary.get("total_findings", 0)
                        critical = summary.get("critical", 0)
                        high = summary.get("high", 0)
                        print(f"[+] {mod_key}: {total} findings ({critical} critical, {high} high)")
                
                except Exception as e:
                    if not quiet:
                        print(f"[!] Error running {mod_key}: {e}")
                    results["findings"][mod_key] = {"error": str(e)}
    
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
        if not quiet:
            print(f"\n[+] JSON report: {json_path}")
    
    if output_format in ["markdown", "both"]:
        md_path = write_report_files(results, output_dir, "markdown")
        if not quiet:
            print(f"[+] Markdown report: {md_path}")
    
    return results


def main():
    """Main entry point."""
    args = parse_args()
    
    if args.command == "version":
        print("MCP Security Scanner v0.1.0")
        return
    
    if args.command == "validate":
        success = validate_config(args.config_path)
        sys.exit(0 if success else 1)
    
    if args.command == "scan":
        if not os.path.exists(args.config_path):
            print(f"[ERROR] Config file not found: {args.config_path}")
            sys.exit(1)
        
        # Determine modules to run
        if "all" in args.modules:
            modules = ["auth", "sandbox", "exfil", "rate"]
        else:
            modules = args.modules
        
        results = run_scan(
            config_path=args.config_path,
            modules=modules,
            output_format=args.output,
            output_dir=args.output_dir,
            quiet=args.quiet,
            min_severity=args.min_severity
        )
        
        # Print summary
        total_findings = sum(
            len(f) for f in results["findings"].values() if isinstance(f, list)
        )
        
        print("\n" + "=" * 50)
        print("SCAN COMPLETE")
        print("=" * 50)
        print(f"Modules run: {', '.join(results['modules_run'])}")
        print(f"Total findings: {total_findings}")
        
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
    parse_args()  # Will show help and exit


if __name__ == "__main__":
    main()
