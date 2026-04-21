#!/usr/bin/env python3
"""
Secrets Detection Module for MCP Security Scanner

Detects hardcoded secrets, API keys, credentials, and sensitive tokens
in MCP server configurations.
"""

import re
import os
import yaml
from typing import Dict, List, Any, Tuple
from pathlib import Path


# Secret patterns with high confidence
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?i)(aws[_-]?access[_-]?key[_-]?id|AKIA)[0-9A-Z]{16,}",
        "risk_level": "critical",
        "description": "AWS Access Key ID detected",
        "cwe": "CWE-798",
        "remediation": "Use IAM roles or environment variables instead of hardcoded credentials"
    },
    "aws_secret_key": {
        "pattern": r"(?i)(aws[_-]?secret[_-]?access[_-]?key)[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}",
        "risk_level": "critical",
        "description": "AWS Secret Access Key detected",
        "cwe": "CWE-798",
        "remediation": "Use IAM roles or environment variables instead of hardcoded credentials"
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "risk_level": "critical",
        "description": "Private key detected in configuration",
        "cwe": "CWE-321",
        "remediation": "Store private keys in secure secret management systems"
    },
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)[\"']?\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}",
        "risk_level": "high",
        "description": "Generic API key detected",
        "cwe": "CWE-798",
        "remediation": "Use environment variables or secret management for API keys"
    },
    "bearer_token": {
        "pattern": r"(?i)(bearer|token)[\"']?\s*[=:]\s*[\"']?[a-zA-Z0-9_\-\.]{20,}",
        "risk_level": "high",
        "description": "Bearer token or auth token detected",
        "cwe": "CWE-798",
        "remediation": "Use dynamic token generation and secure storage"
    },
    "database_url": {
        "pattern": r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@",
        "risk_level": "critical",
        "description": "Database connection string with credentials",
        "cwe": "CWE-798",
        "remediation": "Use environment variables for database connection strings"
    },
    "jwt_secret": {
        "pattern": r"(?i)(jwt[_-]?secret|jwt[_-]?key)[\"']?\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{16,}",
        "risk_level": "critical",
        "description": "JWT secret key detected",
        "cwe": "CWE-798",
        "remediation": "Generate JWT secrets securely and store in environment variables"
    },
    "oauth_secret": {
        "pattern": r"(?i)(oauth[_-]?secret|client[_-]?secret)[\"']?\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}",
        "risk_level": "high",
        "description": "OAuth client secret detected",
        "cwe": "CWE-798",
        "remediation": "Store OAuth secrets in secure environment variables"
    },
    "github_token": {
        "pattern": r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}",
        "risk_level": "critical",
        "description": "GitHub token detected",
        "cwe": "CWE-798",
        "remediation": "Use GitHub Apps or environment variables for tokens"
    },
    "slack_token": {
        "pattern": r"(?i)(xox[baprs]-)[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "risk_level": "high",
        "description": "Slack token detected",
        "cwe": "CWE-798",
        "remediation": "Store Slack tokens in secure environment variables"
    },
    "stripe_key": {
        "pattern": r"(?i)(sk_live_|rk_live_|pk_live_)[a-zA-Z0-9]{24,}",
        "risk_level": "critical",
        "description": "Stripe API key detected",
        "cwe": "CWE-798",
        "remediation": "Use environment variables for payment provider keys"
    },
    "sendgrid_key": {
        "pattern": r"(?i)(SG\.)[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
        "risk_level": "high",
        "description": "SendGrid API key detected",
        "cwe": "CWE-798",
        "remediation": "Store SendGrid keys in secure environment variables"
    },
    "hardcoded_password": {
        "pattern": r"(?i)(password|passwd|pwd)[\"']?\s*[=:]\s*[\"']?[^\s\"']{8,}",
        "risk_level": "critical",
        "description": "Hardcoded password detected",
        "cwe": "CWE-798",
        "remediation": "Never hardcode passwords; use secure secret management"
    },
    "encryption_key": {
        "pattern": r"(?i)(encryption[_-]?key|encrypt[_-]?key|aes[_-]?key)[\"']?\s*[=:]\s*[\"']?[a-fA-F0-9]{32,}",
        "risk_level": "critical",
        "description": "Encryption key detected in configuration",
        "cwe": "CWE-321",
        "remediation": "Store encryption keys in secure key management systems"
    },
    "webhook_secret": {
        "pattern": r"(?i)(webhook[_-]?secret|wh[_-]?secret)[\"']?\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{16,}",
        "risk_level": "high",
        "description": "Webhook secret detected",
        "cwe": "CWE-798",
        "remediation": "Store webhook secrets in environment variables"
    }
}


def scan_file_for_secrets(file_path: str, config_data: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Scan a file or config data for hardcoded secrets.
    
    Args:
        file_path: Path to the file to scan
        config_data: Pre-loaded config data (optional)
    
    Returns:
        List of findings
    """
    findings = []
    
    # Load config if not provided
    if config_data is None:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    config_data = yaml.safe_load(content)
                else:
                    config_data = {"raw_content": content}
        except Exception as e:
            return [{"error": f"Failed to load file: {e}"}]
    
    # Convert config to string for pattern matching
    config_str = yaml.dump(config_data) if isinstance(config_data, dict) else str(config_data)
    
    # Scan for each pattern
    for secret_type, secret_config in SECRET_PATTERNS.items():
        matches = re.finditer(secret_config["pattern"], config_str)
        
        for match in matches:
            # Get context around the match
            start = max(0, match.start() - 50)
            end = min(len(config_str), match.end() + 50)
            context = config_str[start:end].replace('\n', ' ')
            
            # Mask the actual secret value
            masked_match = mask_secret(match.group())
            
            finding = {
                "type": "secrets_detection",
                "secret_type": secret_type,
                "risk_level": secret_config["risk_level"],
                "title": secret_config["description"],
                "description": f"Found {secret_config['description']} in configuration",
                "cwe": secret_config["cwe"],
                "remediation": secret_config["remediation"],
                "location": file_path,
                "matched_value": masked_match,
                "context": context.strip(),
                "confidence": "high"
            }
            
            findings.append(finding)
    
    return findings


def mask_secret(secret_value: str) -> str:
    """
    Mask a secret value for safe display.
    Shows first 4 and last 4 characters only.
    """
    if len(secret_value) <= 8:
        return "*" * len(secret_value)
    
    return f"{secret_value[:4]}...{secret_value[-4:]}"


def detect_secrets_in_env(config_path: str) -> Dict[str, Any]:
    """
    Check if secrets are properly configured via environment variables.
    
    Args:
        config_path: Path to MCP config file
    
    Returns:
        Dict with findings and summary
    """
    findings = []
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return {
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "error": str(e)
        }
    
    # Check for hardcoded secrets
    hardcoded_findings = scan_file_for_secrets(config_path, config)
    findings.extend(hardcoded_findings)
    
    # Check for proper env var usage
    config_str = yaml.dump(config)
    env_var_pattern = r'\$\{?[A-Z_][A-Z0-9_]*\}?|\$[A-Z_][A-Z0-9_]*'
    env_vars_found = re.findall(env_var_pattern, config_str)
    
    # Positive finding: good env var usage
    if env_vars_found:
        findings.append({
            "type": "secrets_detection",
            "secret_type": "env_var_usage",
            "risk_level": "info",
            "title": "Environment variables detected",
            "description": f"Found {len(env_vars_found)} environment variable references, indicating proper secret management",
            "cwe": "N/A",
            "remediation": "Continue using environment variables for sensitive values",
            "location": config_path,
            "env_vars_count": len(env_vars_found),
            "confidence": "high"
        })
    
    # Calculate summary
    summary = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("risk_level") == "critical"),
        "high": sum(1 for f in findings if f.get("risk_level") == "high"),
        "medium": sum(1 for f in findings if f.get("risk_level") == "medium"),
        "low": sum(1 for f in findings if f.get("risk_level") == "low"),
        "info": sum(1 for f in findings if f.get("risk_level") == "info")
    }
    
    return {
        "findings": findings,
        "summary": summary,
        "module": "secrets_detection",
        "version": "1.0.0"
    }


def scan_mcp_secrets(config_path: str) -> Dict[str, Any]:
    """
    Main entry point for secrets detection module.
    
    Args:
        config_path: Path to MCP server configuration file
    
    Returns:
        Dict with findings and summary
    """
    return detect_secrets_in_env(config_path)


# For direct module testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python secrets_detection.py <config.yaml>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    result = scan_mcp_secrets(config_file)
    
    print(f"\n{'='*60}")
    print("SECRETS DETECTION RESULTS")
    print(f"{'='*60}")
    print(f"Total findings: {result['summary']['total_findings']}")
    print(f"Critical: {result['summary']['critical']}")
    print(f"High: {result['summary']['high']}")
    print(f"Medium: {result['summary']['medium']}")
    print(f"Low: {result['summary']['low']}")
    
    if result["findings"]:
        print(f"\n{'='*60}")
        print("FINDINGS")
        print(f"{'='*60}")
        
        for i, finding in enumerate(result["findings"], 1):
            print(f"\n[{i}] {finding['title']}")
            print(f"    Risk: {finding['risk_level'].upper()}")
            print(f"    CWE: {finding['cwe']}")
            print(f"    Location: {finding['location']}")
            if 'matched_value' in finding:
                print(f"    Matched: {finding['matched_value']}")
            print(f"    Remediation: {finding['remediation']}")
