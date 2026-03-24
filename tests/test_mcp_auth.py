#!/usr/bin/env python3
"""
Unit tests for MCP Authentication Scanner.
"""

import unittest
import tempfile
import os
import yaml
import sys
from pathlib import Path

# Add src to path (modules are in src/)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp_auth import MCPAuthScanner, AuthRiskLevel, scan_mcp_auth


class TestMCPAuthScanner(unittest.TestCase):
    """Test cases for MCP authentication scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = MCPAuthScanner()
        self.maxDiff = None
    
    def test_auth_disabled_detection(self):
        """Test detection of disabled authentication."""
        config = {
            "authentication": {
                "enabled": False
            }
        }
        
        findings = self.scanner.scan_auth_config(config)
        
        self.assertGreater(len(findings), 0)
        critical_findings = [f for f in findings if f.risk_level == "critical"]
        self.assertGreater(len(critical_findings), 0)
        
        auth_disabled = [f for f in critical_findings if "Authentication Disabled" in f.title]
        self.assertEqual(len(auth_disabled), 1)
    
    def test_weak_token_algorithm_detection(self):
        """Test detection of weak token algorithms."""
        config = {
            "authentication": {
                "enabled": True,
                "token_algorithm": "none"
            }
        }
        
        findings = self.scanner.scan_auth_config(config)
        
        weak_alg = [f for f in findings if "Weak Token Algorithm" in f.title]
        self.assertEqual(len(weak_alg), 1)
        self.assertEqual(weak_alg[0].risk_level, "high")
    
    def test_weak_secret_detection(self):
        """Test detection of weak secret keys."""
        config = {
            "authentication": {
                "enabled": True,
                "token_algorithm": "HS256",
                "secret": "short"
            }
        }
        
        findings = self.scanner.scan_auth_config(config)
        
        weak_secret = [f for f in findings if "Weak Secret Key" in f.title]
        self.assertEqual(len(weak_secret), 1)
    
    def test_hardcoded_credentials_detection(self):
        """Test detection of hardcoded credentials."""
        config = {
            "database": {
                "password": "secret123"
            }
        }
        
        findings = self.scanner.scan_auth_config(config)
        
        hardcoded = [f for f in findings if "Hardcoded" in f.title]
        self.assertGreater(len(hardcoded), 0)
    
    def test_insecure_cookie_detection(self):
        """Test detection of insecure cookie settings."""
        config = {
            "session": {
                "secure_cookie": False,
                "http_only": False,
                "timeout_seconds": 100000
            }
        }
        
        findings = self.scanner.scan_auth_config(config)
        
        insecure_cookie = [f for f in findings if "Insecure Cookie" in f.title]
        self.assertEqual(len(insecure_cookie), 1)
    
    def test_sensitive_endpoint_without_auth(self):
        """Test detection of unauthenticated sensitive endpoints."""
        config = {}
        
        endpoint_config = {
            "requires_auth": False
        }
        
        findings = self.scanner.scan_endpoint_auth("/admin", endpoint_config)
        
        unauth_endpoint = [f for f in findings if "Unauthenticated Sensitive Endpoint" in f.title]
        self.assertEqual(len(unauth_endpoint), 1)
        self.assertEqual(unauth_endpoint[0].risk_level, "high")
    
    def test_auth_endpoint_no_rate_limit(self):
        """Test detection of missing rate limit on auth endpoints."""
        config = {}
        
        endpoint_config = {
            "requires_auth": True,
            "rate_limit": None
        }
        
        findings = self.scanner.scan_endpoint_auth("/auth/login", endpoint_config)
        
        no_rate = [f for f in findings if "No Rate Limiting on Auth Endpoint" in f.title]
        self.assertEqual(len(no_rate), 1)
    
    def test_dangerous_tool_without_auth(self):
        """Test detection of dangerous tools without authentication."""
        tools = [
            {
                "name": "shell_exec",
                "requires_auth": False
            },
            {
                "name": "config_modify",
                "requires_auth": False
            }
        ]
        
        findings = self.scanner.scan_tool_permissions(tools)
        
        dangerous = [f for f in findings if "Unrestricted Dangerous Tool" in f.title]
        self.assertGreater(len(dangerous), 0)
        self.assertEqual(dangerous[0].risk_level, "critical")
    
    def test_summary_calculation(self):
        """Test summary statistics calculation."""
        self.scanner.scan_auth_config({
            "authentication": {"enabled": False}
        })
        
        summary = self.scanner.get_summary()
        
        self.assertIn("total_findings", summary)
        self.assertIn("critical", summary)
        self.assertGreater(summary["total_findings"], 0)
        self.assertGreater(summary["critical"], 0)
    
    def test_findings_serialization(self):
        """Test findings can be serialized to dict."""
        self.scanner.scan_auth_config({
            "authentication": {"enabled": False}
        })
        
        findings = self.scanner.get_all_findings()
        
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        self.assertIsInstance(findings[0], dict)
        self.assertIn("finding_id", findings[0])
        self.assertIn("title", findings[0])
        self.assertIn("risk_level", findings[0])


class TestScanMCPAuthIntegration(unittest.TestCase):
    """Integration tests for scan_mcp_auth function."""
    
    def test_scan_with_valid_config(self):
        """Test scanning with a valid config file."""
        config = {
            "authentication": {
                "enabled": True,
                "token_algorithm": "RS256"
            },
            "tools": [],
            "endpoints": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            result = scan_mcp_auth(temp_path)
            
            self.assertIn("findings", result)
            self.assertIn("summary", result)
            self.assertIn("endpoints_scanned", result)
        finally:
            os.unlink(temp_path)
    
    def test_scan_detects_critical_issues(self):
        """Test that critical issues are detected."""
        config = {
            "authentication": {
                "enabled": False
            },
            "tools": [
                {"name": "shell", "requires_auth": False}
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            result = scan_mcp_auth(temp_path)
            
            critical_count = result["summary"].get("critical", 0)
            self.assertGreater(critical_count, 0)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
