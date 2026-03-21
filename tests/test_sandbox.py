#!/usr/bin/env python3
"""
Unit tests for Tool Sandbox Validator.
"""

import unittest
import tempfile
import os
import yaml
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tool_sandbox import ToolSandboxValidator, SandboxRiskLevel, validate_tool_sandbox


class TestToolSandboxValidator(unittest.TestCase):
    """Test cases for tool sandbox validator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = ToolSandboxValidator()
        self.maxDiff = None
    
    def test_command_injection_detection(self):
        """Test detection of command injection vectors."""
        tool_config = {
            "name": "shell_runner",
            "type": "shell",
            "parameters": {
                "cmd": {
                    "sanitize": False,
                    "allowlist": None
                }
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        cmd_injection = [f for f in findings if "Command Injection" in f.title]
        self.assertEqual(len(cmd_injection), 1)
        self.assertEqual(cmd_injection[0].risk_level, "critical")
    
    def test_unrestricted_shell_detection(self):
        """Test detection of unrestricted shell access."""
        tool_config = {
            "name": "shell_exec",
            "type": "shell",
            "shell": True,
            "restricted_shell": False
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        unrestricted = [f for f in findings if "Unrestricted Shell" in f.title]
        self.assertGreater(len(unrestricted), 0)
    
    def test_shell_true_subprocess_detection(self):
        """Test detection of shell=True in subprocess."""
        tool_config = {
            "name": "process_runner",
            "type": "exec",
            "execution": {
                "shell": True,
                "inherit_env": True
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        shell_true = [f for f in findings if "Shell=True" in f.title]
        self.assertEqual(len(shell_true), 1)
    
    def test_path_traversal_detection(self):
        """Test detection of path traversal vulnerabilities."""
        tool_config = {
            "name": "file_reader",
            "type": "file_read",
            "parameters": {
                "path": {
                    "restrict_base_dir": False
                }
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        traversal = [f for f in findings if "Path Traversal" in f.title]
        self.assertEqual(len(traversal), 1)
        self.assertEqual(traversal[0].risk_level, "high")
    
    def test_world_writable_detection(self):
        """Test detection of world-writable directory access."""
        tool_config = {
            "name": "file_writer",
            "type": "file_write",
            "filesystem": {
                "allow_world_writable": True
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        world_writable = [f for f in findings if "World-Writable" in f.title]
        self.assertEqual(len(world_writable), 1)
    
    def test_sensitive_file_access_detection(self):
        """Test detection of sensitive file access."""
        tool_config = {
            "name": "system_reader",
            "type": "file_read",
            "filesystem": {
                "allowed_paths": ["/etc/passwd", "/etc/shadow"]
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        sensitive = [f for f in findings if "Sensitive File Access" in f.title]
        self.assertGreater(len(sensitive), 0)
    
    def test_ssrf_internal_network_detection(self):
        """Test detection of SSRF via internal network access."""
        tool_config = {
            "name": "http_fetcher",
            "type": "http",
            "network": {
                "block_internal": False,
                "url_allowlist": None
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        ssrf_internal = [f for f in findings if "Internal Network Access" in f.title]
        self.assertEqual(len(ssrf_internal), 1)
        self.assertEqual(ssrf_internal[0].risk_level, "high")
    
    def test_unsafe_protocol_detection(self):
        """Test detection of unsafe protocols."""
        tool_config = {
            "name": "url_fetcher",
            "type": "fetch",
            "network": {
                "allowed_protocols": ["https", "file", "gopher"]
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        unsafe = [f for f in findings if "Unsafe Protocol" in f.title]
        self.assertGreater(len(unsafe), 0)
    
    def test_sandbox_disabled_detection(self):
        """Test detection of disabled sandboxing."""
        tool_config = {
            "name": "dangerous_tool",
            "type": "shell",
            "sandbox": {
                "enabled": False
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        disabled = [f for f in findings if "Sandboxing Disabled" in f.title]
        self.assertEqual(len(disabled), 1)
        self.assertEqual(disabled[0].risk_level, "critical")
    
    def test_no_resource_limits_detection(self):
        """Test detection of missing resource limits."""
        tool_config = {
            "name": "unlimited_tool",
            "type": "exec",
            "sandbox": {
                "enabled": True,
                "resource_limits": None,
                "timeout_seconds": 0
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        no_limits = [f for f in findings if "No Resource Limits" in f.title]
        self.assertEqual(len(no_limits), 1)
    
    def test_privileged_container_detection(self):
        """Test detection of privileged container mode."""
        tool_config = {
            "name": "container_tool",
            "type": "exec",
            "sandbox": {
                "enabled": True,
                "container": {
                    "privileged": True,
                    "read_only_root": False
                }
            }
        }
        
        findings = self.validator.validate_tool_config(tool_config)
        
        privileged = [f for f in findings if "Privileged Container" in f.title]
        self.assertEqual(len(privileged), 1)
        self.assertEqual(privileged[0].risk_level, "critical")
    
    def test_validate_all_tools(self):
        """Test validation of multiple tools."""
        tools = [
            {
                "name": "shell_exec",
                "type": "shell",
                "parameters": {"cmd": {"sanitize": False}}
            },
            {
                "name": "file_reader",
                "type": "file_read",
                "parameters": {"path": {"restrict_base_dir": False}}
            },
            {
                "name": "http_fetch",
                "type": "http",
                "network": {"block_internal": False}
            }
        ]
        
        findings = self.validator.validate_all_tools(tools)
        
        self.assertGreater(len(findings), 0)
        
        # Should have findings from all three tools
        tools_with_findings = set(f.affected_tool for f in findings)
        self.assertIn("shell_exec", tools_with_findings)
        self.assertIn("file_reader", tools_with_findings)
        self.assertIn("http_fetch", tools_with_findings)
    
    def test_summary_calculation(self):
        """Test summary statistics calculation."""
        tool_config = {
            "name": "test_tool",
            "type": "shell",
            "sandbox": {"enabled": False}
        }
        
        self.validator.validate_tool_config(tool_config)
        
        summary = self.validator.get_summary()
        
        self.assertIn("total_findings", summary)
        self.assertIn("critical", summary)
        self.assertIn("tools_validated", summary)
        self.assertGreater(summary["total_findings"], 0)
    
    def test_findings_serialization(self):
        """Test findings can be serialized to dict."""
        tool_config = {
            "name": "test_tool",
            "type": "shell",
            "sandbox": {"enabled": False}
        }
        
        self.validator.validate_tool_config(tool_config)
        
        findings = self.validator.get_all_findings()
        
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        self.assertIsInstance(findings[0], dict)
        self.assertIn("finding_id", findings[0])
        self.assertIn("title", findings[0])
        self.assertIn("risk_level", findings[0])
        self.assertIn("cwe_id", findings[0])


class TestValidateToolSandboxIntegration(unittest.TestCase):
    """Integration tests for validate_tool_sandbox function."""
    
    def test_validate_with_valid_config(self):
        """Test validation with a valid config file."""
        config = {
            "tools": [
                {
                    "name": "safe_tool",
                    "type": "file_read",
                    "sandbox": {"enabled": True}
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            result = validate_tool_sandbox(temp_path)
            
            self.assertIn("findings", result)
            self.assertIn("summary", result)
            self.assertIn("tools_validated", result)
        finally:
            os.unlink(temp_path)
    
    def test_validate_detects_critical_issues(self):
        """Test that critical sandbox issues are detected."""
        config = {
            "tools": [
                {
                    "name": "dangerous",
                    "type": "shell",
                    "sandbox": {"enabled": False},
                    "parameters": {"cmd": {"sanitize": False}}
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            result = validate_tool_sandbox(temp_path)
            
            critical_count = result["summary"].get("critical", 0)
            self.assertGreater(critical_count, 0)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
