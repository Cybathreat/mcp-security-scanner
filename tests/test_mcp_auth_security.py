"""
Tests for MCP Authentication & Authorization Security Scanner
"""

import pytest
import os
import tempfile
import json
from pathlib import Path

# Import the scanner module
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_auth_security import MCPAuthSecurityScanner, scan_mcp_auth


class TestMCPAuthSecurityScanner:
    """Test suite for MCPAuthSecurityScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = MCPAuthSecurityScanner()
        self.test_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def _create_test_file(self, content: str, filename: str = 'test_config.json') -> str:
        """Create a temporary test file."""
        filepath = os.path.join(self.test_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return filepath
    
    # ==================== Missing Authentication Tests ====================
    
    def test_detect_missing_auth_json(self):
        """Test detection of missing authentication in JSON config."""
        config = {
            "server": "mcp-server",
            "port": 8080,
            "endpoints": ["/api/v1"]
            # No auth field
        }
        filepath = self._create_test_file(json.dumps(config, indent=2))
        findings = self.scanner.scan_config_file(filepath)
        
        missing_auth = [f for f in findings if f['type'] == 'missing_authentication']
        assert len(missing_auth) > 0, "Should detect missing authentication"
        assert missing_auth[0]['severity'] == 'critical'
    
    def test_detect_explicit_disabled_auth(self):
        """Test detection of explicitly disabled authentication."""
        config = {
            "server": "mcp-server",
            "auth": "none",
            "authentication": "disabled"
        }
        filepath = self._create_test_file(json.dumps(config, indent=2))
        findings = self.scanner.scan_config_file(filepath)
        
        missing_auth = [f for f in findings if f['type'] == 'missing_authentication']
        assert len(missing_auth) > 0
    
    def test_no_false_positive_with_auth(self):
        """Test that proper auth config doesn't trigger false positive."""
        config = {
            "server": "mcp-server",
            "auth": {
                "type": "oauth2",
                "provider": "auth0",
                "required": True
            }
        }
        filepath = self._create_test_file(json.dumps(config, indent=2))
        findings = self.scanner.scan_config_file(filepath)
        
        missing_auth = [f for f in findings if f['type'] == 'missing_authentication']
        assert len(missing_auth) == 0, "Should not flag proper auth config"
    
    # ==================== Weak Authentication Tests ====================
    
    def test_detect_weak_api_key(self):
        """Test detection of weak API key."""
        content = """
        {
            "api_key": "test",
            "server": "mcp-server"
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        weak_auth = [f for f in findings if f['type'] == 'weak_authentication']
        assert len(weak_auth) > 0
        assert 'test' in weak_auth[0]['message']
    
    def test_detect_weak_password(self):
        """Test detection of weak password."""
        content = """
        {
            "password": "admin",
            "server": "mcp-server"
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        weak_auth = [f for f in findings if f['type'] == 'weak_authentication']
        assert len(weak_auth) > 0
    
    def test_detect_weak_token(self):
        """Test detection of weak token."""
        content = "token = '123456'\nserver = 'mcp-server'"
        filepath = self._create_test_file(content, 'test_config.yaml')
        findings = self.scanner.scan_config_file(filepath)
        
        weak_auth = [f for f in findings if f['type'] == 'weak_authentication']
        assert len(weak_auth) > 0
    
    # ==================== Credential Exposure Tests ====================
    
    def test_detect_exposed_api_key(self):
        """Test detection of exposed API key."""
        content = """
        {
            "api_key": "sk_test_fake_key_for_testing_purposes_only_12345",
            "server": "mcp-server"
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        cred_exposure = [f for f in findings if f['type'] == 'credential_exposure']
        assert len(cred_exposure) > 0
        assert 'api_key' in cred_exposure[0]['message']
    
    def test_detect_exposed_secret_key(self):
        """Test detection of exposed secret key."""
        content = """
        secret_key = "super_secret_key_1234567890abcdef"
        """
        filepath = self._create_test_file(content, 'test_config.toml')
        findings = self.scanner.scan_config_file(filepath)
        
        cred_exposure = [f for f in findings if f['type'] == 'credential_exposure']
        assert len(cred_exposure) > 0
    
    def test_detect_exposed_bearer_token(self):
        """Test detection of exposed bearer token."""
        content = """
        authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
        """
        filepath = self._create_test_file(content, 'test_config.yaml')
        findings = self.scanner.scan_config_file(filepath)
        
        cred_exposure = [f for f in findings if f['type'] == 'credential_exposure']
        assert len(cred_exposure) > 0
    
    def test_detect_exposed_password(self):
        """Test detection of exposed password."""
        content = """
        {
            "database": {
                "password": "SuperSecretPassword123!"
            }
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        cred_exposure = [f for f in findings if f['type'] == 'credential_exposure']
        assert len(cred_exposure) > 0
    
    # ==================== Authorization Bypass Tests ====================
    
    def test_detect_admin_true_bypass(self):
        """Test detection of admin=true bypass pattern."""
        content = """
        {
            "user": "guest",
            "admin": true,
            "role": "user"
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        auth_bypass = [f for f in findings if f['type'] == 'authorization_bypass']
        assert len(auth_bypass) > 0
    
    def test_detect_wildcard_permissions(self):
        """Test detection of wildcard permissions."""
        content = """
        {
            "permissions": "*",
            "scope": "all"
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        auth_bypass = [f for f in findings if f['type'] == 'authorization_bypass']
        assert len(auth_bypass) > 0
    
    def test_detect_skip_auth(self):
        """Test detection of skip_auth flag."""
        content = """
        {
            "skip_auth": true,
            "bypass": true
        }
        """
        filepath = self._create_test_file(content)
        findings = self.scanner.scan_config_file(filepath)
        
        auth_bypass = [f for f in findings if f['type'] == 'authorization_bypass']
        assert len(auth_bypass) > 0
    
    # ==================== Directory Scanning Tests ====================
    
    def test_scan_directory(self):
        """Test scanning a directory with multiple config files."""
        # Create multiple config files
        config1 = {"auth": "none"}
        config2 = {"api_key": "test"}
        config3 = {"auth": {"type": "oauth2"}}  # Safe
        
        with open(os.path.join(self.test_dir, 'config1.json'), 'w') as f:
            json.dump(config1, f)
        with open(os.path.join(self.test_dir, 'config2.json'), 'w') as f:
            json.dump(config2, f)
        with open(os.path.join(self.test_dir, 'config3.json'), 'w') as f:
            json.dump(config3, f)
        
        findings = self.scanner.scan_directory(self.test_dir, recursive=False)
        
        # Should find issues in config1 and config2
        assert len(findings) >= 2
    
    def test_scan_directory_recursive(self):
        """Test recursive directory scanning."""
        # Create subdirectory
        subdir = os.path.join(self.test_dir, 'subdir')
        os.makedirs(subdir)
        
        config = {"auth": "disabled"}
        with open(os.path.join(subdir, 'nested_config.json'), 'w') as f:
            json.dump(config, f)
        
        findings = self.scanner.scan_directory(self.test_dir, recursive=True)
        
        # Should find the nested config
        assert len(findings) > 0
    
    # ==================== Report Generation Tests ====================
    
    def test_generate_report_empty(self):
        """Test report generation with no findings."""
        report = self.scanner.generate_report([])
        assert 'No authentication/authorization issues detected' in report
        assert '✅' in report
    
    def test_generate_report_with_findings(self):
        """Test report generation with findings."""
        findings = [
            {
                'file': '/path/to/config.json',
                'severity': 'critical',
                'type': 'missing_authentication',
                'message': 'MCP server configured without authentication',
                'line': 5
            },
            {
                'file': '/path/to/config.json',
                'severity': 'high',
                'type': 'weak_authentication',
                'message': 'Weak authentication detected: api_key = test',
                'line': 10
            }
        ]
        report = self.scanner.generate_report(findings)
        
        assert 'MCP Authentication & Authorization Security Report' in report
        assert 'Total issues found: 2' in report
        assert '[CRITICAL]' in report
        assert '[HIGH]' in report
    
    # ==================== Line Number Detection Tests ====================
    
    def test_find_line_number(self):
        """Test line number detection."""
        content = """line1
line2
target_line
line4
"""
        line_num = self.scanner._find_line_number(content, 'target_line')
        assert line_num == 3
    
    def test_find_line_number_not_found(self):
        """Test line number detection when text not found."""
        content = "line1\nline2\nline3"
        line_num = self.scanner._find_line_number(content, 'not_found')
        assert line_num == 0
    
    # ==================== Convenience Function Tests ====================
    
    def test_scan_mcp_auth_file(self):
        """Test the convenience function with a file."""
        content = {"auth": "none"}
        filepath = self._create_test_file(json.dumps(content))
        report = scan_mcp_auth(filepath)
        
        assert 'CRITICAL' in report or 'critical' in report.lower()
    
    def test_scan_mcp_auth_directory(self):
        """Test the convenience function with a directory."""
        content = {"auth": "disabled"}
        filepath = self._create_test_file(json.dumps(content))
        report = scan_mcp_auth(self.test_dir)
        
        assert 'MCP Authentication' in report
    
    def test_scan_mcp_auth_not_found(self):
        """Test the convenience function with non-existent target."""
        report = scan_mcp_auth('/nonexistent/path')
        assert 'Error' in report
        assert 'not found' in report


class TestMCPAuthSecurityScannerEdgeCases:
    """Edge case tests for MCPAuthSecurityScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = MCPAuthSecurityScanner()
        self.test_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_empty_file(self):
        """Test scanning an empty file."""
        filepath = os.path.join(self.test_dir, 'empty.json')
        with open(filepath, 'w') as f:
            f.write('')
        
        findings = self.scanner.scan_config_file(filepath)
        # Should not crash, may have findings or not
        assert isinstance(findings, list)
    
    def test_invalid_json(self):
        """Test scanning invalid JSON."""
        filepath = os.path.join(self.test_dir, 'invalid.json')
        with open(filepath, 'w') as f:
            f.write('{invalid json}')
        
        findings = self.scanner.scan_config_file(filepath)
        # Should handle gracefully
        assert isinstance(findings, list)
    
    def test_large_file(self):
        """Test scanning a large config file."""
        config = {"auth": "none", "data": ["x" * 1000] * 100}
        filepath = os.path.join(self.test_dir, 'large.json')
        with open(filepath, 'w') as f:
            json.dump(config, f)
        
        findings = self.scanner.scan_config_file(filepath)
        assert isinstance(findings, list)
    
    def test_unicode_content(self):
        """Test scanning file with unicode content."""
        content = """
        {
            "name": "服务器配置",
            "auth": "none",
            "description": "Configuration with émojis 🔒 and spëcial çharacters"
        }
        """
        filepath = os.path.join(self.test_dir, 'unicode.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        findings = self.scanner.scan_config_file(filepath)
        assert isinstance(findings, list)
    
    def test_yaml_format(self):
        """Test scanning YAML format."""
        content = """
server:
  name: mcp-server
  auth: none
  port: 8080
"""
        filepath = os.path.join(self.test_dir, 'config.yaml')
        with open(filepath, 'w') as f:
            f.write(content)
        
        findings = self.scanner.scan_config_file(filepath)
        assert isinstance(findings, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
