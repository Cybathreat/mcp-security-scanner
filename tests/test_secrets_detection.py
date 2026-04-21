#!/usr/bin/env python3
"""
Tests for Secrets Detection Module
"""

import pytest
import os
import tempfile
import yaml
from pathlib import Path

# Import the module under test
from src.secrets_detection import (
    scan_file_for_secrets,
    detect_secrets_in_env,
    scan_mcp_secrets,
    mask_secret,
    SECRET_PATTERNS
)


class TestSecretMasking:
    """Test secret masking functionality."""
    
    def test_mask_short_secret(self):
        """Test masking of short secrets."""
        assert mask_secret("abc") == "***"
        assert mask_secret("12345678") == "********"
    
    def test_mask_long_secret(self):
        """Test masking of long secrets."""
        result = mask_secret("AKIAIOSFODNN7EXAMPLE123")
        assert result.startswith("AKIA")
        assert result.endswith("E123")
        assert "..." in result
    
    def test_mask_api_key(self):
        """Test masking of typical API key."""
        api_key = "sk_live_REDACTED_TEST_KEY_VALUE"
        result = mask_secret(api_key)
        assert len(result) < len(api_key)
        assert result.startswith("sk_l")


class TestSecretPatterns:
    """Test secret pattern detection."""
    
    def test_aws_access_key_pattern(self):
        """Test AWS access key detection."""
        pattern = SECRET_PATTERNS["aws_access_key"]["pattern"]
        import re
        
        # Should match
        assert re.search(pattern, "aws_access_key_id = AKIAREDACTEDTESTKEY123")
        assert re.search(pattern, "AKIA1234567890ABCDEF")
        
        # Should not match
        assert not re.search(pattern, "AKIA123")  # Too short
    
    def test_private_key_pattern(self):
        """Test private key detection."""
        pattern = SECRET_PATTERNS["private_key"]["pattern"]
        import re
        
        assert re.search(pattern, "-----BEGIN RSA PRIVATE KEY-----")
        assert re.search(pattern, "-----BEGIN PRIVATE KEY-----")
        assert re.search(pattern, "-----BEGIN EC PRIVATE KEY-----")
    
    def test_database_url_pattern(self):
        """Test database URL with credentials detection."""
        pattern = SECRET_PATTERNS["database_url"]["pattern"]
        import re
        
        assert re.search(pattern, "mongodb://admin:password123@localhost:27017")
        assert re.search(pattern, "postgres://user:secret@db.example.com/mydb")
        assert re.search(pattern, "mysql://root:rootpass@127.0.0.1/app")
    
    def test_github_token_pattern(self):
        """Test GitHub token detection."""
        pattern = SECRET_PATTERNS["github_token"]["pattern"]
        import re
        
        assert re.search(pattern, "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert re.search(pattern, "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
    def test_hardcoded_password_pattern(self):
        """Test hardcoded password detection."""
        pattern = SECRET_PATTERNS["hardcoded_password"]["pattern"]
        import re
        
        assert re.search(pattern, 'password = "supersecret123"')
        assert re.search(pattern, "PASSWORD: mysecretpassword")
        assert re.search(pattern, 'pwd="admin1234"')


class TestFileScanning:
    """Test file scanning functionality."""
    
    def test_scan_clean_config(self):
        """Test scanning a config with no secrets."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config = {
                "server": {
                    "host": "localhost",
                    "port": 8080
                },
                "auth": {
                    "enabled": True,
                    "token_algorithm": "RS256"
                }
            }
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            findings = scan_file_for_secrets(temp_path)
            # Should have no critical/high findings
            critical_high = [f for f in findings if f.get("risk_level") in ["critical", "high"]]
            assert len(critical_high) == 0
        finally:
            os.unlink(temp_path)
    
    def test_scan_config_with_aws_key(self):
        """Test scanning a config with AWS credentials."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config = {
                "aws": {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE123",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }
            }
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            findings = scan_file_for_secrets(temp_path)
            aws_findings = [f for f in findings if "aws" in f.get("secret_type", "").lower()]
            assert len(aws_findings) >= 1
            assert any(f["risk_level"] == "critical" for f in aws_findings)
        finally:
            os.unlink(temp_path)
    
    def test_scan_config_with_database_url(self):
        """Test scanning a config with database credentials."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "database": {
                    "url": "mongodb://admin:password123@localhost:27017/production"
                }
            }, f)
            temp_path = f.name
        
        try:
            findings = scan_file_for_secrets(temp_path)
            db_findings = [f for f in findings if "database" in f.get("secret_type", "").lower()]
            assert len(db_findings) >= 1
            assert any(f["risk_level"] == "critical" for f in db_findings)
        finally:
            os.unlink(temp_path)
    
    def test_scan_config_with_private_key(self):
        """Test scanning a config with embedded private key."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
authentication:
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
    -----END RSA PRIVATE KEY-----
""")
            temp_path = f.name
        
        try:
            findings = scan_file_for_secrets(temp_path)
            key_findings = [f for f in findings if "private_key" in f.get("secret_type", "")]
            assert len(key_findings) >= 1
            assert any(f["risk_level"] == "critical" for f in key_findings)
        finally:
            os.unlink(temp_path)
    
    def test_scan_config_with_env_vars(self):
        """Test that env var usage is noted as info finding."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "auth": {
                    "secret": "${AUTH_SECRET}",
                    "api_key": "$API_KEY"
                }
            }, f)
            temp_path = f.name
        
        try:
            result = detect_secrets_in_env(temp_path)
            # Should have info finding for env var usage
            info_findings = [f for f in result["findings"] if f.get("risk_level") == "info"]
            assert len(info_findings) >= 1
        finally:
            os.unlink(temp_path)


class TestModuleIntegration:
    """Test the main module entry points."""
    
    def test_scan_mcp_secrets_returns_structure(self):
        """Test that main function returns expected structure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({"test": "value"}, f)
            temp_path = f.name
        
        try:
            result = scan_mcp_secrets(temp_path)
            
            assert "findings" in result
            assert "summary" in result
            assert "module" in result
            assert result["module"] == "secrets_detection"
            
            # Check summary structure
            summary = result["summary"]
            assert "total_findings" in summary
            assert "critical" in summary
            assert "high" in summary
            assert "medium" in summary
            assert "low" in summary
        finally:
            os.unlink(temp_path)
    
    def test_scan_mcp_secrets_with_real_config(self):
        """Test with actual MCP config structure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config = {
                "authentication": {
                    "enabled": True,
                    "jwt_secret": "my-super-secret-jwt-key-12345"
                },
                "database": {
                    "url": "${DATABASE_URL}"
                },
                "tools": [
                    {
                        "name": "slack_bot",
                        "token": "xoxb-REDACTED-TEST-TOKEN-PLACEHOLDER"
                    }
                ]
            }
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            result = scan_mcp_secrets(temp_path)
            
            # Should find JWT secret and Slack token
            assert result["summary"]["total_findings"] >= 2
            assert result["summary"]["critical"] >= 1 or result["summary"]["high"] >= 1
        finally:
            os.unlink(temp_path)


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_nonexistent_file(self):
        """Test handling of nonexistent file."""
        result = detect_secrets_in_env("/nonexistent/path/config.yaml")
        assert "error" in result
        assert result["findings"] == []
    
    def test_empty_config(self):
        """Test handling of empty config."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            temp_path = f.name
        
        try:
            result = scan_mcp_secrets(temp_path)
            assert result["findings"] == [] or len(result["findings"]) == 0
        finally:
            os.unlink(temp_path)
    
    def test_malformed_yaml(self):
        """Test handling of malformed YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("this is not: valid: yaml: {{{{")
            temp_path = f.name
        
        try:
            result = detect_secrets_in_env(temp_path)
            # Should handle gracefully with error
            assert "error" in result or result["findings"] == []
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
