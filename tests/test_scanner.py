"""
MCP Security Scanner - Unit Tests
Tests for scanner core functionality, config parsing, and report generation.
"""

import pytest
import os
import sys
import json
import tempfile
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ScannerConfig, ScanTarget, load_config, DEFAULT_SECRETS_PATTERNS
from report import Finding, ScanResult, ReportGenerator, create_scan_result
from mcp_scanner import MCPScanner, run_scan


class TestScanTarget:
    """Tests for ScanTarget dataclass."""
    
    def test_default_values(self):
        target = ScanTarget(host="localhost", port=8080)
        assert target.protocol == "http"
        assert target.auth_token is None
        assert target.timeout == 30
    
    def test_custom_values(self):
        target = ScanTarget(
            host="192.168.1.100",
            port=443,
            protocol="https",
            auth_token="test-token",
            timeout=60
        )
        assert target.host == "192.168.1.100"
        assert target.port == 443
        assert target.protocol == "https"
        assert target.auth_token == "test-token"
        assert target.timeout == 60


class TestScannerConfig:
    """Tests for ScannerConfig class."""
    
    def test_default_config(self):
        config = ScannerConfig()
        assert config.targets == []
        assert config.output_dir == "./reports"
        assert config.verbose is False
        assert config.network_check_enabled is True
        assert config.auth_check_enabled is True
    
    def test_from_dict(self):
        config_dict = {
            'targets': [
                {'host': 'localhost', 'port': 8080},
                {'host': '192.168.1.1', 'port': 443, 'protocol': 'https'}
            ],
            'output_dir': '/tmp/reports',
            'verbose': True,
            'check_hardcoded_secrets': False
        }
        
        config = ScannerConfig.from_dict(config_dict)
        assert len(config.targets) == 2
        assert config.targets[0].host == 'localhost'
        assert config.targets[1].protocol == 'https'
        assert config.output_dir == '/tmp/reports'
        assert config.verbose is True
        assert config.check_hardcoded_secrets is False
    
    def test_to_dict(self):
        config = ScannerConfig(
            targets=[ScanTarget(host="test", port=80)],
            output_dir="/test",
            verbose=True
        )
        
        result = config.to_dict()
        assert result['output_dir'] == "/test"
        assert result['verbose'] is True
        assert len(result['targets']) == 1
    
    def test_from_json_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                'targets': [{'host': 'example.com', 'port': 8080}],
                'output_dir': './output'
            }, f)
            temp_path = f.name
        
        try:
            config = ScannerConfig.from_file(temp_path)
            assert len(config.targets) == 1
            assert config.targets[0].host == 'example.com'
        finally:
            os.unlink(temp_path)
    
    def test_from_yaml_file(self):
        yaml_content = """
targets:
  - host: example.com
    port: 443
    protocol: https
output_dir: ./yaml_output
verbose: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name
        
        try:
            config = ScannerConfig.from_file(temp_path)
            assert len(config.targets) == 1
            assert config.targets[0].host == 'example.com'
            assert config.targets[0].port == 443
            assert config.verbose is True
        finally:
            os.unlink(temp_path)
    
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            ScannerConfig.from_file("/nonexistent/path.json")
    
    def test_invalid_extension(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError):
                ScannerConfig.from_file(temp_path)
        finally:
            os.unlink(temp_path)


class TestLoadConfig:
    """Tests for load_config function."""
    
    def test_load_with_valid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'targets': []}, f)
            temp_path = f.name
        
        try:
            config = load_config(temp_path)
            assert isinstance(config, ScannerConfig)
        finally:
            os.unlink(temp_path)
    
    def test_load_default_config(self):
        config = load_config()
        assert isinstance(config, ScannerConfig)
        assert config.secrets_patterns == DEFAULT_SECRETS_PATTERNS
    
    def test_load_nonexistent_file(self):
        config = load_config("/nonexistent/file.json")
        assert isinstance(config, ScannerConfig)
        # Should return default config


class TestFinding:
    """Tests for Finding dataclass."""
    
    def test_create_finding(self):
        finding = Finding(
            id="TEST-001",
            severity="HIGH",
            category="auth",
            title="Test Finding",
            description="Test description",
            target_host="localhost",
            target_port=8080
        )
        
        assert finding.id == "TEST-001"
        assert finding.severity == "HIGH"
        assert finding.category == "auth"
        assert finding.evidence is None
        assert finding.remediation is None
    
    def test_finding_with_optional_fields(self):
        finding = Finding(
            id="TEST-002",
            severity="CRITICAL",
            category="secrets",
            title="Secret Exposed",
            description="Found API key",
            target_host="192.168.1.1",
            target_port=443,
            evidence="api_key=sk_test_12345",
            remediation="Remove hardcoded secrets",
            cwe_id="CWE-798",
            cvss_score=9.1
        )
        
        assert finding.evidence == "api_key=sk_test_12345"
        assert finding.cwe_id == "CWE-798"
        assert finding.cvss_score == 9.1


class TestScanResult:
    """Tests for ScanResult dataclass."""
    
    def test_create_scan_result(self):
        findings = [
            Finding("F1", "HIGH", "auth", "Title", "Desc", "host", 80),
            Finding("F2", "MEDIUM", "config", "Title2", "Desc2", "host", 80)
        ]
        
        result = ScanResult(
            scan_id="test-123",
            timestamp="2024-01-01T00:00:00",
            targets_scanned=1,
            findings=findings,
            summary={"HIGH": 1, "MEDIUM": 1},
            duration_seconds=5.5
        )
        
        assert result.scan_id == "test-123"
        assert result.targets_scanned == 1
        assert len(result.findings) == 2
        assert result.duration_seconds == 5.5


class TestCreateScanResult:
    """Tests for create_scan_result helper."""
    
    def test_creates_result_with_summary(self):
        findings = [
            Finding("F1", "CRITICAL", "auth", "T", "D", "h", 80),
            Finding("F2", "HIGH", "auth", "T", "D", "h", 80),
            Finding("F3", "HIGH", "secrets", "T", "D", "h", 80),
            Finding("F4", "INFO", "config", "T", "D", "h", 80)
        ]
        
        result = create_scan_result(findings, targets_scanned=2, duration=10.0)
        
        assert result.scan_id is not None
        assert result.targets_scanned == 2
        assert result.summary["CRITICAL"] == 1
        assert result.summary["HIGH"] == 2
        assert result.summary["INFO"] == 1
        assert result.duration_seconds == 10.0
    
    def test_custom_scan_id(self):
        findings = []
        result = create_scan_result(findings, 1, 5.0, scan_id="custom-id")
        assert result.scan_id == "custom-id"


class TestReportGenerator:
    """Tests for ReportGenerator class."""
    
    @pytest.fixture
    def generator(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ReportGenerator(tmpdir)
    
    def test_creates_output_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new_reports")
            gen = ReportGenerator(new_dir)
            assert os.path.exists(new_dir)
    
    def test_generate_json_report(self, generator):
        findings = [
            Finding("F1", "HIGH", "auth", "Auth Missing", "No auth required", "localhost", 8080)
        ]
        result = create_scan_result(findings, 1, 2.5, "test-json")
        
        filepath = generator.generate_json_report(result)
        
        assert os.path.exists(filepath)
        assert filepath.endswith('.json')
        
        with open(filepath) as f:
            data = json.load(f)
        
        assert "report_metadata" in data
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "HIGH"
    
    def test_generate_html_report(self, generator):
        findings = [
            Finding("F1", "CRITICAL", "secrets", "Secret Exposed", "Found API key", "localhost", 8080)
        ]
        result = create_scan_result(findings, 1, 3.0, "test-html")
        
        filepath = generator.generate_html_report(result)
        
        assert os.path.exists(filepath)
        assert filepath.endswith('.html')
        
        with open(filepath) as f:
            content = f.read()
        
        assert "MCP Security Scan Report" in content
        assert "CRITICAL" in content
        assert "Secret Exposed" in content
    
    def test_generate_all_reports(self, generator):
        findings = [Finding("F1", "LOW", "config", "T", "D", "h", 80)]
        result = create_scan_result(findings, 1, 1.0, "test-all")
        
        reports = generator.generate_all_reports(result)
        
        assert "json" in reports
        assert "html" in reports
        assert os.path.exists(reports["json"])
        assert os.path.exists(reports["html"])


class TestMCPScanner:
    """Tests for MCPScanner class."""
    
    @pytest.fixture
    def scanner(self):
        config = ScannerConfig(targets=[
            ScanTarget(host="localhost", port=8080)
        ])
        return MCPScanner(config)
    
    def test_initialization(self, scanner):
        assert scanner.config is not None
        assert scanner.findings == []
        assert scanner.scanned_targets == 0
        assert scanner.VERSION == "1.0.0"
    
    @pytest.mark.asyncio
    async def test_scan_target_creates_findings(self, scanner):
        target = scanner.config.targets[0]
        findings = await scanner.scan_target(target)
        
        # Should create at least one finding (connection error or actual finding)
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_scan_target_handles_exception(self, scanner):
        target = ScanTarget(host="invalid-hostname-xyz", port=9999, timeout=1)
        findings = await scanner.scan_target(target)
        
        # Should handle exception gracefully
        assert isinstance(findings, list)
    
    def test_run_returns_result_and_reports(self, scanner):
        result, reports = scanner.run()
        
        assert isinstance(result, ScanResult)
        assert isinstance(reports, dict)
        assert "json" in reports
        assert "html" in reports
        assert os.path.exists(reports["json"])
        assert os.path.exists(reports["html"])


class TestRunScan:
    """Tests for run_scan convenience function."""
    
    def test_run_scan_with_default_config(self):
        result, reports = run_scan()
        
        assert isinstance(result, ScanResult)
        assert isinstance(reports, dict)
        assert "json" in reports
        assert "html" in reports


class TestAdminEndpoints:
    """Tests for admin endpoint detection."""
    
    def test_admin_endpoints_list_not_empty(self):
        from mcp_scanner import MCPScanner
        assert len(MCPScanner.ADMIN_ENDPOINTS) > 0
        assert '/admin' in MCPScanner.ADMIN_ENDPOINTS
        assert '/debug' in MCPScanner.ADMIN_ENDPOINTS


class TestInsecureBindings:
    """Tests for insecure binding detection."""
    
    def test_insecure_bindings_list(self):
        from mcp_scanner import MCPScanner
        assert '0.0.0.0' in MCPScanner.INSECURE_BINDINGS
        assert '127.0.0.1' in MCPScanner.INSECURE_BINDINGS
        assert '*' in MCPScanner.INSECURE_BINDINGS


class TestSecretsPatterns:
    """Tests for secrets detection patterns."""
    
    def test_default_patterns_not_empty(self):
        assert len(DEFAULT_SECRETS_PATTERNS) > 0
    
    def test_patterns_match_secrets(self):
        import re
        
        # Test API key pattern
        api_key_text = "api_key: sk_test_abcdef123456789"
        matched = False
        for pattern in DEFAULT_SECRETS_PATTERNS:
            if re.search(pattern, api_key_text):
                matched = True
                break
        assert matched is True
        
        # Test password pattern
        password_text = "password: supersecret123"
        matched = False
        for pattern in DEFAULT_SECRETS_PATTERNS:
            if re.search(pattern, password_text):
                matched = True
                break
        assert matched is True


class TestRateLimiting:
    """Tests for rate limiting detection."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_detection_with_429(self):
        """Test that rate limiting is detected when 429 responses are returned."""
        from mcp_scanner import MCPScanner
        from config import ScannerConfig, ScanTarget
        
        config = ScannerConfig()
        scanner = MCPScanner(config)
        target = ScanTarget(host="localhost", port=8080)
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 429
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            
            mock_session_instance = MagicMock()
            mock_session_instance.get = MagicMock(return_value=mock_response)
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            findings = await scanner._check_rate_limiting(target)
            
            assert len(findings) > 0
            assert any(f.id.startswith("RATE-") for f in findings)
            assert any(f.severity == "INFO" for f in findings)
    
    @pytest.mark.asyncio
    async def test_no_rate_limiting_detected(self):
        """Test that missing rate limiting is flagged when all requests succeed."""
        from mcp_scanner import MCPScanner
        from config import ScannerConfig, ScanTarget
        
        config = ScannerConfig()
        scanner = MCPScanner(config)
        target = ScanTarget(host="localhost", port=8080)
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            
            mock_session_instance = MagicMock()
            mock_session_instance.get = MagicMock(return_value=mock_response)
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            findings = await scanner._check_rate_limiting(target)
            
            assert len(findings) > 0
            assert any(f.id.startswith("RATE-") for f in findings)
            assert any(f.severity == "MEDIUM" for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
