# MCP Security Scanner

A comprehensive security scanner for Model Context Protocol (MCP) servers. Detects authentication weaknesses, sandboxing misconfigurations, data exfiltration vectors, and rate limiting issues.

## Overview

MCP servers provide AI models with access to external tools and data sources. This scanner audits MCP configurations for security vulnerabilities before deployment.

## Features

- **Authentication Scanner**: Detects weak auth configs, hardcoded credentials, missing auth on sensitive endpoints
- **Tool Sandbox Validator**: Identifies command injection, path traversal, SSRF, container escape vectors
- **Data Exfiltration Detector**: Finds insecure data transmission, logging leaks, missing classification
- **Rate Limiting Analyzer**: Detects missing rate limits, DDoS amplification, resource exhaustion risks

## Installation

```bash
# Clone the repository
git clone https://github.com/Cybathreat/mcp-security-scanner.git
cd mcp-security-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
# Run all security modules
python src/cli.py scan config/config.yaml

# Run specific modules
python src/cli.py scan config/config.yaml --modules auth sandbox

# Specify output format
python src/cli.py scan config/config.yaml --output json
python src/cli.py scan config/config.yaml --output markdown
python src/cli.py scan config/config.yaml --output both

# Set output directory
python src/cli.py scan config/config.yaml --output-dir ./reports

# Filter by minimum severity
python src/cli.py scan config/config.yaml --min-severity high

# Quiet mode (suppress progress)
python src/cli.py scan config/config.yaml --quiet
```

### Validate Configuration

```bash
# Check YAML syntax
python src/cli.py validate config/config.yaml
```

### Available Commands

```
mcp-security-scanner scan     Run security scans
mcp-security-scanner validate Validate config syntax
mcp-security-scanner version  Show version
```

## Output

Reports are generated in `./reports/` by default:

- **JSON**: Machine-readable format for CI/CD integration
- **Markdown**: Human-readable report with executive summary

### Example Report Structure

```json
{
  "report_metadata": {
    "tool": "MCP Security Scanner",
    "version": "0.1.0",
    "generated_at": "2026-03-21T..."
  },
  "executive_summary": {
    "total_findings": 15,
    "by_severity": {
      "critical": 3,
      "high": 5,
      "medium": 4,
      "low": 3
    },
    "overall_risk_level": "CRITICAL"
  },
  "scan_results": {...},
  "recommendations": [...]
}
```

## Security Modules

### 1. Authentication (auth)

Scans for:
- Disabled authentication
- Weak token algorithms (none, MD5, SHA1)
- Short secret keys
- Hardcoded credentials
- Insecure session cookies
- Unauthenticated sensitive endpoints
- Dangerous tools without auth

**CWEs**: CWE-306, CWE-327, CWE-326, CWE-798, CWE-614, CWE-284

### 2. Tool Sandboxing (sandbox)

Scans for:
- Command injection vectors
- Unrestricted shell access
- Path traversal vulnerabilities
- SSRF via internal network access
- Unsafe protocols (file://, gopher://)
- Disabled sandboxing
- Privileged containers
- Missing resource limits

**CWEs**: CWE-78, CWE-22, CWE-918, CWE-400, CWE-377

### 3. Data Exfiltration (exfil)

Scans for:
- Unrestricted data access
- Unencrypted transmission
- Weak TLS configuration
- Sensitive data logging
- Missing PII detection
- Unauthenticated bulk endpoints
- Timing oracles

**CWEs**: CWE-284, CWE-311, CWE-327, CWE-532, CWE-359, CWE-208

### 4. Rate Limiting (rate)

Scans for:
- Disabled global rate limiting
- Missing auth endpoint limits
- No login attempt limits
- Missing resource limits
- DDoS amplification vectors
- Query complexity limits

**CWEs**: CWE-400, CWE-307, CWE-208

## Configuration

Create a `config.yaml` for your MCP server:

```yaml
authentication:
  enabled: true
  token_algorithm: "RS256"
  secret: "${MCP_SECRET_KEY}"

session:
  secure_cookie: true
  http_only: true

rate_limiting:
  enabled: true
  requests_per_minute: 100

tools:
  - name: "shell_exec"
    type: "shell"
    requires_auth: true
    sandbox:
      enabled: true
```

See `config/config.yaml` for the full default configuration.

## Exit Codes

- `0`: Scan complete, no critical findings
- `1`: Error (config not found, invalid YAML)
- `2`: Critical findings detected

## CI/CD Integration

```yaml
# GitHub Actions example
- name: MCP Security Scan
  run: |
    pip install -r requirements.txt
    python src/cli.py scan mcp-config.yaml --output json
    if [ $? -eq 2 ]; then
      echo "Critical security issues found!"
      exit 1
    fi
```

## Programmatic Usage

```python
from mcp_auth import scan_mcp_auth
from tool_sandbox import validate_tool_sandbox
from data_exfil import detect_data_exfil_vectors
from rate_limiting import detect_rate_limit_issues

# Run individual scanners
auth_results = scan_mcp_auth("config.yaml")
sandbox_results = validate_tool_sandbox("config.yaml")
exfil_results = detect_data_exfil_vectors("config.yaml")
rate_results = detect_rate_limit_issues("config.yaml")

# Check for critical findings
if auth_results["summary"]["critical"] > 0:
    print("Critical auth issues found!")
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_mcp_auth.py -v
python -m pytest tests/test_sandbox.py -v
```

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for security auditing purposes. See DISCLAIMER.md for legal terms.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Version

v0.1.0 - MVP Release
