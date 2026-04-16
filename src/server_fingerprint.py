#!/usr/bin/env python3
"""
MCP Server Fingerprinting Module

Identifies MCP server type, version, capabilities, and technology stack.
Used for asset discovery and targeted security assessments.
"""

import re
import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime, timezone


class ServerType(Enum):
    UNKNOWN = "unknown"
    FASTMCP = "fastmcp"
    LANGCHAIN_MCP = "langchain_mcp"
    CUSTOM = "custom"
    OPENAPI_PROXY = "openapi_proxy"
    GRPC_GATEWAY = "grpc_gateway"


@dataclass
class FingerprintFinding:
    finding_id: str
    title: str
    description: str
    risk_level: str
    server_type: str
    evidence: str
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None


@dataclass
class ServerFingerprint:
    """Complete fingerprint of an MCP server."""
    host: str
    port: int
    server_type: ServerType = ServerType.UNKNOWN
    server_version: Optional[str] = None
    mcp_protocol_version: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    tools_count: int = 0
    resources_count: int = 0
    prompts_count: int = 0
    auth_methods: List[str] = field(default_factory=list)
    transport: str = "unknown"
    tls_enabled: bool = False
    server_headers: Dict[str, str] = field(default_factory=dict)
    exposed_endpoints: List[str] = field(default_factory=list)
    technology_stack: List[str] = field(default_factory=list)
    findings: List[FingerprintFinding] = field(default_factory=list)
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MCPFingerprintScanner:
    """
    Scanner for MCP server fingerprinting.
    
    Identifies:
    - Server type (FastMCP, LangChain, custom, etc.)
    - Version information
    - Supported capabilities (tools, resources, prompts)
    - Authentication methods
    - Transport protocol
    - Technology stack
    - Security misconfigurations
    """
    
    # Known server signatures
    SERVER_SIGNATURES = {
        "fastmcp": {
            "headers": ["FastMCP", "fastmcp"],
            "endpoints": ["/mcp", "/fastmcp", "/sse"],
            "capabilities_markers": ["tools", "resources", "prompts"]
        },
        "langchain_mcp": {
            "headers": ["LangChain", "langchain"],
            "endpoints": ["/mcp", "/agent", "/chain"],
            "capabilities_markers": ["agent", "chain", "memory"]
        },
        "openapi_proxy": {
            "headers": ["OpenAPI", "Swagger"],
            "endpoints": ["/openapi.json", "/swagger", "/docs"],
            "capabilities_markers": ["paths", "components"]
        },
        "grpc_gateway": {
            "headers": ["gRPC", "grpc-web"],
            "endpoints": ["/grpc", "/proto"],
            "capabilities_markers": ["services", "methods"]
        }
    }
    
    # Common MCP endpoints to probe
    MCP_ENDPOINTS = [
        "/mcp", "/sse", "/message", "/capabilities", "/health",
        "/.well-known/mcp", "/api/mcp", "/v1/mcp"
    ]
    
    # Version detection patterns
    VERSION_PATTERNS = [
        r'(?i)version[:\s]+v?(\d+\.\d+\.\d+)',
        r'(?i)v(\d+\.\d+\.\d+)',
        r'(?i)release[:\s]+(\d+\.\d+\.\d+)',
        r'"version"\s*:\s*"([^"]+)"',
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[FingerprintFinding] = []
    
    async def fingerprint_server(self, host: str, port: int, protocol: str = "http") -> ServerFingerprint:
        """Perform comprehensive fingerprinting of an MCP server."""
        fingerprint = ServerFingerprint(host=host, port=port)
        
        base_url = f"{protocol}://{host}:{port}"
        fingerprint.tls_enabled = (protocol == "https")
        fingerprint.transport = protocol.upper()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Step 1: Probe main endpoint
                await self._probe_main_endpoint(session, base_url, fingerprint)
                
                # Step 2: Check capabilities endpoint
                await self._probe_capabilities(session, base_url, fingerprint)
                
                # Step 3: Enumerate endpoints
                await self._enumerate_endpoints(session, base_url, fingerprint)
                
                # Step 4: Detect server type
                self._detect_server_type(fingerprint)
                
                # Step 5: Extract version
                self._extract_version(fingerprint)
                
                # Step 6: Identify security findings
                self._identify_security_findings(fingerprint)
        except Exception:
            # Server unreachable or connection error - return partial fingerprint
            self._identify_security_findings(fingerprint)
        
        return fingerprint
    
    async def _probe_main_endpoint(self, session: aiohttp.ClientSession, 
                                    base_url: str, fingerprint: ServerFingerprint):
        """Probe the main MCP endpoint for server info."""
        try:
            async with session.get(base_url, timeout=self.timeout) as resp:
                fingerprint.server_headers = dict(resp.headers)
                
                # Check for Server header
                server_header = resp.headers.get('Server', '')
                if server_header:
                    fingerprint.technology_stack.append(f"Server: {server_header}")
                
                # Try to parse response as JSON
                try:
                    content = await resp.json()
                    if isinstance(content, dict):
                        # Look for MCP-specific fields
                        if 'capabilities' in content:
                            caps = content['capabilities']
                            if isinstance(caps, dict):
                                if caps.get('tools'):
                                    fingerprint.capabilities.append('tools')
                                if caps.get('resources'):
                                    fingerprint.capabilities.append('resources')
                                if caps.get('prompts'):
                                    fingerprint.capabilities.append('prompts')
                        
                        # Check for protocol version
                        if 'protocolVersion' in content:
                            fingerprint.mcp_protocol_version = content['protocolVersion']
                        
                        # Count tools/resources if available
                        if 'tools' in content:
                            tools = content.get('tools', [])
                            if isinstance(tools, list):
                                fingerprint.tools_count = len(tools)
                        
                        if 'resources' in content:
                            resources = content.get('resources', [])
                            if isinstance(resources, list):
                                fingerprint.resources_count = len(resources)
                
                except (json.JSONDecodeError, aiohttp.ContentTypeError):
                    pass  # Not JSON, continue
        
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
    
    async def _probe_capabilities(self, session: aiohttp.ClientSession,
                                   base_url: str, fingerprint: ServerFingerprint):
        """Probe capabilities endpoint."""
        cap_endpoints = ["/capabilities", "/mcp/capabilities", "/api/capabilities"]
        
        for endpoint in cap_endpoints:
            try:
                async with session.get(f"{base_url}{endpoint}", timeout=self.timeout) as resp:
                    if resp.status == 200:
                        fingerprint.exposed_endpoints.append(endpoint)
                        try:
                            content = await resp.json()
                            if isinstance(content, dict):
                                # Extract capability details
                                for cap in ['tools', 'resources', 'prompts', 'logging']:
                                    if cap in content:
                                        if cap not in fingerprint.capabilities:
                                            fingerprint.capabilities.append(cap)
                        except:
                            pass
            except:
                pass
    
    async def _enumerate_endpoints(self, session: aiohttp.ClientSession,
                                    base_url: str, fingerprint: ServerFingerprint):
        """Enumerate known MCP and admin endpoints."""
        for endpoint in self.MCP_ENDPOINTS:
            try:
                async with session.get(f"{base_url}{endpoint}", timeout=5) as resp:
                    if resp.status in [200, 401, 403]:
                        if endpoint not in fingerprint.exposed_endpoints:
                            fingerprint.exposed_endpoints.append(endpoint)
                        
                        # Check for auth requirement
                        if resp.status == 401:
                            auth_header = resp.headers.get('WWW-Authenticate', '')
                            if auth_header and 'Bearer' in auth_header:
                                if 'Bearer' not in fingerprint.auth_methods:
                                    fingerprint.auth_methods.append('Bearer')
                            elif auth_header and 'Basic' in auth_header:
                                if 'Basic' not in fingerprint.auth_methods:
                                    fingerprint.auth_methods.append('Basic')
            except:
                pass
    
    def _detect_server_type(self, fingerprint: ServerFingerprint):
        """Detect server type based on collected evidence."""
        all_text = json.dumps(fingerprint.server_headers).lower()
        all_text += " " + " ".join(fingerprint.exposed_endpoints).lower()
        all_text += " " + " ".join(fingerprint.capabilities).lower()
        
        for server_type, signatures in self.SERVER_SIGNATURES.items():
            score = 0
            
            # Check headers
            for header in signatures["headers"]:
                if header.lower() in all_text:
                    score += 2
            
            # Check endpoints
            for endpoint in signatures["endpoints"]:
                if endpoint in fingerprint.exposed_endpoints:
                    score += 1
            
            # Check capabilities
            for cap in signatures["capabilities_markers"]:
                if cap in all_text:
                    score += 1
            
            if score >= 2:
                fingerprint.server_type = ServerType(server_type)
                return
        
        # Default to custom if MCP endpoints found
        if fingerprint.capabilities or any('/mcp' in e for e in fingerprint.exposed_endpoints):
            fingerprint.server_type = ServerType.CUSTOM
    
    def _extract_version(self, fingerprint: ServerFingerprint):
        """Extract version information from headers and responses."""
        # Check Server header
        server_header = fingerprint.server_headers.get('Server', '')
        for pattern in self.VERSION_PATTERNS:
            match = re.search(pattern, server_header)
            if match:
                fingerprint.server_version = match.group(1)
                return
        
        # Check X-Powered-By or similar
        for header_name in ['X-Powered-By', 'X-Version', 'X-App-Version']:
            if header_name in fingerprint.server_headers:
                header_value = fingerprint.server_headers[header_name]
                for pattern in self.VERSION_PATTERNS:
                    match = re.search(pattern, header_value)
                    if match:
                        fingerprint.server_version = match.group(1)
                        return
    
    def _identify_security_findings(self, fingerprint: ServerFingerprint):
        """Identify security-relevant findings from fingerprint."""
        finding_id = 0
        
        # Finding: Version disclosure
        if fingerprint.server_version:
            finding_id += 1
            self.findings.append(FingerprintFinding(
                finding_id=f"FP-{finding_id:03d}",
                title="Server Version Disclosed",
                description=f"Server version {fingerprint.server_version} is exposed in headers or responses",
                risk_level="LOW",
                server_type=fingerprint.server_type.value,
                evidence=f"Version: {fingerprint.server_version}",
                remediation="Remove version information from public headers to prevent targeted attacks",
                cwe_id="CWE-200"
            ))
        
        # Finding: Capabilities enumeration
        if len(fingerprint.capabilities) > 0:
            finding_id += 1
            self.findings.append(FingerprintFinding(
                finding_id=f"FP-{finding_id:03d}",
                title="Server Capabilities Enumerated",
                description=f"Server exposes {len(fingerprint.capabilities)} capabilities: {', '.join(fingerprint.capabilities)}",
                risk_level="INFO",
                server_type=fingerprint.server_type.value,
                evidence=f"Capabilities: {fingerprint.capabilities}",
                remediation="Consider limiting capability enumeration to authenticated users"
            ))
        
        # Finding: No authentication detected
        if not fingerprint.auth_methods and fingerprint.exposed_endpoints:
            finding_id += 1
            self.findings.append(FingerprintFinding(
                finding_id=f"FP-{finding_id:03d}",
                title="No Authentication Required",
                description="Server endpoints accessible without authentication",
                risk_level="HIGH",
                server_type=fingerprint.server_type.value,
                evidence=f"Exposed endpoints: {fingerprint.exposed_endpoints[:5]}",
                remediation="Implement authentication for all MCP server endpoints",
                cwe_id="CWE-306"
            ))
        
        # Finding: Admin endpoints exposed
        admin_patterns = ['/admin', '/debug', '/config', '/internal']
        exposed_admin = [e for e in fingerprint.exposed_endpoints if any(p in e for p in admin_patterns)]
        if exposed_admin:
            finding_id += 1
            self.findings.append(FingerprintFinding(
                finding_id=f"FP-{finding_id:03d}",
                title="Admin/Debug Endpoints Exposed",
                description=f"Administrative endpoints are publicly accessible: {', '.join(exposed_admin)}",
                risk_level="MEDIUM",
                server_type=fingerprint.server_type.value,
                evidence=f"Admin endpoints: {exposed_admin}",
                remediation="Remove or restrict access to admin/debug endpoints in production",
                cwe_id="CWE-489"
            ))
        
        # Finding: TLS not enabled
        if not fingerprint.tls_enabled:
            finding_id += 1
            self.findings.append(FingerprintFinding(
                finding_id=f"FP-{finding_id:03d}",
                title="Unencrypted Transport",
                description="Server is using unencrypted HTTP transport",
                risk_level="MEDIUM",
                server_type=fingerprint.server_type.value,
                evidence="Protocol: HTTP (no TLS)",
                remediation="Enable TLS/HTTPS for all MCP server communications",
                cwe_id="CWE-311"
            ))
        
        fingerprint.findings = self.findings.copy()
    
    def get_fingerprint_summary(self, fingerprint: ServerFingerprint) -> Dict[str, Any]:
        """Get a summary of the fingerprint."""
        return {
            "host": f"{fingerprint.host}:{fingerprint.port}",
            "server_type": fingerprint.server_type.value,
            "version": fingerprint.server_version or "unknown",
            "protocol_version": fingerprint.mcp_protocol_version or "unknown",
            "capabilities": fingerprint.capabilities,
            "tools_count": fingerprint.tools_count,
            "resources_count": fingerprint.resources_count,
            "prompts_count": fingerprint.prompts_count,
            "auth_methods": fingerprint.auth_methods,
            "transport": fingerprint.transport,
            "tls_enabled": fingerprint.tls_enabled,
            "exposed_endpoints_count": len(fingerprint.exposed_endpoints),
            "findings_count": len(fingerprint.findings)
        }


def fingerprint_mcp_server(host: str, port: int, protocol: str = "http",
                           timeout: int = 10) -> Dict[str, Any]:
    """
    Convenience function to fingerprint an MCP server.
    
    Args:
        host: Server hostname or IP
        port: Server port
        protocol: http or https
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with fingerprint data and summary
    """
    scanner = MCPFingerprintScanner(timeout=timeout)
    fingerprint = asyncio.run(scanner.fingerprint_server(host, port, protocol))
    
    return {
        "fingerprint": asdict(fingerprint),
        "summary": scanner.get_fingerprint_summary(fingerprint),
        "findings": [asdict(f) for f in fingerprint.findings]
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python server_fingerprint.py <host> <port> [protocol]")
        print("Example: python server_fingerprint.py localhost 8080 http")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    protocol = sys.argv[3] if len(sys.argv) > 3 else "http"
    
    result = fingerprint_mcp_server(host, port, protocol)
    print(json.dumps(result, indent=2))
