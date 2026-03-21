"""
MCP Security Scanner - Configuration Parser
Handles loading and validating scanner configuration from YAML/JSON files.
"""

import os
import json
import yaml
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class ScanTarget:
    """Represents a single MCP server target to scan."""
    host: str
    port: int
    protocol: str = "http"
    auth_token: Optional[str] = None
    timeout: int = 30


@dataclass
class ScannerConfig:
    """Main configuration container for the MCP scanner."""
    targets: List[ScanTarget] = field(default_factory=list)
    output_dir: str = "./reports"
    verbose: bool = False
    secrets_patterns: List[str] = field(default_factory=list)
    network_check_enabled: bool = True
    auth_check_enabled: bool = True
    config_check_enabled: bool = True
    
    # Security checks toggles
    check_hardcoded_secrets: bool = True
    check_insecure_bindings: bool = True
    check_missing_auth: bool = True
    check_exposed_admin_endpoints: bool = True
    
    @classmethod
    def from_file(cls, config_path: str) -> "ScannerConfig":
        """Load configuration from YAML or JSON file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                raw_config = yaml.safe_load(f)
            elif config_path.endswith('.json'):
                raw_config = json.load(f)
            else:
                raise ValueError("Config file must be .yaml, .yml, or .json")
        
        return cls.from_dict(raw_config)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "ScannerConfig":
        """Build ScannerConfig from dictionary."""
        targets = []
        for t in config_dict.get('targets', []):
            targets.append(ScanTarget(
                host=t.get('host', 'localhost'),
                port=t.get('port', 8080),
                protocol=t.get('protocol', 'http'),
                auth_token=t.get('auth_token'),
                timeout=t.get('timeout', 30)
            ))
        
        return cls(
            targets=targets,
            output_dir=config_dict.get('output_dir', './reports'),
            verbose=config_dict.get('verbose', False),
            secrets_patterns=config_dict.get('secrets_patterns', []),
            network_check_enabled=config_dict.get('network_check_enabled', True),
            auth_check_enabled=config_dict.get('auth_check_enabled', True),
            config_check_enabled=config_dict.get('config_check_enabled', True),
            check_hardcoded_secrets=config_dict.get('check_hardcoded_secrets', True),
            check_insecure_bindings=config_dict.get('check_insecure_bindings', True),
            check_missing_auth=config_dict.get('check_missing_auth', True),
            check_exposed_admin_endpoints=config_dict.get('check_exposed_admin_endpoints', True)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export config to dictionary."""
        return {
            'targets': [
                {
                    'host': t.host,
                    'port': t.port,
                    'protocol': t.protocol,
                    'auth_token': t.auth_token,
                    'timeout': t.timeout
                } for t in self.targets
            ],
            'output_dir': self.output_dir,
            'verbose': self.verbose,
            'secrets_patterns': self.secrets_patterns,
            'network_check_enabled': self.network_check_enabled,
            'auth_check_enabled': self.auth_check_enabled,
            'config_check_enabled': self.config_check_enabled,
            'check_hardcoded_secrets': self.check_hardcoded_secrets,
            'check_insecure_bindings': self.check_insecure_bindings,
            'check_missing_auth': self.check_missing_auth,
            'check_exposed_admin_endpoints': self.check_exposed_admin_endpoints
        }


# Default secrets patterns for detection
DEFAULT_SECRETS_PATTERNS = [
    r'(?i)api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9]{16,}',
    r'(?i)secret[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9]{16,}',
    r'(?i)password\s*[=:]\s*["\']?[^\s"\']+',
    r'(?i)bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
    r'(?i)private[_-]?key\s*[=:]\s*["\']?-----BEGIN',
    r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?[A-Z0-9]{16,}',
    r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}',
]


def load_config(config_path: Optional[str] = None) -> ScannerConfig:
    """Load scanner configuration from file or use defaults."""
    if config_path and os.path.exists(config_path):
        return ScannerConfig.from_file(config_path)
    
    # Return default config if no file provided
    return ScannerConfig(
        secrets_patterns=DEFAULT_SECRETS_PATTERNS
    )
