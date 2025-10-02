"""
Centralized configuration management with validation.
"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, validator


class HttpAuthConfig(BaseModel):
    """HTTP authentication configuration."""
    username: str
    password: str


class OpenSearchConfig(BaseModel):
    """OpenSearch configuration."""
    host: str = "localhost"
    port: int = 9200
    use_ssl: bool = False
    verify_certs: bool = False
    http_auth: Optional[HttpAuthConfig] = None
    index_prefix: str = "pqctlog_"
    timeout: int = 30
    max_retries: int = 3


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    max_entries: int = 1000
    scan_interval: int = 3600
    worker_threads: int = 5


class TLSScannerConfig(BaseModel):
    """TLS scanner configuration."""
    enabled: bool = True
    timeout: int = 10
    max_workers: int = 10
    scan_interval: int = 86400
    ports: List[int] = Field(default_factory=lambda: [443, 8443])
    tls_versions: List[str] = Field(default_factory=lambda: ["TLSv1.3", "TLSv1.2"])
    ciphersuites: List[str] = Field(default_factory=list)
    post_quantum_ciphers: List[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    file: Optional[str] = None
    max_size: int = 10485760  # 10MB
    backup_count: int = 5

    @validator('level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()


class AppConfig(BaseModel):
    """Main application configuration."""
    opensearch: OpenSearchConfig = Field(default_factory=OpenSearchConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    tls_scanner: TLSScannerConfig = Field(default_factory=TLSScannerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    class Config:
        env_prefix = "PQCTLOG_"
        case_sensitive = False


class ConfigManager:
    """Centralized configuration manager."""
    
    _instance: Optional['ConfigManager'] = None
    _config: Optional[AppConfig] = None
    
    def __new__(cls) -> 'ConfigManager':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def load_config(self, config_path: Optional[str] = None) -> AppConfig:
        """Load configuration from file and environment variables."""
        if self._config is not None:
            return self._config
            
        # Load from file
        file_config = self._load_config_file(config_path)
        
        # Override with environment variables
        env_config = self._load_env_config()
        
        # Merge configurations
        merged_config = self._merge_configs(file_config, env_config)
        
        # Validate and create config object
        self._config = AppConfig(**merged_config)
        return self._config
    
    def get_config(self) -> AppConfig:
        """Get the current configuration."""
        if self._config is None:
            return self.load_config()
        return self._config
    
    def _load_config_file(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            # Check default locations
            for path in ['config.yaml', 'config/config.yaml', Path.home() / '.pqctlog' / 'config.yaml']:
                if Path(path).exists():
                    config_path = str(path)
                    break
        
        if config_path is None or not Path(config_path).exists():
            return {}
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ValueError(f"Error loading config from {config_path}: {e}")
    
    def _load_env_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}
        
        # OpenSearch config
        if os.getenv('PQCTLOG_OPENSEARCH_HOST'):
            env_config.setdefault('opensearch', {})['host'] = os.getenv('PQCTLOG_OPENSEARCH_HOST')
        if os.getenv('PQCTLOG_OPENSEARCH_PORT'):
            env_config.setdefault('opensearch', {})['port'] = int(os.getenv('PQCTLOG_OPENSEARCH_PORT'))
        if os.getenv('PQCTLOG_OPENSEARCH_USERNAME'):
            env_config.setdefault('opensearch', {}).setdefault('http_auth', {})['username'] = os.getenv('PQCTLOG_OPENSEARCH_USERNAME')
        if os.getenv('PQCTLOG_OPENSEARCH_PASSWORD'):
            env_config.setdefault('opensearch', {}).setdefault('http_auth', {})['password'] = os.getenv('PQCTLOG_OPENSEARCH_PASSWORD')
        
        # Logging config
        if os.getenv('PQCTLOG_LOG_LEVEL'):
            env_config.setdefault('logging', {})['level'] = os.getenv('PQCTLOG_LOG_LEVEL')
        
        return env_config
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result


# Global config manager instance
config_manager = ConfigManager()


def get_config() -> AppConfig:
    """Get the application configuration."""
    return config_manager.get_config()


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load and return the application configuration."""
    return config_manager.load_config(config_path)