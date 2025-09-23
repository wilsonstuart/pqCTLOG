"""
Configuration management for the pqCTLOG application.
"""
import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

# Default configuration
DEFAULT_CONFIG = {
    'opensearch': {
        'host': 'localhost',
        'port': 9200,
        'use_ssl': False,
        'verify_certs': False,
        'http_auth': {
            'username': 'admin',
            'password': 'admin'
        },
        'index_prefix': 'pqctlog_'
    },
    'ct_logs': [
        {
            'url': 'https://ct.googleapis.com/logs/argon2023',
            'name': 'Google Argon2023'
        },
        {
            'url': 'https://ct1.digicert-ct.com/log/',
            'name': 'DigiCert Log Server'
        }
    ],
    'scanner': {
        'max_entries': 1000,
        'scan_interval': 3600,
        'worker_threads': 5
    },
    'tls_scanner': {
        'timeout': 5,
        'ports': [443, 8443],
        'ciphersuites': [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_CBC_SHA'
        ]
    },
    'logging': {
        'level': 'INFO',
        'file': 'pqctlog.log',
        'max_size': 10485760,  # 10MB
        'backup_count': 5
    }
}

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or use defaults.
    
    Args:
        config_path: Path to the configuration file. If None, looks in default locations.
        
    Returns:
        Configuration dictionary
    """
    # If no config path provided, check default locations
    if config_path is None:
        # Check current directory
        if os.path.exists('config.yaml'):
            config_path = 'config.yaml'
        # Check in config directory
        elif os.path.exists('config/config.yaml'):
            config_path = 'config/config.yaml'
        # Check in user config directory
        else:
            config_dir = os.path.join(Path.home(), '.pqctlog')
            user_config = os.path.join(config_dir, 'config.yaml')
            if os.path.exists(user_config):
                config_path = user_config
    
    # If no config file found, use defaults
    if config_path is None or not os.path.exists(config_path):
        return DEFAULT_CONFIG
    
    # Load config from file and merge with defaults
    try:
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f) or {}
        
        # Deep merge file config with defaults
        config = _deep_merge(DEFAULT_CONFIG, file_config)
        return config
    except Exception as e:
        print(f"Error loading config from {config_path}: {e}")
        return DEFAULT_CONFIG

def save_config(config: Dict[str, Any], config_path: Optional[str] = None) -> bool:
    """Save configuration to file.
    
    Args:
        config: Configuration dictionary to save
        config_path: Path to save the configuration file. If None, uses default location.
        
    Returns:
        True if successful, False otherwise
    """
    if config_path is None:
        config_dir = os.path.join(Path.home(), '.pqctlog')
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, 'config.yaml')
    
    try:
        with open(config_path, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        print(f"Error saving config to {config_path}: {e}")
        return False

def _deep_merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge two dictionaries.
    
    Args:
        base: Base dictionary
        update: Dictionary with updates to merge into base
        
    Returns:
        Merged dictionary
    """
    result = base.copy()
    
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result
