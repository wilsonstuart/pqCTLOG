"""
Tests for configuration management.
"""
import pytest
from unittest.mock import patch, mock_open
import yaml

from src.core.config import ConfigManager, AppConfig, load_config


class TestConfigManager:
    """Test configuration manager functionality."""
    
    def test_singleton_pattern(self):
        """Test that ConfigManager follows singleton pattern."""
        manager1 = ConfigManager()
        manager2 = ConfigManager()
        assert manager1 is manager2
    
    @patch('builtins.open', new_callable=mock_open, read_data="""
opensearch:
  host: "test-host"
  port: 9201
logging:
  level: "DEBUG"
""")
    @patch('pathlib.Path.exists')
    def test_load_config_from_file(self, mock_exists, mock_file):
        """Test loading configuration from file."""
        mock_exists.return_value = True
        
        manager = ConfigManager()
        manager._config = None  # Reset singleton state
        
        config = manager.load_config('test_config.yaml')
        
        assert config.opensearch.host == "test-host"
        assert config.opensearch.port == 9201
        assert config.logging.level == "DEBUG"
    
    @patch.dict('os.environ', {
        'PQCTLOG_OPENSEARCH_HOST': 'env-host',
        'PQCTLOG_OPENSEARCH_PORT': '9202',
        'PQCTLOG_LOG_LEVEL': 'ERROR'
    })
    def test_env_override(self):
        """Test that environment variables override file config."""
        manager = ConfigManager()
        manager._config = None  # Reset singleton state
        
        # Mock empty file config
        with patch.object(manager, '_load_config_file', return_value={}):
            config = manager.load_config()
        
        assert config.opensearch.host == "env-host"
        assert config.opensearch.port == 9202
        assert config.logging.level == "ERROR"
    
    def test_default_config(self):
        """Test default configuration values."""
        manager = ConfigManager()
        manager._config = None  # Reset singleton state
        
        with patch.object(manager, '_load_config_file', return_value={}):
            with patch.object(manager, '_load_env_config', return_value={}):
                config = manager.load_config()
        
        assert config.opensearch.host == "localhost"
        assert config.opensearch.port == 9200
        assert config.logging.level == "INFO"


class TestAppConfig:
    """Test application configuration model."""
    
    def test_valid_config(self):
        """Test creating valid configuration."""
        config_data = {
            'opensearch': {
                'host': 'localhost',
                'port': 9200
            },
            'logging': {
                'level': 'INFO'
            }
        }
        
        config = AppConfig(**config_data)
        assert config.opensearch.host == 'localhost'
        assert config.logging.level == 'INFO'
    
    def test_invalid_log_level(self):
        """Test validation of log level."""
        config_data = {
            'logging': {
                'level': 'INVALID'
            }
        }
        
        with pytest.raises(ValueError, match="Log level must be one of"):
            AppConfig(**config_data)
    
    def test_default_values(self):
        """Test default configuration values."""
        config = AppConfig()
        
        assert config.opensearch.host == "localhost"
        assert config.opensearch.port == 9200
        assert config.logging.level == "INFO"
        assert config.scanner.max_entries == 1000