"""Tests for environment validation and configuration."""
import pytest
import os
import sys
from unittest.mock import patch

# Add the scripts directory to Python path for imports  
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))


class TestEnvironmentValidation:
    """Test environment variable validation."""
    
    @patch.dict(os.environ, {
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_PROJECT_ID': '12345', 
        'CI_JOB_TOKEN': 'test-token-123'
    }, clear=False)
    def test_valid_environment(self):
        """Test that valid environment variables are accepted."""
        # Import here to avoid module-level validation errors in other tests
        from mirror_manager import validate_environment
        
        config = validate_environment()
        assert config['gitlab_api'] == 'https://gitlab.example.com/api/v4'
        assert config['project_id'] == '12345'
        assert config['job_token'] == 'test-token-123'
    
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_environment_variables(self):
        """Test that missing environment variables cause proper exit."""
        # Clear the module cache to force re-import
        if 'mirror_manager' in sys.modules:
            del sys.modules['mirror_manager']
        
        with pytest.raises(SystemExit) as exc_info:
            from mirror_manager import validate_environment
            validate_environment()
        
        assert exc_info.value.code == 1
    
    @patch.dict(os.environ, {
        'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
        'CI_PROJECT_ID': '12345'
        # Missing CI_JOB_TOKEN
    }, clear=True)
    def test_partial_environment_variables(self):
        """Test that partially missing environment variables cause proper exit."""
        # Clear the module cache to force re-import
        if 'mirror_manager' in sys.modules:
            del sys.modules['mirror_manager']
        
        with pytest.raises(SystemExit) as exc_info:
            from mirror_manager import validate_environment
            validate_environment()
        
        assert exc_info.value.code == 1


if __name__ == "__main__":
    pytest.main([__file__])