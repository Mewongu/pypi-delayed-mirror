"""Tests for package and version validation functions."""
import pytest
import sys
import os

# Add the scripts directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from validation import validate_package_name, validate_version, parse_requirements_file
from tempfile import NamedTemporaryFile


class TestPackageValidation:
    """Test package name validation."""
    
    def test_valid_package_names(self):
        """Test valid package names are accepted."""
        valid_names = [
            "setuptools",
            "setuptools-scm", 
            "PyYAML",
            "requests",
            "pip-audit",
            "Django",
            "flask",
            "numpy",
            "scipy"
        ]
        
        for name in valid_names:
            assert validate_package_name(name), f"Valid package name rejected: {name}"
    
    def test_invalid_package_names(self):
        """Test invalid package names are rejected."""
        invalid_names = [
            "../../../etc/passwd",  # Path injection
            ".hidden",              # Starts with dot
            "package.",             # Ends with dot  
            "pack..age",            # Double dots
            "a" * 300,              # Too long
            "",                     # Empty
            "pack age",             # Space
            "pack@age",             # Invalid character
        ]
        
        for name in invalid_names:
            assert not validate_package_name(name), f"Invalid package name accepted: {name}"


class TestVersionValidation:
    """Test version validation."""
    
    def test_valid_versions(self):
        """Test valid version strings are accepted."""
        valid_versions = [
            "1.0.0",
            "2.3.1", 
            "10.15.20",
            "1.0.0a1",
            "2.0.0b5",
            "1.5.0rc2",
            "3.0.0.post1",
            "1.0.0.dev5",
            "0.1.0",
            "100.200.300"
        ]
        
        for version in valid_versions:
            assert validate_version(version), f"Valid version rejected: {version}"
    
    def test_invalid_versions(self):
        """Test invalid version strings are rejected."""
        invalid_versions = [
            "../../../etc/passwd",  # Path injection
            ".1.0.0",              # Starts with dot
            "1.0.0.",              # Ends with dot
            "1..0.0",              # Double dots
            "a" * 100,             # Too long
            "",                    # Empty
            "1.0.0 beta",          # Space
            "v1.0.0",              # Prefix
        ]
        
        for version in invalid_versions:
            assert not validate_version(version), f"Invalid version accepted: {version}"


class TestRequirementsParsing:
    """Test requirements file parsing."""
    
    def test_valid_requirements_file(self):
        """Test parsing valid requirements file."""
        content = """# Test requirements file
setuptools-scm==9.2.2
PyYAML==6.0.1
requests==2.32.5

# Comment line
pip-audit==2.7.0
"""
        
        with NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            
            requirements, error = parse_requirements_file(f.name)
            
            # Cleanup
            os.unlink(f.name)
            
        assert error is None, f"Parsing failed with error: {error}"
        assert len(requirements) == 4
        
        expected = [
            ("setuptools-scm", "9.2.2"),
            ("PyYAML", "6.0.1"), 
            ("requests", "2.32.5"),
            ("pip-audit", "2.7.0")
        ]
        
        assert set(requirements) == set(expected)
    
    def test_requirements_with_extras_are_rejected(self):
        """Test that packages with extras are properly rejected."""
        content = """requests[security]==2.32.5
setuptools-scm==9.2.2
"""
        
        with NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            
            requirements, error = parse_requirements_file(f.name)
            
            # Cleanup
            os.unlink(f.name)
            
        assert error is None
        # Only setuptools-scm should be included, requests[security] should be skipped
        assert len(requirements) == 1
        assert requirements[0] == ("setuptools-scm", "9.2.2")
    
    def test_non_pinned_versions_are_rejected(self):
        """Test that non-pinned versions are rejected."""
        content = """requests>=2.0.0
setuptools-scm~=9.2.0
PyYAML==6.0.1
"""
        
        with NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            
            requirements, error = parse_requirements_file(f.name)
            
            # Cleanup
            os.unlink(f.name)
            
        assert error is None
        # Only PyYAML should be included, others should be skipped
        assert len(requirements) == 1
        assert requirements[0] == ("PyYAML", "6.0.1")
    
    def test_missing_file_error(self):
        """Test proper error handling for missing file."""
        requirements, error = parse_requirements_file("/nonexistent/file.txt")
        
        assert requirements is None
        assert error is not None
        assert "no such file" in error.lower() or "not found" in error.lower()


if __name__ == "__main__":
    pytest.main([__file__])