"""Validation functions separated for testing."""
import re
from pip_requirements_parser import RequirementsFile


def validate_package_name(name):
    """Validate package name according to PEP 508 standards."""
    # PEP 508: package names must match this pattern
    pattern = r'^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$'
    if not re.match(pattern, name, re.IGNORECASE):
        return False
    # Additional security checks
    if '..' in name or name.startswith('.') or name.endswith('.'):
        return False
    if len(name) > 214:  # PyPI limit
        return False
    return True


def validate_version(version):
    """Validate version string according to PEP 440 standards."""
    # Simplified version validation - allow common patterns
    # This covers: 1.0.0, 1.0.0a1, 1.0.0.post1, 1.0.0.dev1, etc.
    pattern = r'^[0-9]+(\.[0-9]+)*([a-z]+[0-9]*)?(\.(post|dev)[0-9]*)?$'
    if not re.match(pattern, version, re.IGNORECASE):
        return False
    # Additional security checks
    if len(version) > 64:  # Reasonable limit
        return False
    # Block suspicious patterns
    if '..' in version or version.startswith('.') or version.endswith('.'):
        return False
    return True


def parse_requirements_file(file_path):
    """Parse requirements file using proper pip requirements parser."""
    try:
        rf = RequirementsFile.from_file(file_path)
        parsed_requirements = []
        
        for req in rf.requirements:
            # Only support pinned versions (==) for security
            if len(req.specifier) != 1:
                print(f"⚠️  SKIPPING: {req.name} - Only pinned versions (==) are supported")
                continue
                
            spec = list(req.specifier)[0]
            if spec.operator != "==":
                print(f"⚠️  SKIPPING: {req.name} - Only pinned versions (==) are supported, found {spec.operator}")
                continue
            
            pkg_name = req.name
            version = spec.version
            
            # Validate package name and version
            if not validate_package_name(pkg_name):
                print(f"❌ INVALID: {pkg_name} - Invalid package name format")
                continue
                
            if not validate_version(version):
                print(f"❌ INVALID: {pkg_name}=={version} - Invalid version format")
                continue
                
            # Check for extras (not supported in our security model)
            if req.extras:
                print(f"⚠️  SKIPPING: {pkg_name}[{','.join(req.extras)}]=={version} - Extras not supported")
                continue
            
            parsed_requirements.append((pkg_name, version))
            
        return parsed_requirements, None
        
    except FileNotFoundError:
        return None, f"Requirements file not found: {file_path}"
    except (ValueError, TypeError, KeyError) as e:
        return None, f"Invalid requirements file format: {str(e)}"
    except Exception as e:
        return None, f"Error parsing requirements file: {str(e)}"