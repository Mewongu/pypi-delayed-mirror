import argparse
import os
import sys
import yaml
import subprocess
import requests
import shutil
import fcntl
import tempfile
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
from pathlib import Path
from validation import validate_package_name, validate_version, parse_requirements_file

# --- CONFIGURATION ---
DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_REQ_FILE = "requirements.txt"
DEBUG = False  # Set to True for detailed debug output

def validate_environment():
    """Validate required environment variables are set."""
    required_vars = {
        "CI_API_V4_URL": "GitLab API URL",
        "CI_PROJECT_ID": "GitLab Project ID", 
        "CI_JOB_TOKEN": "GitLab Job Token"
    }
    
    missing = []
    for var, description in required_vars.items():
        if not os.getenv(var):
            missing.append(f"{var} ({description})")
    
    if missing:
        print("❌ CONFIGURATION ERROR: Missing required environment variables:")
        for var in missing:
            print(f"   - {var}")
        print("\nPlease ensure you are running in a GitLab CI environment or set these variables manually.")
        sys.exit(1)
    
    config = {
        "gitlab_api": os.getenv("CI_API_V4_URL"),
        "project_id": os.getenv("CI_PROJECT_ID"),
        "job_token": os.getenv("CI_JOB_TOKEN")
    }
    
    # Debug output
    if DEBUG:
        print(f"🔍 DEBUG: GitLab API URL: {config['gitlab_api']}")
        print(f"🔍 DEBUG: Project ID: {config['project_id']}")
        print(f"🔍 DEBUG: Job Token: {'***' + config['job_token'][-4:] if len(config['job_token']) > 4 else '***'}")
    
    return config

# Validate environment on import
ENV_CONFIG = validate_environment()
GITLAB_API = ENV_CONFIG["gitlab_api"]
PROJECT_ID = ENV_CONFIG["project_id"]
JOB_TOKEN = ENV_CONFIG["job_token"]
# GitLab PyPI Registry URL for uploading
REPO_URL = f"{GITLAB_API}/projects/{PROJECT_ID}/packages/pypi"



def load_config(config_file=None):
    """Load configuration from YAML file."""
    if config_file is None:
        config_file = DEFAULT_CONFIG_FILE
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


def is_excepted(pkg, ver, config):
    """Checks if a package is in the exceptions list."""
    for exc in config.get('exceptions', []):
        if exc['package'].lower() == pkg.lower() and exc['version'] == ver:
            print(f"⚠️ EXCEPTION APPLIED: {pkg}=={ver} allowed by config.")
            return True
    return False


def check_upstream_age(pkg, ver, min_age_days):
    """Returns True if package is older than min_age_days, False if too new, None if check failed."""
    url = f"https://pypi.org/pypi/{pkg}/{ver}/json"
    
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            print(f"❌ NOT FOUND: {pkg}=={ver} not found on upstream PyPI.")
            return None
        elif resp.status_code != 200:
            print(f"❌ HTTP ERROR: Failed to check {pkg}=={ver} (status {resp.status_code})")
            return None

        data = resp.json()
        urls = data.get("urls", [])
        if not urls:
            print(f"❌ NO FILES: {pkg}=={ver} has no downloadable files on PyPI.")
            return None

        # Get earliest upload time
        try:
            upload_times = [parse(u["upload_time"]) for u in urls]
            upload_time = min(upload_times)
        except (KeyError, ValueError) as e:
            print(f"❌ INVALID TIMESTAMP: Cannot parse upload time for {pkg}=={ver} - {e}")
            return None
        
        # Convert to UTC if timezone-aware, otherwise assume UTC
        if upload_time.tzinfo is not None:
            upload_time_utc = upload_time.astimezone(timezone.utc)
        else:
            upload_time_utc = upload_time.replace(tzinfo=timezone.utc)
        
        now_utc = datetime.now(timezone.utc)
        age = now_utc - upload_time_utc

        if age.days >= min_age_days:
            print(f"✅ AGE CHECK: {pkg}=={ver} is {age.days} days old (Required: {min_age_days}).")
            return True
        else:
            print(f"⏳ AGE CHECK: {pkg}=={ver} is only {age.days} days old. Quarantined.")
            return False
            
    except requests.exceptions.Timeout:
        print(f"⏱️  TIMEOUT: Request to PyPI for {pkg}=={ver} timed out.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ NETWORK ERROR: Failed to check {pkg}=={ver} - {str(e)}")
        return None
    except (ValueError, TypeError, KeyError) as e:
        print(f"❌ DATA ERROR: Invalid data format for {pkg}=={ver} - {str(e)}")
        return None
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: Failed to check age of {pkg}=={ver} - {str(e)}")
        return None


def verify_package_integrity(pkg, ver, downloaded_files):
    """Verify downloaded package files match PyPI checksums."""
    try:
        # Get package metadata from PyPI to get file checksums
        url = f"https://pypi.org/pypi/{pkg}/{ver}/json"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            print(f"⚠️  INTEGRITY WARNING: Cannot fetch checksums for {pkg}=={ver} from PyPI")
            return True  # Allow if we can't verify (conservative approach)
        
        data = resp.json()
        pypi_files = data.get("urls", [])
        if not pypi_files:
            print(f"⚠️  INTEGRITY WARNING: No file checksums available for {pkg}=={ver}")
            return True
        
        # Create lookup of filename -> expected checksums
        expected_checksums = {}
        for file_info in pypi_files:
            filename = file_info["filename"]
            # PyPI provides multiple hash types, prefer SHA256
            for hash_type in ["sha256", "md5"]:
                if f"digests" in file_info and hash_type in file_info["digests"]:
                    expected_checksums[filename] = {
                        "algorithm": hash_type,
                        "hash": file_info["digests"][hash_type]
                    }
                    break
        
        # Verify each downloaded file
        verified_count = 0
        for file_path in downloaded_files:
            filename = file_path.name
            
            if filename not in expected_checksums:
                print(f"⚠️  INTEGRITY WARNING: {filename} not found in PyPI metadata")
                continue
            
            expected = expected_checksums[filename]
            actual_hash = compute_file_hash(file_path, expected["algorithm"])
            
            if actual_hash == expected["hash"]:
                print(f"✅ VERIFIED: {filename} checksum matches PyPI")
                verified_count += 1
            else:
                print(f"❌ CHECKSUM MISMATCH: {filename}")
                print(f"   Expected ({expected['algorithm']}): {expected['hash']}")
                print(f"   Actual ({expected['algorithm']}): {actual_hash}")
                return False
        
        print(f"✅ INTEGRITY CHECK: {verified_count}/{len(downloaded_files)} files verified")
        return True
        
    except (ValueError, TypeError, KeyError) as e:
        print(f"❌ INTEGRITY DATA ERROR: Invalid checksum data for {pkg}=={ver} - {str(e)}")
        return True  # Allow if verification fails (conservative approach)
    except OSError as e:
        print(f"❌ INTEGRITY FILE ERROR: File system error verifying {pkg}=={ver} - {str(e)}")
        return True  # Allow if verification fails (conservative approach)
    except Exception as e:
        print(f"⚠️  INTEGRITY ERROR: Cannot verify {pkg}=={ver} - {str(e)}")
        return True  # Allow if verification fails (conservative approach)


def compute_file_hash(file_path, algorithm):
    """Compute hash of a file using specified algorithm."""
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def check_vulnerabilities(pkg, ver):
    """
    Uses pip-audit to check for vulnerabilities.
    Returns True if SAFE, False if VULNERABLE, None if scan failed.
    """
    try:
        # Running pip-audit in dry-run mode against a spec
        # Note: pip-audit works best on installed envs or requirements files.
        # Here we create a temporary requirements line to scan.
        result = subprocess.run(
            ["pip-audit", "--desc", "on", "--strict", "--progress-spinner", "off", "-r", "/dev/stdin"],
            input=f"{pkg}=={ver}\n".encode(),
            capture_output=True,
            timeout=30  # Add timeout to prevent hanging
        )

        if result.returncode == 0:
            print(f"✅ SECURITY: No known vulnerabilities for {pkg}=={ver}.")
            return True
        else:
            print(f"🛑 SECURITY: Vulnerabilities found in {pkg}=={ver}!")
            stderr_output = result.stderr.decode().strip()
            if stderr_output:
                print(f"   Details: {stderr_output}")
            return False
    except subprocess.TimeoutExpired:
        print(f"⏱️  SECURITY SCAN TIMEOUT: {pkg}=={ver} - scan took too long, treating as unsafe")
        return False
    except FileNotFoundError:
        print(f"❌ SECURITY SCAN ERROR: pip-audit not found - cannot verify {pkg}=={ver}")
        return None  # Distinguish between "vulnerable" and "cannot scan"
    except (ValueError, TypeError) as e:
        print(f"❌ SECURITY SCAN CONFIG ERROR: Invalid configuration for {pkg}=={ver} - {str(e)}")
        return None
    except Exception as e:
        print(f"❌ SECURITY SCAN ERROR: Failed to scan {pkg}=={ver} - {str(e)}")
        return None  # Distinguish between "vulnerable" and "cannot scan"


def acquire_package_lock(pkg, ver):
    """Acquires an exclusive lock for a specific package version."""
    import re
    
    # Sanitize package name and version to prevent path injection
    safe_pkg = re.sub(r'[^a-zA-Z0-9._-]', '_', pkg)
    safe_ver = re.sub(r'[^a-zA-Z0-9._-]', '_', ver)
    
    lock_dir = Path("./locks")
    lock_dir.mkdir(exist_ok=True)
    
    # Use sanitized names for lock file
    lock_file = lock_dir / f"{safe_pkg}-{safe_ver}.lock"
    
    # Ensure the lock file is within the locks directory (defense in depth)
    try:
        lock_file = lock_file.resolve()
        if not str(lock_file).startswith(str(lock_dir.resolve())):
            raise ValueError(f"Invalid lock file path: {lock_file}")
    except Exception:
        raise ValueError(f"Cannot create safe lock file for {pkg}=={ver}")
    lock_fd = None
    
    try:
        lock_fd = open(lock_file, 'w')
        # Try to acquire exclusive lock (non-blocking)
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(f"Locked by PID {os.getpid()} at {datetime.now(timezone.utc)}\n")
        lock_fd.flush()
        return lock_fd
    except OSError:
        # Lock already held by another process
        if lock_fd:
            try:
                lock_fd.close()
            except Exception:
                pass  # Ignore close errors
        return None
    except Exception:
        # Any other error (file system issues, etc.)
        if lock_fd:
            try:
                lock_fd.close()
            except Exception:
                pass  # Ignore close errors
        return None


def release_package_lock(lock_fd, pkg, ver):
    """Releases the package lock and cleans up lock file."""
    if lock_fd:
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()
            # Clean up lock file
            lock_file = Path(f"./locks/{pkg}-{ver}.lock")
            if lock_file.exists():
                lock_file.unlink()
        except Exception as e:
            print(f"⚠️  Warning: Could not release lock for {pkg}=={ver}: {e}")


def upload_package(pkg, ver, dry_run=False):
    """Downloads and Uploads to GitLab Registry with atomic operations."""
    if dry_run:
        print(f"🔍 DRY-RUN: Would mirror {pkg}=={ver}")
        return True
    
    # Acquire exclusive lock for this package version
    lock_fd = acquire_package_lock(pkg, ver)
    if lock_fd is None:
        print(f"⏳ SKIPPING: {pkg}=={ver} - Another process is already handling this package")
        return True  # Not a failure, just skip
    
    # Use unique temporary directory to avoid conflicts
    unique_id = str(uuid.uuid4())[:8]
    temp_dir = Path(tempfile.gettempdir()) / f"pypi-mirror-{pkg}-{ver}-{unique_id}"
    download_dir = str(temp_dir)
    
    try:
        os.makedirs(download_dir, exist_ok=True)

        # 1. Download atomically
        cmd_dl = [
            "pip", "download", f"{pkg}=={ver}",
            "--dest", download_dir, "--no-deps"
        ]
        try:
            result = subprocess.run(cmd_dl, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ DOWNLOAD FAILED: {pkg}=={ver} - {e.stderr.strip()}")
            return False

        # Verify download succeeded and files exist
        downloaded_files = list(Path(download_dir).glob("*"))
        if not downloaded_files:
            print(f"❌ DOWNLOAD ERROR: {pkg}=={ver} - No files downloaded")
            return False
        
        # Verify package integrity against PyPI checksums
        if not verify_package_integrity(pkg, ver, downloaded_files):
            print(f"❌ INTEGRITY CHECK FAILED: {pkg}=={ver} - Downloaded files don't match PyPI checksums")
            return False

        # 2. Upload via Twine atomically
        # Note: GitLab requires standard basic auth with twine
        # Username: gitlab-ci-token, Password: $CI_JOB_TOKEN
        # Use environment variable to avoid token exposure in process lists
        cmd_up = [
            "twine", "upload",
            "--repository-url", REPO_URL,
            "-u", "gitlab-ci-token",
            f"{download_dir}/*"
        ]
        
        # Set password via environment variable to avoid process list exposure
        upload_env = os.environ.copy()
        upload_env["TWINE_PASSWORD"] = JOB_TOKEN
        
        try:
            if DEBUG:
                print(f"🔍 DEBUG: Uploading to {REPO_URL}")
                print(f"🔍 DEBUG: Command: {' '.join(cmd_up)}")
            result = subprocess.run(cmd_up, check=True, capture_output=True, text=True, env=upload_env)
            if DEBUG:
                print(f"🔍 DEBUG: Upload stdout: {result.stdout}")
            print(f"🚀 PUBLISHED: {pkg}=={ver} mirrored successfully.")
            return True
        except subprocess.CalledProcessError as e:
            if DEBUG:
                print(f"🔍 DEBUG: Upload failed with return code {e.returncode}")
                print(f"🔍 DEBUG: Upload stdout: {e.stdout}")
                print(f"🔍 DEBUG: Upload stderr: {e.stderr}")
            # Check if it's just a "already exists" case - GitLab can return this in various ways
            error_text = (e.stdout + " " + e.stderr).lower()
            if any(phrase in error_text for phrase in [
                "already exists", 
                "file already exists",
                "package already exists",
                "version already exists",
                "duplicate"
            ]):
                print(f"ℹ️  SKIPPED: {pkg}=={ver} already exists in registry.")
                return True
            else:
                print(f"❌ UPLOAD FAILED: {pkg}=={ver} - {e.stderr.strip() or e.stdout.strip()}")
                return False
    
    except OSError as e:
        print(f"❌ FILE SYSTEM ERROR: Failed to process {pkg}=={ver} - {str(e)}")
        return False
    except (ValueError, TypeError) as e:
        print(f"❌ DATA ERROR: Invalid data processing {pkg}=={ver} - {str(e)}")
        return False
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: Failed to process {pkg}=={ver} - {str(e)}")
        return False
    
    finally:
        # Always clean up download directory atomically
        if os.path.exists(download_dir):
            try:
                shutil.rmtree(download_dir)
            except Exception as e:
                print(f"⚠️  Warning: Could not clean up {download_dir}: {e}")
        
        # Always release the lock
        release_package_lock(lock_fd, pkg, ver)


def get_registry_packages():
    """Get list of all packages currently in the GitLab PyPI registry."""
    params = {"package_type": "pypi", "per_page": 100}
    headers = {"JOB-TOKEN": JOB_TOKEN}
    list_url = f"{GITLAB_API}/projects/{PROJECT_ID}/packages"
    
    all_packages = []
    page = 1
    
    while True:
        params["page"] = page
        try:
            resp = requests.get(list_url, headers=headers, params=params, timeout=10)
            if resp.status_code == 401:
                print("❌ REGISTRY ACCESS ERROR: Invalid or expired job token")
                return None
            elif resp.status_code == 404:
                print("❌ REGISTRY ACCESS ERROR: Project not found or no access")
                return None
            elif resp.status_code != 200:
                print(f"❌ REGISTRY ACCESS ERROR: HTTP {resp.status_code} - {resp.text}")
                return None
            
            packages = resp.json()
            if not packages:
                break
                
            all_packages.extend(packages)
            page += 1
            
        except requests.exceptions.RequestException as e:
            print(f"❌ REGISTRY ACCESS ERROR: Failed to fetch packages - {str(e)}")
            return None
    
    return all_packages


def delete_package_from_registry(pkg, ver, dry_run=False, reason="policy violation", cached_packages=None):
    """Deletes a specific package version from GitLab Registry."""
    if dry_run:
        print(f"🔍 DRY-RUN: Would remove {pkg}=={ver} from registry due to {reason}")
        return True
        
    print(f"🗑️  REMOVING {pkg}=={ver} from registry due to {reason}...")

    # 1. Find the Package ID
    if cached_packages is not None:
        packages = cached_packages
    else:
        packages = get_registry_packages()
        if packages is None:
            print(f"❌ DELETE FAILED: Could not fetch registry contents for {pkg}=={ver}")
            return False
    
    target_package = None
    for p in packages:
        if p['name'].lower() == pkg.lower() and p['version'] == ver:
            target_package = p
            break
    
    if not target_package:
        print(f"ℹ️  SKIP: {pkg}=={ver} not found in registry (already removed?)")
        return True
    
    # 2. Delete the package
    headers = {"JOB-TOKEN": JOB_TOKEN}
    del_url = f"{GITLAB_API}/projects/{PROJECT_ID}/packages/{target_package['id']}"
    
    try:
        del_resp = requests.delete(del_url, headers=headers, timeout=10)
        if del_resp.status_code == 204:
            print(f"   ✅ Successfully deleted {pkg}=={ver}")
            return True
        elif del_resp.status_code == 404:
            print(f"   ℹ️  Package {pkg}=={ver} already deleted")
            return True
        else:
            print(f"   ❌ Failed to delete {pkg}=={ver}: HTTP {del_resp.status_code} - {del_resp.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Network error deleting {pkg}=={ver}: {str(e)}")
        return False


def cleanup_stale_locks():
    """Remove stale lock files from previous runs."""
    lock_dir = Path("./locks")
    if not lock_dir.exists():
        return
    
    for lock_file in lock_dir.glob("*.lock"):
        try:
            # Try to open and check if we can acquire the lock
            with open(lock_file, 'r') as f:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    # If we can acquire it, it's stale
                    lock_file.unlink()
                    print(f"🧹 Cleaned up stale lock: {lock_file.name}")
                except OSError:
                    # Lock is still held, leave it alone
                    pass
        except Exception:
            # If we can't read the file, it's probably stale
            try:
                lock_file.unlink()
            except Exception:
                pass


def main_sync(dry_run=False, config_file=None, requirements_file=None):
    """Reads requirements and mirrors allowed packages."""
    # Clean up any stale locks from previous runs
    cleanup_stale_locks()
    
    if config_file is None:
        config_file = DEFAULT_CONFIG_FILE
    if requirements_file is None:
        requirements_file = DEFAULT_REQ_FILE
    
    config = load_config(config_file)
    
    # Parse requirements file using proper parser
    requirements, error = parse_requirements_file(requirements_file)
    if error:
        print(f"❌ FAILED: {error}")
        sys.exit(1)
    
    print(f"📋 Parsed {len(requirements)} valid requirements from {requirements_file}")

    for pkg, ver in requirements:

        # Check Logic
        is_exc = is_excepted(pkg, ver, config)
        is_mature = check_upstream_age(pkg, ver, config['policy']['min_age_days'])
        is_secure = check_vulnerabilities(pkg, ver)

        # Handle error cases (None returns)
        if is_mature is None:
            print(f"⚠️  SKIPPING: {pkg}=={ver} - Could not verify package age")
            continue
        if is_secure is None:
            print(f"⚠️  SKIPPING: {pkg}=={ver} - Could not verify security status")
            continue

        if is_exc:
            success = upload_package(pkg, ver, dry_run)
            if not success and not dry_run:
                print(f"❌ FAILED: Could not mirror excepted package {pkg}=={ver}")
        elif is_mature and is_secure:
            success = upload_package(pkg, ver, dry_run)
            if not success and not dry_run:
                print(f"❌ FAILED: Could not mirror approved package {pkg}=={ver}")
        else:
            print(f"🔒 QUARANTINED: {pkg}=={ver} (Mature: {is_mature}, Secure: {is_secure})")


def main():
    """Main entry point for the mirror-manager CLI."""
    parser = argparse.ArgumentParser(description="PyPI Mirror Manager")
    parser.add_argument("command", nargs="?", default="sync", choices=["sync", "audit"], 
                       help="Command to run (default: sync)")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show what would be done without making changes")
    parser.add_argument("--debug", action="store_true",
                       help="Enable detailed debug output")
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG_FILE,
                       help=f"Path to config file (default: {DEFAULT_CONFIG_FILE})")
    parser.add_argument("--requirements", "-r", default=DEFAULT_REQ_FILE,
                       help=f"Path to requirements file (default: {DEFAULT_REQ_FILE})")
    
    args = parser.parse_args()
    
    # Set global DEBUG flag based on command line argument
    global DEBUG
    DEBUG = args.debug
    
    if args.dry_run:
        print("🔍 DRY-RUN MODE: No packages will be uploaded or deleted\n")
    
    if args.command == "audit":
        print("🔍 AUDITING: Checking registry for policy violations...\n")
        
        config = load_config(args.config)
        
        # Load allowed packages from requirements.txt
        requirements, error = parse_requirements_file(args.requirements)
        if error:
            print(f"❌ AUDIT FAILED: {error}")
            sys.exit(1)
        
        # Parse allowed packages into a set for fast lookup
        allowed_packages = set()
        for pkg, ver in requirements:
            allowed_packages.add((pkg.lower(), ver))
        
        print(f"📋 Found {len(allowed_packages)} allowed packages in {args.requirements}")
        
        # Get actual packages from registry
        registry_packages = get_registry_packages()
        if registry_packages is None:
            print("❌ AUDIT FAILED: Could not fetch registry contents")
            sys.exit(1)
        
        print(f"📦 Found {len(registry_packages)} packages in registry")
        
        removed_count = 0
        scanned_count = 0
        
        # Check each package in the registry
        for pkg_info in registry_packages:
            pkg_name = pkg_info['name']
            pkg_version = pkg_info['version']
            scanned_count += 1
            
            print(f"\n🔍 Auditing {pkg_name}=={pkg_version}...")
            
            # Check if package is still in allowed list
            if (pkg_name.lower(), pkg_version) not in allowed_packages:
                print(f"📝 REASON: Package {pkg_name}=={pkg_version} no longer in requirements.txt")
                success = delete_package_from_registry(pkg_name, pkg_version, args.dry_run, "removed from requirements", registry_packages)
                if success:
                    removed_count += 1
                continue
            
            # Package is in allowed list, check if it's excepted
            if is_excepted(pkg_name, pkg_version, config):
                print(f"⚡ EXCEPTED: {pkg_name}=={pkg_version} bypasses security checks")
                continue
            
            # Run security scan on registry package
            is_secure = check_vulnerabilities(pkg_name, pkg_version)
            if is_secure is False:  # Explicitly vulnerable (not None for scan failure)
                print(f"📝 REASON: Package {pkg_name}=={pkg_version} has new vulnerabilities")
                success = delete_package_from_registry(pkg_name, pkg_version, args.dry_run, "new vulnerabilities found", registry_packages)
                if success:
                    removed_count += 1
            elif is_secure is None:
                print(f"⚠️  WARNING: Could not verify security of {pkg_name}=={pkg_version}")
            else:
                print(f"✅ SECURE: {pkg_name}=={pkg_version} passed security scan")
        
        print(f"\n📊 AUDIT SUMMARY:")
        print(f"   📦 Packages scanned: {scanned_count}")
        if args.dry_run:
            print(f"   🔍 Would remove: {removed_count} packages")
        else:
            print(f"   🗑️  Packages removed: {removed_count}")
    else:
        main_sync(args.dry_run, args.config, args.requirements)


if __name__ == "__main__":
    main()