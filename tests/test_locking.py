"""Tests for file locking functionality."""
import pytest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch

# Add the scripts directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))


class TestPackageLocking:
    """Test package locking functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        # Create temporary directory for locks
        self.temp_dir = Path(tempfile.mkdtemp())
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        
        # Set valid environment variables to avoid validation errors
        self.env_patcher = patch.dict(os.environ, {
            'CI_API_V4_URL': 'https://gitlab.example.com/api/v4',
            'CI_PROJECT_ID': '12345',
            'CI_JOB_TOKEN': 'test-token'
        })
        self.env_patcher.start()
    
    def teardown_method(self):
        """Clean up test environment."""
        self.env_patcher.stop()
        os.chdir(self.original_cwd)
        shutil.rmtree(self.temp_dir)
    
    def test_acquire_and_release_lock(self):
        """Test basic lock acquisition and release."""
        from mirror_manager import acquire_package_lock, release_package_lock
        
        # Acquire lock
        lock_fd = acquire_package_lock("test-package", "1.0.0")
        assert lock_fd is not None, "Failed to acquire lock"
        
        # Verify lock file exists
        lock_dir = Path("./locks")
        assert lock_dir.exists()
        
        lock_files = list(lock_dir.glob("*.lock"))
        assert len(lock_files) == 1
        assert "test-package" in lock_files[0].name
        
        # Release lock
        release_package_lock(lock_fd, "test-package", "1.0.0")
        
        # Verify lock file is removed
        lock_files = list(lock_dir.glob("*.lock"))
        assert len(lock_files) == 0
    
    def test_concurrent_lock_acquisition_fails(self):
        """Test that second lock acquisition fails when first is held."""
        from mirror_manager import acquire_package_lock, release_package_lock
        
        # Acquire first lock
        lock1 = acquire_package_lock("test-package", "1.0.0")
        assert lock1 is not None
        
        # Try to acquire second lock (should fail)
        lock2 = acquire_package_lock("test-package", "1.0.0") 
        assert lock2 is None, "Second lock should have failed"
        
        # Release first lock
        release_package_lock(lock1, "test-package", "1.0.0")
        
        # Now second attempt should work
        lock3 = acquire_package_lock("test-package", "1.0.0")
        assert lock3 is not None, "Lock should be available after release"
        
        release_package_lock(lock3, "test-package", "1.0.0")
    
    def test_path_injection_protection(self):
        """Test that path injection attempts are sanitized."""
        from mirror_manager import acquire_package_lock, release_package_lock
        
        # Try path injection
        lock_fd = acquire_package_lock("../../../etc/passwd", "1.0.0")
        assert lock_fd is not None, "Lock should still work with sanitized name"
        
        # Verify the lock file is in the correct directory
        lock_dir = Path("./locks") 
        lock_files = list(lock_dir.glob("*.lock"))
        assert len(lock_files) == 1
        
        # Verify the filename is sanitized
        lock_file = lock_files[0]
        assert "passwd" in lock_file.name  # Sanitized version
        assert ".." not in lock_file.name  # No path traversal
        assert "/" not in lock_file.name   # No path separators
        
        # Verify it's actually in the locks directory
        assert lock_file.parent.name == "locks"
        
        release_package_lock(lock_fd, "../../../etc/passwd", "1.0.0")
    
    def test_cleanup_stale_locks(self):
        """Test cleanup of stale lock files."""
        from mirror_manager import cleanup_stale_locks
        
        # Create lock directory with a stale lock file
        lock_dir = Path("./locks")
        lock_dir.mkdir(exist_ok=True)
        
        stale_lock = lock_dir / "stale-package-1.0.0.lock" 
        stale_lock.write_text("Old lock file")
        
        assert stale_lock.exists()
        
        # Run cleanup
        cleanup_stale_locks()
        
        # Stale lock should be removed
        assert not stale_lock.exists()


if __name__ == "__main__":
    pytest.main([__file__])