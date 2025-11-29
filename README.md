# Secure PyPI Index Mirror

This repository manages the organization's private Python Package Index. It acts as a **Quarantined Proxy** between the public PyPI and our internal environment.

**Policies enforced by this system:**
1.  **Maturity:** Packages must be at least **14 days old** on the public PyPI to be mirrored.
2.  **Security:** Packages are scanned for CVEs before mirroring.
3.  **Auditing:** Mirrored packages are re-scanned nightly; if a new vulnerability is discovered, the package is automatically removed (Quarantined).


---

## ✅ Recent Improvements

This codebase has undergone recent improvements to enhance its reliability, security, and maintainability:

*   **Robust Dependency Management:** The CI/CD pipeline now uses `pip install -e .` for consistent and reliable dependency installation.
*   **Improved Requirements Parsing:** The `requirements.txt` parsing has been fortified with `pip-requirements-parser` for accurate and secure handling of package specifications.
*   **Efficient Audit Process:** The audit function now efficiently fetches package lists once, significantly reducing API calls and improving performance.
*   **Comprehensive Test Suite:** A new, extensive test suite has been implemented, covering critical functionalities like package validation and locking mechanisms.
*   **Race Condition Prevention:** A file-based locking mechanism is now in place during package uploads, ensuring data integrity and preventing concurrency issues.
*   **Enhanced Code Quality:** General code quality has been improved with more specific exception handling and flexible file path management.

---

## 🚀 For Developers: How to use this Index

To install packages from this secure mirror, configure your `pip` to point to the GitLab Package Registry.

### Option A: Per-project (Recommended)
Add this to your project's `requirements.txt` or `pip.conf`:

```ini
--extra-index-url https://YOUR_GITLAB_URL/api/v4/projects/YOUR_PROJECT_ID/packages/pypi/simple
```

Replace `YOUR_GITLAB_URL` with your GitLab instance URL and `YOUR_PROJECT_ID` with the project ID containing the PyPI packages.

### Option B: Global Configuration
For a global setup, create or edit `~/.config/pip/pip.conf` (`%APPDATA%\pip\pip.ini` on Windows) and add the following:

```ini
[global]
extra-index-url = https://YOUR_GITLAB_URL/api/v4/projects/YOUR_PROJECT_ID/packages/pypi/simple
```

---

## 🛠️ For Maintainers: Managing the Mirror

This section is for developers who manage the packages available in the private mirror.

### Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd pypi-delayed-mirror
    ```

2.  **Create a virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    The project uses `pip` for dependency management. Install the project in editable mode to get both the runtime dependencies and the CLI script:
    ```bash
    pip install -e .
    ```
    
    For development work, also install the optional development dependencies:
    ```bash
    pip install -e ".[dev]"
    ```

### Configuration

**Environment Variables:**

The mirror requires these environment variables to operate (automatically available in GitLab CI):

*   `CI_API_V4_URL`: GitLab API URL (e.g., `https://gitlab.example.com/api/v4`)
*   `CI_PROJECT_ID`: GitLab Project ID where packages will be stored
*   `CI_JOB_TOKEN`: GitLab Job Token for authentication

**Configuration File:**

The mirror's behavior is controlled by `config.yaml`:

*   `policy.min_age_days`: (Integer) The number of days a package must exist on the public PyPI before it can be mirrored.
*   `exceptions`: (List of Objects) A list of packages that bypass the standard checks. Each object should have:
    *   `package`: The name of the package.
    *   `version`: The specific version to allow.
    *   `reason`: A string explaining why the exception is needed.

### Usage

The core logic is managed by the `mirror-manager` script.

*   **Sync Packages:**
    This is the most common command. It reads the `requirements.txt` file, checks each package against the defined policies (age, vulnerabilities), and uploads valid packages to the GitLab registry.
    ```bash
    mirror-manager sync
    ```

*   **Audit the Registry:**
    This command scans all packages currently in the private registry. If any package is found to have a new vulnerability or has been removed from the `requirements.txt`, it will be deleted from the registry.
    ```bash
    mirror-manager audit
    ```

*   **Dry Run:**
    To see what changes a command would make without actually uploading or deleting packages, use the `--dry-run` flag.
    ```bash
    mirror-manager sync --dry-run
    mirror-manager audit --dry-run
    ```