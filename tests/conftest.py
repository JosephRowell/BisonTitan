"""
BisonTitan Test Configuration
Shared fixtures and configuration for pytest.
"""

import sys
import tempfile
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture(scope="session")
def project_root():
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def config_dir(project_root):
    """Return the config directory."""
    return project_root / "config"


@pytest.fixture(scope="session")
def rules_dir(config_dir):
    """Return the YARA rules directory."""
    return config_dir / "rules"


@pytest.fixture
def temp_directory():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_text_file(temp_directory):
    """Create a sample text file for testing."""
    filepath = temp_directory / "sample.txt"
    filepath.write_text("This is a sample file for testing BisonTitan.")
    return filepath


@pytest.fixture
def sample_suspicious_file(temp_directory):
    """Create a file with suspicious content for testing."""
    filepath = temp_directory / "suspicious.ps1"
    content = """
    # Suspicious PowerShell script for testing
    $client = New-Object System.Net.Sockets.TCPClient("127.0.0.1", 4444)
    Invoke-Expression "test"
    """
    filepath.write_text(content)
    return filepath


@pytest.fixture
def eicar_test_file(temp_directory):
    """Create EICAR test file (standard AV test pattern)."""
    filepath = temp_directory / "eicar.txt"
    # This is the official EICAR test string - safe, used to test AV
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    filepath.write_text(eicar)
    return filepath
