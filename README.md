# BisonTitan

**Windows Security Suite for Threat Detection & Vulnerability Assessment**

[![CI/CD](https://github.com/YOUR_USERNAME/BisonTitan/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/BisonTitan/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

BisonTitan is a comprehensive Windows security toolkit that provides:

- **Vulnerability Scanning** - Port scanning, service detection, CVE enrichment
- **Log Analysis** - Windows Event Log analysis with MITRE ATT&CK mapping
- **File Scanning** - YARA-based malware detection
- **Browser Fingerprinting** - Privacy assessment
- **Attack Simulation** - Security testing scenarios

## Features

| Feature | Description |
|---------|-------------|
| Port Scanner | Detect open ports with risk assessment |
| CVE Lookup | Real-time vulnerability lookup via NVD API |
| Event Log Analysis | Parse Security/System/Application logs |
| MITRE ATT&CK | Map threats to ATT&CK techniques |
| Service Detection | Verbose service install analysis |
| YARA Scanning | Custom malware rule matching |
| Firewall Rules | Copy-paste netsh commands |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/BisonTitan.git
cd BisonTitan

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -e .

# For development
pip install -e ".[dev]"
```

### Dependencies

**Required:**
- Python 3.11+
- streamlit
- sqlalchemy
- pyyaml
- psutil
- plotly

**Optional (enhanced features):**
- `python-nmap` - Full port scanning
- `yara-python` - Malware detection
- `pywin32` - Windows Event Log access
- `playwright` - Browser fingerprinting

### Running the GUI

```bash
# Start the Streamlit dashboard
streamlit run src/bisontitan/gui/app.py

# Or use the module
python -m bisontitan.gui
```

The GUI will open in your browser at `http://localhost:8501`

### Command Line

```bash
# Quick vulnerability scan
python -m bisontitan scan --target 127.0.0.1 --type quick

# Full port scan
python -m bisontitan scan --target 127.0.0.1 --type full

# Analyze Windows logs (requires admin)
python -m bisontitan logs --type Security --hours 24

# Start API server
python -m bisontitan.api_stub serve --port 8000
```

## Configuration

Copy and customize the config file:

```bash
cp config/config.yaml.example config/config.yaml
```

### Environment Variables

```bash
# Optional API keys for enhanced features
export SUPABASE_URL=https://your-project.supabase.co
export SUPABASE_KEY=your-api-key
export NVD_API_KEY=your-nvd-key
export ABUSEIPDB_API_KEY=your-abuseipdb-key
```

### YARA Rules

Add custom YARA rules to `config/rules/`:

```yara
rule SuspiciousExecutable {
    meta:
        description = "Detects suspicious patterns"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $cmd = "cmd.exe" nocase
    condition:
        $mz at 0 and $cmd
}
```

## Usage Examples

### Vulnerability Scan

```python
from bisontitan.vuln_checker import VulnChecker

checker = VulnChecker()
result = checker.quick_scan("127.0.0.1")

print(f"Risk Score: {result.risk_score}/10")
for port in result.open_ports:
    print(f"  Port {port.port}: {port.service} [{port.risk_level}]")
```

### Log Analysis

```python
from bisontitan.log_analyzer import LogAnalyzer

analyzer = LogAnalyzer()
result = analyzer.full_analysis(log_type="Security", hours=24)

for anomaly in result.anomalies:
    print(f"[{anomaly.severity}] {anomaly.description}")
    print(f"  MITRE: {anomaly.mitre_techniques}")
```

### File Scanning

```python
from bisontitan.scanner import FileScanner

scanner = FileScanner()
scanner.load_yara_rules()

result = scanner.scan_file("suspicious.exe")
if result.threat_level.value in ["high", "critical"]:
    print(f"THREAT DETECTED: {result.matches}")
```

## GUI Pages

| Page | Description |
|------|-------------|
| Dashboard | Overview of security status |
| Scanner | Vulnerability/Port/File/Process scans |
| Privacy Check | Browser fingerprint analysis |
| Log Analysis | Windows Event Log analysis |
| Vulnerabilities | Detailed vulnerability assessment |
| Attack Simulation | Security testing scenarios |
| Settings | Configuration management |

## Project Structure

```
BisonTitan/
├── src/bisontitan/
│   ├── __init__.py
│   ├── scanner.py          # File/process scanning
│   ├── vuln_checker.py     # Port scanning, CVE lookup
│   ├── log_analyzer.py     # Windows log analysis
│   ├── threat_intel.py     # Threat intelligence
│   ├── fingerprint.py      # Browser fingerprinting
│   ├── db.py               # Database layer
│   ├── config.py           # Configuration
│   ├── api_stub.py         # REST API
│   └── gui/
│       └── app.py          # Streamlit dashboard
├── config/
│   ├── config.yaml         # Main configuration
│   ├── service_whitelist.yaml  # Known services
│   └── rules/              # YARA rules
├── tests/
│   └── test_gui_smoke.py   # Test suite
├── .github/
│   └── workflows/
│       └── ci.yml          # CI/CD pipeline
└── README.md
```

## Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/BisonTitan.git
cd BisonTitan

# Create a feature branch
git checkout -b feature/your-feature-name

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run linter
ruff check src/bisontitan/
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Add docstrings to public functions
- Keep functions focused and small

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Run the test suite (`pytest tests/ -v`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Commit Messages

Follow conventional commits:

```
feat: add new scanning feature
fix: resolve port detection issue
docs: update README installation
test: add tests for log analyzer
refactor: improve CVE lookup performance
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=bisontitan --cov-report=html

# Run specific test class
python -m pytest tests/test_gui_smoke.py::TestVulnChecker -v
```

## Security

### Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@example.com](mailto:security@example.com). Do not create public GitHub issues for security vulnerabilities.

### Safe Usage

- **Only scan systems you own or have authorization to test**
- Run with minimal privileges when possible
- Keep API keys secure (use environment variables)
- Review firewall rules before applying

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) for threat framework
- [NVD](https://nvd.nist.gov/) for vulnerability data
- [YARA](https://virustotal.github.io/yara/) for malware detection
- [Streamlit](https://streamlit.io/) for the GUI framework

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

**Disclaimer:** This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this software.
