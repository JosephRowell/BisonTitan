# =============================================================================
# BisonTitan Makefile
# Cross-platform build automation
# =============================================================================

.PHONY: all install install-dev build pip exe test clean lint format help

# Default Python
PYTHON ?= python3

# Detect OS
ifeq ($(OS),Windows_NT)
	PYTHON = python
	RM = del /q
	RMDIR = rmdir /s /q
	SEP = \\
else
	RM = rm -f
	RMDIR = rm -rf
	SEP = /
endif

# =============================================================================
# Default target
# =============================================================================
all: build

# =============================================================================
# Installation targets
# =============================================================================
install:
	@echo "Installing BisonTitan..."
	$(PYTHON) -m pip install .

install-dev:
	@echo "Installing BisonTitan with development dependencies..."
	$(PYTHON) -m pip install --upgrade pip setuptools wheel
	$(PYTHON) -m pip install -e ".[all]"

install-full:
	@echo "Installing BisonTitan with all features..."
	$(PYTHON) -m pip install -e ".[full]"

# =============================================================================
# Build targets
# =============================================================================
build: pip exe
	@echo "Build complete!"

pip:
	@echo "Building pip package..."
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build
	@echo "Output: dist/bisontitan-*.whl"

exe:
	@echo "Building standalone executable..."
	$(PYTHON) -m pip install --upgrade pyinstaller
	$(PYTHON) -m PyInstaller bisontitan.spec --clean --noconfirm
	@echo "Output: dist/bisontitan"

# =============================================================================
# Testing targets
# =============================================================================
test:
	@echo "Running tests..."
	$(PYTHON) -m pytest tests/ -v --tb=short

test-cov:
	@echo "Running tests with coverage..."
	$(PYTHON) -m pytest tests/ -v --cov=src/bisontitan --cov-report=html --cov-report=term

test-quick:
	@echo "Running quick tests..."
	$(PYTHON) -m pytest tests/ -x -q

# =============================================================================
# Code quality targets
# =============================================================================
lint:
	@echo "Running linters..."
	$(PYTHON) -m ruff check src/ tests/
	$(PYTHON) -m mypy src/bisontitan/

format:
	@echo "Formatting code..."
	$(PYTHON) -m black src/ tests/
	$(PYTHON) -m ruff check --fix src/ tests/

check: lint test
	@echo "All checks passed!"

# =============================================================================
# Run targets
# =============================================================================
run:
	$(PYTHON) -m bisontitan

run-gui:
	$(PYTHON) -m bisontitan gui

run-scan:
	$(PYTHON) -m bisontitan scan --files .

# =============================================================================
# Clean targets
# =============================================================================
clean:
	@echo "Cleaning build artifacts..."
ifeq ($(OS),Windows_NT)
	-$(RMDIR) build 2>nul
	-$(RMDIR) dist 2>nul
	-$(RMDIR) .pytest_cache 2>nul
	-$(RMDIR) .mypy_cache 2>nul
	-$(RMDIR) .ruff_cache 2>nul
	-$(RMDIR) htmlcov 2>nul
	-for /d %%d in (src\*.egg-info) do $(RMDIR) "%%d" 2>nul
	-for /d /r . %%d in (__pycache__) do @if exist "%%d" $(RMDIR) "%%d" 2>nul
else
	$(RMDIR) build/ dist/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/ 2>/dev/null || true
	$(RMDIR) src/*.egg-info 2>/dev/null || true
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
endif
	@echo "Clean complete!"

clean-all: clean
	@echo "Removing virtual environment..."
ifeq ($(OS),Windows_NT)
	-$(RMDIR) .venv 2>nul
else
	$(RMDIR) .venv 2>/dev/null || true
endif

# =============================================================================
# Release targets
# =============================================================================
release-check:
	@echo "Checking release readiness..."
	$(PYTHON) -m pip install --upgrade twine
	$(PYTHON) -m twine check dist/*

release-test:
	@echo "Uploading to TestPyPI..."
	$(PYTHON) -m twine upload --repository testpypi dist/*

release:
	@echo "Uploading to PyPI..."
	$(PYTHON) -m twine upload dist/*

# =============================================================================
# Help
# =============================================================================
help:
	@echo "BisonTitan Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Installation:"
	@echo "  install       Install BisonTitan"
	@echo "  install-dev   Install with dev dependencies"
	@echo "  install-full  Install with all features"
	@echo ""
	@echo "Building:"
	@echo "  build         Build pip package and executable"
	@echo "  pip           Build pip package only"
	@echo "  exe           Build standalone executable only"
	@echo ""
	@echo "Testing:"
	@echo "  test          Run test suite"
	@echo "  test-cov      Run tests with coverage report"
	@echo "  test-quick    Run tests, stop on first failure"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint          Run linters (ruff, mypy)"
	@echo "  format        Format code (black, ruff)"
	@echo "  check         Run lint and test"
	@echo ""
	@echo "Running:"
	@echo "  run           Run BisonTitan CLI"
	@echo "  run-gui       Launch GUI dashboard"
	@echo "  run-scan      Run file scan on current directory"
	@echo ""
	@echo "Cleaning:"
	@echo "  clean         Remove build artifacts"
	@echo "  clean-all     Remove build artifacts and venv"
	@echo ""
	@echo "Release:"
	@echo "  release-check Check package before upload"
	@echo "  release-test  Upload to TestPyPI"
	@echo "  release       Upload to PyPI"
