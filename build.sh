#!/bin/bash
# =============================================================================
# BisonTitan Build Script for Linux/macOS
# Builds pip package and/or standalone executable
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================================${NC}"
echo -e "${CYAN}                    BisonTitan Build Script v1.0.0${NC}"
echo -e "${CYAN}============================================================================${NC}"
echo

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 not found${NC}"
    echo "Please install Python 3.12+ from https://python.org"
    exit 1
fi

PYVER=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}[OK]${NC} Python version: $PYVER"

# Default options
BUILD_PIP=0
BUILD_EXE=0
INSTALL_DEV=0
RUN_TESTS=0
CLEAN=0

# Parse arguments
if [ $# -eq 0 ]; then
    BUILD_PIP=1
    BUILD_EXE=1
fi

while [ $# -gt 0 ]; do
    case "$1" in
        pip)
            BUILD_PIP=1
            ;;
        exe)
            BUILD_EXE=1
            ;;
        all)
            BUILD_PIP=1
            BUILD_EXE=1
            ;;
        install)
            INSTALL_DEV=1
            ;;
        test)
            RUN_TESTS=1
            ;;
        clean)
            CLEAN=1
            ;;
        --help|-h)
            echo
            echo -e "${CYAN}BisonTitan Build Script${NC}"
            echo
            echo "Usage: ./build.sh [options]"
            echo
            echo "Options:"
            echo "  pip       Build pip package only (wheel + sdist)"
            echo "  exe       Build standalone executable only"
            echo "  all       Build both pip package and executable (default)"
            echo "  install   Install development dependencies first"
            echo "  test      Run test suite"
            echo "  clean     Remove build artifacts"
            echo "  --help    Show this help message"
            echo
            echo "Examples:"
            echo "  ./build.sh                    Build everything"
            echo "  ./build.sh pip                Build pip package only"
            echo "  ./build.sh exe                Build executable only"
            echo "  ./build.sh clean install all  Clean, install deps, build all"
            echo
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
    shift
done

# Clean build artifacts
if [ $CLEAN -eq 1 ]; then
    echo
    echo -e "${YELLOW}[CLEAN]${NC} Removing build artifacts..."
    rm -rf build/ dist/ *.egg-info src/*.egg-info
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Clean complete"
fi

# Install development dependencies
if [ $INSTALL_DEV -eq 1 ]; then
    echo
    echo -e "${YELLOW}[INSTALL]${NC} Installing development dependencies..."
    python3 -m pip install --upgrade pip setuptools wheel
    python3 -m pip install -e ".[all]"
    echo -e "${GREEN}[OK]${NC} Dependencies installed"
fi

# Run tests
if [ $RUN_TESTS -eq 1 ]; then
    echo
    echo -e "${YELLOW}[TEST]${NC} Running test suite..."
    if python3 -m pytest tests/ -v --tb=short; then
        echo -e "${GREEN}[OK]${NC} All tests passed"
    else
        echo -e "${RED}[WARNING]${NC} Some tests failed"
    fi
fi

# Build pip package
if [ $BUILD_PIP -eq 1 ]; then
    echo
    echo -e "${YELLOW}[BUILD]${NC} Building pip package..."

    # Clean previous builds
    rm -f dist/*.whl dist/*.tar.gz 2>/dev/null || true

    # Build wheel and sdist
    python3 -m pip install --upgrade build
    python3 -m build

    echo -e "${GREEN}[OK]${NC} Pip package built successfully"
    echo "    Output: dist/bisontitan-*.whl"
    echo "    Output: dist/bisontitan-*.tar.gz"
fi

# Build standalone executable
if [ $BUILD_EXE -eq 1 ]; then
    echo
    echo -e "${YELLOW}[BUILD]${NC} Building standalone executable..."

    # Check if PyInstaller is installed
    if ! python3 -c "import PyInstaller" &> /dev/null; then
        echo -e "${YELLOW}[INSTALL]${NC} Installing PyInstaller..."
        python3 -m pip install pyinstaller>=6.0.0
    fi

    # Build executable
    python3 -m PyInstaller bisontitan.spec --clean --noconfirm

    echo -e "${GREEN}[OK]${NC} Executable built successfully"
    echo "    Output: dist/bisontitan"

    # Show file size
    if [ -f "dist/bisontitan" ]; then
        SIZE=$(du -h dist/bisontitan | cut -f1)
        echo "    Size: $SIZE"
    fi
fi

echo
echo -e "${CYAN}============================================================================${NC}"
echo -e "${GREEN}Build complete!${NC}"
echo -e "${CYAN}============================================================================${NC}"
echo

# Show next steps
echo -e "${YELLOW}Next steps:${NC}"
if [ $BUILD_PIP -eq 1 ]; then
    echo "  - Install locally: pip install dist/bisontitan-1.0.0-py3-none-any.whl"
    echo "  - Upload to PyPI:  twine upload dist/*"
fi
if [ $BUILD_EXE -eq 1 ]; then
    echo "  - Test executable: ./dist/bisontitan --version"
    echo "  - Run scan:        ./dist/bisontitan scan --files ."
fi
echo
