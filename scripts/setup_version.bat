@echo off
REM ============================================================================
REM BisonTitan Version Setup Script
REM Initializes git repo and creates version tags for setuptools_scm
REM ============================================================================

setlocal EnableDelayedExpansion

set "GREEN=[32m"
set "YELLOW=[33m"
set "RED=[31m"
set "CYAN=[36m"
set "RESET=[0m"

echo %CYAN%============================================================================%RESET%
echo %CYAN%                BisonTitan Version Setup%RESET%
echo %CYAN%============================================================================%RESET%
echo.

REM Check if git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo %RED%ERROR: Git not found in PATH%RESET%
    echo Please install Git from https://git-scm.com/
    exit /b 1
)

echo %GREEN%[OK]%RESET% Git is installed

REM Navigate to project root
cd /d "%~dp0.."
echo %GREEN%[OK]%RESET% Working directory: %CD%

REM Check if already a git repo
if exist ".git" (
    echo %GREEN%[OK]%RESET% Git repository already initialized
) else (
    echo %YELLOW%[INIT]%RESET% Initializing git repository...
    git init
    if errorlevel 1 (
        echo %RED%ERROR: Failed to initialize git%RESET%
        exit /b 1
    )
    echo %GREEN%[OK]%RESET% Git repository initialized
)

REM Create .gitignore if it doesn't exist
if not exist ".gitignore" (
    echo %YELLOW%[CREATE]%RESET% Creating .gitignore...
    (
        echo # Python
        echo __pycache__/
        echo *.py[cod]
        echo *$py.class
        echo *.so
        echo .Python
        echo build/
        echo dist/
        echo *.egg-info/
        echo .eggs/
        echo *.egg
        echo.
        echo # Virtual environments
        echo .venv/
        echo venv/
        echo ENV/
        echo.
        echo # IDE
        echo .idea/
        echo .vscode/
        echo *.swp
        echo *.swo
        echo.
        echo # Testing
        echo .pytest_cache/
        echo .coverage
        echo htmlcov/
        echo .tox/
        echo.
        echo # Type checking
        echo .mypy_cache/
        echo.
        echo # Build
        echo *.spec.bak
        echo.
        echo # Auto-generated version
        echo src/bisontitan/_version.py
        echo.
        echo # OS
        echo .DS_Store
        echo Thumbs.db
    ) > .gitignore
    echo %GREEN%[OK]%RESET% .gitignore created
)

REM Add all files
echo %YELLOW%[ADD]%RESET% Staging files...
git add -A
if errorlevel 1 (
    echo %RED%ERROR: Failed to stage files%RESET%
    exit /b 1
)

REM Check if there are commits
git rev-parse HEAD >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%[COMMIT]%RESET% Creating initial commit...
    git commit -m "Initial commit: BisonTitan Security Suite v1.0.0"
    if errorlevel 1 (
        echo %RED%ERROR: Failed to create initial commit%RESET%
        exit /b 1
    )
    echo %GREEN%[OK]%RESET% Initial commit created
)

REM Check existing tags
echo.
echo %CYAN%Existing tags:%RESET%
git tag -l "v*"
echo.

REM Parse command line for version
set VERSION=%1
if "%VERSION%"=="" set VERSION=v1.0.1

REM Check if tag already exists
git tag -l "%VERSION%" | findstr /r "." >nul
if not errorlevel 1 (
    echo %YELLOW%[SKIP]%RESET% Tag %VERSION% already exists
    goto :show_version
)

REM Create new tag
echo %YELLOW%[TAG]%RESET% Creating tag %VERSION%...
git tag -a %VERSION% -m "Release %VERSION%"
if errorlevel 1 (
    echo %RED%ERROR: Failed to create tag%RESET%
    exit /b 1
)
echo %GREEN%[OK]%RESET% Tag %VERSION% created

:show_version
REM Show current version
echo.
echo %CYAN%============================================================================%RESET%
echo %CYAN%Current tags:%RESET%
git tag -l "v*" --sort=-v:refname
echo.

REM Install in development mode to generate _version.py
echo %YELLOW%[INSTALL]%RESET% Installing package to generate version file...
pip install -e . -q
if errorlevel 1 (
    echo %YELLOW%[WARNING]%RESET% Install failed, trying with setuptools_scm only...
    pip install setuptools_scm -q
    python -c "from setuptools_scm import get_version; print(f'Version: {get_version()}')"
) else (
    echo %GREEN%[OK]%RESET% Package installed
)

REM Show the generated version
echo.
echo %CYAN%============================================================================%RESET%
echo %GREEN%Version setup complete!%RESET%
echo %CYAN%============================================================================%RESET%
echo.

REM Test version
echo %YELLOW%Testing version output:%RESET%
python -c "from bisontitan import __version__; print(f'  bisontitan.__version__ = {__version__}')"
echo.

echo %YELLOW%Test CLI version:%RESET%
python -m bisontitan --version
echo.

echo %YELLOW%Next steps:%RESET%
echo   - Commit any remaining changes: git add -A ^&^& git commit -m "message"
echo   - Create new releases:          git tag -a v1.0.2 -m "Release v1.0.2"
echo   - Push tags to remote:          git push origin --tags
echo.

exit /b 0
