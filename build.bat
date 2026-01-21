@echo off
REM ============================================================================
REM BisonTitan Build Script for Windows
REM Builds pip package and/or standalone executable
REM ============================================================================

setlocal EnableDelayedExpansion

REM Colors for output
set "GREEN=[32m"
set "YELLOW=[33m"
set "RED=[31m"
set "CYAN=[36m"
set "RESET=[0m"

echo %CYAN%============================================================================%RESET%
echo %CYAN%                    BisonTitan Build Script v1.0.0%RESET%
echo %CYAN%============================================================================%RESET%
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo %RED%ERROR: Python not found in PATH%RESET%
    echo Please install Python 3.12+ from https://python.org
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version') do set PYVER=%%v
echo %GREEN%[OK]%RESET% Python version: %PYVER%

REM Parse arguments
set BUILD_PIP=0
set BUILD_EXE=0
set INSTALL_DEV=0
set RUN_TESTS=0
set CLEAN=0
set SIGN_EXE=0
set GEN_ICON=0

if "%1"=="" (
    set BUILD_PIP=1
    set BUILD_EXE=1
)

:parse_args
if "%1"=="" goto :done_args
if /i "%1"=="pip" set BUILD_PIP=1
if /i "%1"=="exe" set BUILD_EXE=1
if /i "%1"=="all" (
    set BUILD_PIP=1
    set BUILD_EXE=1
)
if /i "%1"=="install" set INSTALL_DEV=1
if /i "%1"=="test" set RUN_TESTS=1
if /i "%1"=="clean" set CLEAN=1
if /i "%1"=="sign" set SIGN_EXE=1
if /i "%1"=="icon" set GEN_ICON=1
if /i "%1"=="release" (
    set BUILD_PIP=1
    set BUILD_EXE=1
    set SIGN_EXE=1
    set GEN_ICON=1
)
if /i "%1"=="--help" goto :show_help
if /i "%1"=="-h" goto :show_help
shift
goto :parse_args
:done_args

REM Clean build artifacts
if %CLEAN%==1 (
    echo.
    echo %YELLOW%[CLEAN]%RESET% Removing build artifacts...
    if exist build rmdir /s /q build
    if exist dist rmdir /s /q dist
    if exist *.egg-info rmdir /s /q *.egg-info
    if exist src\*.egg-info rmdir /s /q src\*.egg-info
    for /d %%d in (src\bisontitan\__pycache__) do rmdir /s /q "%%d" 2>nul
    for /d %%d in (tests\__pycache__) do rmdir /s /q "%%d" 2>nul
    echo %GREEN%[OK]%RESET% Clean complete
)

REM Install development dependencies
if %INSTALL_DEV%==1 (
    echo.
    echo %YELLOW%[INSTALL]%RESET% Installing development dependencies...
    python -m pip install --upgrade pip setuptools wheel
    python -m pip install -e ".[all]"
    if errorlevel 1 (
        echo %RED%[ERROR]%RESET% Failed to install dependencies
        exit /b 1
    )
    echo %GREEN%[OK]%RESET% Dependencies installed
)

REM Run tests
if %RUN_TESTS%==1 (
    echo.
    echo %YELLOW%[TEST]%RESET% Running test suite...
    python -m pytest tests/ -v --tb=short
    if errorlevel 1 (
        echo %RED%[WARNING]%RESET% Some tests failed
    ) else (
        echo %GREEN%[OK]%RESET% All tests passed
    )
)

REM Build pip package
if %BUILD_PIP%==1 (
    echo.
    echo %YELLOW%[BUILD]%RESET% Building pip package...

    REM Clean previous builds
    if exist dist\*.whl del /q dist\*.whl
    if exist dist\*.tar.gz del /q dist\*.tar.gz

    REM Build wheel and sdist
    python -m pip install --upgrade build
    python -m build

    if errorlevel 1 (
        echo %RED%[ERROR]%RESET% Failed to build pip package
        exit /b 1
    )

    echo %GREEN%[OK]%RESET% Pip package built successfully
    echo     Output: dist\bisontitan-*.whl
    echo     Output: dist\bisontitan-*.tar.gz
)

REM Generate icon
if %GEN_ICON%==1 (
    echo.
    echo %YELLOW%[ICON]%RESET% Generating application icon...

    REM Check if Pillow is installed
    python -c "import PIL" >nul 2>&1
    if errorlevel 1 (
        echo %YELLOW%[INSTALL]%RESET% Installing Pillow...
        python -m pip install Pillow -q
    )

    REM Generate icon
    if exist "assets\generate_icon.py" (
        python assets\generate_icon.py
        if errorlevel 1 (
            echo %YELLOW%[WARNING]%RESET% Icon generation failed, continuing...
        ) else (
            echo %GREEN%[OK]%RESET% Icon generated: assets\icon.ico
        )
    ) else (
        echo %YELLOW%[SKIP]%RESET% Icon generator not found
    )
)

REM Build standalone executable
if %BUILD_EXE%==1 (
    echo.
    echo %YELLOW%[BUILD]%RESET% Building standalone executable...

    REM Check if PyInstaller is installed
    python -c "import PyInstaller" >nul 2>&1
    if errorlevel 1 (
        echo %YELLOW%[INSTALL]%RESET% Installing PyInstaller...
        python -m pip install pyinstaller>=6.0.0
    )

    REM Build executable
    python -m PyInstaller bisontitan.spec --clean --noconfirm

    if errorlevel 1 (
        echo %RED%[ERROR]%RESET% Failed to build executable
        exit /b 1
    )

    echo %GREEN%[OK]%RESET% Executable built successfully
    echo     Output: dist\bisontitan.exe

    REM Show file size
    for %%F in (dist\bisontitan.exe) do (
        set SIZE=%%~zF
        set /a SIZE_MB=!SIZE!/1048576
        echo     Size: !SIZE_MB! MB
    )
)

REM Sign executable
if %SIGN_EXE%==1 (
    echo.
    if not exist "dist\bisontitan.exe" (
        echo %YELLOW%[SKIP]%RESET% No executable to sign. Build exe first.
    ) else (
        echo %YELLOW%[SIGN]%RESET% Signing executable...

        if exist "scripts\sign.bat" (
            call scripts\sign.bat dist\bisontitan.exe
            if errorlevel 1 (
                echo %YELLOW%[WARNING]%RESET% Signing failed, continuing...
            ) else (
                echo %GREEN%[OK]%RESET% Executable signed
            )
        ) else (
            echo %YELLOW%[SKIP]%RESET% Sign script not found: scripts\sign.bat
        )
    )
)

echo.
echo %CYAN%============================================================================%RESET%
echo %GREEN%Build complete!%RESET%
echo %CYAN%============================================================================%RESET%
echo.

REM Show next steps
echo %YELLOW%Next steps:%RESET%
if %BUILD_PIP%==1 (
    echo   - Install locally: pip install dist\bisontitan-*.whl
    echo   - Upload to PyPI:  twine upload dist\*
)
if %BUILD_EXE%==1 (
    echo   - Test executable: dist\bisontitan.exe --version
    echo   - Run scan:        dist\bisontitan.exe scan --files .
    if %SIGN_EXE%==0 (
        echo   - Sign for distribution: build.bat sign
    )
)
if %SIGN_EXE%==1 (
    echo   - Verify signature: signtool verify /pa dist\bisontitan.exe
)
echo.

exit /b 0

:show_help
echo.
echo %CYAN%BisonTitan Build Script%RESET%
echo.
echo Usage: build.bat [options]
echo.
echo Options:
echo   pip       Build pip package only (wheel + sdist)
echo   exe       Build standalone executable only
echo   all       Build both pip package and executable (default)
echo   install   Install development dependencies first
echo   test      Run test suite
echo   clean     Remove build artifacts
echo   icon      Generate application icon (requires Pillow)
echo   sign      Sign the executable (requires certificate)
echo   release   Full release build (icon + pip + exe + sign)
echo   --help    Show this help message
echo.
echo Examples:
echo   build.bat                    Build pip + exe (no signing)
echo   build.bat pip                Build pip package only
echo   build.bat exe                Build executable only
echo   build.bat icon exe           Generate icon, build exe
echo   build.bat exe sign           Build and sign executable
echo   build.bat release            Full release (icon, build, sign)
echo   build.bat clean install all  Clean, install deps, build all
echo.
echo Code Signing:
echo   1. Create dev cert:  scripts\create_dev_cert.bat
echo   2. Configure:        Edit scripts\sign.bat
echo   3. Sign:             build.bat exe sign
echo.
exit /b 0
