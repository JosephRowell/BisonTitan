@echo off
REM ============================================================================
REM BisonTitan Code Signing Script
REM Signs executables with Authenticode for Windows
REM ============================================================================
REM
REM REQUIREMENTS:
REM   - Windows SDK (for signtool.exe)
REM   - Code signing certificate (.pfx file or hardware token)
REM
REM CERTIFICATE OPTIONS:
REM   1. EV Certificate (Extended Validation) - Recommended for distribution
REM      - DigiCert, Sectigo, GlobalSign (~$400-600/year)
REM      - Requires hardware token (USB)
REM      - Instant SmartScreen reputation
REM
REM   2. OV Certificate (Organization Validation) - Good for internal
REM      - DigiCert, Sectigo (~$200-400/year)
REM      - Software-based (.pfx file)
REM      - Builds SmartScreen reputation over time
REM
REM   3. Self-Signed (Development only) - FREE
REM      - See: scripts\create_dev_cert.bat
REM      - NOT trusted by Windows - shows warning
REM      - Good for testing signing workflow
REM
REM ============================================================================

setlocal EnableDelayedExpansion

set "GREEN=[32m"
set "YELLOW=[33m"
set "RED=[31m"
set "CYAN=[36m"
set "RESET=[0m"

echo %CYAN%============================================================================%RESET%
echo %CYAN%                    BisonTitan Code Signing%RESET%
echo %CYAN%============================================================================%RESET%
echo.

REM ============================================================================
REM Configuration - EDIT THESE VALUES
REM ============================================================================

REM Path to signtool.exe (Windows SDK)
set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"

REM Certificate options (uncomment ONE method):

REM Method 1: PFX file (OV certificate or self-signed)
set "CERT_METHOD=pfx"
set "PFX_FILE=%~dp0..\certs\bisontitan.pfx"
set "PFX_PASSWORD="
REM For password prompt, leave PFX_PASSWORD empty
REM For automated builds, set: set "PFX_PASSWORD=YourPassword"

REM Method 2: Certificate store (installed certificate)
REM set "CERT_METHOD=store"
REM set "CERT_SUBJECT=BisonTitan"
REM set "CERT_STORE=My"

REM Method 3: Hardware token (EV certificate - DigiCert, etc.)
REM set "CERT_METHOD=token"
REM set "TOKEN_SHA1=YOUR_CERTIFICATE_SHA1_THUMBPRINT"

REM Timestamp server (required for long-term validity)
set "TIMESTAMP_URL=http://timestamp.digicert.com"
REM Alternatives:
REM   http://timestamp.sectigo.com
REM   http://timestamp.globalsign.com
REM   http://tsa.starfieldtech.com

REM Description shown in signature
set "DESCRIPTION=BisonTitan Security Suite"
set "URL=https://github.com/bisontitan/bisontitan"

REM ============================================================================
REM Find signtool.exe
REM ============================================================================

if not exist "%SIGNTOOL%" (
    echo %YELLOW%[SEARCH]%RESET% Looking for signtool.exe...

    REM Search common locations
    for %%V in (22621 22000 19041 18362 17763) do (
        if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.%%V.0\x64\signtool.exe" (
            set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.%%V.0\x64\signtool.exe"
            goto :found_signtool
        )
    )

    REM Try PATH
    where signtool.exe >nul 2>&1
    if not errorlevel 1 (
        set "SIGNTOOL=signtool.exe"
        goto :found_signtool
    )

    echo %RED%ERROR: signtool.exe not found%RESET%
    echo.
    echo Install Windows SDK from:
    echo   https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
    echo.
    echo Or install Visual Studio with "Desktop development with C++"
    exit /b 1
)

:found_signtool
echo %GREEN%[OK]%RESET% signtool.exe found: %SIGNTOOL%

REM ============================================================================
REM Parse arguments
REM ============================================================================

set "TARGET=%~1"
if "%TARGET%"=="" (
    set "TARGET=%~dp0..\dist\bisontitan.exe"
)

if not exist "%TARGET%" (
    echo %RED%ERROR: Target file not found: %TARGET%%RESET%
    echo.
    echo Usage: sign.bat [path\to\executable.exe]
    echo.
    echo Build the executable first:
    echo   build.bat exe
    exit /b 1
)

echo %GREEN%[OK]%RESET% Target: %TARGET%
echo.

REM ============================================================================
REM Sign the executable
REM ============================================================================

echo %YELLOW%[SIGN]%RESET% Signing executable...

if "%CERT_METHOD%"=="pfx" (
    REM Sign with PFX file
    if not exist "%PFX_FILE%" (
        echo %RED%ERROR: PFX file not found: %PFX_FILE%%RESET%
        echo.
        echo Create a self-signed certificate for testing:
        echo   scripts\create_dev_cert.bat
        exit /b 1
    )

    if "%PFX_PASSWORD%"=="" (
        REM Prompt for password
        "%SIGNTOOL%" sign /f "%PFX_FILE%" /d "%DESCRIPTION%" /du "%URL%" /fd SHA256 /tr "%TIMESTAMP_URL%" /td SHA256 /v "%TARGET%"
    ) else (
        REM Use provided password
        "%SIGNTOOL%" sign /f "%PFX_FILE%" /p "%PFX_PASSWORD%" /d "%DESCRIPTION%" /du "%URL%" /fd SHA256 /tr "%TIMESTAMP_URL%" /td SHA256 /v "%TARGET%"
    )

) else if "%CERT_METHOD%"=="store" (
    REM Sign with certificate from Windows store
    "%SIGNTOOL%" sign /n "%CERT_SUBJECT%" /s "%CERT_STORE%" /d "%DESCRIPTION%" /du "%URL%" /fd SHA256 /tr "%TIMESTAMP_URL%" /td SHA256 /v "%TARGET%"

) else if "%CERT_METHOD%"=="token" (
    REM Sign with hardware token (EV certificate)
    REM Note: Token PIN prompt will appear
    "%SIGNTOOL%" sign /sha1 "%TOKEN_SHA1%" /d "%DESCRIPTION%" /du "%URL%" /fd SHA256 /tr "%TIMESTAMP_URL%" /td SHA256 /v "%TARGET%"

) else (
    echo %RED%ERROR: Unknown CERT_METHOD: %CERT_METHOD%%RESET%
    exit /b 1
)

if errorlevel 1 (
    echo.
    echo %RED%[ERROR]%RESET% Signing failed
    exit /b 1
)

echo.
echo %GREEN%[OK]%RESET% Signing successful

REM ============================================================================
REM Verify signature
REM ============================================================================

echo.
echo %YELLOW%[VERIFY]%RESET% Verifying signature...

"%SIGNTOOL%" verify /pa /v "%TARGET%"

if errorlevel 1 (
    echo.
    echo %YELLOW%[WARNING]%RESET% Signature verification failed
    echo This is normal for self-signed certificates
) else (
    echo.
    echo %GREEN%[OK]%RESET% Signature verified
)

REM ============================================================================
REM Show signature details
REM ============================================================================

echo.
echo %CYAN%============================================================================%RESET%
echo %CYAN%Signature Details:%RESET%
echo %CYAN%============================================================================%RESET%

"%SIGNTOOL%" verify /pa /d "%TARGET%" 2>nul

echo.
echo %GREEN%Signing complete!%RESET%
echo.
echo %YELLOW%Next steps:%RESET%
echo   - Test the signed executable
echo   - For self-signed: Users must trust your certificate
echo   - For OV/EV: Distribute normally, SmartScreen will trust it
echo.

exit /b 0
