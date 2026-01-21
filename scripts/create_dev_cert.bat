@echo off
REM ============================================================================
REM BisonTitan Development Certificate Generator
REM Creates a self-signed certificate for code signing (development/testing)
REM ============================================================================
REM
REM WARNING: Self-signed certificates are NOT trusted by Windows!
REM          - Users will see SmartScreen warnings
REM          - Good for testing the signing workflow
REM          - NOT for production distribution
REM
REM For production, purchase a certificate from:
REM   - DigiCert: https://www.digicert.com/signing/code-signing-certificates
REM   - Sectigo:  https://sectigo.com/ssl-certificates-tls/code-signing
REM   - GlobalSign: https://www.globalsign.com/en/code-signing-certificate
REM
REM ============================================================================

setlocal EnableDelayedExpansion

set "GREEN=[32m"
set "YELLOW=[33m"
set "RED=[31m"
set "CYAN=[36m"
set "RESET=[0m"

echo %CYAN%============================================================================%RESET%
echo %CYAN%           BisonTitan Development Certificate Generator%RESET%
echo %CYAN%============================================================================%RESET%
echo.
echo %YELLOW%WARNING: This creates a SELF-SIGNED certificate for DEVELOPMENT ONLY%RESET%
echo %YELLOW%         Windows will NOT trust this certificate by default%RESET%
echo.

REM ============================================================================
REM Configuration
REM ============================================================================

set "CERT_NAME=BisonTitan Development"
set "CERT_CN=BisonTitan Dev Code Signing"
set "CERT_DIR=%~dp0..\certs"
set "PFX_FILE=%CERT_DIR%\bisontitan.pfx"
set "CER_FILE=%CERT_DIR%\bisontitan.cer"

REM Validity period (days)
set "VALIDITY_DAYS=365"

REM ============================================================================
REM Check for PowerShell
REM ============================================================================

powershell -Command "exit 0" >nul 2>&1
if errorlevel 1 (
    echo %RED%ERROR: PowerShell not available%RESET%
    exit /b 1
)

echo %GREEN%[OK]%RESET% PowerShell available
echo.

REM ============================================================================
REM Create certs directory
REM ============================================================================

if not exist "%CERT_DIR%" (
    echo %YELLOW%[CREATE]%RESET% Creating certs directory...
    mkdir "%CERT_DIR%"
)

REM ============================================================================
REM Check if certificate already exists
REM ============================================================================

if exist "%PFX_FILE%" (
    echo %YELLOW%[EXISTS]%RESET% Certificate already exists: %PFX_FILE%
    echo.
    choice /C YN /M "Overwrite existing certificate"
    if errorlevel 2 (
        echo %YELLOW%[SKIP]%RESET% Keeping existing certificate
        goto :show_info
    )
    echo.
)

REM ============================================================================
REM Prompt for password
REM ============================================================================

echo %CYAN%Enter a password for the certificate (or press Enter for default):%RESET%
set /p "CERT_PASSWORD="
if "%CERT_PASSWORD%"=="" set "CERT_PASSWORD=BisonTitan123!"

echo.

REM ============================================================================
REM Create self-signed certificate using PowerShell
REM ============================================================================

echo %YELLOW%[CREATE]%RESET% Creating self-signed certificate...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=%CERT_CN%' -FriendlyName '%CERT_NAME%' -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(%VALIDITY_DAYS%) -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256; ^
    $pwd = ConvertTo-SecureString -String '%CERT_PASSWORD%' -Force -AsPlainText; ^
    Export-PfxCertificate -Cert $cert -FilePath '%PFX_FILE%' -Password $pwd | Out-Null; ^
    Export-Certificate -Cert $cert -FilePath '%CER_FILE%' | Out-Null; ^
    Write-Host 'Certificate thumbprint:' $cert.Thumbprint; ^
    Write-Host 'Certificate created successfully!'"

if errorlevel 1 (
    echo.
    echo %RED%[ERROR]%RESET% Failed to create certificate
    echo.
    echo Try running as Administrator, or use makecert.exe:
    echo   makecert -r -pe -n "CN=%CERT_CN%" -ss My -sr CurrentUser ^
    echo           -a sha256 -len 2048 -cy end -eku 1.3.6.1.5.5.7.3.3 ^
    echo           "%CER_FILE%"
    exit /b 1
)

echo.
echo %GREEN%[OK]%RESET% Certificate created successfully!

:show_info
echo.
echo %CYAN%============================================================================%RESET%
echo %CYAN%Certificate Information%RESET%
echo %CYAN%============================================================================%RESET%
echo.
echo   PFX File:    %PFX_FILE%
echo   CER File:    %CER_FILE%
echo   Password:    %CERT_PASSWORD%
echo   Valid for:   %VALIDITY_DAYS% days
echo.

REM ============================================================================
REM Instructions
REM ============================================================================

echo %CYAN%============================================================================%RESET%
echo %CYAN%Usage Instructions%RESET%
echo %CYAN%============================================================================%RESET%
echo.
echo %YELLOW%1. Sign your executable:%RESET%
echo    scripts\sign.bat dist\bisontitan.exe
echo.
echo %YELLOW%2. For users to trust your dev builds:%RESET%
echo    a. Copy %CER_FILE% to their machine
echo    b. Double-click the .cer file
echo    c. Click "Install Certificate"
echo    d. Select "Local Machine" (requires admin)
echo    e. Select "Place all certificates in the following store"
echo    f. Browse and select "Trusted Publishers"
echo    g. Click Finish
echo.
echo %YELLOW%3. Or install via PowerShell (Admin):%RESET%
echo    Import-Certificate -FilePath "%CER_FILE%" ^
echo        -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
echo.

REM ============================================================================
REM Optional: Install to Trusted Publishers (local machine)
REM ============================================================================

echo %CYAN%============================================================================%RESET%
choice /C YN /M "Install certificate to Trusted Publishers (requires Admin)"
if errorlevel 2 goto :done

echo.
echo %YELLOW%[INSTALL]%RESET% Installing certificate (may require UAC prompt)...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"Import-Certificate -FilePath \"%CER_FILE%\" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher\"' -Wait"

if errorlevel 1 (
    echo %YELLOW%[SKIP]%RESET% Installation skipped or failed
) else (
    echo %GREEN%[OK]%RESET% Certificate installed to Trusted Publishers
    echo        Your signed executables will now be trusted on this machine
)

:done
echo.
echo %GREEN%Done!%RESET%
echo.
echo %YELLOW%Remember:%RESET%
echo   - Self-signed certs are for DEVELOPMENT ONLY
echo   - Purchase a real certificate for production distribution
echo   - Keep your .pfx file and password secure!
echo.

exit /b 0
