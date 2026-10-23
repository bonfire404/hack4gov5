@echo off
title Hack4Gov Toolkit Setup
cd /d "%~dp0"

echo ==============================================================================
echo              HACK4GOV CTF TOOLKIT - DEPENDENCY INSTALLER
echo ==============================================================================
echo.

where python >nul 2>nul
if %errorlevel% equ 0 (
    set PY_CMD=python
) else (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        set PY_CMD=py
    ) else (
        echo [-] Error: Python was not found in system PATH.
        echo Please ensure Python 3 is installed and added to PATH.
        pause
        exit /b 1
    )
)

echo [*] Python detected: %PY_CMD%
echo [*] Installing required Python packages from requirements.txt...
echo.

%PY_CMD% -m pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo.
    echo ==============================================================================
    echo [+] SUCCESS: All CTF dependencies installed successfully!
    echo ==============================================================================
) else (
    echo.
    echo [-] Warning: One or more dependencies failed to install.
    echo [*] Check your network connection or permissions.
)

echo.
pause
