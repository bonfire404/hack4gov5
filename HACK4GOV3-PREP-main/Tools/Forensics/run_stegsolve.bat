@echo off
title StegSolve Launcher
cd /d "%~dp0"

where java >nul 2>nul
if %errorlevel% neq 0 (
    echo [-] Error: Java was not found in your system PATH.
    echo [*] Please verify Java JRE/JDK is installed.
    pause
    exit /b 1
)

echo [*] Launching StegSolve...
start "" java -jar "%~dp0stegsolve.jar"
