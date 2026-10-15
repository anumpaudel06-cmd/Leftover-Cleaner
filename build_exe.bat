@echo off
REM ==============================================================================
REM GhostPurge - Windows Production Standalone Executable Build Script
REM Packaging: PyInstaller with embedded Windows UAC Administrator Manifest
REM ==============================================================================

setlocal enabledelayedexpansion

echo [GhostPurge Build System] Initializing environment check...

REM Check for Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in system PATH.
    echo Please install Python 3.11 or higher from https://python.org
    pause
    exit /b 1
)

echo [1/5] Checking virtual environment...
if not exist "venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment at .\venv ...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

call venv\Scripts\activate.bat

echo [2/5] Installing/Upgrading build dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
)

echo [3/5] Running pre-build unit tests (Safety Engine Verification)...
python -m unittest discover -s tests -p "test_*.py"
if %errorlevel% neq 0 (
    echo [CRITICAL ERROR] Pre-build safety verification tests failed!
    echo Aborting build to prevent deployment of unsafe binary.
    pause
    exit /b 1
)

echo [4/5] Compiling GhostPurge to standalone single executable...
REM Compile with PyInstaller:
REM --onefile: Bundle all dependencies into a single portable .exe
REM --windowed: Suppress console window in production GUI mode
REM --manifest: Embed app.manifest requesting UAC elevation (requireAdministrator)
REM --name: Executable output name
REM --clean: Clean PyInstaller cache before building

pyinstaller ^
    --onefile ^
    --windowed ^
    --clean ^
    --name="GhostPurge" ^
    --manifest="app.manifest" ^
    --add-data="src;src" ^
    --hidden-import="customtkinter" ^
    --hidden-import="winreg" ^
    --hidden-import="ctypes" ^
    --hidden-import="subprocess" ^
    --collect-all="customtkinter" ^
    src\main.py

if %errorlevel% neq 0 (
    echo [ERROR] PyInstaller compilation failed. Check build logs.
    pause
    exit /b 1
)

echo [5/5] Build succeeded!
echo Output executable created at:
echo   .\dist\GhostPurge.exe
echo.
echo Verification:
echo   - Elevation requirement: embedded via manifest
echo   - High DPI awareness: PerMonitorV2 enabled
echo   - Safety engine: test suite passed (100%% assertions clean)
echo.
pause
