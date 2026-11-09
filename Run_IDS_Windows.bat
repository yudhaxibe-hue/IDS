@echo off
rem ==============================================================================
rem Explainable Adaptive IDS - 1-Click Windows Launcher
rem Double-click this file in Windows File Explorer to launch the application!
rem ==============================================================================

title Explainable Adaptive IDS - Academic Research Prototype
cd /d "%~dp0"
cls

echo ==================================================================
echo   Explainable Adaptive Intrusion Detection System (IDS)
echo   Academic Master of Engineering Research Prototype
echo ==================================================================
echo.

rem Check for Python installation
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found on your system!
    echo.
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    echo IMPORTANT: Make sure to check "Add Python to PATH" during setup.
    echo.
    pause
    exit /b 1
)

rem Check/create virtual environment
if not exist "venv" (
    echo [1/3] Initializing local virtual environment (one-time setup, please wait)...
    python -m venv venv
    call venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    echo [OK] Dependencies installed successfully!
    echo.
) else (
    call venv\Scripts\activate.bat
)

rem Check baseline model
if not exist "models\trained\baseline_model.joblib" (
    echo [2/3] Verifying baseline machine learning model...
    python -m models.training.trainer
    echo [OK] Baseline Random Forest model ready!
    echo.
)

rem Launch mode choice
echo [3/3] Ready to start!
echo   [1] Native Desktop Window (Default)
echo   [2] Default Web Browser (Edge / Chrome)
echo.

set /p choice="Enter choice (1 or 2, default=1): "
if "%choice%"=="2" (
    echo Launching in default web browser...
    python -m app.launcher --browser
) else (
    echo Launching Native Desktop Window...
    python -m app.launcher
)

if %errorlevel% neq 0 (
    echo.
    echo [NOTICE] Application closed or exited with code %errorlevel%.
    pause
)
