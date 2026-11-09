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
    echo [ERROR] Python is not installed on this PC!
    echo.
    echo For a 100%% zero-python experience, please download the standalone
    echo pre-packaged Windows application directly from GitHub Releases:
    echo.
    echo https://github.com/yudhaxibe-hue/IDS/releases/latest
    echo.
    echo Opening the download page in your browser...
    start https://github.com/yudhaxibe-hue/IDS/releases/latest
    echo.
    pause
    exit /b 1
)

rem Check/create virtual environment
if not exist "venv" (
    echo [1/3] Initializing local environment (one-time setup, please wait)...
    python -m venv venv
    call venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    echo [OK] Setup completed successfully!
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

rem Launch directly
echo [3/3] Launching Explainable Adaptive IDS...
echo The application window will open automatically in a few seconds...
echo.

if "%1"=="--browser" (
    python -m app.launcher --browser
) else (
    python -m app.launcher
)

if %errorlevel% neq 0 (
    echo.
    echo [NOTICE] Application closed or exited.
    pause
)
