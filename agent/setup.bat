@echo off
echo ============================================================
echo   NIDS Agent Setup — Windows
echo   University of Botswana - Final Year Project
echo ============================================================
echo.

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Download Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [1/2] Installing Python dependencies...
pip install scapy scikit-learn pandas numpy requests joblib
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo [2/2] Verifying model files...
if not exist "model\best_model.pkl" (
    echo [ERROR] model\best_model.pkl not found!
    echo Make sure the model\ folder is in the same directory as this script.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   Setup complete!
echo.
echo   To start the agent, run:
echo     run-agent.bat
echo.
echo   Or with a custom name:
echo     python nids_agent.py --agent-name MY-PC-NAME
echo ============================================================
pause
