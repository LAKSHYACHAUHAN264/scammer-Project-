@echo off
echo ==========================================
echo   PhishGuard - Backend Startup Script
echo ==========================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python...
python --version
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

echo.
echo [2/3] Installing dependencies...
pip install -r requirements.txt --quiet

echo.
echo [3/3] Starting PhishGuard API server...
echo.
echo  API URL:  http://localhost:8000
echo  Docs URL: http://localhost:8000/docs
echo  Press CTRL+C to stop
echo.
uvicorn main:app --reload --port 8000 --host 0.0.0.0
pause
