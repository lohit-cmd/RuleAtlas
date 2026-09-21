@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto run
where py >nul 2>nul
if errorlevel 1 (
  python -m venv .venv
) else (
  py -3 -m venv .venv
)
if errorlevel 1 goto failed
:run
.venv\Scripts\python.exe -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11 or newer is required'"
if errorlevel 1 goto failed
.venv\Scripts\python.exe -c "import yaml" >nul 2>nul
if errorlevel 1 .venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed
if not exist "data\ruleatlas.db" .venv\Scripts\python.exe -m ruleatlas demo
echo.
echo Open http://127.0.0.1:8765 in your browser once the server is ready.
echo Keep this window open. Press Ctrl+C to stop.
.venv\Scripts\python.exe -m ruleatlas serve
if errorlevel 1 goto failed
exit /b 0
:failed
echo.
echo Startup failed. Install Python 3.11+ and check the error above.
echo Default HTTPS archive sync does not require Git.
pause
exit /b 1
