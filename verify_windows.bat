@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto test
where py >nul 2>nul
if errorlevel 1 (
  python -m venv .venv
) else (
  py -3 -m venv .venv
)
if errorlevel 1 goto failed
:test
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed
.venv\Scripts\python.exe tests\self_check.py
if errorlevel 1 goto failed
echo.
echo Offline tests passed. Report: test-results\self-check.json
echo Your existing index and source catalog were not modified.
pause
exit /b 0
:failed
echo.
echo Verification failed. Check the error above and test-results\self-check.json if created.
pause
exit /b 1
