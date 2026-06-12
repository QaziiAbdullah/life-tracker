@echo off
title Life Tracker

echo.
echo  =============================================
echo    LIFE TRACKER  ^|  Personal Progress System
echo  =============================================
echo.

:: Kill any existing server on port 8765
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr LISTENING ^| findstr :8765') do (
    taskkill /f /pid %%a >nul 2>&1
)

:: Start server hidden in background
start "" /min powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0server.ps1"

echo  Starting server, please wait...
timeout /t 2 /nobreak >nul

:: Open in default browser
start "" "http://localhost:8765"

echo  Life Tracker opened in your browser!
echo  URL: http://localhost:8765
echo.
echo  - Data is saved automatically in your browser.
echo  - Close this window any time (server keeps running).
echo  - Run stop.bat to shut down the server.
echo.
pause
