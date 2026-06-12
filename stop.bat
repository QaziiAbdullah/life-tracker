@echo off
title Stopping Life Tracker...

echo Stopping Life Tracker server...

:: Kill the process listening on port 8765
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr LISTENING ^| findstr :8765') do (
    taskkill /f /pid %%a >nul 2>&1
)

echo Life Tracker server stopped.
timeout /t 2 /nobreak >nul
