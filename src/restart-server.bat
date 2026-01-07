@echo off
REM Restart script for XeoKey server
REM This script pulls updates and restarts the server
REM Usage: Called automatically by the server, or run manually from src/ directory

echo [%date% %time%] Restarting XeoKey server...

REM Change to the script directory (where server.ts is)
cd /d "%~dp0"

REM Pull latest changes
echo Pulling latest changes from GitHub...
git pull origin master
if %errorlevel% neq 0 (
    echo ERROR: Git pull failed!
    pause
    exit /b %errorlevel%
)

echo Git pull successful!

REM Wait a moment for any file system sync
echo Waiting for file system sync...
timeout /t 2 /nobreak >nul

REM Start the new server instance in a new window (detached)
echo Starting new server instance...
start "" /B "XeoKey Server" cmd /c "bun start"

REM Wait a moment for the new server to start
echo Waiting for new server to initialize...
timeout /t 3 /nobreak >nul

REM Exit this process (the old server process will end)
echo Old server process exiting...
exit /b 0

