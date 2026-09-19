@echo off
REM ===========================================================================
REM  Syncaxis IAM - start the service (Windows Server)
REM
REM  Runs the compiled build in the background, logs to iam.log / iam.err.log,
REM  and records the process id in iam.pid (both in LOG_DIR) so stop-iam.bat
REM  can stop it. LOG_DIR comes from the LOG_DIR environment variable, else
REM  from LOG_DIR in service\.env, else defaults to a "logs" folder next to
REM  this script. In production set it to a path OUTSIDE the app folder,
REM  e.g. LOG_DIR=D:\Logs\syncaxis-iam (created automatically if missing).
REM  First run (or after pulling new code) it installs dependencies and
REM  builds automatically; pass "rebuild" to force a rebuild:
REM      start-iam.bat rebuild
REM
REM  Requires: Node.js on PATH, and service\.env filled in (see .env.example).
REM ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "SERVICE_DIR=%~dp0service"
set "ENTRY=%SERVICE_DIR%\dist\src\server.js"

where node >nul 2>&1 || (echo ERROR: Node.js was not found on PATH. & exit /b 1)
if not exist "%SERVICE_DIR%\.env" (echo ERROR: %SERVICE_DIR%\.env is missing - copy .env.example and fill it in. & exit /b 1)

if not defined LOG_DIR (
    for /f "usebackq tokens=1,* delims==" %%a in ("%SERVICE_DIR%\.env") do (
        if /I "%%a"=="LOG_DIR" set "LOG_DIR=%%b"
    )
)
if not defined LOG_DIR set "LOG_DIR=%~dp0logs"
set "LOG_DIR=!LOG_DIR:"=!"
if "!LOG_DIR:~-1!"=="\" set "LOG_DIR=!LOG_DIR:~0,-1!"
set "PID_FILE=!LOG_DIR!\iam.pid"

if not exist "!LOG_DIR!" mkdir "!LOG_DIR!" 2>nul
if not exist "!LOG_DIR!" (echo ERROR: could not create log folder "!LOG_DIR!" - check LOG_DIR in service\.env. & exit /b 1)

REM Refuse to start a second copy.
if exist "!PID_FILE!" (
    set /p OLD_PID=<"!PID_FILE!"
    tasklist /FI "PID eq !OLD_PID!" 2>nul | "%SystemRoot%\System32\find.exe" "!OLD_PID!" >nul && (
        echo Syncaxis IAM is already running ^(PID !OLD_PID!^). Run stop-iam.bat first.
        exit /b 1
    )
    del "!PID_FILE!" >nul 2>&1
)

if not exist "%SERVICE_DIR%\node_modules" set NEEDS_BUILD=1
if not exist "%ENTRY%" set NEEDS_BUILD=1
if /I "%~1"=="rebuild" set NEEDS_BUILD=1

if defined NEEDS_BUILD (
    echo Installing dependencies and building...
    pushd "%SERVICE_DIR%"
    call npm install || (popd & echo ERROR: npm install failed. & exit /b 1)
    call npm run build || (popd & echo ERROR: build failed. & exit /b 1)
    popd
)

REM Start detached; Start-Process gives us the real node.exe PID to record.
powershell -NoProfile -Command ^
  "$p = Start-Process -FilePath 'node' -ArgumentList 'dist\src\server.js' -WorkingDirectory '%SERVICE_DIR%' -RedirectStandardOutput '!LOG_DIR!\iam.log' -RedirectStandardError '!LOG_DIR!\iam.err.log' -WindowStyle Hidden -PassThru; Set-Content -Path '!PID_FILE!' -Value $p.Id -Encoding ascii"

ping -n 5 127.0.0.1 >nul
set /p NEW_PID=<"!PID_FILE!"
tasklist /FI "PID eq %NEW_PID%" 2>nul | "%SystemRoot%\System32\find.exe" "%NEW_PID%" >nul && (
    echo Syncaxis IAM started ^(PID %NEW_PID%^). Logs: !LOG_DIR!\iam.log
    exit /b 0
)
echo ERROR: the service exited right after starting. Last errors:
type "!LOG_DIR!\iam.err.log"
del "!PID_FILE!" >nul 2>&1
exit /b 1
