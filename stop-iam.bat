@echo off
REM ===========================================================================
REM  Syncaxis IAM - stop the service started by start-iam.bat (Windows Server)
REM
REM  Stops the process recorded in iam.pid inside LOG_DIR (and its child
REM  processes). LOG_DIR is resolved exactly as in start-iam.bat: environment
REM  variable, then LOG_DIR in service\.env, then a "logs" folder next to this
REM  script.
REM  If the PID file is missing or stale, falls back to whatever is listening
REM  on the service's PORT (from service\.env, default 4100).
REM ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not defined LOG_DIR (
    if exist "%~dp0service\.env" (
        for /f "usebackq tokens=1,* delims==" %%a in ("%~dp0service\.env") do (
            if /I "%%a"=="LOG_DIR" set "LOG_DIR=%%b"
        )
    )
)
if not defined LOG_DIR set "LOG_DIR=%~dp0logs"
set "LOG_DIR=!LOG_DIR:"=!"
if "!LOG_DIR:~-1!"=="\" set "LOG_DIR=!LOG_DIR:~0,-1!"
set "PID_FILE=!LOG_DIR!\iam.pid"
set "STOPPED="

if exist "!PID_FILE!" (
    set /p PID=<"!PID_FILE!"
    tasklist /FI "PID eq !PID!" 2>nul | "%SystemRoot%\System32\find.exe" "!PID!" >nul && (
        taskkill /PID !PID! /T /F >nul 2>&1
        echo Stopped Syncaxis IAM ^(PID !PID!^).
        set STOPPED=1
    )
    del "!PID_FILE!" >nul 2>&1
)

if not defined STOPPED (
    REM Same precedence the service itself uses: environment variable, then .env, then 4100.
    if not defined PORT (
        set "PORT=4100"
        if exist "%~dp0service\.env" (
            for /f "usebackq tokens=1,* delims==" %%a in ("%~dp0service\.env") do (
                if /I "%%a"=="PORT" set "PORT=%%b"
            )
        )
    )
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr /R /C:":!PORT! .*LISTENING"') do (
        taskkill /PID %%p /T /F >nul 2>&1
        echo Stopped process %%p listening on port !PORT!.
        set STOPPED=1
    )
)

if not defined STOPPED echo Syncaxis IAM is not running.
exit /b 0
