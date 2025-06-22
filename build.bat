@echo off
setlocal enabledelayedexpansion

:: Set environment variables for faster compilation
set NUITKA_CACHE_DIR=build_cache
set NUITKA_COMPILE_JOBS=%NUMBER_OF_PROCESSORS%
set PYTHONHASHSEED=0
set PYTHONOPTIMIZE=2

:: Create cache directory
if not exist "%NUITKA_CACHE_DIR%" mkdir "%NUITKA_CACHE_DIR%"

:: System optimizations for faster compilation
echo Optimizing system for faster compilation...
powershell -Command "Get-Process python -ErrorAction SilentlyContinue | Set-ProcessPriority -Priority High" 2>nul
powershell -Command "Get-Process nuitka -ErrorAction SilentlyContinue | Set-ProcessPriority -Priority High" 2>nul

:: Clear temp files to free up space
echo Clearing temporary files...
del /q /f %TEMP%\*.tmp >nul 2>&1
del /q /f %TEMP%\*.log >nul 2>&1

echo Starting optimized build with %NUITKA_COMPILE_JOBS% parallel jobs...

nuitka ^
  --onefile ^
  --standalone ^
  --enable-plugin=pyqt5 ^
  --remove-output ^
  --windows-console-mode=disable ^
  --windows-uac-admin ^
  --output-dir=releases ^
  --follow-imports ^
  --windows-icon-from-ico=media/icon.ico ^
  --include-data-dir=configs=configs ^
  --include-data-dir=media=media ^
  --include-data-dir=scripts=scripts ^
  --include-package=screens ^
  --jobs=%NUITKA_COMPILE_JOBS% ^
  --lto=yes ^
  --assume-yes-for-downloads ^
  --prefer-source-code ^
  --no-pyi-file ^
  --enable-plugin=numpy ^
  --disable-ccache ^
  basilisk.py

if %ERRORLEVEL% EQU 0 (
    echo Build completed successfully!
    echo Executable location: releases\basilisk.exe
    
    :: Show file size
    for %%A in ("releases\basilisk.exe") do (
        echo File size: %%~zA bytes
    )
) else (
    echo Build failed with error code %ERRORLEVEL%
)

pause
