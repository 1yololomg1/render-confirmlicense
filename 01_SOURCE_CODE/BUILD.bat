@echo off
title CONFIRM Build Script
cd /d "%~dp0"

echo.
echo ========================================
echo CONFIRM.exe Build Script
echo ========================================
echo.
echo Building CONFIRM.exe with cx_Freeze...
echo This window will stay open.
echo.

python setup_cxfreeze.py build

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    echo Check errors above.
) else (
    echo.
    echo ========================================
    echo Build completed successfully!
    echo ========================================
    echo.
    echo Your executable is in: build\exe.win-amd64-3.XX\
    echo.
)

echo.
echo Press any key to close this window...
pause >nul
