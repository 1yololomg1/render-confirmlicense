@echo off
REM DOUBLE-CLICK THIS FILE TO BUILD
REM This window will stay open - guaranteed!

cd /d "%~dp0"

echo.
echo ========================================
echo CONFIRM Build Script
echo ========================================
echo.
echo Cleaning previous builds...
if exist build rmdir /s /q build >nul 2>&1
if exist dist rmdir /s /q dist >nul 2>&1
echo Cleanup complete.
echo.
echo Starting build...
echo.

python setup_cxfreeze.py build

echo.
echo ========================================
echo Done! Press any key to close.
echo ========================================
pause

