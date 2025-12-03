@echo off
REM DOUBLE-CLICK THIS FILE TO BUILD
REM This window will stay open - guaranteed!

cd /d "%~dp0"

echo.
echo ========================================
echo CONFIRM Build Script
echo ========================================
echo.
echo Starting...
echo.

python setup_cxfreeze.py build

echo.
echo ========================================
echo Done! Press any key to close.
echo ========================================
pause

