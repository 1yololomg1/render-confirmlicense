@echo off
title CONFIRM EXE Builder
color 0E

echo.
echo ===============================================
echo    CONFIRM EXE Builder
echo    Copyright (c) 2024 TraceSeis, Inc.
echo ===============================================
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if %errorLevel% neq 0 (
    echo [ERROR] PyInstaller not found!
    echo Please install PyInstaller first:
    echo pip install pyinstaller
    pause
    exit /b 1
)

echo [INFO] PyInstaller found - proceeding with build
echo.

REM Navigate to source directory
cd /d "%~dp0\..\01_SOURCE_CODE"

echo [BUILD] Building CONFIRM.exe with updated files...
echo [INFO] This includes all recent copyright and documentation updates
echo.

REM Build the executable with optimized settings
pyinstaller --onefile ^
    --windowed ^
    --name="CONFIRM" ^
    --icon=icon.ico ^
    --add-data="protection_module.py;." ^
    --hidden-import="tkinter" ^
    --hidden-import="pandas" ^
    --hidden-import="numpy" ^
    --hidden-import="matplotlib" ^
    --hidden-import="seaborn" ^
    --hidden-import="scipy" ^
    --hidden-import="requests" ^
    --hidden-import="cryptography" ^
    --hidden-import="psutil" ^
    --distpath="../CONFIRM_Distribution_Optimized" ^
    CONFIRM_Integrated.py

if %errorLevel% == 0 (
    echo.
    echo ===============================================
    echo    BUILD SUCCESSFUL!
    echo ===============================================
    echo.
    echo [SUCCESS] New CONFIRM.exe created with all updates:
    echo           - Updated copyright headers
    echo           - Corrected documentation references
    echo           - Fixed license tier information
    echo           - Updated contact information
    echo.
    echo [LOCATION] CONFIRM_Distribution_Optimized\CONFIRM.exe
    echo.
    echo [NEXT] The optimized distribution is ready for deployment!
) else (
    echo.
    echo ===============================================
    echo    BUILD FAILED!
    echo ===============================================
    echo.
    echo [ERROR] Failed to build CONFIRM.exe
    echo Please check the error messages above
)

echo.
pause
