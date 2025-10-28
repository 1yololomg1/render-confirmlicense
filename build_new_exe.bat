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
cd /d "%~dp001_SOURCE_CODE"

echo [BUILD] Building CONFIRM.exe with updated files...
echo [INFO] This includes all recent copyright and documentation updates
echo.

REM Clean any previous build artifacts first
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist __pycache__ rmdir /s /q __pycache__

REM Build the executable using the spec file (contains all fixes)
pyinstaller --clean --noconfirm ^
    --distpath="../CONFIRM_Distribution_Optimized" ^
    CONFIRM.spec

if %errorLevel% == 0 (
    REM Clean up build artifacts (keep only the final exe)
    if exist build rmdir /s /q build
    if exist dist rmdir /s /q dist
    
    echo.
    echo ===============================================
    echo    BUILD SUCCESSFUL!
    echo ===============================================
    echo.
    echo [SUCCESS] New CONFIRM.exe created with all updates:
    echo           - Fixed dependency checking for frozen exe
    echo           - Fixed threading/mainloop issues
    echo           - All required packages bundled
    echo           - Console enabled for debugging
    echo.
    echo [LOCATION] CONFIRM_Distribution_Optimized\CONFIRM.exe
    echo.
    echo [NOTE] Build artifacts cleaned up
    echo [NOTE] Only final exe remains in CONFIRM_Distribution_Optimized\
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
