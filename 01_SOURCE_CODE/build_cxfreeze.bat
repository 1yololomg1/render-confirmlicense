@echo off
REM Build CONFIRM.exe using cx_Freeze
REM Copyright (c) 2024 TraceSeis, Inc. All rights reserved.
REM
REM cx_Freeze handles scipy/numpy MUCH better than Nuitka!

REM Keep window open - prevent immediate closure on errors
setlocal enabledelayedexpansion

echo ========================================
echo CONFIRM.exe Build Script (cx_Freeze)
echo ========================================
echo.
echo TIP: If you get "Access is denied" errors, run cleanup_build_folder.bat first
echo.

REM Change to source directory
cd /d "%~dp0"
if errorlevel 1 (
    echo ERROR: Failed to change to script directory
    echo Current directory: %CD%
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ========================================
    echo ERROR: Python is not found!
    echo ========================================
    echo.
    echo Python is not in your PATH or not installed.
    echo Please install Python or add it to your PATH.
    echo.
    echo You can check by running: python --version
    echo.
    pause
    exit /b 1
)

echo Python found.
echo.

REM Check if cx_Freeze is installed
python -c "import cx_Freeze" >nul 2>&1
if errorlevel 1 (
    echo cx_Freeze not found. Installing...
    python -m pip install cx_Freeze
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install cx_Freeze
        echo Please install manually with: pip install cx_Freeze
        pause
        exit /b 1
    )
    echo cx_Freeze installed successfully.
    echo.
)

echo cx_Freeze found. Starting build...
echo.

REM Kill any running CONFIRM.exe processes first
echo Checking for running CONFIRM.exe processes...
taskkill /F /IM CONFIRM.exe >nul 2>&1
taskkill /F /IM CONFIRM_Integrated.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo.
echo Cleaning previous build...
echo.

REM Aggressive cleanup with retry loop
set CLEANUP_RETRIES=0
:cleanup_loop
set CLEANUP_NEEDED=0

REM Try to clean build directory and all subdirectories
if exist build (
    set CLEANUP_NEEDED=1
    set /a CLEANUP_RETRIES+=1
    echo Attempting to remove build directory (attempt !CLEANUP_RETRIES!)...
    
    REM First, try to remove the exe.win-amd64-3.XX subdirectory specifically
    for /d %%d in (build\exe.*) do (
        echo   Removing %%d...
        rmdir /s /q "%%d" >nul 2>&1
        if exist "%%d" (
            echo   Waiting for files to release...
            timeout /t 2 /nobreak >nul
        )
    )
    
    REM Now try to remove the entire build directory
    rmdir /s /q build >nul 2>&1
    if exist build (
        if !CLEANUP_RETRIES! GEQ 5 (
            echo Build directory still locked after 5 attempts. Trying to rename...
            goto :rename_build_dir
        )
        echo Waiting for file handles to release (3 seconds)...
        timeout /t 3 /nobreak >nul
        goto :cleanup_loop
    ) else (
        echo Build directory removed successfully.
    )
)

REM Try to clean dist directory
if exist dist (
    set CLEANUP_NEEDED=1
    echo Attempting to remove dist directory...
    rmdir /s /q dist >nul 2>&1
    if exist dist (
        echo Waiting for file handles to release...
        timeout /t 2 /nobreak >nul
        goto :cleanup_loop
    ) else (
        echo Dist directory removed successfully.
    )
)

REM If cleanup was needed, wait a bit more for all handles to release
if !CLEANUP_NEEDED!==1 (
    echo Waiting for all file handles to release...
    timeout /t 3 /nobreak >nul
)

REM Skip rename if we successfully cleaned
goto :cleanup_done

:rename_build_dir
REM Final attempt - rename the locked directory
echo Attempting to rename locked build directory...
set RENAME_COUNT=1
:find_rename
if exist build_old_!RENAME_COUNT! (
    set /a RENAME_COUNT+=1
    goto :find_rename
)
ren build build_old_!RENAME_COUNT! >nul 2>&1
if errorlevel 1 (
    echo.
    echo ========================================
    echo ERROR: Cannot clean or rename build directory!
    echo ========================================
    echo.
    echo Files are locked by another process.
    echo.
    echo Please try these steps:
    echo   1. Close ALL File Explorer windows
    echo   2. Close any programs that might be using files from build folder
    echo   3. Check Task Manager for any CONFIRM.exe processes
    echo   4. Temporarily disable antivirus real-time scanning
    echo   5. Close any IDEs or text editors with the folder open
    echo   6. Restart your computer
    echo   7. Run this script again
    echo.
    echo If the problem persists, manually delete or rename the 'build' folder
    echo from File Explorer, then run this script again.
    echo.
    pause
    exit /b 1
    ) else (
        echo Build directory renamed to build_old_!RENAME_COUNT! - you can delete it later
    )

:cleanup_done

echo.
echo Cleanup complete. Starting build...
echo.

REM Final safety check - verify build directory doesn't exist or is empty
if exist build (
    REM Check if it's empty or only contains empty subdirectories
    dir /b build >nul 2>&1
    if errorlevel 1 (
        REM Directory is empty or inaccessible - try one more cleanup
        echo Final cleanup attempt...
        timeout /t 2 /nobreak >nul
        rmdir /s /q build >nul 2>&1
    )
)
echo.

echo Building CONFIRM.exe...
echo This will take a few minutes...
echo.

python setup_cxfreeze.py build

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    echo Check the error messages above for details.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.

REM Find and display the output folder
for /d %%i in (build\exe.*) do (
    set OUTPUT_DIR=%%i
    echo Output folder: %%i
    echo.
    echo ========================================
    echo BUILD SUMMARY
    echo ========================================
    echo.
    echo NOTE: The CONFIRM.exe file is small (~23KB) because cx_Freeze creates
    echo a loader executable. All actual libraries are in the lib\ folder.
    echo.
    echo This is NORMAL and EXPECTED behavior for cx_Freeze.
    echo.
    echo To distribute your application, distribute the ENTIRE folder:
    echo   %%i
    echo.
    echo ========================================
    echo Checking build contents...
    echo ========================================
    echo.
    
    REM Check for critical files
    if exist "%%i\CONFIRM.exe" (
        echo [OK] CONFIRM.exe found
        for %%f in ("%%i\CONFIRM.exe") do echo      Size: %%~zf bytes
    ) else (
        echo [ERROR] CONFIRM.exe NOT FOUND!
    )
    
    echo.
    if exist "%%i\lib" (
        echo [OK] lib folder found
        dir /b "%%i\lib" | find /c /v "" >nul 2>&1
        for /f %%c in ('dir /b "%%i\lib" 2^>nul ^| find /c /v ""') do echo      Contains: %%c items
    ) else (
        echo [ERROR] lib folder NOT FOUND!
    )
    
    echo.
    if exist "%%i\lib\numpy" (
        echo [OK] NumPy library included
    ) else (
        echo [WARNING] NumPy library may be missing
    )
    
    if exist "%%i\lib\scipy" (
        echo [OK] SciPy library included
    ) else (
        echo [WARNING] SciPy library may be missing
    )
    
    if exist "%%i\lib\matplotlib" (
        echo [OK] Matplotlib library included
    ) else (
        echo [WARNING] Matplotlib library may be missing
    )
    
    if exist "%%i\lib\pandas" (
        echo [OK] Pandas library included
    ) else (
        echo [WARNING] Pandas library may be missing
    )
    
    if exist "%%i\lib\protection_module.py" (
        echo [OK] Protection module included
    ) else (
        echo [WARNING] Protection module may be missing
    )
    
    echo.
    echo ========================================
    echo DISTRIBUTION INSTRUCTIONS
    echo ========================================
    echo.
    echo To distribute your application:
    echo   1. Copy the entire folder: %%i
    echo   2. Include all files and subfolders
    echo   3. Users should run CONFIRM.exe from this folder
    echo.
    echo The total size should be several hundred MB (this is normal).
    echo The small .exe file is just a loader - all code is in lib\.
    echo.
    echo ========================================
)

echo.
echo Script completed.
echo.
echo Press any key to close this window...
pause >nul
