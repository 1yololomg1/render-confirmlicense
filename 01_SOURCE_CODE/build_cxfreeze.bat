@echo off
REM ============================================================================
REM CONFIRM.exe Build Script - Professional Build Configuration
REM ============================================================================
REM Copyright (c) 2024 TraceSeis, Inc. All rights reserved.
REM
REM This script builds CONFIRM.exe using cx_Freeze, which handles scipy/numpy
REM dependencies much better than alternative packagers.
REM
REM Build Output Structure:
REM   - Packages are bundled in lib\ folder
REM   - numpy.libs\ contains numpy DLLs
REM   - scipy.libs\ contains scipy DLLs  
REM   - matplotlib.libs\ contains matplotlib DLLs
REM   - protection_module.py is included in lib\
REM   - All standard library modules are in lib\
REM ============================================================================

setlocal enabledelayedexpansion
set "BUILD_VERSION=1.0.0"
set "BUILD_DATE=%date% %time%"

echo.
echo ============================================================================
echo  CONFIRM Statistical Validation Engine - Build Script
echo  Version: %BUILD_VERSION%
echo  Build Date: %BUILD_DATE%
echo ============================================================================
echo.
echo  This script will build a standalone executable distribution.
echo  Building with cx_Freeze for optimal NumPy/SciPy compatibility.
echo.

REM Change to script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to change to script directory
    pause
    exit /b 1
)

echo Current directory: %CD%
echo.

REM Check for Python with version display
echo [1/6] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Python is not found in your PATH!
    echo.
    echo Please ensure:
    echo   1. Python 3.9 or higher is installed
    echo   2. Python is added to your system PATH
    echo   3. You can run "python --version" from command line
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo   %PYTHON_VERSION% - OK
echo.

REM Check for cx_Freeze
echo [2/6] Checking build dependencies...
python -c "import cx_Freeze" >nul 2>&1
if errorlevel 1 (
    echo   cx_Freeze not found. Installing required package...
    python -m pip install --quiet --upgrade cx_Freeze
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install cx_Freeze!
        echo.
        echo Please install manually with: pip install cx_Freeze
        echo.
        pause
        exit /b 1
    )
    echo   cx_Freeze installed successfully
) else (
    echo   cx_Freeze - OK
)
echo.

REM Kill any running CONFIRM.exe processes
echo [3/6] Preparing build environment...
echo   Checking for running CONFIRM.exe processes...
tasklist /FI "IMAGENAME eq CONFIRM.exe" 2>NUL | find /I /N "CONFIRM.exe">NUL
if errorlevel 1 (
    echo   No running instances found - OK
) else (
    echo   Terminating running instances...
    taskkill /F /IM CONFIRM.exe >nul 2>&1
    taskkill /F /IM CONFIRM_Integrated.exe >nul 2>&1
    timeout /t 2 /nobreak >nul
    echo   Processes terminated - OK
)
echo.

REM Cleanup previous build
echo [4/6] Cleaning previous build artifacts...
if exist build (
    echo   Removing previous build directory...
    rmdir /s /q build >nul 2>&1
    if exist build (
        echo   WARNING: Build directory is locked. Attempting rename...
        set RENAME_INDEX=1
        :rename_loop
        if exist build_old_!RENAME_INDEX! (
            set /a RENAME_INDEX+=1
            goto rename_loop
        )
        ren build build_old_!RENAME_INDEX! >nul 2>&1
        if errorlevel 1 (
            echo.
            echo [ERROR] Cannot clean or rename build directory!
            echo.
            echo Please ensure:
            echo   1. All programs using build folder are closed
            echo   2. File Explorer is not viewing the build folder
            echo   3. Antivirus is not scanning the folder
            echo.
            pause
            exit /b 1
        )
        echo   Previous build saved as: build_old_!RENAME_INDEX!
    ) else (
        echo   Build directory cleaned - OK
    )
) else (
    echo   No previous build found - OK
)

if exist dist (
    echo   Removing dist directory...
    rmdir /s /q dist >nul 2>&1
    echo   Dist directory cleaned - OK
)

echo   Cleanup complete
echo.

REM Run the build
echo [5/6] Building executable...
echo   This process may take 2-5 minutes depending on your system.
echo   Please wait while dependencies are packaged...
echo.
echo   Command: python setup_cxfreeze.py build
echo.

python setup_cxfreeze.py build
set BUILD_RESULT=%errorlevel%

if %BUILD_RESULT% neq 0 (
    echo.
    echo ============================================================================
    echo  BUILD FAILED
    echo ============================================================================
    echo.
    echo  Exit code: %BUILD_RESULT%
    echo.
    echo  Please review the error messages above. Common issues:
    echo    - Missing Python packages (run: pip install -r requirements.txt)
    echo    - Insufficient disk space
    echo    - Antivirus blocking file operations
    echo    - Permission issues
    echo.
    echo  For assistance, contact: info@traceseis.com
    echo.
    pause
    exit /b 1
)

echo.
echo   Build process completed successfully!
echo.

REM Verify build output
echo [6/6] Verifying build output...
echo.

set EXE_FOUND=0
for /d %%i in (build\exe.*) do (
    set OUTPUT_DIR=%%i
    set EXE_FOUND=1
    
    echo ============================================================================
    echo  BUILD SUCCESSFUL
    echo ============================================================================
    echo.
    echo  Output Directory: %%i
    echo  Build Version: %BUILD_VERSION%
    echo.
    echo  IMPORTANT: The CONFIRM.exe file (~23KB) is a loader executable.
    echo            All libraries are in the lib\ folder. This is expected.
    echo.
    echo  Package Structure:
    echo    - lib\           : All Python packages and dependencies
    echo    - lib\numpy.libs\: NumPy DLL files
    echo    - lib\scipy.libs\: SciPy DLL files
    echo    - lib\matplotlib.libs\: Matplotlib DLL files
    echo    - protection_module.py: Security module
    echo.
    echo ============================================================================
    echo  Build Verification
    echo ============================================================================
    echo.
    
    REM Verify critical files
    set "VERIFY_ERROR=0"
    
    if exist "%%i\CONFIRM.exe" (
        echo   [OK] CONFIRM.exe
        for %%f in ("%%i\CONFIRM.exe") do set EXE_SIZE=%%~zf
        set /a EXE_SIZE_KB=!EXE_SIZE!/1024
        echo       Size: !EXE_SIZE_KB! KB (loader executable)
    ) else (
        echo   [ERROR] CONFIRM.exe NOT FOUND!
        set VERIFY_ERROR=1
    )
    
    if exist "%%i\lib" (
        echo   [OK] lib\ directory
    ) else (
        echo   [ERROR] lib\ directory NOT FOUND!
        set VERIFY_ERROR=1
    )
    
    if exist "%%i\lib\numpy" (
        echo   [OK] NumPy library
    ) else (
        echo   [WARNING] NumPy library not detected
    )
    
    if exist "%%i\lib\scipy" (
        echo   [OK] SciPy library
    ) else (
        echo   [WARNING] SciPy library not detected
    )
    
    if exist "%%i\lib\matplotlib" (
        echo   [OK] Matplotlib library
    ) else (
        echo   [WARNING] Matplotlib library not detected
    )
    
    if exist "%%i\lib\pandas" (
        echo   [OK] Pandas library
    ) else (
        echo   [WARNING] Pandas library not detected
    )
    
    if exist "%%i\lib\protection_module.py" (
        echo   [OK] Protection module
    ) else (
        echo   [WARNING] Protection module not detected
    )
    
    if exist "%%i\lib\numpy.libs" (
        echo   [OK] NumPy DLL files (numpy.libs\)
    ) else (
        echo   [WARNING] NumPy DLLs not detected
    )
    
    if exist "%%i\lib\scipy.libs" (
        echo   [OK] SciPy DLL files (scipy.libs\)
    ) else (
        echo   [WARNING] SciPy DLLs not detected
    )
    
    if exist "%%i\lib\matplotlib.libs" (
        echo   [OK] Matplotlib DLL files (matplotlib.libs\)
    ) else (
        echo   [WARNING] Matplotlib DLLs not detected
    )
    
    echo.
    if !VERIFY_ERROR! equ 1 (
        echo ============================================================================
        echo  BUILD VERIFICATION FAILED
        echo ============================================================================
        echo.
        echo  Critical files are missing. The build may be incomplete.
        echo  Please review the errors above and rebuild.
        echo.
    ) else (
        echo ============================================================================
        echo  Distribution Instructions
        echo ============================================================================
        echo.
        echo  To distribute CONFIRM:
        echo    1. Copy the ENTIRE folder: %%i
        echo    2. Include all files and subfolders (do not modify structure)
        echo    3. Users run CONFIRM.exe from within this folder
        echo.
        echo  Expected Size: 200-500 MB (normal for scientific Python applications)
        echo  Distribution Format: Folder-based (cx_Freeze standard)
        echo.
        echo  Note: The small .exe file is a loader - all code is in lib\
        echo.
    )
    
    echo ============================================================================
)

REM Fallback search if auto-detection failed
if "!EXE_FOUND!"=="0" (
    echo.
    echo ============================================================================
    echo  Build Output Detection Issue
    echo ============================================================================
    echo.
    echo  Searching for output directory...
    echo.
    
    if exist "build\exe.win-amd64-3.11\CONFIRM.exe" (
        echo   [FOUND] build\exe.win-amd64-3.11\
        set OUTPUT_DIR=build\exe.win-amd64-3.11
    ) else if exist "build\exe.win-amd64-3.10\CONFIRM.exe" (
        echo   [FOUND] build\exe.win-amd64-3.10\
        set OUTPUT_DIR=build\exe.win-amd64-3.10
    ) else if exist "build\exe.win-amd64-3.9\CONFIRM.exe" (
        echo   [FOUND] build\exe.win-amd64-3.9\
        set OUTPUT_DIR=build\exe.win-amd64-3.9
    ) else (
        echo   [ERROR] CONFIRM.exe not found in build directory!
        echo.
        echo   Troubleshooting steps:
        echo     1. Verify build completed without errors
        echo     2. Check build\exe.win-amd64-* directories manually
        echo     3. Review error messages above
        echo     4. Ensure sufficient disk space is available
        echo.
    )
)

echo.
echo ============================================================================
echo  Build Script Complete
echo ============================================================================
echo.
echo  For support or questions: info@traceseis.com
echo.
echo  Press any key to close...
pause >nul
