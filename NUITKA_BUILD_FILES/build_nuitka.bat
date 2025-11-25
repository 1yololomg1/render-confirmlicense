@echo off
REM Build CONFIRM.exe using Nuitka
REM Copyright (c) 2024 TraceSeis, Inc. All rights reserved.

echo ========================================
echo CONFIRM.exe Build Script (Nuitka)
echo ========================================
echo.

REM Check if Nuitka is installed
python -m nuitka --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Nuitka is not installed!
    echo Please install it with: pip install nuitka
    pause
    exit /b 1
)

echo Nuitka found. Starting build...
echo.

REM Change to source directory
cd /d "%~dp0"

REM Clean previous build
if exist dist rmdir /s /q dist
if exist CONFIRM.build rmdir /s /q CONFIRM.build
if exist CONFIRM.dist rmdir /s /q CONFIRM.dist
if exist CONFIRM.onefile-build rmdir /s /q CONFIRM.onefile-build

echo Building CONFIRM.exe with Nuitka...
echo This may take several minutes...
echo.

REM Build with Nuitka
python -m nuitka ^
    --main=CONFIRM_Integrated.py ^
    --output-dir=dist ^
    --output-filename=CONFIRM.exe ^
    --windows-console-mode=disable ^
    --standalone ^
    --onefile ^
    --include-module=protection_module ^
    --include-module=requests ^
    --include-module=pandas ^
    --include-module=numpy ^
    --include-module=scipy ^
    --include-module=matplotlib ^
    --include-module=seaborn ^
    --include-module=openpyxl ^
    --include-module=cryptography ^
    --include-module=psutil ^
    --include-module=tkinter ^
    --include-module=tkinter.ttk ^
    --include-module=tkinter.messagebox ^
    --include-module=tkinter.simpledialog ^
    --include-module=tkinter.filedialog ^
    --include-module=matplotlib.backends.backend_tkagg ^
    --include-module=scipy.stats ^
    --include-module=scipy.ndimage ^
    --include-module=importlib.metadata ^
    --include-module=importlib_metadata ^
    --assume-yes-for-downloads ^
    --show-progress ^
    --show-memory ^
    --no-prefer-source-code ^
    --windows-company-name="TraceSeis, Inc." ^
    --windows-product-name="CONFIRM Statistical Validation Engine" ^
    --windows-file-version=1.0.0.0 ^
    --windows-product-version=1.0.0.0 ^
    --windows-file-description="CONFIRM Statistical Analysis Suite" ^
    --copyright="Copyright (C) 2024 TraceSeis, Inc. All rights reserved."

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
echo CONFIRM.exe should be in the dist folder.
echo.

REM Copy to distribution folder if it exists
if exist "..\CONFIRM_Distribution_Optimized" (
    echo Copying to CONFIRM_Distribution_Optimized...
    copy /Y dist\CONFIRM.exe "..\CONFIRM_Distribution_Optimized\CONFIRM.exe" >nul
    echo Done!
    echo.
)

pause

