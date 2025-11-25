@echo off
REM Fast CONFIRM Build Script using PyInstaller
REM Should complete in 5-10 minutes instead of 4 hours

echo ========================================
echo CONFIRM Fast Build with PyInstaller
echo ========================================
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller
        pause
        exit /b 1
    )
)

echo.
echo Building CONFIRM executable...
echo This should take 5-10 minutes (much faster than Nuitka!)
echo.

REM Build with PyInstaller
python -m PyInstaller --name=CONFIRM_Integrated --onefile --windowed --icon=NONE --add-data="protection_module.py;." --hidden-import=numpy --hidden-import=pandas --hidden-import=matplotlib --hidden-import=seaborn --hidden-import=scipy --hidden-import=openpyxl --hidden-import=requests --hidden-import=cryptography --hidden-import=tkinter --collect-all=matplotlib --collect-all=seaborn --clean CONFIRM_Integrated.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    echo Check the error messages above.
    pause
    exit /b 1
)

echo.
echo ========================================
echo BUILD COMPLETE!
echo ========================================
echo.
echo Executable location:
echo   dist\CONFIRM_Integrated.exe
echo.
echo File size will be larger than Nuitka (~150-200 MB)
echo but build time is MUCH faster (5-10 min vs 4 hours)
echo.

REM Test if file was created
if exist "dist\CONFIRM_Integrated.exe" (
    echo SUCCESS: Executable created successfully!
    echo.
    echo You can now:
    echo   1. Test: cd dist ^&^& CONFIRM_Integrated.exe
    echo   2. Send to beta tester: dist\CONFIRM_Integrated.exe
) else (
    echo WARNING: Executable not found in expected location
    echo Check dist\ folder manually
)

echo.
pause
