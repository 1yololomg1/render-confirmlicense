@echo off
title CONFIRM Installation
color 0A

echo.
echo ===============================================
echo    CONFIRM Statistical Analysis Suite
echo    Copyright (c) 2024 TraceSeis, Inc.
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [ADMIN] Running with administrator privileges
) else (
    echo [WARNING] Not running as administrator
    echo Some features may require admin rights
)

echo.
echo [SETUP] Creating installation directory...
if not exist "%USERPROFILE%\CONFIRM" mkdir "%USERPROFILE%\CONFIRM"
if not exist "%USERPROFILE%\CONFIRM\Results" mkdir "%USERPROFILE%\CONFIRM\Results"

echo [SETUP] Copying application files...
copy "CONFIRM.exe" "%USERPROFILE%\CONFIRM\" >nul
copy "CONFIRM_Quick_Start.pdf" "%USERPROFILE%\CONFIRM\" >nul 2>&1

echo [SETUP] Creating desktop shortcut...
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\CONFIRM.lnk'); $Shortcut.TargetPath = '%USERPROFILE%\CONFIRM\CONFIRM.exe'; $Shortcut.Save()" >nul 2>&1

echo [SETUP] Creating start menu shortcut...
if not exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\CONFIRM" mkdir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\CONFIRM"
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\CONFIRM\CONFIRM.lnk'); $Shortcut.TargetPath = '%USERPROFILE%\CONFIRM\CONFIRM.exe'; $Shortcut.Save()" >nul 2>&1

echo.
echo ===============================================
echo    INSTALLATION COMPLETE!
echo ===============================================
echo.
echo [SUCCESS] CONFIRM has been installed to:
echo           %USERPROFILE%\CONFIRM\
echo.
echo [SHORTCUTS] Desktop and Start Menu shortcuts created
echo [RESULTS]  Results folder: %USERPROFILE%\CONFIRM\Results\
echo.
echo [NEXT STEPS]
echo 1. Double-click the desktop shortcut to launch CONFIRM
echo 2. Enter your license key when prompted
echo 3. Start analyzing your Excel files!
echo.
echo [SUPPORT] info@traceseis.com
echo.

pause
echo.
echo [LAUNCH] Starting CONFIRM...
start "" "%USERPROFILE%\CONFIRM\CONFIRM.exe"
exit
