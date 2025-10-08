@echo off
echo CONFIRM Statistical Validation Engine
echo ====================================
echo.
echo Installing CONFIRM...
echo.

REM Create installation directory
if not exist "C:\Program Files\CONFIRM" mkdir "C:\Program Files\CONFIRM"

REM Copy executable
copy "CONFIRM.exe" "C:\Program Files\CONFIRM\"

REM Create desktop shortcut
echo Creating desktop shortcut...
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\CONFIRM.lnk'); $Shortcut.TargetPath = 'C:\Program Files\CONFIRM\CONFIRM.exe'; $Shortcut.Save()"

echo.
echo Installation completed!
echo You can now run CONFIRM from the desktop shortcut or Start menu.
pause
