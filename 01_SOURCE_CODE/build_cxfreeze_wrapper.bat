@echo off
REM Wrapper to keep window open when running build_cxfreeze.bat
REM This ensures the window stays open even if there are errors

cd /d "%~dp0"
call build_cxfreeze.bat
set EXIT_CODE=%errorlevel%

echo.
echo ========================================
echo Script finished with exit code: %EXIT_CODE%
echo ========================================
echo.
echo Press any key to close this window...
pause >nul


