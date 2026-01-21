@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ============================================================
rem Script: switch_confirm_license.bat
rem Structure Overview:
rem - Configuration: path variables for main, edited, original files
rem - Safety checks: verify required files exist before copying
rem - Actions: auto-switch to edited by default, restore on request
rem - Feedback: print status and next steps
rem ============================================================

set "ROOT_DIR=%~dp0"
set "SRC_DIR=%ROOT_DIR%01_SOURCE_CODE"
set "MAIN_FILE=%SRC_DIR%\CONFIRM_Integrated.py"
set "EDITED_FILE=%SRC_DIR%\CONFIRM_Integrated_copy.py"
set "ORIGINAL_FILE=%SRC_DIR%\CONFIRM_Integrated_original.py"

rem Default behavior: use edited copy as main
rem Optional argument: /restore to revert to original backup
if /i "%~1"=="/restore" goto restore_original
goto use_edited

:use_edited
if not exist "%EDITED_FILE%" (
  echo ERROR: Edited copy not found:
  echo   "%EDITED_FILE%"
  goto end
)

if not exist "%ORIGINAL_FILE%" (
  if exist "%MAIN_FILE%" (
    copy /y "%MAIN_FILE%" "%ORIGINAL_FILE%" >nul
    echo Saved original to:
    echo   "%ORIGINAL_FILE%"
  ) else (
    echo ERROR: Main file not found:
    echo   "%MAIN_FILE%"
    goto end
  )
)

copy /y "%EDITED_FILE%" "%MAIN_FILE%" >nul
echo Main script now uses edited copy.
echo To restore the original, run:
echo   switch_confirm_license.bat /restore
goto end

:restore_original
if not exist "%ORIGINAL_FILE%" (
  echo ERROR: Original backup not found:
  echo   "%ORIGINAL_FILE%"
  echo If the original is still in git, you can recover it with:
  echo   git checkout -- "01_SOURCE_CODE/CONFIRM_Integrated.py"
  goto end
)

copy /y "%ORIGINAL_FILE%" "%MAIN_FILE%" >nul
echo Main script restored to original.
goto end

:end
echo.
echo Done.
endlocal
