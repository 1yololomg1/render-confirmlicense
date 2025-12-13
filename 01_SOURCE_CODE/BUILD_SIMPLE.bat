@echo off
REM Ultra-simple build script that definitely keeps window open
REM Copyright (c) 2024 TraceSeis, Inc. All rights reserved.

cd /d "%~dp0"
title CONFIRM Build - Window will stay open

echo.
echo ========================================
echo CONFIRM.exe Build Script
echo ========================================
echo.
echo Running build script...
echo.

call build_cxfreeze.bat

echo.
echo ========================================
echo DONE - Press any key to close window
echo ========================================
pause

