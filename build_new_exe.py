#!/usr/bin/env python3
"""
CONFIRM EXE Builder Script
Copyright (c) 2024 TraceSeis, Inc.
All rights reserved.

This script builds a new CONFIRM.exe with all recent updates including:
- Updated copyright headers
- Corrected documentation references  
- Fixed license tier information
- Updated contact information
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_dependencies():
    """Check if PyInstaller is available"""
    try:
        import PyInstaller
        print("[INFO] PyInstaller found - version:", PyInstaller.__version__)
        return True
    except ImportError:
        print("[ERROR] PyInstaller not found!")
        print("Please install PyInstaller first:")
        print("pip install pyinstaller")
        return False

def build_executable():
    """Build the CONFIRM.exe with all updates"""
    
    # Get the script directory
    script_dir = Path(__file__).parent
    source_dir = script_dir / "01_SOURCE_CODE"
    output_dir = script_dir / "CONFIRM_Distribution_Optimized"
    
    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True)
    
    print("\n" + "="*50)
    print("    CONFIRM EXE Builder")
    print("    Copyright (c) 2024 TraceSeis, Inc.")
    print("="*50)
    print()
    
    print("[BUILD] Building CONFIRM.exe with updated files...")
    print("[INFO] This includes all recent copyright and documentation updates")
    print()
    
    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",
        "--windowed", 
        "--name=CONFIRM",
        "--add-data=protection_module.py;.",
        "--hidden-import=tkinter",
        "--hidden-import=pandas",
        "--hidden-import=numpy", 
        "--hidden-import=matplotlib",
        "--hidden-import=seaborn",
        "--hidden-import=scipy",
        "--hidden-import=requests",
        "--hidden-import=cryptography",
        "--hidden-import=psutil",
        f"--distpath={output_dir}",
        "CONFIRM_Integrated.py"
    ]
    
    # Change to source directory
    os.chdir(source_dir)
    
    try:
        # Run PyInstaller
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("\n" + "="*50)
            print("    BUILD SUCCESSFUL!")
            print("="*50)
            print()
            print("[SUCCESS] New CONFIRM.exe created with all updates:")
            print("           - Updated copyright headers")
            print("           - Corrected documentation references")
            print("           - Fixed license tier information") 
            print("           - Updated contact information")
            print()
            print(f"[LOCATION] {output_dir}\\CONFIRM.exe")
            print()
            print("[NEXT] The optimized distribution is ready for deployment!")
            return True
        else:
            print("\n" + "="*50)
            print("    BUILD FAILED!")
            print("="*50)
            print()
            print("[ERROR] Failed to build CONFIRM.exe")
            print("Error output:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"[ERROR] Build process failed: {e}")
        return False

def main():
    """Main build process"""
    if not check_dependencies():
        return False
    
    return build_executable()

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)
    
    input("\nPress Enter to continue...")
