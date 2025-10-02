#!/usr/bin/env python3
"""
CONFIRM EXE Builder
Creates a standalone executable for distribution
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        import PyInstaller
        print("✓ PyInstaller is installed")
        return True
    except ImportError:
        print("✗ PyInstaller not found")
        return False

def install_pyinstaller():
    """Install PyInstaller"""
    print("Installing PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✓ PyInstaller installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install PyInstaller: {e}")
        return False

def create_spec_file():
    """Create PyInstaller spec file for CONFIRM"""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['CONFIRM_Integrated.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'pandas',
        'numpy',
        'scipy',
        'sklearn',
        'matplotlib',
        'seaborn',
        'openpyxl',
        'requests',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.simpledialog',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CONFIRM',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
    version_file='version_info.txt' if os.path.exists('version_info.txt') else None,
)
'''
    
    with open('CONFIRM.spec', 'w') as f:
        f.write(spec_content)
    
    print("✓ Created CONFIRM.spec file")

def create_version_info():
    """Create version info file"""
    version_content = '''# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
# filevers and prodvers should be always a tuple with four items: (1, 2, 3, 4)
# Set not needed items to zero 0.
filevers=(1,0,0,0),
prodvers=(1,0,0,0),
# Contains a bitmask that specifies the valid bits 'flags'r
mask=0x3f,
# Contains a bitmask that specifies the Boolean attributes of the file.
flags=0x0,
# The operating system for which this file was designed.
# 0x4 - NT and there is no need to change it.
OS=0x4,
# The general type of file.
# 0x1 - the file is an application.
fileType=0x1,
# The function of the file.
# 0x0 - the function is not defined for this fileType
subtype=0x0,
# Creation date and time stamp.
date=(0, 0)
),
  kids=[
StringFileInfo(
  [
  StringTable(
    u'040904B0',
    [StringStruct(u'CompanyName', u'TraceSeis, Inc.'),
    StringStruct(u'FileDescription', u'CONFIRM Statistical Analysis Suite'),
    StringStruct(u'FileVersion', u'1.0.0.0'),
    StringStruct(u'InternalName', u'CONFIRM'),
    StringStruct(u'LegalCopyright', u'Copyright (C) 2024 TraceSeis, Inc.'),
    StringStruct(u'OriginalFilename', u'CONFIRM.exe'),
    StringStruct(u'ProductName', u'CONFIRM Professional Statistical Analysis Suite'),
    StringStruct(u'ProductVersion', u'1.0.0.0')])
  ]), 
VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
    
    with open('version_info.txt', 'w') as f:
        f.write(version_content)
    
    print("✓ Created version_info.txt file")

def create_icon():
    """Create a simple icon file (placeholder)"""
    # This would create an actual icon file
    # For now, we'll skip this and let PyInstaller use default
    print("ℹ No custom icon provided, using default")

def build_exe():
    """Build the EXE file"""
    print("\nBuilding EXE file...")
    try:
        # Run PyInstaller
        cmd = [sys.executable, "-m", "PyInstaller", "--clean", "CONFIRM.spec"]
        subprocess.check_call(cmd)
        
        print("✓ EXE built successfully!")
        
        # Check if EXE was created
        exe_path = Path("dist") / "CONFIRM.exe"
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"✓ EXE created: {exe_path}")
            print(f"✓ File size: {size_mb:.1f} MB")
            return True
        else:
            print("✗ EXE file not found in dist folder")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"✗ Build failed: {e}")
        return False

def create_distribution_package():
    """Create distribution package"""
    print("\nCreating distribution package...")
    
    try:
        # Create dist folder structure
        dist_dir = Path("CONFIRM_Distribution")
        dist_dir.mkdir(exist_ok=True)
        
        # Copy EXE
        exe_src = Path("dist") / "CONFIRM.exe"
        exe_dst = dist_dir / "CONFIRM.exe"
        if exe_src.exists():
            shutil.copy2(exe_src, exe_dst)
            print(f"✓ Copied EXE to {exe_dst}")
        
        # Create README for distribution
        readme_content = '''# CONFIRM Statistical Analysis Suite

## Installation
1. Download CONFIRM.exe
2. Double-click to run
3. Enter your license key when prompted

## License Activation
- You will need a valid license key
- The software will bind to your computer
- Contact support if you need help

## System Requirements
- Windows 10 or later
- Internet connection for license validation

## Support
Contact TraceSeis, Inc. for support and licensing questions.
'''
        
        readme_file = dist_dir / "README.txt"
        with open(readme_file, 'w') as f:
            f.write(readme_content)
        
        print(f"✓ Created distribution package in {dist_dir}")
        return True
        
    except Exception as e:
        print(f"✗ Failed to create distribution package: {e}")
        return False

def cleanup():
    """Clean up build files"""
    print("\nCleaning up build files...")
    
    cleanup_dirs = ["build", "__pycache__"]
    cleanup_files = ["CONFIRM.spec", "version_info.txt"]
    
    for dir_name in cleanup_dirs:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name)
            print(f"✓ Removed {dir_name}")
    
    for file_name in cleanup_files:
        if Path(file_name).exists():
            Path(file_name).unlink()
            print(f"✓ Removed {file_name}")

def main():
    """Main build function"""
    print("CONFIRM EXE Builder")
    print("=" * 30)
    
    # Check if CONFIRM_Integrated.py exists
    if not Path("CONFIRM_Integrated.py").exists():
        print("✗ CONFIRM_Integrated.py not found!")
        print("Please make sure you're in the correct directory.")
        return
    
    # Check/install PyInstaller
    if not check_pyinstaller():
        if not install_pyinstaller():
            print("Failed to install PyInstaller. Please install manually:")
            print("pip install pyinstaller")
            return
    
    # Create build files
    create_spec_file()
    create_version_info()
    create_icon()
    
    # Build EXE
    if not build_exe():
        print("Build failed!")
        return
    
    # Create distribution package
    if not create_distribution_package():
        print("Failed to create distribution package!")
        return
    
    # Cleanup
    cleanup()
    
    print("\n" + "=" * 50)
    print("Build completed successfully!")
    print("\nYour EXE file is ready for distribution:")
    print("📁 CONFIRM_Distribution/CONFIRM.exe")
    print("\nYou can now distribute this EXE file to your customers!")
    print("The license system will work exactly the same as the Python version.")

if __name__ == "__main__":
    main()

