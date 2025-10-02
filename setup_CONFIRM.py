#!/usr/bin/env python3
"""
CONFIRM Setup Script
Helps you set up the integrated CONFIRM application with the new license system
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✓ Python version: {sys.version.split()[0]}")
    return True

def install_dependencies():
    """Install required Python packages"""
    print("\nInstalling required packages...")
    
    required_packages = [
        "pandas",
        "numpy", 
        "scipy",
        "scikit-learn",
        "matplotlib",
        "seaborn",
        "openpyxl",
        "requests"
    ]
    
    for package in required_packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install {package}: {e}")
            return False
    
    return True

def create_desktop_shortcut():
    """Create desktop shortcut for CONFIRM"""
    try:
        desktop = Path.home() / "Desktop"
        shortcut_path = desktop / "CONFIRM.lnk"
        
        # Create a simple batch file for now
        batch_content = f'''@echo off
cd /d "{Path.cwd()}"
python CONFIRM_Integrated.py
pause
'''
        
        batch_file = Path.cwd() / "run_CONFIRM.bat"
        with open(batch_file, 'w') as f:
            f.write(batch_content)
        
        print(f"✓ Created run_CONFIRM.bat in {Path.cwd()}")
        print(f"  You can double-click this file to run CONFIRM")
        
    except Exception as e:
        print(f"✗ Could not create shortcut: {e}")

def test_license_server():
    """Test connection to license server"""
    try:
        import requests
        response = requests.get("https://render-confirmlicense.onrender.com", timeout=10)
        if response.status_code == 200:
            print("✓ License server is accessible")
            return True
        else:
            print(f"✗ License server returned status: {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Cannot connect to license server: {e}")
        return False

def main():
    """Main setup function"""
    print("CONFIRM Statistical Analysis Suite - Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        return
    
    # Install dependencies
    if not install_dependencies():
        print("\nSetup failed. Please install dependencies manually.")
        return
    
    # Test license server
    print("\nTesting license server connection...")
    test_license_server()
    
    # Create desktop shortcut
    print("\nCreating desktop shortcut...")
    create_desktop_shortcut()
    
    print("\n" + "=" * 50)
    print("Setup completed!")
    print("\nTo run CONFIRM:")
    print("1. Double-click 'run_CONFIRM.bat' on your desktop")
    print("2. Or run: python CONFIRM_Integrated.py")
    print("\nThe application will prompt you for your license key when you first run it.")
    print("Make sure you have your license key ready!")

if __name__ == "__main__":
    main()
