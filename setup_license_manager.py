#!/usr/bin/env python3
"""
License Manager Setup Script
Helps configure the license management system
"""

import os
import sys
from pathlib import Path

def setup_environment():
    """Setup environment variables and configuration"""
    print("CONFIRM License Manager Setup")
    print("=" * 40)
    
    # Get API URL
    api_url = input("Enter API URL (e.g., https://render-confirmlicense.onrender.com): ").strip()
    if not api_url:
        print("Error: API URL is required")
        return False
    
    # Remove /api suffix if present
    if api_url.endswith('/api'):
        api_url = api_url[:-4]
        print(f"Removed /api suffix, using: {api_url}")
    
    # Get admin key
    admin_key = input("Enter admin secret key: ").strip()
    if not admin_key:
        print("Error: Admin key is required")
        return False
    
    # Create .env file
    env_content = f"""# License Manager Configuration
LICENSE_API_URL={api_url}
ADMIN_SECRET_KEY={admin_key}
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("\nConfiguration saved to .env file")
    
    # Update the GUI config
    try:
        from license_manager_config import config
        config.API_BASE_URL = api_url
        config.ADMIN_KEY = admin_key
        config.save_config()
        print("Configuration updated successfully")
    except ImportError:
        print("Warning: Could not update GUI configuration")
    
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    print("\nChecking dependencies...")
    
    required_packages = [
        'tkinter',
        'requests',
        'pathlib'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            elif package == 'requests':
                import requests
            elif package == 'pathlib':
                import pathlib
            print(f"OK {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"ERROR {package} - MISSING")
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Please install them using:")
        print("pip install requests")
        return False
    
    return True

def test_api_connection():
    """Test connection to the API"""
    print("\nTesting API connection...")
    
    try:
        from license_manager_config import config
        import requests
        
        # Test with a simple request
        response = requests.get(config.API_BASE_URL.replace('/api', ''), timeout=10)
        if response.status_code == 200:
            print("OK API connection successful")
            return True
        else:
            print(f"ERROR API returned status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"ERROR API connection failed: {str(e)}")
        return False

def create_desktop_shortcut():
    """Create desktop shortcut for easy access"""
    print("\nCreating desktop shortcut...")
    
    try:
        import platform
        system = platform.system()
        
        if system == "Windows":
            # Create Windows shortcut
            desktop = Path.home() / "Desktop"
            shortcut_path = desktop / "CONFIRM License Manager.lnk"
            
            # This would require pywin32 for actual shortcut creation
            print("Desktop shortcut creation not implemented for Windows")
            
        elif system == "Darwin":  # macOS
            # Create macOS application bundle
            print("Desktop shortcut creation not implemented for macOS")
            
        else:  # Linux
            # Create .desktop file
            desktop = Path.home() / "Desktop"
            desktop_file = desktop / "confirm-license-manager.desktop"
            
            desktop_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=CONFIRM License Manager
Comment=License Management System
Exec=python3 {Path.cwd() / 'license_manager_gui.py'}
Icon=applications-office
Terminal=false
Categories=Office;
"""
            
            with open(desktop_file, 'w') as f:
                f.write(desktop_content)
            
            # Make executable
            os.chmod(desktop_file, 0o755)
            print("OK Desktop shortcut created")
            
    except Exception as e:
        print(f"ERROR Could not create desktop shortcut: {str(e)}")

def main():
    """Main setup function"""
    print("CONFIRM License Manager Setup")
    print("This script will help you configure the license management system.")
    print()
    
    # Check dependencies
    if not check_dependencies():
        print("\nPlease install missing dependencies and run this script again.")
        return
    
    # Setup environment
    if not setup_environment():
        print("\nSetup failed. Please check your configuration.")
        return
    
    # Test API connection
    if not test_api_connection():
        print("\nAPI connection test failed. Please check your URL and try again.")
        return
    
    # Create desktop shortcut
    create_desktop_shortcut()
    
    print("\n" + "=" * 40)
    print("Setup completed successfully!")
    print()
    print("You can now run the license manager using:")
    print("python3 license_manager_gui.py")
    print()
    print("Or access the web interface at:")
    print("https://your-app-name.onrender.com/admin")
    print()
    print("Make sure to replace 'your-app-name.onrender.com' with your actual Render app URL.")

if __name__ == "__main__":
    main()
