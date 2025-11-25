# Nuitka Build Files

This folder contains all files needed to build CONFIRM.exe using Nuitka.

## Files Included

### Core Source Files
- **CONFIRM_Integrated.py** - Main application entry point
- **protection_module.py** - Hardware protection and license validation module
- **license_manager_gui.py** - License management GUI interface

### Build Scripts
- **build_nuitka.bat** - Windows batch script to build the executable with Nuitka

### Build Configuration
- **CONFIRM_Integrated.spec** - PyInstaller spec file (legacy, not used by Nuitka)
- **CONFIRM.spec** - Alternative spec file (legacy, not used by Nuitka)

## How to Build

1. Ensure Python 3.8+ is installed
2. Install Nuitka: `pip install nuitka`
3. Install all dependencies: `pip install pandas numpy matplotlib scipy seaborn openpyxl requests cryptography psutil`
4. Run the build script: `build_nuitka.bat`
5. The executable will be created in the `dist` folder

## Build Requirements

The build script includes all necessary modules:
- pandas, numpy, scipy, matplotlib, seaborn
- openpyxl (Excel file handling)
- requests (HTTP requests)
- cryptography (license encryption)
- psutil (system information)
- tkinter (GUI framework)

## Notes

- The build process may take 30-60 minutes depending on your system
- The resulting executable will be standalone and include all dependencies
- Output will be in the `dist` folder as `CONFIRM.exe`

