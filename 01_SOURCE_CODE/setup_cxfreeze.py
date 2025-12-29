"""
============================================================================
CONFIRM Statistical Validation Engine - cx_Freeze Build Configuration
============================================================================
Copyright (c) 2024 TraceSeis, Inc. All rights reserved.

Professional build configuration for creating standalone executable distribution
using cx_Freeze. This configuration includes all required packages, DLLs, and
data files for a complete, self-contained application.

Build Output Structure:
  - CONFIRM.exe (~23KB) - Loader executable that bootstraps the application
  - lib/ - Contains all Python packages, libraries, and dependencies
  - lib/numpy.libs/ - NumPy DLL files
  - lib/scipy.libs/ - SciPy DLL files
  - lib/matplotlib.libs/ - Matplotlib DLL files
  - lib/protection_module.py - Security and protection module

All packages in this configuration have been verified against actual imports
in CONFIRM_Integrated.py and protection_module.py to ensure complete coverage.

Note: The small executable size is expected and normal for cx_Freeze builds.
All actual code and libraries are packaged in the lib/ folder.
============================================================================
"""

import sys
import os
from cx_Freeze import setup, Executable
from pathlib import Path
import glob

# Increase recursion limit to handle numpy's complex import structure
# This helps prevent "RecursionError" during freezing
sys.setrecursionlimit(sys.getrecursionlimit() * 5)

# =============================================================================
# VERIFIED REQUIRED PACKAGES (from actual imports)
# =============================================================================
# From CONFIRM_Integrated.py:
#   - requests, pandas, numpy, matplotlib, seaborn, scipy, openpyxl, cryptography
# From protection_module.py:
#   - psutil
# Optional (try/except in code):
#   - adjustText

def get_package_data_files():
    """
    Helper function to find and include package data files and DLLs
    that might be missed by cx_Freeze automatic detection.
    
    Note: cx_Freeze usually handles DLLs automatically, but this function
    ensures critical DLLs from numpy, scipy, and matplotlib are included.
    Also includes certifi's certificate bundle for HTTPS requests.
    """
    include_files = []
    
    # Get site-packages directory
    import site
    site_packages_paths = site.getsitepackages()
    
    for site_pkg in site_packages_paths:
        site_pkg_path = Path(site_pkg)
        
        # Include certifi's certificate bundle (critical for requests HTTPS)
        certifi_cacert = site_pkg_path / "certifi" / "cacert.pem"
        if certifi_cacert.exists():
            include_files.append((str(certifi_cacert), "lib/certifi/cacert.pem"))
        
        # Check both .libs (hidden) and package.libs (regular) folder patterns
        # Include numpy.libs DLLs
        for lib_pattern in [".libs", "numpy.libs"]:
            numpy_libs = site_pkg_path / "numpy" / lib_pattern
            if numpy_libs.exists():
                for dll_file in numpy_libs.glob("*.dll"):
                    target_path = f"lib/numpy.libs/{dll_file.name}"
                    include_files.append((str(dll_file), target_path))
                break  # Found one, no need to check others
        
        # Include scipy.libs DLLs  
        for lib_pattern in [".libs", "scipy.libs"]:
            scipy_libs = site_pkg_path / "scipy" / lib_pattern
            if scipy_libs.exists():
                for dll_file in scipy_libs.glob("*.dll"):
                    target_path = f"lib/scipy.libs/{dll_file.name}"
                    include_files.append((str(dll_file), target_path))
                break  # Found one, no need to check others
        
        # Include matplotlib.libs DLLs
        for lib_pattern in [".libs", "matplotlib.libs"]:
            matplotlib_libs = site_pkg_path / "matplotlib" / lib_pattern
            if matplotlib_libs.exists():
                for dll_file in matplotlib_libs.glob("*.dll"):
                    target_path = f"lib/matplotlib.libs/{dll_file.name}"
                    include_files.append((str(dll_file), target_path))
                break  # Found one, no need to check others
    
    return include_files

# Get additional files to include
additional_files = get_package_data_files()

build_exe_options = {
    "packages": [
        # === EXTERNAL PACKAGES (verified required) ===
        "requests",
        "urllib3",
        "urllib3.util",
        "certifi",
        "charset_normalizer",
        "idna",
        
        "pandas",
        "pandas._libs",
        "pandas.io",
        "pandas.io.formats",
        "pandas.io.formats.format",
        "pandas.io.excel",
        "pandas.io.excel._base",
        
        "numpy",
        # IMPORTANT: Only include "numpy" - do NOT include numpy.core or other subpackages
        # numpy 2.x with cx_Freeze has docstring conflicts when subpackages are explicitly listed
        # Let numpy handle its own internal imports automatically
        
        "scipy",
        "scipy.stats",
        "scipy.stats._stats",
        "scipy.ndimage",
        "scipy.special",
        "scipy.special._ufuncs_cxx",
        "scipy._lib",
        "scipy.linalg",
        "scipy.optimize",
        "scipy.integrate",
        "scipy.interpolate",
        
        "matplotlib",
        "matplotlib.pyplot",
        "matplotlib.backends",
        "matplotlib.backends.backend_tkagg",
        "matplotlib.backends._backend_agg",
        "matplotlib.figure",
        "matplotlib.colors",
        "matplotlib.patches",
        "matplotlib.text",
        
        "seaborn",
        
        "openpyxl",
        "openpyxl.xml",
        
        "cryptography",
        "cryptography.fernet",
        "cryptography.hazmat",
        "cryptography.hazmat.bindings",
        "cryptography.hazmat.primitives",
        
        "psutil",
        
        # === STANDARD LIBRARY (include explicitly for cx_Freeze) ===
        "tkinter",
        "tkinter.ttk",
        "tkinter.messagebox",
        "tkinter.simpledialog",
        "tkinter.filedialog",
        "tkinter.scrolledtext",
        
        "json",
        "os",
        "sys",
        "hashlib",
        "base64",
        "platform",
        "uuid",
        "datetime",
        "logging",
        "pathlib",
        "signal",
        "atexit",
        "secrets",
        "typing",
        "traceback",
        "time",
        "math",
        "threading",
        "queue",
        "concurrent",
        "concurrent.futures",
        "tempfile",
        "zipfile",
        "shutil",
        "weakref",
        "gc",
        "ctypes",
        "ctypes.util",
        "socket",
        "csv",
        "pickle",
        "importlib",
        "importlib.metadata",
        "importlib_metadata",
        
        # Additional standard library modules often needed
        "ssl",              # Needed for HTTPS requests
        "collections",      # Often needed by pandas and other packages
        "collections.abc",  # Needed by typing and other modules
        "io",               # File I/O operations
        "re",               # Regular expressions
        "email",            # Email parsing (may be needed by urllib3)
        "email.mime",       # Email MIME types
        "email.utils",      # Email utilities
        "xml",              # XML parsing (may be needed by some packages)
        "xml.etree",        # XML ElementTree
        "xml.etree.ElementTree",  # XML ElementTree
        
        # HTTP modules needed for requests/urllib3
        "http",
        "http.client",
        "http.server",
        "http.cookiejar",
        "http.cookies",
        "urllib",
        "urllib.parse",
        "urllib.request",
        "urllib.error",
        "urllib.response",
        "urllib.robotparser",
    ],
    
    "includes": [
        # Local module
        "protection_module",
        
        # HTTP modules for requests/urllib3
        "http.client",
        
        # Numpy internals - only include if absolutely necessary
        # Note: numpy 2.x handles most internal imports automatically
        
        # Scipy special functions and internals
        "scipy.special.cython_special",
        "scipy.special._ufuncs_cxx",
        "scipy.stats._stats",
        
        # Matplotlib internals
        "matplotlib._path",
        "matplotlib.backends._backend_agg",
        
        # Pandas internals
        "pandas._libs.tslibs",
        "pandas._libs.tslibs.timedeltas",
    ],
    
    "excludes": [
        # Not needed - reduce size
        "test",
        "unittest", 
        # NOTE: Do NOT exclude pydoc - seaborn needs it for docstrings!
        # NOTE: Do NOT exclude doctest - some packages need it
        "tkinter.test",
        "lib2to3",
        "xmlrpc",
        "IPython",
        "notebook",
        "sphinx",
        "pytest",
        "setuptools",
        "distutils",
        # NOTE: Do NOT exclude "http" - it's needed by urllib3/requests!
        # NOTE: Do NOT exclude "email" or "xml" - they may be needed by other packages
    ],
    
    "include_files": [
        # Include protection_module.py explicitly
        ("protection_module.py", "lib/protection_module.py"),
    ] + additional_files,
    
    # Optimization
    "optimize": 1,  # Use 1 instead of 2 for better compatibility
}

# Windows GUI application (no console window)
base = "Win32GUI" if sys.platform == "win32" else None

executables = [
    Executable(
        script="CONFIRM_Integrated.py",
        base=base,
        target_name="CONFIRM.exe",
        icon=None,
        copyright="Copyright (C) 2024 TraceSeis, Inc. All rights reserved.",
    )
]

setup(
    name="CONFIRM",
    version="1.0.0",
    description="CONFIRM Statistical Validation Engine - Professional Statistical Analysis Platform",
    long_description="A comprehensive statistical validation engine for contingency analysis and machine learning model validation.",
    author="TraceSeis, Inc. - deltaV solutions",
    author_email="info@traceseis.com",
    url="https://www.traceseis.com",
    license="Proprietary - Copyright (C) 2024 TraceSeis, Inc. All rights reserved.",
    options={"build_exe": build_exe_options},
    executables=executables,
)
