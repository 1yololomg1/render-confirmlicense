#!/bin/bash
# Build CONFIRM.exe using Nuitka (Linux/Mac - cross-compile for Windows)
# Copyright (c) 2024 TraceSeis, Inc. All rights reserved.

echo "========================================"
echo "CONFIRM.exe Build Script (Nuitka)"
echo "========================================"
echo ""

# Check if Nuitka is installed
if ! python -m nuitka --version >/dev/null 2>&1; then
    echo "ERROR: Nuitka is not installed!"
    echo "Please install it with: pip install nuitka"
    exit 1
fi

echo "Nuitka found. Starting build..."
echo ""

# Change to script directory
cd "$(dirname "$0")"

# Clean previous build
rm -rf dist CONFIRM.build CONFIRM.dist CONFIRM.onefile-build

echo "Building CONFIRM.exe with Nuitka..."
echo "This may take several minutes..."
echo ""

# Build with Nuitka
python -m nuitka \
    --main=CONFIRM_Integrated.py \
    --output-dir=dist \
    --output-filename=CONFIRM.exe \
    --windows-console-mode=disable \
    --standalone \
    --onefile \
    --include-module=protection_module \
    --include-module=requests \
    --include-module=pandas \
    --include-module=numpy \
    --include-module=scipy \
    --include-module=matplotlib \
    --include-module=seaborn \
    --include-module=openpyxl \
    --include-module=cryptography \
    --include-module=psutil \
    --include-module=tkinter \
    --include-module=tkinter.ttk \
    --include-module=tkinter.messagebox \
    --include-module=tkinter.simpledialog \
    --include-module=tkinter.filedialog \
    --include-module=matplotlib.backends.backend_tkagg \
    --include-module=scipy.stats \
    --include-module=scipy.ndimage \
    --include-module=importlib.metadata \
    --include-module=importlib_metadata \
    --assume-yes-for-downloads \
    --show-progress \
    --show-memory \
    --no-prefer-source-code \
    --windows-company-name="TraceSeis, Inc." \
    --windows-product-name="CONFIRM Statistical Validation Engine" \
    --windows-file-version=1.0.0.0 \
    --windows-product-version=1.0.0.0 \
    --windows-file-description="CONFIRM Statistical Analysis Suite" \
    --copyright="Copyright (C) 2024 TraceSeis, Inc. All rights reserved."

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Build failed!"
    echo "Check the error messages above for details."
    exit 1
fi

echo ""
echo "========================================"
echo "Build completed successfully!"
echo "========================================"
echo ""
echo "CONFIRM.exe should be in the dist folder."
echo ""

# Copy to distribution folder if it exists
if [ -d "../CONFIRM_Distribution_Optimized" ]; then
    echo "Copying to CONFIRM_Distribution_Optimized..."
    cp -f dist/CONFIRM.exe ../CONFIRM_Distribution_Optimized/CONFIRM.exe
    echo "Done!"
    echo ""
fi

