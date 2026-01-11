#!/usr/bin/env python3
"""
Generate a locked requirements file with exact package versions.

This script creates requirements-lock.txt with pinned versions of all dependencies
to ensure consistent builds across different environments.

Usage:
    python generate_requirements_lock.py

The script will:
1. Read requirements.txt (with version ranges)
2. Install packages and query installed versions
3. Generate requirements-lock.txt with exact versions
"""

import subprocess
import sys
import re
from pathlib import Path

def validate_path_within_base(path, base_dir):
    """
    Validate that a path resolves to within the base directory.
    Prevents directory traversal attacks.
    
    Args:
        path: Path to validate (Path object or string)
        base_dir: Base directory that the path must be within (Path object or string)
    
    Returns:
        Path: Resolved absolute path if valid
        None: If path is outside base_dir
    
    Raises:
        ValueError: If path is outside the base directory
    """
    base_dir = Path(base_dir).resolve()
    path = Path(path).resolve()
    
    # Check if the resolved path is within the base directory
    try:
        path.relative_to(base_dir)
    except ValueError:
        raise ValueError(f"Path {path} is outside allowed base directory {base_dir}")
    
    return path

def get_installed_version(package_name):
    """Get the installed version of a package."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'show', package_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('Version:'):
                    return line.split(':', 1)[1].strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"Warning: Could not get version for {package_name}: {e}")
    return None

def parse_requirements_file(requirements_path, base_dir):
    """
    Parse requirements.txt and extract package names.
    
    Args:
        requirements_path: Path to requirements file (already validated)
        base_dir: Base directory for path validation
    """
    packages = []
    requirements_path = Path(requirements_path).resolve()
    base_dir = Path(base_dir).resolve()
    
    # Security validation: ensure path is within base directory
    try:
        requirements_path = validate_path_within_base(requirements_path, base_dir)
    except ValueError as e:
        print(f"Error: Security validation failed - {e}")
        return packages
    
    if not requirements_path.exists():
        print(f"Error: {requirements_path} not found")
        return packages
    
    # Security check: ensure it's a file, not a directory or symlink
    if not requirements_path.is_file():
        print(f"Error: {requirements_path} is not a regular file")
        return packages
    
    # Safe to open - path has been validated
    with open(requirements_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Extract package name (handle version specifiers)
            # Format: package>=version or package==version, etc.
            match = re.match(r'^([a-zA-Z0-9_-]+[a-zA-Z0-9_.-]*)', line)
            if match:
                package_name = match.group(1)
                packages.append((package_name, line))
    
    return packages

def generate_lock_file(requirements_path, lock_path, base_dir):
    """
    Generate requirements-lock.txt with exact versions.
    
    Args:
        requirements_path: Path to requirements file (already validated)
        lock_path: Path to output lock file (already validated)
        base_dir: Base directory for path validation
    """
    requirements_path = Path(requirements_path).resolve()
    lock_path = Path(lock_path).resolve()
    base_dir = Path(base_dir).resolve()
    
    # Security validation: ensure paths are within base directory
    try:
        requirements_path = validate_path_within_base(requirements_path, base_dir)
        lock_path = validate_path_within_base(lock_path, base_dir)
    except ValueError as e:
        print(f"Error: Security validation failed - {e}")
        return False
    
    # Security check: ensure lock_path is a valid file path
    # Ensure parent directory exists and is writable
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading {requirements_path}...")
    packages = parse_requirements_file(requirements_path, base_dir)
    
    if not packages:
        print("No packages found in requirements.txt")
        return False
    
    print(f"Found {len(packages)} packages")
    print("Querying installed versions...")
    
    locked_packages = []
    failed_packages = []
    
    for package_name, original_line in packages:
        version = get_installed_version(package_name)
        if version:
            locked_line = f"{package_name}=={version}"
            locked_packages.append(locked_line)
            print(f"  ✓ {package_name}=={version}")
        else:
            # If we can't get version, use original line but warn
            locked_packages.append(original_line)
            failed_packages.append(package_name)
            print(f"  ⚠ {package_name} - using original specifier")
    
    # Write lock file (path already validated)
    print(f"\nWriting {lock_path}...")
    # Safe to open - path has been validated within base directory
    with open(lock_path, 'w', encoding='utf-8') as f:
        f.write("# Locked requirements file - generated by generate_requirements_lock.py\n")
        f.write("# This file contains exact package versions for reproducible builds\n")
        f.write("# DO NOT EDIT MANUALLY - regenerate using: python generate_requirements_lock.py\n\n")
        
        for line in locked_packages:
            f.write(line + '\n')
    
    print(f"\n✓ Generated {lock_path}")
    
    if failed_packages:
        print(f"\n⚠ Warning: Could not determine versions for: {', '.join(failed_packages)}")
        print("  These packages may need to be installed first:")
        print(f"  pip install {' '.join(failed_packages)}")
    
    return True

def main():
    """Main entry point."""
    script_dir = Path(__file__).parent.resolve()
    
    # Construct paths relative to script directory
    requirements_path_raw = script_dir / 'requirements.txt'
    lock_path_raw = script_dir / 'requirements-lock.txt'
    
    # Validate paths to prevent directory traversal attacks
    try:
        requirements_path = validate_path_within_base(requirements_path_raw, script_dir)
        lock_path = validate_path_within_base(lock_path_raw, script_dir)
    except ValueError as e:
        print(f"Error: Security validation failed - {e}")
        print("Path traversal detected. Aborting for security.")
        sys.exit(1)
    
    print("=" * 60)
    print("Requirements Lock File Generator")
    print("=" * 60)
    print()
    
    if not requirements_path.exists():
        print(f"Error: {requirements_path} not found")
        print("Please ensure requirements.txt exists in the project root")
        sys.exit(1)
    
    # Check if packages are installed
    print("Checking if packages are installed...")
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            print("Warning: pip list failed - packages may not be installed")
    except Exception as e:
        print(f"Warning: Could not check installed packages: {e}")
    
    print()
    
    if generate_lock_file(requirements_path, lock_path, script_dir):
        print("\n" + "=" * 60)
        print("Lock file generation complete!")
        print("=" * 60)
        print("\nTo use the lock file for installation:")
        print(f"  pip install -r {lock_path}")
        print("\nTo update the lock file after changing requirements.txt:")
        print("  1. Update requirements.txt")
        print("  2. pip install -r requirements.txt")
        print("  3. python generate_requirements_lock.py")
    else:
        print("\nLock file generation failed")
        sys.exit(1)

if __name__ == '__main__':
    main()

