# Lockfile System Documentation

This project implements two types of lockfiles for improved reliability and consistency:

## 1. Application Instance Lockfile

### Purpose
Prevents multiple instances of the application from running simultaneously. This is critical for:
- **License Management**: Ensures only one license validation occurs at a time
- **Resource Protection**: Prevents file conflicts and data corruption
- **State Consistency**: Maintains consistent application state

### Implementation
- **Location**: `%LOCALAPPDATA%\CONFIRM\confirm.lock` (Windows) or `~/.confirm/confirm.lock` (Unix)
- **Format**: `PID:timestamp`
- **Behavior**: 
  - Automatically created on application startup
  - Automatically removed on application exit
  - Checks for stale locks (process no longer running)
  - Cross-platform support (Windows and Unix-like systems)

### How It Works
1. On startup, the application checks if a lockfile exists
2. If found, it verifies the process is still running
3. If process is dead, removes stale lock and continues
4. If process is alive, shows error message and exits
5. On exit, lockfile is automatically cleaned up

### Error Handling
- If lockfile cannot be created (permissions), application continues (fail-open)
- Stale locks are automatically detected and removed
- Windows message box shown if another instance detected

## 2. Python Dependency Lockfile

### Purpose
Ensures consistent dependency versions across different environments and builds.

### Files
- **requirements.txt**: Contains version ranges (e.g., `numpy>=1.24.0`)
- **requirements-lock.txt**: Contains exact versions (e.g., `numpy==1.24.3`)
- **generate_requirements_lock.py**: Script to generate the lock file

### Usage

#### Generate Lock File
```bash
# First, install packages from requirements.txt
pip install -r requirements.txt

# Then generate the lock file
python generate_requirements_lock.py
```

#### Install from Lock File (Recommended for Production)
```bash
pip install -r requirements-lock.txt
```

#### Update Lock File
1. Update `requirements.txt` with new version ranges
2. Install updated packages: `pip install -r requirements.txt`
3. Regenerate lock file: `python generate_requirements_lock.py`

### Benefits
- **Reproducible Builds**: Same versions across dev, test, and production
- **Build Consistency**: Prevents "works on my machine" issues
- **Security**: Known, tested versions of dependencies
- **Debugging**: Easier to identify version-specific issues

### Best Practices
- **Development**: Use `requirements.txt` for flexibility
- **Production/CI**: Use `requirements-lock.txt` for consistency
- **Version Updates**: Update lock file after testing new versions
- **Version Control**: Commit both files to repository

## Node.js Lockfile

The Node.js server component already uses `package-lock.json` (automatically maintained by npm).

**Location**: `02_SERVER/package-lock.json`

This ensures consistent Node.js dependencies for the license server.

## Summary

| Lockfile Type | File | Purpose | Auto-Generated |
|--------------|------|---------|----------------|
| Application Instance | `confirm.lock` | Single-instance enforcement | Yes (on startup) |
| Python Dependencies | `requirements-lock.txt` | Dependency version locking | Manual (via script) |
| Node.js Dependencies | `package-lock.json` | Dependency version locking | Yes (via npm) |

## Troubleshooting

### Instance Lockfile Issues

**Problem**: "Another instance detected" but no other instance running
- **Solution**: Manually delete `%LOCALAPPDATA%\CONFIRM\confirm.lock`

**Problem**: Lockfile not removed on crash
- **Solution**: Lockfile is automatically cleaned up on next startup (stale lock detection)

### Dependency Lockfile Issues

**Problem**: `generate_requirements_lock.py` can't find package versions
- **Solution**: Ensure packages are installed: `pip install -r requirements.txt`

**Problem**: Lock file out of date
- **Solution**: Regenerate: `python generate_requirements_lock.py`

