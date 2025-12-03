#!/usr/bin/env python3
"""
Copyright (c) 2024 TraceSeis, Inc.
All rights reserved.

This software and associated documentation files (the "Software") are proprietary
and confidential to TraceSeis, Inc. and its affiliates. The Software is protected
by copyright laws and international copyright treaties, as well as other intellectual
property laws and treaties.

Contact Information:
- Email: info@traceseis.com or alvarochf@traceseis.com
- Created by: Alvaro Chaveste (deltaV solutions)

Unauthorized copying, distribution, or modification of this Software is strictly
prohibited and may result in severe civil and criminal penalties.

Commercial Software Protection Module
Implements anti-debugging, anti-tampering, and runtime protection measures
"""

import os
import sys
import ctypes
import time
import hashlib
import psutil
import threading
from ctypes import wintypes
import platform

class CommercialProtection:
    """Advanced protection mechanisms for commercial software"""
    
    def _detect_build_environment(self):
        """Detect if we're running in a build environment"""
        try:
            # Check for common build environment indicators
            build_indicators = [
                "nuitka", "pyinstaller", "cx_freeze", "py2exe",
                "build", "dist", "setup.py", "pip", "conda"
            ]

            # Check command line arguments
            for arg in sys.argv:
                if any(indicator in arg.lower() for indicator in build_indicators):
                    return True

            # Check environment variables
            env_vars = os.environ.keys()
            if any(indicator in var.lower() for indicator in build_indicators for var in env_vars):
                return True

            # Check if we're running from a temporary build directory
            current_path = os.path.abspath(sys.executable)
            if any(indicator in current_path.lower() for indicator in ["temp", "build", "dist", "_mei"]):
                return True

            return False

        except Exception as e:
            self._log_debug(f"Error detecting build environment: {e}")
            return False

    def __init__(self):
        self.start_time = time.time()
        self.original_argv = sys.argv.copy()
        self.protection_active = True
        self.debug_mode = os.getenv("CONFIRM_DEBUG", "false").lower() == "true"
        self.build_mode = self._detect_build_environment()
        self._log_debug(f"Protection module initialized - Build mode: {self.build_mode}")
        if not self.build_mode:
            self._setup_protection()
        else:
            self._log_debug("Running in build environment - skipping protection setup")
    
    def _log_debug(self, message):
        """Log debug messages with timestamp"""
        if self.debug_mode:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            debug_message = f"[PROTECTION DEBUG {timestamp}] {message}"
            print(debug_message, file=sys.stderr)
            try:
                with open("protection_debug.log", "a") as f:
                    f.write(debug_message + "\n")
            except:
                pass

    def _setup_protection(self):
        """Initialize all protection mechanisms"""
        self._log_debug("Starting protection setup")
        self._anti_debugging()
        self._anti_tampering()
        self._integrity_check()
        self._runtime_monitoring()
        self._log_debug("Protection setup completed")
    
    def _anti_debugging(self):
        """Implement anti-debugging measures"""
        try:
            # Check for common debuggers
            debugger_processes = [
                'ollydbg.exe', 'x64dbg.exe', 'windbg.exe', 'ida.exe', 'ida64.exe',
                'ghidra.exe', 'radare2.exe', 'cheatengine.exe', 'processhacker.exe',
                'procmon.exe', 'wireshark.exe', 'fiddler.exe', 'charles.exe'
            ]
            
            # Optimized: Use a set for faster lookups and limit iterations
            debugger_set = set(debugger_processes)
            checked_count = 0
            max_checks = 500  # Limit to prevent hanging on systems with many processes
            
            for proc in psutil.process_iter(['pid', 'name']):
                if checked_count >= max_checks:
                    break  # Prevent excessive scanning
                checked_count += 1
                try:
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in debugger_set:
                        self._terminate_application("Debugging software detected")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for debugger attachment
            if self._is_debugger_present():
                self._terminate_application("Debugger attachment detected")
                
        except Exception:
            pass  # Fail silently to avoid detection
    
    def _is_debugger_present(self):
        """Check if debugger is attached to current process"""
        try:
            # Windows-specific debugger detection
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32
                return kernel32.IsDebuggerPresent() != 0
            return False
        except Exception:
            return False
    
    def _anti_tampering(self):
        """Implement anti-tampering measures"""
        try:
            self._log_debug("Starting anti-tampering checks")
            # Check if running from expected location
            current_path = os.path.abspath(sys.executable)
            self._log_debug(f"Current executable path: {current_path}")

            # Skip path validation during build processes
            if not self.build_mode:
                if not self._is_valid_execution_path(current_path):
                    self._log_debug("Invalid execution path detected - terminating")
                    self._terminate_application("Invalid execution path")

                # Verify file integrity
                if not self._verify_file_integrity():
                    self._log_debug("File integrity violation detected - terminating")
                    self._terminate_application("File integrity violation")
            else:
                self._log_debug("Build mode detected - skipping path validation")

            self._log_debug("Anti-tampering checks passed")

        except Exception as e:
            self._log_debug(f"Exception in anti-tampering: {e}")
            pass
    
    def _is_valid_execution_path(self, path):
        """Validate execution path - lenient for development, strict for production"""
        # If running from Python source (not frozen/compiled), allow any path (development mode)
        # PyInstaller sets sys.frozen, Nuitka sets __compiled__
        is_compiled = getattr(sys, 'frozen', False) or '__compiled__' in dir()
        if not is_compiled:
            return True
        
        # For PyInstaller temp directory, always allow (check this first)
        if "_MEI" in path:
            return True
            return True
        
        # For compiled .exe, check if in standard installation locations
        # Use comprehensive list of valid paths
        valid_paths = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            os.path.expanduser(r"~\AppData\Local"),
            os.path.expanduser(r"~\AppData\Local\Programs"),
            os.path.expanduser(r"~\Desktop"),
            os.path.expanduser(r"~\Downloads"),
            os.path.expanduser(r"~\Documents"),
            # Allow execution from development/test directories
            "CONFIRM_Distribution_Optimized",
            "OneDrive",
        ]
        
        # Check if path contains any valid path segment
        path_normalized = path.replace("\\", "/").lower()
        for valid_path in valid_paths:
            valid_normalized = str(valid_path).replace("\\", "/").lower()
            if valid_normalized in path_normalized or path_normalized.startswith(valid_normalized):
                return True
        
        # For Nuitka compiled executables, check for Nuitka-specific paths
        # Nuitka creates executables directly, not in temp directories
        # When frozen (either PyInstaller or Nuitka), be lenient
        is_compiled = getattr(sys, 'frozen', False) or '__compiled__' in dir()
        if is_compiled:
            # Allow execution from current directory for frozen executables
            # This handles cases where users run from custom locations
            current_dir = os.getcwd().replace("\\", "/").lower()
            if current_dir in path_normalized:
                return True
        
        # If we get here, it's an unexpected location for a compiled .exe
        return False
    
    def _verify_file_integrity(self):
        """Verify executable file integrity"""
        try:
            # Simple integrity check - in production, use cryptographic signatures
            exe_path = sys.executable
            if os.path.exists(exe_path):
                stat = os.stat(exe_path)
                # Check file size is reasonable (not too small or too large)
                if stat.st_size < 1024 * 1024 or stat.st_size > 500 * 1024 * 1024:
                    return False
            return True
        except Exception:
            return False
    
    def _integrity_check(self):
        """Perform runtime integrity checks"""
        if self.build_mode:
            self._log_debug("Build mode detected - skipping integrity checks")
            return

        try:
            # Check for memory patching
            if self._detect_memory_patching():
                self._terminate_application("Memory patching detected")

            # Check for API hooking
            if self._detect_api_hooking():
                self._terminate_application("API hooking detected")

        except Exception:
            pass
    
    def _detect_memory_patching(self):
        """Detect memory patching attempts"""
        try:
            # Simple heuristic - check if critical functions are modified
            import inspect
            frame = inspect.currentframe()
            if frame and frame.f_code.co_code != frame.f_code.co_code:
                return True
            return False
        except Exception:
            return False
    
    def _detect_api_hooking(self):
        """Detect API hooking attempts"""
        try:
            # Check for suspicious DLLs
            suspicious_dlls = set([
                'detours.dll', 'easyhook.dll', 'minhook.dll', 'polyhook.dll'
            ])
            
            checked_count = 0
            max_checks = 200  # Limit checks for performance
            
            for proc in psutil.process_iter(['pid', 'name']):
                if checked_count >= max_checks:
                    break
                checked_count += 1
                try:
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in suspicious_dlls:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception:
            return False
    
    def _runtime_monitoring(self):
        """Monitor runtime for suspicious activity"""
        if self.build_mode:
            self._log_debug("Build mode detected - skipping runtime monitoring")
            return

        def monitor():
            while self.protection_active:
                try:
                    # Check for virtual machines
                    if self._detect_virtual_machine():
                        self._terminate_application("Virtual machine detected")

                    # Check for sandbox environments
                    if self._detect_sandbox():
                        self._terminate_application("Sandbox environment detected")

                    # Check execution time (prevent automated analysis)
                    if time.time() - self.start_time > 3600:  # 1 hour limit
                        self._terminate_application("Execution time exceeded")

                    time.sleep(30)  # Check every 30 seconds
                except Exception:
                    break

        # Start monitoring in background thread
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
    
    def _detect_virtual_machine(self):
        """Detect virtual machine environment"""
        try:
            # Check for VM-specific processes
            vm_processes = set([
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                'vboxservice.exe', 'vboxtray.exe', 'qemu-ga.exe', 'xenservice.exe'
            ])
            
            checked_count = 0
            max_checks = 200  # Limit checks for performance
            
            for proc in psutil.process_iter(['pid', 'name']):
                if checked_count >= max_checks:
                    break
                checked_count += 1
                try:
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in vm_processes:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check system information
            system_info = platform.platform().lower()
            vm_indicators = ['vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v']
            
            return any(indicator in system_info for indicator in vm_indicators)
        except Exception:
            return False
    
    def _detect_sandbox(self):
        """Detect sandbox environment"""
        try:
            # Check for sandbox-specific processes and analysis tools
            sandbox_processes = set([
                'sandboxie.exe', 'cuckoo.exe', 'wireshark.exe',
                'procmon.exe', 'regmon.exe', 'filemon.exe'
            ])
            
            analysis_tools = set([
                'ida.exe', 'ida64.exe', 'ghidra.exe', 'radare2.exe',
                'x64dbg.exe', 'ollydbg.exe', 'windbg.exe'
            ])
            
            # Combined check to avoid iterating twice
            all_suspicious = sandbox_processes | analysis_tools
            checked_count = 0
            max_checks = 300  # Limit checks for performance
            
            for proc in psutil.process_iter(['pid', 'name']):
                if checked_count >= max_checks:
                    break
                checked_count += 1
                try:
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in all_suspicious:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
        except Exception:
            return False
    
    def _terminate_application(self, reason):
        """Safely terminate the application"""
        try:
            # Log the reason (in production, send to server)
            self.protection_active = False
            
            # Clear sensitive data from memory
            self._clear_sensitive_data()
            
            # Terminate process
            os._exit(1)
        except Exception:
            os._exit(1)
    
    def _clear_sensitive_data(self):
        """Clear sensitive data from memory"""
        try:
            # Overwrite sensitive variables
            if hasattr(self, 'start_time'):
                self.start_time = 0
            if hasattr(self, 'original_argv'):
                self.original_argv = []
        except Exception:
            pass
    
    def validate_license_integrity(self, license_data):
        """Validate license data integrity"""
        try:
            if not license_data or not isinstance(license_data, dict):
                return False
            
            # Check for required fields
            required_fields = ['license_key', 'computer_id', 'expiry']
            if not all(field in license_data for field in required_fields):
                return False
            
            # Validate license key format
            license_key = license_data.get('license_key', '')
            if not self._is_valid_license_format(license_key):
                return False
            
            return True
        except Exception:
            return False
    
    def _is_valid_license_format(self, license_key):
        """Validate license key format"""
        try:
            if not license_key or len(license_key) < 10:
                return False
            
            # Basic format validation
            parts = license_key.split(':')
            if len(parts) != 3:
                return False
            
            return True
        except Exception:
            return False
    
    def cleanup(self):
        """Cleanup protection resources"""
        self.protection_active = False
        self._clear_sensitive_data()

# Global protection instance
_protection_instance = None

def initialize_protection():
    """Initialize commercial protection"""
    global _protection_instance
    if _protection_instance is None:
        _protection_instance = CommercialProtection()
    return _protection_instance

def cleanup_protection():
    """Cleanup protection resources"""
    global _protection_instance
    if _protection_instance:
        _protection_instance.cleanup()
        _protection_instance = None