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
from typing import Optional, Callable

class ProtectionViolation(Exception):
    """Exception raised when protection mechanisms detect a security violation"""
    def __init__(self, reason: str, error_code: str, severity: str = "critical"):
        """
        Initialize protection violation
        
        Args:
            reason: Human-readable reason for violation
            error_code: Machine-readable error code for diagnostics
            severity: "critical" (must terminate) or "warning" (log but continue)
        """
        super().__init__(reason)
        self.reason = reason
        self.error_code = error_code
        self.severity = severity
        self.timestamp = time.time()

class CommercialProtection:
    """Advanced protection mechanisms for commercial software"""
    
    def __init__(self, error_callback: Optional[Callable[[ProtectionViolation], None]] = None, 
                 logger=None):
        """
        Initialize protection system
        
        Args:
            error_callback: Optional callback function to handle protection violations.
                          If provided, violations will call this instead of raising exceptions.
            logger: Optional logger instance. If provided, will use for logging instead of debug file.
        """
        self.start_time = time.time()
        self.original_argv = sys.argv.copy()
        self.protection_active = True
        self.debug_mode = os.getenv("CONFIRM_DEBUG", "false").lower() == "true"
        self.error_callback = error_callback
        self.logger = logger
        self.build_mode = self._detect_build_environment()
        self.vm_detected = False
        self.violation_count = 0
        
        self._log_debug(f"Protection module initialized - Build mode: {self.build_mode}")
        
        if not self.build_mode:
            try:
                self._setup_protection()
            except ProtectionViolation as e:
                self._handle_violation(e)
        else:
            self._log_debug("Running in build environment - skipping protection setup")
    
    def _detect_build_environment(self):
        """Detect if we're running in a build environment"""
        try:
            build_indicators = [
                "nuitka", "pyinstaller", "cx_freeze", "py2exe",
                "build", "dist", "setup.py", "pip", "conda"
            ]

            for arg in sys.argv:
                if any(indicator in arg.lower() for indicator in build_indicators):
                    return True

            env_vars = os.environ.keys()
            if any(indicator in var.lower() for indicator in build_indicators for var in env_vars):
                return True

            current_path = os.path.abspath(sys.executable)
            if any(indicator in current_path.lower() for indicator in ["temp", "build", "dist", "_mei"]):
                return True

            return False

        except Exception as e:
            self._log_debug(f"Error detecting build environment: {e}")
            return False
    
    def _log_debug(self, message):
        """Log debug messages with timestamp"""
        if self.debug_mode:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            debug_message = f"[PROTECTION DEBUG {timestamp}] {message}"
            
            if self.logger:
                self.logger.debug(debug_message)
            else:
                print(debug_message, file=sys.stderr)
                try:
                    with open("protection_debug.log", "a") as f:
                        f.write(debug_message + "\n")
                except:
                    pass
    
    def _log_error(self, message):
        """Log error messages"""
        if self.logger:
            self.logger.error(f"[PROTECTION] {message}")
        else:
            try:
                with open("protection_debug.log", "a") as f:
                    f.write(f"[PROTECTION ERROR] {message}\n")
            except:
                pass
    
    def _log_info(self, message):
        """Log info messages - always logs regardless of debug_mode"""
        if self.logger:
            self.logger.info(f"[PROTECTION] {message}")
        else:
            try:
                with open("protection_debug.log", "a") as f:
                    f.write(f"[PROTECTION INFO] {message}\n")
            except:
                pass
    
    def _handle_violation(self, violation: ProtectionViolation):
        """Handle a protection violation"""
        self.violation_count += 1
        error_msg = f"Protection violation [{violation.error_code}]: {violation.reason}"
        
        self._log_error(error_msg)
        
        if violation.severity == "critical":
            if self.error_callback:
                try:
                    self.error_callback(violation)
                except Exception as e:
                    self._log_error(f"Error callback failed: {e}")
                    raise violation
            else:
                raise violation
        else:
            self._log_debug(f"Non-critical violation (continuing): {violation.reason}")
    
    def _setup_protection(self):
        """Initialize all protection mechanisms"""
        self._log_debug("Starting protection setup")
        self._anti_debugging()
        self._anti_tampering()
        self._integrity_check()
        self._runtime_monitoring()
        self._log_debug("Protection setup completed")
    
    def _scan_processes_with_timeout(self, process_names, max_checks=200, timeout_seconds=5):
        """
        Scan running processes with timeout protection
        
        Args:
            process_names: Set of process names to check for
            max_checks: Maximum number of processes to check
            timeout_seconds: Maximum time to spend scanning
            
        Returns:
            List of matching process names found
        """
        found = []
        start_time = time.time()
        checked_count = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if checked_count >= max_checks:
                    break
                if time.time() - start_time > timeout_seconds:
                    self._log_debug(f"Process scan timed out after {timeout_seconds}s")
                    break
                    
                checked_count += 1
                try:
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in process_names:
                        found.append(proc_name)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            self._log_debug(f"Error during process scan: {e}")
        
        return found
    
    def _anti_debugging(self):
        """Implement anti-debugging measures"""
        try:
            debugger_processes = set([
                'ollydbg.exe', 'x64dbg.exe', 'windbg.exe', 'ida.exe', 'ida64.exe',
                'ghidra.exe', 'radare2.exe', 'cheatengine.exe', 'processhacker.exe',
                'procmon.exe', 'wireshark.exe', 'fiddler.exe', 'charles.exe'
            ])
            
            found_debuggers = self._scan_processes_with_timeout(
                debugger_processes, 
                max_checks=300, 
                timeout_seconds=5
            )
            
            if found_debuggers:
                violation = ProtectionViolation(
                    reason=f"Debugging software detected: {', '.join(found_debuggers)}",
                    error_code="PROT-001",
                    severity="critical"
                )
                self._handle_violation(violation)
            
            if self._is_debugger_present():
                violation = ProtectionViolation(
                    reason="Debugger attachment detected",
                    error_code="PROT-002",
                    severity="critical"
                )
                self._handle_violation(violation)
                
        except ProtectionViolation:
            raise
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            self._log_debug(f"Exception in anti-debugging check: {e}")
        except Exception as e:
            self._log_debug(f"Unexpected exception in anti-debugging check: {e}")
    
    def _is_debugger_present(self):
        """Check if debugger is attached to current process"""
        try:
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
            current_path = os.path.abspath(sys.executable)
            self._log_debug(f"Current executable path: {current_path}")

            if not self.build_mode:
                if not self._is_valid_execution_path(current_path):
                    violation = ProtectionViolation(
                        reason=f"Invalid execution path: {current_path}",
                        error_code="PROT-003",
                        severity="critical"
                    )
                    self._handle_violation(violation)

                if not self._verify_file_integrity():
                    violation = ProtectionViolation(
                        reason="File integrity violation detected",
                        error_code="PROT-004",
                        severity="critical"
                    )
                    self._handle_violation(violation)
            else:
                self._log_debug("Build mode detected - skipping path validation")

            self._log_debug("Anti-tampering checks passed")

        except ProtectionViolation:
            raise
        except (OSError, PermissionError) as e:
            self._log_debug(f"Exception in anti-tampering: {e}")
        except Exception as e:
            self._log_debug(f"Unexpected exception in anti-tampering: {e}")
    
    def _is_valid_execution_path(self, path):
        """Validate execution path - professional approach with reasonable restrictions"""
        is_compiled = getattr(sys, 'frozen', False) or '__compiled__' in dir()
        if not is_compiled:
            return True
        
        if "_MEI" in path:
            return True
        
        valid_paths = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            os.path.expanduser(r"~\AppData\Local"),
            os.path.expanduser(r"~\AppData\Local\Programs"),
            os.path.expanduser(r"~\AppData\Roaming"),
            os.path.expanduser(r"~\Desktop"),
            os.path.expanduser(r"~\Downloads"),
            os.path.expanduser(r"~\Documents"),
            os.path.expanduser(r"~\OneDrive"),
            "CONFIRM_Distribution_Optimized",
            "OneDrive",
        ]
        
        path_normalized = path.replace("\\", "/").lower()
        for valid_path in valid_paths:
            valid_normalized = str(valid_path).replace("\\", "/").lower()
            if valid_normalized in path_normalized or path_normalized.startswith(valid_normalized):
                return True
        
        is_compiled = getattr(sys, 'frozen', False) or '__compiled__' in dir()
        if is_compiled:
            current_dir = os.getcwd().replace("\\", "/").lower()
            if current_dir in path_normalized:
                return True
        
            path_drive = os.path.splitdrive(path)[0].lower()
            if path_drive:
                valid_drives = ['c:', 'd:', 'e:', 'f:', 'g:', 'h:', 'i:', 'j:', 'k:', 'l:', 'm:', 'n:', 'o:', 'p:', 'q:', 'r:', 's:', 't:', 'u:', 'v:', 'w:', 'x:', 'y:', 'z:']
                if path_drive in valid_drives:
                    suspicious_segments = ['temp', 'tmp', 'windows/system32', 'windows/syswow64']
                    if not any(sus in path_normalized for sus in suspicious_segments):
                        return True
        
        return False
    
    def _verify_file_integrity(self):
        """Verify executable file integrity"""
        try:
            exe_path = sys.executable
            self._log_info(f"Verifying file integrity for: {exe_path}")
            
            if not os.path.exists(exe_path):
                self._log_error(f"File integrity check failed: File does not exist at {exe_path}")
                return False
            
            try:
                stat = os.stat(exe_path)
                file_size = stat.st_size
                file_size_mb = file_size / (1024 * 1024)
                self._log_info(f"File exists: True, Size: {file_size_mb:.2f} MB ({file_size} bytes)")
                
                min_size = 1024 * 1024  # 1 MB
                max_size = 500 * 1024 * 1024  # 500 MB
                
                if file_size < min_size:
                    self._log_error(f"File integrity check failed: File size ({file_size_mb:.2f} MB, {file_size} bytes) is below minimum (1 MB)")
                    return False
                
                if file_size > max_size:
                    self._log_error(f"File integrity check failed: File size ({file_size_mb:.2f} MB, {file_size} bytes) exceeds maximum (500 MB)")
                    return False
                
                self._log_info("File integrity check passed: Size is within valid range")
                return True
                
            except (OSError, PermissionError) as e:
                error_type = type(e).__name__
                self._log_error(f"File integrity check failed: {error_type} - {str(e)} (Path: {exe_path})")
                return False
                
        except Exception as e:
            error_type = type(e).__name__
            self._log_error(f"File integrity check failed: Unexpected {error_type} - {str(e)} (Path: {exe_path if 'exe_path' in locals() else 'unknown'})")
            return False
    
    def _integrity_check(self):
        """Perform runtime integrity checks"""
        if self.build_mode:
            self._log_debug("Build mode detected - skipping integrity checks")
            return

        try:
            if self._detect_memory_patching():
                violation = ProtectionViolation(
                    reason="Memory patching detected",
                    error_code="PROT-005",
                    severity="critical"
                )
                self._handle_violation(violation)

            if self._detect_api_hooking():
                violation = ProtectionViolation(
                    reason="API hooking detected",
                    error_code="PROT-006",
                    severity="critical"
                )
                self._handle_violation(violation)

        except ProtectionViolation:
            raise
        except Exception as e:
            self._log_debug(f"Exception in integrity check: {e}")
    
    def _detect_memory_patching(self):
        """Detect memory patching attempts"""
        try:
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
            suspicious_dlls = set([
                'detours.dll', 'easyhook.dll', 'minhook.dll', 'polyhook.dll'
            ])
            
            found_dlls = self._scan_processes_with_timeout(
                suspicious_dlls,
                max_checks=150,
                timeout_seconds=3
            )
            
            return len(found_dlls) > 0
        except Exception as e:
            self._log_debug(f"Exception in API hooking detection: {e}")
            return False
    
    def _runtime_monitoring(self):
        """Monitor runtime for suspicious activity"""
        if self.build_mode:
            self._log_debug("Build mode detected - skipping runtime monitoring")
            return

        def monitor():
            while self.protection_active:
                try:
                    vm_detected = self._detect_virtual_machine()
                    if vm_detected and not self.vm_detected:
                        self.vm_detected = True
                        violation = ProtectionViolation(
                            reason="Virtual machine environment detected (warning only)",
                            error_code="PROT-007",
                            severity="warning"
                        )
                        self._handle_violation(violation)

                    if self._detect_sandbox():
                        violation = ProtectionViolation(
                            reason="Sandbox environment detected",
                            error_code="PROT-008",
                            severity="critical"
                        )
                        self._handle_violation(violation)

                    if time.time() - self.start_time > 3600:
                        violation = ProtectionViolation(
                            reason="Execution time exceeded maximum allowed duration",
                            error_code="PROT-009",
                            severity="critical"
                        )
                        self._handle_violation(violation)

                    time.sleep(30)
                except ProtectionViolation:
                    # Violation was already handled by _handle_violation before it was raised
                    # No need to handle again - just exit the monitor loop
                    break
                except Exception as e:
                    self._log_debug(f"Exception in runtime monitor: {e}")
                    break

        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
    
    def _detect_virtual_machine(self):
        """Detect virtual machine environment - returns True if VM detected"""
        try:
            vm_processes = set([
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                'vboxservice.exe', 'vboxtray.exe', 'qemu-ga.exe', 'xenservice.exe'
            ])
            
            found_vm_processes = self._scan_processes_with_timeout(
                vm_processes,
                max_checks=150,
                timeout_seconds=3
            )
            
            if found_vm_processes:
                return True
            
            system_info = platform.platform().lower()
            vm_indicators = ['vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v']
            
            return any(indicator in system_info for indicator in vm_indicators)
        except Exception as e:
            self._log_debug(f"Exception in VM detection: {e}")
            return False
    
    def _detect_sandbox(self):
        """Detect sandbox environment"""
        try:
            sandbox_processes = set([
                'sandboxie.exe', 'cuckoo.exe', 'wireshark.exe',
                'procmon.exe', 'regmon.exe', 'filemon.exe'
            ])
            
            analysis_tools = set([
                'ida.exe', 'ida64.exe', 'ghidra.exe', 'radare2.exe',
                'x64dbg.exe', 'ollydbg.exe', 'windbg.exe'
            ])
            
            all_suspicious = sandbox_processes | analysis_tools
            
            found_processes = self._scan_processes_with_timeout(
                all_suspicious,
                max_checks=200,
                timeout_seconds=4
            )
            
            return len(found_processes) > 0
        except Exception as e:
            self._log_debug(f"Exception in sandbox detection: {e}")
            return False
    
    def _clear_sensitive_data(self):
        """Clear sensitive data from memory"""
        try:
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
            
            required_fields = ['license_key', 'computer_id', 'expiry']
            if not all(field in license_data for field in required_fields):
                return False
            
            license_key = license_data.get('license_key', '')
            if not self._is_valid_license_format(license_key):
                return False
            
            return True
        except Exception as e:
            self._log_debug(f"Exception in license integrity validation: {e}")
            return False
    
    def _is_valid_license_format(self, license_key):
        """Validate license key format"""
        try:
            if not license_key or len(license_key) < 10:
                return False
            
            parts = license_key.split(':')
            if len(parts) != 3:
                return False
            
            return True
        except Exception as e:
            self._log_debug(f"Exception in license format validation: {e}")
            return False
    
    def cleanup(self):
        """Cleanup protection resources"""
        self.protection_active = False
        self._clear_sensitive_data()

# Global protection instance
_protection_instance = None
_error_callback = None
_logger = None

def set_protection_error_callback(callback: Callable[[ProtectionViolation], None]):
    """Set callback function for handling protection violations"""
    global _error_callback
    _error_callback = callback

def set_protection_logger(logger):
    """Set logger instance for protection module"""
    global _logger
    _logger = logger

def initialize_protection():
    """Initialize commercial protection"""
    global _protection_instance
    if _protection_instance is None:
        try:
            _protection_instance = CommercialProtection(
                error_callback=_error_callback,
                logger=_logger
            )
        except ProtectionViolation as e:
            if _error_callback:
                try:
                    _error_callback(e)
                except Exception as callback_error:
                    if _logger:
                        _logger.error(f"Error callback failed: {callback_error}")
            raise
    return _protection_instance

def cleanup_protection():
    """Cleanup protection resources"""
    global _protection_instance
    if _protection_instance:
        _protection_instance.cleanup()
        _protection_instance = None
