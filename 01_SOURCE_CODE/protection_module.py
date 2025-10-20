"""
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
import subprocess
import platform

class CommercialProtection:
    """Advanced protection mechanisms for commercial software"""
    
    def __init__(self):
        self.start_time = time.time()
        self.original_argv = sys.argv.copy()
        self.protection_active = True
        self._setup_protection()
    
    def _setup_protection(self):
        """Initialize all protection mechanisms"""
        self._anti_debugging()
        self._anti_tampering()
        self._integrity_check()
        self._runtime_monitoring()
    
    def _anti_debugging(self):
        """Implement anti-debugging measures"""
        try:
            # Check for common debuggers
            debugger_processes = [
                'ollydbg.exe', 'x64dbg.exe', 'windbg.exe', 'ida.exe', 'ida64.exe',
                'ghidra.exe', 'radare2.exe', 'cheatengine.exe', 'processhacker.exe',
                'procmon.exe', 'wireshark.exe', 'fiddler.exe', 'charles.exe'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in debugger_processes:
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
            # Check if running from expected location
            current_path = os.path.abspath(sys.executable)
            if not self._is_valid_execution_path(current_path):
                self._terminate_application("Invalid execution path")
            
            # Verify file integrity
            if not self._verify_file_integrity():
                self._terminate_application("File integrity violation")
                
        except Exception:
            pass
    
    def _is_valid_execution_path(self, path):
        """Validate execution path"""
        # Add your expected installation paths here
        valid_paths = [
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            os.path.expanduser("~\\AppData\\Local"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents")
        ]
        
        return any(path.startswith(valid_path) for valid_path in valid_paths)
    
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
            suspicious_dlls = [
                'detours.dll', 'easyhook.dll', 'minhook.dll', 'polyhook.dll'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in suspicious_dlls:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return False
        except Exception:
            return False
    
    def _runtime_monitoring(self):
        """Monitor runtime for suspicious activity"""
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
            vm_processes = [
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                'vboxservice.exe', 'vboxtray.exe', 'vmtoolsd.exe',
                'qemu-ga.exe', 'xenservice.exe'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in vm_processes:
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
            # Check for sandbox-specific processes
            sandbox_processes = [
                'sandboxie.exe', 'cuckoo.exe', 'wireshark.exe',
                'procmon.exe', 'regmon.exe', 'filemon.exe'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in sandbox_processes:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for analysis tools
            analysis_tools = [
                'ida.exe', 'ida64.exe', 'ghidra.exe', 'radare2.exe',
                'x64dbg.exe', 'ollydbg.exe', 'windbg.exe'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in analysis_tools:
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
