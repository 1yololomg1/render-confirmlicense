import requests
import json
import os
import hashlib
import base64
import platform
import uuid
from datetime import datetime, date
import tkinter as tk
from tkinter import messagebox, simpledialog
import sys
import logging
from pathlib import Path
import signal
import atexit
import secrets
from typing import Optional
import threading

try:
    from cryptography.fernet import Fernet, InvalidToken
    _FERNET_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    Fernet = None
    InvalidToken = Exception
    _FERNET_AVAILABLE = False

# Configuration and Constants
FIREBASE_URL = "https://confirm-license-manager-default-rtdb.firebaseio.com"
APP_NAME = "CONFIRM Statistical Validation Engine"
APP_VERSION = "1.0.0"
CONFIG_DIR = Path.home() / ".confirm"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
LICENSE_FILE = CONFIG_DIR / "confirm_license.json"
LOG_FILE = CONFIG_DIR / "confirm.log"

# NEW: License server configuration
LICENSE_SERVER_URL = "https://render-confirmlicense.onrender.com"

# Ensure configuration directory exists
CONFIG_DIR.mkdir(exist_ok=True)

# Initialize logging system
def setup_logging():
    """Initialize comprehensive logging system"""
    try:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        logger = logging.getLogger(APP_NAME)
        logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
        return logger
    except Exception as e:
        # Fallback to basic logging if file logging fails
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(APP_NAME)
        logger.warning(f"Failed to initialize file logging: {e}")
        return logger

# Initialize logger
logger = setup_logging()


class SecurityError(Exception):
    """Custom exception for security-related failures."""


def mask_license_key(license_key: Optional[str]) -> str:
    """Redact sensitive portions of a license key for logging or UI display."""
    if not license_key:
        return "<empty>"

    sanitized = license_key.strip()
    if len(sanitized) <= 8:
        return f"{sanitized[:2]}***{sanitized[-2:]}"

    return f"{sanitized[:4]}***{sanitized[-4:]}"


class LicenseEncryptionManager:
    """Handle encryption and decryption of license payloads."""

    _SALT_FILE = CONFIG_DIR / "license_salt.bin"

    def __init__(self):
        self._fernet: Optional[Fernet] = None
        self.available = _FERNET_AVAILABLE

        if not self.available:
            logger.warning("Cryptography package not available; license persistence will be disabled.")
            return

        try:
            self._fernet = Fernet(self._derive_key())
        except Exception as exc:  # pragma: no cover - defensive
            self.available = False
            logger.error(f"Failed to initialize license encryption: {exc}")

    def _load_or_create_salt(self) -> bytes:
        """Load existing salt or create a new one."""
        if self._SALT_FILE.exists():
            try:
                with open(self._SALT_FILE, 'rb') as f:
                    return f.read()
            except (OSError, IOError) as exc:
                logger.warning(f"Failed to load existing salt: {exc}")

        # Create new salt
        salt = secrets.token_bytes(32)
        try:
            with open(self._SALT_FILE, 'wb') as f:
                f.write(salt)
            logger.info("Created new license encryption salt")
        except (OSError, IOError) as exc:
            logger.error(f"Failed to save salt: {exc}")

        return salt

    def _derive_key(self) -> bytes:
        """Derive encryption key from salt and machine fingerprint."""
        salt = self._load_or_create_salt()
        machine_id = get_computer_fingerprint().encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', machine_id, salt, 100000)

    def encrypt(self, payload: str) -> str:
        """Encrypt a license payload."""
        if not self.available or not self._fernet:
            raise SecurityError("Encryption not available")

        return self._fernet.encrypt(payload.encode('utf-8')).decode('utf-8')

    def decrypt(self, token: str) -> str:
        """Decrypt a license token."""
        if not self.available or not self._fernet:
            raise SecurityError("Decryption not available")

        try:
            return self._fernet.decrypt(token.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            raise SecurityError("Invalid license token")

    def integrity_hash(self, payload: str) -> str:
        """Generate integrity hash for license payload."""
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]


def load_or_create_config():
    """Load configuration file or create with defaults"""
    default_config = {
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "settings": {
            "auto_save_results": True,
            "default_export_format": "xlsx",
            "max_processing_threads": 4,
            "network_timeout": 15,
            "log_level": "INFO",
            "enable_debug_mode": False,
            "auto_backup": True,
            "theme": "professional"
        },
        "paths": {
            "default_export_dir": str(Path.home() / "Documents" / "CONFIRM_Results"),
            "backup_dir": str(CONFIG_DIR / "backups"),
            "temp_dir": str(CONFIG_DIR / "temp")
        },
        "license_info": {
            "last_validated": None,
            "validation_count": 0,
            "offline_mode_enabled": False
        }
    }
    
    try:
        if SETTINGS_FILE.exists():
            logger.debug(f"Loading configuration from {SETTINGS_FILE}")
            
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Validate and merge with defaults
            config = validate_and_merge_config(config, default_config)
            
            # Update version if needed
            if config.get("version") != APP_VERSION:
                logger.info(f"Updating config version from {config.get('version')} to {APP_VERSION}")
                config["version"] = APP_VERSION
                config["updated_at"] = datetime.now().isoformat()
                save_config(config)
                
        else:
            logger.info("Creating default configuration file")
            config = default_config.copy()
            save_config(config)
            
        return config
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return default_config


def validate_and_merge_config(user_config, default_config):
    """Validate and merge user config with defaults"""
    if not isinstance(user_config, dict):
        logger.warning("Invalid configuration format, using defaults")
        return default_config
    
    # Merge settings
    if "settings" in user_config and isinstance(user_config["settings"], dict):
        default_config["settings"].update(user_config["settings"])
    
    # Merge paths
    if "paths" in user_config and isinstance(user_config["paths"], dict):
        default_config["paths"].update(user_config["paths"])
    
    # Merge license info
    if "license_info" in user_config and isinstance(user_config["license_info"], dict):
        default_config["license_info"].update(user_config["license_info"])
    
    return default_config


def save_config(config):
    """Save configuration to file"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.debug(f"Configuration saved to {SETTINGS_FILE}")
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")


def get_computer_fingerprint():
    """Generate a unique computer fingerprint for license binding"""
    try:
        # Get system information
        system_info = []
        
        # CPU information
        try:
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId'], 
                                      capture_output=True, text=True, timeout=10)
                cpu_id = result.stdout.split('\n')[1].strip()
                system_info.append(cpu_id)
            else:
                system_info.append(platform.processor() or "unknown")
        except:
            system_info.append("unknown-cpu")
        
        # Motherboard information
        try:
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.run(['wmic', 'baseboard', 'get', 'SerialNumber'], 
                                      capture_output=True, text=True, timeout=10)
                mb_id = result.stdout.split('\n')[1].strip()
                system_info.append(mb_id)
            else:
                system_info.append("unknown-mb")
        except:
            system_info.append("unknown-mb")
        
        # MAC address
        try:
            mac = uuid.getnode()
            system_info.append(str(mac))
        except:
            system_info.append("unknown-mac")
        
        # Create fingerprint
        fingerprint_data = ":".join(system_info)
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        logger.debug(f"Generated computer fingerprint: {fingerprint[:8]}...")
        return fingerprint
        
    except Exception as e:
        logger.error(f"Failed to generate computer fingerprint: {e}")
        return "unknown-machine"


def hash_sensitive_data(*values: Optional[str], context: str = "default") -> str:
    """Hash sensitive data for logging purposes"""
    combined = f"{context}:{':'.join(str(v) if v else 'None' for v in values)}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def get_detailed_machine_info():
    """Get detailed machine information for debugging"""
    try:
        info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "processor": platform.processor(),
            "machine": platform.machine(),
            "architecture": platform.architecture(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "fingerprint": get_computer_fingerprint()
        }
        return info
    except Exception as e:
        logger.error(f"Failed to get machine info: {e}")
        return {"error": str(e)}


def get_firebase_auth_token(require: bool = True) -> Optional[str]:
    """Get Firebase auth token (placeholder for future implementation)"""
    # This would be implemented if you need Firebase authentication
    # For now, return None as we're using the new license server
    return None


# NEW: Updated license validation using your new server
def bind_license_to_computer(license_key, computer_id):
    """Bind license to computer using new server"""
    try:
        response = requests.post(
            f"{LICENSE_SERVER_URL}/activate",
            headers={'Content-Type': 'application/json'},
            json={
                'license_key': license_key,
                'machine_id': computer_id,
                'email': 'customer@example.com'  # You might want to prompt for this
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                logger.info("License successfully bound to computer")
                return True, "License activated successfully"
            else:
                logger.error(f"License binding failed: {result.get('error')}")
                return False, result.get('error', 'Activation failed')
        else:
            logger.error(f"Server error: {response.status_code}")
            return False, f"Server error: {response.status_code}"
            
    except Exception as e:
        logger.error(f"Network error during license binding: {e}")
        return False, f"Network error: {str(e)}"


# NEW: Updated license validation using your new server
def check_license_with_fingerprint(license_key):
    """Check license validity using new server"""
    try:
        computer_id = get_computer_fingerprint()
        
        response = requests.post(
            f"{LICENSE_SERVER_URL}/validate",
            headers={'Content-Type': 'application/json'},
            json={
                'license_key': license_key,
                'machine_id': computer_id
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('valid'):
                logger.info("License validation successful")
                return {
                    'valid': True,
                    'reason': 'License valid',
                    'expiry': result.get('expiry'),
                    'machine_id': computer_id
                }
            else:
                logger.warning(f"License validation failed: {result.get('error')}")
                return {
                    'valid': False,
                    'reason': result.get('error', 'License invalid')
                }
        else:
            logger.error(f"Server error: {response.status_code}")
            return {'valid': False, 'reason': f'Server error: {response.status_code}'}
            
    except Exception as e:
        logger.error(f"Network error during license validation: {e}")
        return {'valid': False, 'reason': f'Network error: {str(e)}'}


def get_saved_license():
    """Get saved license from local storage"""
    try:
        if not LICENSE_FILE.exists():
            return None
            
        with open(LICENSE_FILE, 'r', encoding='utf-8') as f:
            license_data = json.load(f)
            
        # Validate the saved license
        if 'license_key' in license_data:
            validation_result = check_license_with_fingerprint(license_data['license_key'])
            if validation_result.get('valid'):
                logger.info("Saved license is still valid")
                return license_data
            else:
                logger.warning("Saved license is no longer valid")
                # Remove invalid license
                try:
                    LICENSE_FILE.unlink()
                except:
                    pass
                return None
                
        return None
        
    except Exception as e:
        logger.error(f"Failed to load saved license: {e}")
        return None


def save_license(license_key, additional_data=None):
    """Save license to local storage"""
    try:
        license_data = {
            'license_key': license_key,
            'saved_at': datetime.now().isoformat(),
            'computer_id': get_computer_fingerprint()
        }
        
        if additional_data:
            license_data.update(additional_data)
            
        with open(LICENSE_FILE, 'w', encoding='utf-8') as f:
            json.dump(license_data, f, indent=2, ensure_ascii=False)
            
        logger.info("License saved successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save license: {e}")
        return False


def validate_license_activation():
    """Validate license activation status"""
    try:
        saved_license = get_saved_license()
        if not saved_license:
            return False, "No valid license found"
            
        license_key = saved_license.get('license_key')
        if not license_key:
            return False, "No license key found"
            
        # Validate with server
        validation_result = check_license_with_fingerprint(license_key)
        if validation_result.get('valid'):
            return True, "License is valid"
        else:
            return False, validation_result.get('reason', 'License validation failed')
            
    except Exception as e:
        logger.error(f"License validation error: {e}")
        return False, f"Validation error: {str(e)}"


def check_computer_already_licensed(computer_id):
    """Check if computer is already licensed (placeholder)"""
    # This would check if the computer already has a license
    # For now, we'll let the server handle this
    return False


def show_computer_already_licensed_error(existing_license_key):
    """Show error for already licensed computer"""
    messagebox.showerror(
        "Computer Already Licensed",
        f"This computer is already licensed with key: {mask_license_key(existing_license_key)}\n\n"
        "Please contact support if you need to transfer your license to another computer."
    )


def unbind_computer_from_license(license_key, computer_id):
    """Unbind computer from license (placeholder)"""
    # This would unbind the computer from the license
    # For now, we'll let the server handle this
    return True


class LicenseDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CONFIRM - Professional License Activation")
        self.root.geometry("650x400")  # Professional size
        self.root.resizable(False, False)
        
        # Center the window
        self.root.eval('tk::PlaceWindow . center')
        
        # Variables
        self.license_key = tk.StringVar()
        self.email = tk.StringVar()
        self.result = None
        self.validation_in_progress = False
        
        # Professional styling
        self.root.configure(bg='#f8f9fa')
        
        self.create_widgets()
        
        # Auto-validate on paste or Enter key
        self.license_key.trace('w', self.on_license_changed)
        self.root.bind('<Return>', self.on_enter_pressed)
        
    def create_widgets(self):
        # Professional header
        header_frame = tk.Frame(self.root, bg="#1a365d", height=80)
        header_frame.pack(fill="x", pady=0)
        header_frame.pack_propagate(False)
        
        # Company branding
        tk.Label(header_frame, text="TraceSeis, Inc.®", 
                font=("Arial", 16, "bold"), fg="#ffffff", bg="#1a365d").pack(pady=(15, 2))
        tk.Label(header_frame, text="deltaV solutions division", 
                font=("Arial", 10), fg="#a0aec0", bg="#1a365d").pack(pady=(0, 3))
        tk.Label(header_frame, text="Professional Statistical Analysis Suite", 
                font=("Arial", 11), fg="#e2e8f0", bg="#1a365d").pack()
        
        # Main content
        main_frame = tk.Frame(self.root, bg="#f8f9fa")
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # License activation section
        activation_frame = tk.LabelFrame(main_frame, text="License Activation", 
                                       font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                       padx=20, pady=15)
        activation_frame.pack(fill="x", pady=(0, 20))
        
        # Instructions
        instruction_text = ("Please enter your license key and email below. The software will automatically "
                          "bind to this computer and save your license for future use.")
        tk.Label(activation_frame, text=instruction_text, font=("Arial", 10), 
                bg="#f8f9fa", fg="#4a5568", wraplength=550, justify="left").pack(pady=(0, 15))
        
        # Email entry
        email_frame = tk.Frame(activation_frame, bg="#f8f9fa")
        email_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(email_frame, text="Email Address:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        self.email_entry = tk.Entry(email_frame, textvariable=self.email, 
                                   font=("Arial", 12), width=50, bg="#ffffff", 
                                   fg="#2d3748", relief="solid", bd=1)
        self.email_entry.pack(pady=(5, 0), ipady=8, fill="x")
        
        # License key entry with validation feedback
        entry_frame = tk.Frame(activation_frame, bg="#f8f9fa")
        entry_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(entry_frame, text="License Key:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        self.entry = tk.Entry(entry_frame, textvariable=self.license_key, 
                             font=("Consolas", 12), width=50, bg="#ffffff", 
                             fg="#2d3748", relief="solid", bd=1)
        self.entry.pack(pady=(5, 10), ipady=8, fill="x")
        self.email_entry.focus()
        
        # Status display
        self.status_label = tk.Label(entry_frame, text="Enter your email and license key to continue", 
                                   font=("Arial", 9), bg="#f8f9fa", fg="#718096")
        self.status_label.pack(anchor="w")
        
        # Progress bar for validation
        self.progress = ttk.Progressbar(entry_frame, mode='indeterminate', length=400)
        
        # Action buttons
        button_frame = tk.Frame(activation_frame, bg="#f8f9fa")
        button_frame.pack(fill="x", pady=(15, 0))
        
        # Validate button
        self.validate_btn = tk.Button(button_frame, text="Activate License", 
                                    command=self.validate_license,
                                    font=("Arial", 11, "bold"), bg="#2b6cb0", fg="white",
                                    padx=20, pady=8, relief="flat", cursor="hand2")
        self.validate_btn.pack(side="right", padx=(10, 0))
        
        # Cancel button  
        cancel_btn = tk.Button(button_frame, text="Cancel", command=self.cancel,
                             font=("Arial", 11), bg="#e2e8f0", fg="#4a5568",
                             padx=20, pady=8, relief="flat", cursor="hand2")
        cancel_btn.pack(side="right")
        
        # Computer fingerprint info
        info_frame = tk.LabelFrame(main_frame, text="System Information", 
                                 font=("Arial", 10, "bold"), bg="#f8f9fa", fg="#1a365d",
                                 padx=15, pady=10)
        info_frame.pack(fill="x")
        
        computer_id = get_computer_fingerprint()
        info_text = f"Computer ID: {computer_id}\n\nThis license will be automatically bound to this computer for security purposes."
        tk.Label(info_frame, text=info_text, font=("Consolas", 9), 
                bg="#f8f9fa", fg="#4a5568", justify="left").pack(anchor="w")
    
    def on_license_changed(self, *args):
        """Handle license key input changes"""
        license_key = self.license_key.get().strip()
        email = self.email.get().strip()
        
        if len(license_key) == 0 or len(email) == 0:
            self.status_label.config(text="Enter your email and license key to continue", fg="#718096")
            self.validate_btn.config(state="disabled", bg="#cbd5e0")
        elif len(license_key) < 10:
            self.status_label.config(text="License key too short", fg="#e53e3e")
            self.validate_btn.config(state="disabled", bg="#cbd5e0")
        elif "@" not in email:
            self.status_label.config(text="Please enter a valid email address", fg="#e53e3e")
            self.validate_btn.config(state="disabled", bg="#cbd5e0")
        else:
            self.status_label.config(text="Ready to validate", fg="#38a169")
            self.validate_btn.config(state="normal", bg="#2b6cb0")
    
    def on_enter_pressed(self, event):
        """Handle Enter key press"""
        if not self.validation_in_progress and len(self.license_key.get().strip()) >= 10 and len(self.email.get().strip()) > 0:
            self.validate_license()
    
    def validate_license(self):
        """Validate and activate license"""
        if self.validation_in_progress:
            return
            
        license_key = self.license_key.get().strip()
        email = self.email.get().strip()
        
        if not license_key or not email:
            return
        
        self.validation_in_progress = True
        self.validate_btn.config(state="disabled", text="Validating...", bg="#cbd5e0")
        self.status_label.config(text="Validating license with server...", fg="#3182ce")
        
        # Show progress
        self.progress.pack(pady=(5, 0), fill="x")
        self.progress.start(10)
        
        # Validate in thread to prevent UI blocking
        def validate_thread():
            try:
                # First validate the license
                validation_result = check_license_with_fingerprint(license_key)
                
                if validation_result and validation_result.get("valid"):
                    # License is valid, now activate it
                    success, message = bind_license_to_computer(license_key, get_computer_fingerprint())
                    
                    if success:
                        # Save the license
                        save_license(license_key, {'email': email})
                        validation_result['activated'] = True
                        validation_result['activation_message'] = message
                    else:
                        validation_result['valid'] = False
                        validation_result['reason'] = message
                
                # Update UI from main thread
                self.root.after(0, self.handle_validation_result, validation_result, license_key)
                
            except Exception as e:
                self.root.after(0, self.handle_validation_error, str(e))
        
        threading.Thread(target=validate_thread, daemon=True).start()
    
    def handle_validation_result(self, validation_result, license_key):
        """Handle validation result"""
        self.progress.stop()
        self.progress.pack_forget()
        self.validation_in_progress = False
        
        if validation_result and validation_result.get("valid"):
            # Success - save license and close
            self.status_label.config(text="License activated successfully!", fg="#38a169")
            self.validate_btn.config(text="Success", bg="#38a169")
            
            # Save the result
            self.result = {
                'license_key': license_key,
                'validation_result': validation_result
            }
            
            # Auto-close after brief delay
            self.root.after(1500, self.root.quit)
            
        else:
            # Failed validation
            reason = validation_result.get("reason", "Unknown error") if validation_result else "Validation failed"
            self.status_label.config(text=f"Activation failed: {reason}", fg="#e53e3e")
            self.validate_btn.config(state="normal", text="Retry Activation", bg="#e53e3e")
    
    def handle_validation_error(self, error_msg):
        """Handle validation error"""
        self.progress.stop()
        self.progress.pack_forget()
        self.validation_in_progress = False
        
        self.status_label.config(text=f"Error: {error_msg}", fg="#e53e3e")
        self.validate_btn.config(state="normal", text="Retry Activation", bg="#e53e3e")
    
    def cancel(self):
        """Cancel license activation"""
        self.result = None
        self.root.quit()
        
    def show(self):
        """Show the license dialog and return result"""
        self.root.mainloop()
        return self.result


# Continue with the rest of your original CONFIRM application code...
# I'll include the rest of the file in the next part

# This is just the beginning - I need to copy the rest of your original file
# Let me continue with the rest of the application code
