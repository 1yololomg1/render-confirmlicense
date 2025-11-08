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

CONFIRM Statistical Analysis Suite
Professional statistical analysis software with integrated license management
"""

import requests
import json
import os
import hashlib
import base64
import platform
import uuid
from datetime import datetime, date
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
import sys
import logging
from pathlib import Path
import signal
import atexit
import secrets
from typing import Optional
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import seaborn as sns
from scipy.stats import chi2_contingency, pearsonr
from scipy.ndimage import uniform_filter1d
import traceback
import time
from math import pi
import threading
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures
import tempfile
import zipfile
import shutil
import weakref
import gc

# Import commercial protection module
PROTECTION_AVAILABLE = False
PROTECTION_ERROR = None
try:
    from protection_module import initialize_protection, cleanup_protection
    PROTECTION_AVAILABLE = True
except ImportError as e:
    PROTECTION_ERROR = str(e)
    PROTECTION_AVAILABLE = False
    # Log error will be done after logger is initialized
except Exception as e:
    PROTECTION_ERROR = f"Unexpected error importing protection_module: {str(e)}"
    PROTECTION_AVAILABLE = False

try:
    from cryptography.fernet import Fernet, InvalidToken
    _FERNET_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    Fernet = None
    InvalidToken = Exception
    _FERNET_AVAILABLE = False

# Configuration and Constants
FIREBASE_URL = os.getenv("CONFIRM_FIREBASE_URL", "https://confirm-license-manager-default-rtdb.firebaseio.com")
# NEW: License server configuration
LICENSE_SERVER_URL = os.getenv("CONFIRM_LICENSE_SERVER_URL", "https://render-confirmlicense.onrender.com")
APP_NAME = "CONFIRM Statistical Validation Engine"
APP_VERSION = "1.0.0"
# Use %LOCALAPPDATA% on Windows, fallback to home directory on other platforms
local_app_data = os.getenv("LOCALAPPDATA")
if local_app_data and platform.system() == "Windows":
    CONFIG_DIR = Path(local_app_data) / "CONFIRM"
else:
    CONFIG_DIR = Path.home() / ".confirm"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
LICENSE_FILE = CONFIG_DIR / "confirm_license.json"
LOG_FILE = CONFIG_DIR / "confirm.log"

# Timeout and Performance Constants
NETWORK_REQUEST_TIMEOUT = int(os.getenv("CONFIRM_NETWORK_TIMEOUT", "15"))
OFFLINE_GRACE_PERIOD_HOURS = int(os.getenv("CONFIRM_OFFLINE_GRACE_HOURS", "72"))
LICENSE_MASK_PREFIX_LENGTH = 4
LICENSE_MASK_SUFFIX_LENGTH = 4
MAX_WORKERS = int(os.getenv("CONFIRM_MAX_WORKERS", "2"))
THREAD_POOL_TIMEOUT = 30
EMERGENCY_CLEANUP_TIMEOUT = 10

# Version and Contact Information
__version__ = "1.0.0"
__author__ = "TraceSeis, Inc."
__copyright__ = "Copyright (C) 2025 TraceSeis, Inc."
__license__ = "TraceSeis, Inc. Commercial License"
__contact__ = "info@traceseis.com"

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

# Log protection module import status
if PROTECTION_AVAILABLE:
    logger.info("Protection module imported successfully")
else:
    if PROTECTION_ERROR:
        logger.warning(f"Protection module import failed: {PROTECTION_ERROR}")
        logger.warning("Commercial protection features will not be available")
    else:
        logger.warning("Protection module not available - commercial protection disabled")


class SecurityError(Exception):
    """Custom exception for security-related failures."""


def mask_license_key(license_key: Optional[str]) -> str:
    """Redact sensitive portions of a license key for logging or UI display."""
    if not license_key:
        return "<empty>"

    sanitized = license_key.strip()
    if len(sanitized) <= 16:
        return f"{sanitized[:LICENSE_MASK_PREFIX_LENGTH]}***{sanitized[-LICENSE_MASK_SUFFIX_LENGTH:]}"

    return f"{sanitized[:LICENSE_MASK_PREFIX_LENGTH]}***{sanitized[-LICENSE_MASK_SUFFIX_LENGTH:]}"


def is_within_offline_grace_period(last_validated):
    """Check if last validation is within grace period"""
    if not last_validated:
        return False
    last_validated_dt = datetime.fromisoformat(last_validated)
    hours_since = (datetime.now() - last_validated_dt).total_seconds() / 3600
    return hours_since <= OFFLINE_GRACE_PERIOD_HOURS


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
        if not self._SALT_FILE.exists():
            salt = secrets.token_bytes(16)
            try:
                self._SALT_FILE.write_bytes(salt)
                try:
                    os.chmod(self._SALT_FILE, 0o600)
                except Exception:  # pragma: no cover - platform specific
                    pass
            except Exception as exc:
                logger.error(f"Unable to persist encryption salt: {exc}")
                raise SecurityError("Encryption salt persistence failed") from exc
        else:
            salt = self._SALT_FILE.read_bytes()

        if len(salt) < 16:
            raise SecurityError("Encryption salt is invalid")

        return salt

    def _derive_key(self) -> bytes:
        fingerprint = get_computer_fingerprint()
        salt = self._load_or_create_salt()
        key_material = hashlib.pbkdf2_hmac(
            "sha256",
            fingerprint.encode("utf-8"),
            salt,
            390000,
            dklen=32
        )
        return base64.urlsafe_b64encode(key_material)

    def encrypt(self, payload: str) -> str:
        if not (self.available and self._fernet):
            raise SecurityError("License encryption is unavailable")
        token = self._fernet.encrypt(payload.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, token: str) -> str:
        if not (self.available and self._fernet):
            raise SecurityError("License encryption is unavailable")
        try:
            decrypted = self._fernet.decrypt(token.encode("utf-8"))
            return decrypted.decode("utf-8")
        except InvalidToken as exc:
            raise SecurityError("Invalid encrypted license payload") from exc

    def integrity_hash(self, payload: str) -> str:
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return digest

# Configuration Management
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
        },
        "security": {
            "require_auth_token": True,
            "auth_token": None,
            "allow_legacy_license_requests": False
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
            
        # Ensure required directories exist
        for dir_key, dir_path in config["paths"].items():
            try:
                Path(dir_path).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"Failed to create directory {dir_path}: {e}")
        
        logger.info("Configuration loaded successfully")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        logger.info("Using default configuration")
        return default_config

def validate_and_merge_config(user_config, default_config):
    """Validate user configuration and merge with defaults"""
    try:
        # Start with defaults
        merged_config = default_config.copy()
        
        # Merge user settings, validating each section
        for section, defaults in default_config.items():
            if section in user_config:
                if isinstance(defaults, dict):
                    # Merge dict sections
                    for key, default_value in defaults.items():
                        if key in user_config[section]:
                            # Validate type matches
                            user_value = user_config[section][key]
                            if type(user_value) == type(default_value):
                                merged_config[section][key] = user_value
                            else:
                                logger.warning(f"Config type mismatch for {section}.{key}: expected {type(default_value)}, got {type(user_value)}")
                else:
                    # Simple value
                    if type(user_config[section]) == type(defaults):
                        merged_config[section] = user_config[section]
        
        return merged_config
        
    except Exception as e:
        logger.error(f"Config validation failed: {e}")
        return default_config

def save_config(config):
    """Save configuration to file"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.debug("Configuration saved successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")
        return False

# Load configuration at startup
app_config = load_or_create_config()

def get_computer_fingerprint():
    """Create unique computer ID for license binding with comprehensive error handling"""
    try:
        logger.debug("Generating computer fingerprint...")
        
        # Primary method: MAC address + system info
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0,2*6,2)][::-1])
        system_info = platform.system() + platform.release()
        processor = platform.processor() or "unknown"
        
        computer_data = f"{mac_address}_{system_info}_{processor}"
        fingerprint = hashlib.md5(computer_data.encode()).hexdigest()[:12]
        
        logger.debug(f"Generated fingerprint: {fingerprint}")
        return fingerprint
        
    except Exception as e:
        logger.warning(f"Primary fingerprint method failed: {e}, using fallback")
        
        # Fallback method: hostname-based
        try:
            fallback_data = platform.node() or "unknown_host"
            fingerprint = hashlib.md5(fallback_data.encode()).hexdigest()[:12]
            logger.debug(f"Fallback fingerprint: {fingerprint}")
            return fingerprint
        except Exception as fallback_error:
            logger.error(f"All fingerprint methods failed: {fallback_error}")
            # Ultimate fallback
            return "emergency_id"


def hash_sensitive_data(*values: Optional[str], context: str = "default") -> str:
    """Generate a deterministic hash for sensitive fields so raw data is never stored."""
    normalized = "||".join((value or "unknown") for value in values)
    fingerprint = get_computer_fingerprint()
    composite = f"{context}:{fingerprint}:{normalized}"
    digest = hashlib.sha256(composite.encode("utf-8")).hexdigest()
    return digest

def get_detailed_machine_info():
    """Get comprehensive machine information for license binding"""
    try:
        import socket
        
        machine_info = {
            'os_name': platform.system(),
            'os_version': platform.release(),
            'architecture': platform.architecture()[0],
            'python_version': platform.python_version(),
            'machine_hash': hash_sensitive_data(
                platform.node(),
                platform.machine(),
                platform.processor(),
                socket.gethostname() if socket else None,
                context="machine_profile"
            ),
            'metadata_version': 2
        }

        logger.debug("Collected sanitized machine info for binding")
        return machine_info
        
    except Exception as e:
        logger.warning(f"Failed to collect detailed machine info: {e}")
        return {
            'os_name': platform.system() if callable(getattr(platform, 'system', None)) else 'unknown',
            'metadata_version': 2,
            'error': 'collection_failed'
        }


license_encryption_manager = LicenseEncryptionManager()


def get_firebase_auth_token(require: bool = True) -> Optional[str]:
    """Retrieve the Firebase auth token from environment or configuration."""
    security_config = app_config.get("security", {}) if isinstance(app_config, dict) else {}
    token = os.environ.get("CONFIRM_FIREBASE_AUTH_TOKEN") or security_config.get("auth_token")

    if token:
        return token

    require_token = security_config.get("require_auth_token", True)
    if require and require_token:
        raise SecurityError("Firebase authentication token is required but not configured.")

    if require_token:
        logger.warning("Firebase authentication token missing; requests may be rejected.")

    return None


def bind_license_to_computer(license_key, computer_id):
    """Automatically binds license to computer in Firebase database"""
    masked_license = mask_license_key(license_key)
    logger.info(f"Automatically binding license {masked_license} to computer {computer_id}")
    
    try:
        # Update Firebase with computer binding
        url = f"{FIREBASE_URL}/license/{license_key}.json"
        auth_token = get_firebase_auth_token()
        params = {'auth': auth_token} if auth_token else None

        # First get existing license data
        response = requests.get(url, params=params, timeout=NETWORK_REQUEST_TIMEOUT)
        response.raise_for_status()
        
        license_data = response.json()
        if not license_data:
            logger.error(f"License {masked_license} not found in database")
            return False
        
        # Add computer binding with detailed machine info
        machine_info = get_detailed_machine_info()
        license_data['computer_id'] = computer_id
        license_data['bound_at'] = datetime.now().isoformat()
        license_data['binding_method'] = 'automatic'
        license_data['machine_info'] = machine_info
        
        # Update the license in Firebase
        response = requests.patch(url, params=params, json=license_data, timeout=NETWORK_REQUEST_TIMEOUT)
        response.raise_for_status()
        
        logger.info(f"Successfully bound license {masked_license} to computer {computer_id}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to bind license {masked_license}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error binding license {masked_license}: {e}")
        return False

def check_license_with_fingerprint(license_key):
    """Enhanced license validation with comprehensive error handling and logging"""
    if not license_key or not license_key.strip():
        logger.error("Empty or invalid license key provided")
        return {"valid": False, "reason": "Invalid license key format"}
    
    computer_id = get_computer_fingerprint()
    masked_license = mask_license_key(license_key)
    logger.info(f"Validating license {masked_license} for computer ID: {computer_id}")
    
    try:
        # Use Render server instead of direct Firebase connection
        url = f"{LICENSE_SERVER_URL}/validate"
        logger.debug(f"Checking license for key {masked_license}")
        
        # Make request to Render server
        response = requests.post(url, 
                               headers={'Content-Type': 'application/json'},
                               json={'license_key': license_key.strip(), 'machine_id': computer_id},
                               timeout=NETWORK_REQUEST_TIMEOUT)
        response.raise_for_status()  # Raise exception for HTTP errors
        
        data = response.json()
        logger.debug(f"License validation response: {bool(data)}")
        
        if data.get('valid'):
            logger.info(f"License validation successful: {masked_license}")
            return {
                "valid": True,
                "reason": "License valid",
                "expiry": data.get('expiry'),
                "machine_id": computer_id
            }
        else:
            error_msg = data.get('error', 'License validation failed')
            logger.warning(f"License validation failed: {masked_license} - {error_msg}")
            return {"valid": False, "reason": error_msg}
        
    except SecurityError as sec_err:
        logger.error(f"Security configuration error during license validation: {sec_err}")
        return {"valid": False, "reason": str(sec_err)}

    except requests.exceptions.Timeout:
        logger.error("License validation timeout - checking offline grace period")
        return check_offline_grace_period()
    
    except requests.exceptions.ConnectionError:
        logger.error("License validation connection failed - checking offline grace period")
        return check_offline_grace_period()
    
    except requests.exceptions.RequestException as req_error:
        logger.error(f"License validation request failed: {req_error}")
        return check_offline_grace_period()
    
    except Exception as e:
        logger.error(f"Unexpected error during license validation for {masked_license}: {e}")
        return check_offline_grace_period()


def check_offline_grace_period():
    """Check if we're within the offline grace period"""
    try:
        # Try to load saved license to check last validation time
        saved_license = get_saved_license()
        if saved_license and saved_license.get('validated_at'):
            last_validated = saved_license['validated_at']
            if is_within_offline_grace_period(last_validated):
                logger.info(f"Within offline grace period (last validated: {last_validated})")
                return {"valid": True, "tier": "offline", "expires": "unknown", "reason": "Offline grace period"}
            else:
                logger.warning(f"Offline grace period expired (last validated: {last_validated})")
                return {"valid": False, "reason": "Offline grace period expired - internet connection required"}
        else:
            logger.warning("No saved license found for offline grace period check")
            return {"valid": False, "reason": "No saved license - internet connection required"}
    except Exception as e:
        logger.error(f"Error checking offline grace period: {e}")
        return {"valid": False, "reason": "Offline grace period check failed - internet connection required"}

def get_saved_license():
    """Check for saved license with improved error handling and path management"""
    try:
        logger.debug(f"Checking for saved license at: {LICENSE_FILE}")
        
        if not LICENSE_FILE.exists():
            logger.debug("No saved license file found")
            return None
            
        with open(LICENSE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'payload' in data:
            if not license_encryption_manager.available:
                logger.error("Encrypted license payload detected but encryption is unavailable")
                return None

            try:
                decrypted_payload = license_encryption_manager.decrypt(data['payload'])
                expected_integrity = data.get('integrity')
                if expected_integrity and expected_integrity != license_encryption_manager.integrity_hash(decrypted_payload):
                    logger.error("Encrypted license payload failed integrity verification")
                    return None
                license_payload = json.loads(decrypted_payload)
            except (json.JSONDecodeError, SecurityError) as exc:
                logger.error(f"Failed to decrypt stored license payload: {exc}")
                return None

            license_key = license_payload.get('license_key')
            if license_key:
                logger.info("Loaded encrypted license payload")
                return license_payload  # Return full dict, not just key

            logger.warning("Encrypted license payload missing license key")
            return None

        # Legacy plaintext support (will be migrated automatically if encryption is available)
        legacy_key = data.get('license_key')
        if legacy_key and license_encryption_manager.available:
            logger.warning("Legacy plaintext license file detected; upgrading to encrypted format.")
            additional = {k: v for k, v in data.items() if k != 'license_key'}
            if save_license(legacy_key, additional):
                # Return as dict format
                return {
                    'license_key': legacy_key.strip(),
                    'saved_at': data.get('saved_at'),
                    'computer_id': data.get('computer_id'),
                    'metadata': additional
                }
            logger.error("Failed to upgrade legacy license file to encrypted format")
            return None

        if legacy_key:
            logger.error("Legacy plaintext license detected but encryption is unavailable; license will not be cached.")
            return None

        logger.warning("License file exists but contains no recognizable payload")
        return None
            
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in license file: {e}")
        return None
    except Exception as e:
        logger.error(f"Error reading saved license: {e}")
        return None

def save_license(license_key, additional_data=None):
    """Save license key to file with comprehensive error handling"""
    try:
        if not license_encryption_manager.available:
            logger.error("Cannot persist license securely because encryption is unavailable")
            return False

        logger.info("Saving license key securely...")

        license_payload = {
            'license_key': license_key.strip(),
            'saved_at': datetime.now().isoformat(),
            'computer_id': get_computer_fingerprint()
        }

        if additional_data:
            license_payload['metadata'] = additional_data

        payload_json = json.dumps(license_payload, ensure_ascii=False)
        encrypted_payload = license_encryption_manager.encrypt(payload_json)
        secured_content = {
            'version': 1,
            'payload': encrypted_payload,
            'integrity': license_encryption_manager.integrity_hash(payload_json)
        }

        with open(LICENSE_FILE, 'w', encoding='utf-8') as f:
            json.dump(secured_content, f, indent=2, ensure_ascii=False)

        logger.info(f"Encrypted license saved successfully to {LICENSE_FILE}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save license: {e}")
        return False

def validate_license_activation():
    """Complete license validation workflow with enhanced security"""
    logger.info("Starting license validation workflow...")
    
    # First check for saved license
    saved_license_data = get_saved_license()
    
    if saved_license_data:
        logger.info("Found saved license, validating...")
        saved_license_key = saved_license_data.get('license_key', '').strip()
        validation_result = check_license_with_fingerprint(saved_license_key)
        
        if validation_result["valid"]:
            logger.info("Saved license is valid - computer already activated")
            # Update validated_at timestamp to prevent re-prompting
            try:
                save_license(saved_license_key, {
                    'tier': validation_result.get('tier'),
                    'expires': validation_result.get('expires'),
                    'validated_at': datetime.now().isoformat()
                })
                logger.debug("Updated license validation timestamp")
            except Exception as e:
                logger.warning(f"Failed to update license timestamp (non-critical): {e}")
            return validation_result
        else:
            logger.warning(f"Saved license invalid: {validation_result.get('reason', 'Unknown error')}")
            # Don't immediately delete - might be temporary network issue
            if not validation_result.get("reason", "").startswith("Network"):
                logger.info("Removing invalid saved license")
                try:
                    LICENSE_FILE.unlink(missing_ok=True)
                except Exception as e:
                    logger.error(f"Failed to remove invalid license file: {e}")
    
    # SECURITY CHECK: Verify this computer isn't already bound to another license
    computer_id = get_computer_fingerprint()
    logger.info(f"Checking if computer {computer_id} is already licensed...")
    
    existing_license = check_computer_already_licensed(computer_id)
    if existing_license:
        logger.critical(f"SECURITY VIOLATION: Computer already bound to license {mask_license_key(existing_license)}")
        show_computer_already_licensed_error(existing_license)
        return None
    
    # Need to get license from user
    logger.info("Requesting license key from user...")
    
    # Try to get license through dialog
    dialog = LicenseDialog()
    dialog.root.mainloop()
    
    if dialog.result and dialog.result.get('license_key'):
        license_key = dialog.result['license_key']
        logger.info(f"User provided license key {mask_license_key(license_key)}, validating...")
        
        validation_result = check_license_with_fingerprint(license_key)
        
        if validation_result["valid"]:
            logger.info("User license key is valid, saving...")
            saved = save_license(license_key, {
                'tier': validation_result.get('tier'),
                'expires': validation_result.get('expires'),
                'validated_at': datetime.now().isoformat()
            })
            if not saved:
                logger.error("Failed to persist license securely; license will need to be re-entered next launch.")
            return validation_result
        else:
            logger.error(f"User license key invalid: {validation_result.get('reason')}")
            messagebox.showerror("License Error", 
                               f"License validation failed: {validation_result.get('reason')}")
            return None
    else:
        logger.warning("User cancelled license entry")
        return None

def check_computer_already_licensed(computer_id):
    """Check if this computer is already bound to any license in Firebase"""
    try:
        logger.debug(f"Scanning Firebase for computer {computer_id}...")
        
        auth_token = get_firebase_auth_token()
        params = {
            'auth': auth_token
        } if auth_token else {}

        # Query for licenses bound to this computer only
        params.update({
            'orderBy': json.dumps('computer_id'),
            'equalTo': json.dumps(computer_id),
            'limitToFirst': 1
        })

        url = f"{FIREBASE_URL}/license.json"
        response = requests.get(url, params=params, timeout=NETWORK_REQUEST_TIMEOUT)
        response.raise_for_status()
        
        all_licenses = response.json()
        if not all_licenses:
            logger.debug("No licenses found in database")
            return None
        
        # Check each license for this computer_id
        for license_key, license_data in all_licenses.items():
            if isinstance(license_data, dict):
                stored_computer_id = license_data.get('computer_id')
                if stored_computer_id == computer_id:
                    logger.warning(f"Computer {computer_id} already bound to license {mask_license_key(license_key)}")
                    return license_key
        
        logger.debug(f"Computer {computer_id} not found in any existing licenses")
        return None
        
    except SecurityError as sec_err:
        logger.error(f"Security configuration error during license lookup: {sec_err}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to check computer licensing: {e}")
        # In case of network error, allow activation (fail-open for user experience)
        return None
    except Exception as e:
        logger.error(f"Unexpected error checking computer licensing: {e}")
        return None

def show_computer_already_licensed_error(existing_license_key):
    """Show error dialog when computer is already licensed"""
    try:
        masked_license = mask_license_key(existing_license_key)
        root = tk.Tk()
        root.withdraw()
        
        error_message = f"""Computer Already Licensed

This computer is already activated with license:
{masked_license}

Security Policy:
• Each computer can only use ONE license at a time
• To use a different license, contact support
• This prevents license sharing violations

Contact: info@deltavsolutions.com"""

        messagebox.showerror("License Security Violation", error_message)
        root.destroy()
        
    except Exception as e:
        logger.error(f"Failed to show security error dialog: {e}")

def unbind_computer_from_license(license_key, computer_id):
    """Unbind computer from a license (admin function)"""
    try:
        masked_license = mask_license_key(license_key)
        logger.info(f"Unbinding computer {computer_id} from license {masked_license}")
        
        url = f"{FIREBASE_URL}/license/{license_key}.json"
        auth_token = get_firebase_auth_token()
        params = {'auth': auth_token} if auth_token else None

        response = requests.get(url, params=params, timeout=NETWORK_REQUEST_TIMEOUT)
        response.raise_for_status()
        
        license_data = response.json()
        if not license_data:
            logger.error(f"License {masked_license} not found")
            return False
        
        # Remove computer binding
        license_data['computer_id'] = None
        license_data['bound_at'] = None
        license_data['binding_method'] = None
        license_data['unbound_at'] = datetime.now().isoformat()
        license_data['unbound_reason'] = 'administrative_reset'
        
        # Update Firebase
        response = requests.patch(url, params=params, json=license_data, timeout=NETWORK_REQUEST_TIMEOUT)
        response.raise_for_status()
        
        logger.info(f"Successfully unbound computer {computer_id} from license {masked_license}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to unbind computer from license {masked_license}: {e}")
        return False

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
        instruction_text = ("Please enter your license key below. The software will automatically "
                          "bind to this computer and save your license for future use.")
        tk.Label(activation_frame, text=instruction_text, font=("Arial", 10), 
                bg="#f8f9fa", fg="#4a5568", wraplength=550, justify="left").pack(pady=(0, 15))
        
        # License key entry with validation feedback
        entry_frame = tk.Frame(activation_frame, bg="#f8f9fa")
        entry_frame.pack(fill="x", pady=(0, 10))
        
        tk.Label(entry_frame, text="License Key:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        self.entry = tk.Entry(entry_frame, textvariable=self.license_key, 
                             font=("Consolas", 12), width=50, bg="#ffffff", 
                             fg="#2d3748", relief="solid", bd=1)
        self.entry.pack(pady=(5, 10), ipady=8, fill="x")
        self.entry.focus()
        
        # Status display
        self.status_label = tk.Label(entry_frame, text="Enter your license key to continue", 
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
        
        if len(license_key) == 0:
            self.status_label.config(text="Enter your license key to continue", fg="#718096")
            self.validate_btn.config(state="disabled", bg="#cbd5e0")
        elif len(license_key) < 10:
            self.status_label.config(text="License key too short", fg="#e53e3e")
            self.validate_btn.config(state="disabled", bg="#cbd5e0")
        else:
            self.status_label.config(text="Ready to validate", fg="#38a169")
            self.validate_btn.config(state="normal", bg="#2b6cb0")
    
    def on_enter_pressed(self, event):
        """Handle Enter key press"""
        if not self.validation_in_progress and len(self.license_key.get().strip()) >= 10:
            self.validate_license()
    
    def validate_license(self):
        """Validate license key automatically"""
        if self.validation_in_progress:
            return
            
        license_key = self.license_key.get().strip()
        if not license_key:
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
                validation_result = check_license_with_fingerprint(license_key)
                
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
        

# Thread Pool Safety Constants (moved from top constants section)

class SafeThreadPoolManager:
    """
    Thread-safe thread pool manager with comprehensive cleanup and error handling.
    Prevents resource leaks and ensures graceful shutdown even under failure conditions.
    """
    def __init__(self, max_workers=None):
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        self._executor = None
        self._lock = threading.Lock()
        self._shutdown_called = False
        self._active_futures = set()
        
        # Register cleanup on program exit
        atexit.register(self._emergency_cleanup)
        
    def get_executor(self):
        """Thread-safe lazy initialization of thread pool executor"""
        if self._executor is None or self._executor._shutdown:
            with self._lock:
                if self._executor is None or self._executor._shutdown:
                    self._executor = concurrent.futures.ThreadPoolExecutor(
                        max_workers=self.max_workers,
                        thread_name_prefix="StatisticalAnalyzer"
                    )
        return self._executor
    
    def submit_task(self, fn, *args, **kwargs):
        """Submit a task and track it for cleanup"""
        executor = self.get_executor()
        future = executor.submit(fn, *args, **kwargs)
        
        with self._lock:
            self._active_futures.add(future)
            # Remove completed futures to prevent memory leaks
            self._active_futures = {f for f in self._active_futures if not f.done()}
        
        return future
    
    def shutdown(self, wait=True, timeout=THREAD_POOL_TIMEOUT):
        """Comprehensive shutdown with timeout and cleanup"""
        if self._shutdown_called:
            return True
            
        self._shutdown_called = True
        
        if self._executor is None:
            return True
            
        try:
            # Cancel all pending futures first
            with self._lock:
                for future in list(self._active_futures):
                    if not future.done():
                        future.cancel()
                self._active_futures.clear()
            
            # Cancel pending tasks in executor
            if hasattr(self._executor, '_threads'):
                with self._executor._shutdown_lock:
                    self._executor._shutdown = True
                    
            # Attempt graceful shutdown
            self._executor.shutdown(wait=False)
            
            if wait:
                # Wait with timeout
                start_time = time.time()
                while self._executor._threads and (time.time() - start_time) < timeout:
                    time.sleep(0.1)
                    
                # Force shutdown if still running
                if self._executor._threads:
                    logger.warning("Forcing thread pool shutdown after timeout")
                    # Last resort - mark executor as shutdown
                    for thread in list(self._executor._threads):
                        if thread.is_alive():
                            thread.join(timeout=1)
                            
            return True
            
        except Exception as e:
            logger.error(f"Error during thread pool shutdown: {e}")
            return False
        finally:
            self._executor = None
    
    def _emergency_cleanup(self):
        """Emergency cleanup called by atexit"""
        if not self._shutdown_called:
            logger.critical("Emergency thread pool cleanup...")
            self.shutdown(wait=True, timeout=EMERGENCY_CLEANUP_TIMEOUT)

def signal_handler(signum, frame):
    """Handle Ctrl+C and other interrupt signals gracefully"""
    logger.info("Received interrupt signal, cleaning up...")
    # Force cleanup and exit
    sys.exit(0)

# Register signal handlers for graceful shutdown
signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)

class VisualizationWindow:
    """Separate window for displaying visualizations with better UI"""
    def __init__(self, parent, analyzer):
        self.parent = parent
        self.analyzer = analyzer
        self.window = None
        self.notebook = None
        
    def create_window(self):
        """Create the visualization window"""
        self.window = tk.Toplevel(self.parent)
        self.window.title("CONFIRM Statistical Analysis - Visualizations")
        self.window.geometry("2000x900")  # Much wider to show all charts without cutoff
        self.window.configure(bg='#f5f5f5')
        
        # Center the window on screen
        self.center_window()
        
        # Make window resizable
        self.window.resizable(True, True)
        
        # Setup the UI
        self.setup_ui()
        
        # Bind close event
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        return self.window
    
    def center_window(self):
        """Center the visualization window on screen"""
        self.window.update_idletasks()
        
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        
        window_width = 1500
        window_height = 900
        
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        self.window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    def setup_ui(self):
        """Setup the visualization window UI"""
        # Main container
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title section
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = ttk.Label(title_frame, text="ANALYSIS VISUALIZATIONS", 
                               font=('Arial', 18, 'bold'), foreground='darkblue')
        title_label.pack(side=tk.LEFT)
        
        # Status info
        if hasattr(self.analyzer, 'batch_results') and self.analyzer.batch_results:
            status_text = f"Multi-Sheet Analysis ({len(self.analyzer.batch_results)} sheets)"
        else:
            status_text = "Single Sheet Analysis"
        
        status_label = ttk.Label(title_frame, text=status_text,
                                font=('Arial', 12), foreground='green')
        status_label.pack(side=tk.RIGHT)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(button_frame, text="Export All Charts", 
                  command=self.export_all_charts, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Refresh", 
                  command=self.refresh_visualizations, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Close Window", 
                  command=self.on_close, width=15).pack(side=tk.RIGHT)
        
        # Create notebook for tabs with larger size
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Load visualizations
        self.load_visualizations()
    
    def load_visualizations(self):
        """Load all available visualizations into the window"""
        try:
            if hasattr(self, 'notebook') and self.notebook:
                for tab in self.notebook.tabs():
                    self.notebook.forget(tab)
            
            # Check if we have batch results (multi-sheet) or single sheet
            if hasattr(self.analyzer, 'batch_results') and self.analyzer.batch_results:
                if len(self.analyzer.batch_results) > 1:
                    self.create_multi_sheet_visualizations()
                else:
                    self.create_single_sheet_visualizations()
            elif hasattr(self.analyzer, 'confusion_matrix') and self.analyzer.confusion_matrix is not None:
                self.create_single_sheet_visualizations()
            else:
                logger.warning("No valid data available for visualization")
                self.create_placeholder()
        except Exception as e:
            logger.warning(f"Failed to load visualizations: {e}")
            self.create_error_tab(str(e))
    
    def create_multi_sheet_visualizations(self):
        """Create visualizations for multi-sheet analysis"""
        try:
            # Summary Dashboard
            self.create_summary_dashboard_in_window()
            
            # Performance Comparison
            self.create_performance_comparison_in_window()
            
            # NEW: Multi-Sheet Side-by-Side View
            self.create_multi_sheet_side_by_side_view()
            
            # Individual Sheet Details (enhanced)
            self.create_individual_sheets_in_window()
            
            # NEW: All Sheets Combined View
            self.create_all_sheets_combined_view()
            
            # NEW: Multi-Sheet Radar Analysis
            self.create_multi_sheet_radar_analysis_in_window()
            
            # NEW: Multi-Sheet Pie Chart Analysis
            self.create_multi_sheet_pie_chart_analysis_in_window()
            
        except Exception as e:
            self.create_error_tab(f"Multi-sheet visualization error: {str(e)}")
    
    def create_single_sheet_visualizations(self):
        """Create visualizations for single sheet analysis"""
        try:
            # Get the single sheet data
            if hasattr(self.analyzer, 'batch_results') and self.analyzer.batch_results:
                sheet_name = list(self.analyzer.batch_results.keys())[0]
                sheet_data = self.analyzer.batch_results[sheet_name]
            else:
                sheet_name = "Current Analysis"
                sheet_data = None
            
            # Confusion Heatmap
            self.create_confusion_heatmap_in_window()
            
            # Distribution Charts
            self.create_distribution_charts_in_window()
            
            # Metrics Comparison
            self.create_metrics_comparison_in_window()
            
            # Radar Chart Analysis
            self.create_radar_analysis_in_window()
            
            # Pie Chart Analysis
            self.create_pie_chart_analysis_in_window()
            
        except Exception as e:
            self.create_error_tab(f"Single-sheet visualization error: {str(e)}")
    
    def create_summary_dashboard_in_window(self):
        """Create summary dashboard tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Summary Dashboard")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Add content
        if hasattr(self.analyzer, 'comparison_summary') and self.analyzer.comparison_summary is not None:
            self.create_comparison_summary_content(scrollable_frame)
        else:
            ttk.Label(scrollable_frame, text="No comparison data available", 
                     font=('Arial', 14)).pack(pady=50)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling: bind to the figure widget as well
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
        # Bind to any Matplotlib figures in the frame
        for child in scrollable_frame.winfo_children():
            try:
                if hasattr(child, 'bind'):
                    child.bind("<MouseWheel>", _on_mousewheel)
                    child.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
                    child.bind("<Button-4>", _on_mousewheel)
                    child.bind("<Button-5>", _on_mousewheel)
                    child.bind("<Shift-Button-4>", _on_shift_mousewheel)
                    child.bind("<Shift-Button-5>", _on_shift_mousewheel)
            except Exception:
                pass
    
    def create_comparison_summary_content(self, parent):
        """Create the comparison summary content"""
        # Title
        title_label = ttk.Label(parent, text="MULTI-SHEET ANALYSIS SUMMARY", 
                               font=('Arial', 16, 'bold'), foreground='darkblue')
        title_label.pack(pady=(20, 30))
        
        # Best configuration highlight
        best_config = self.analyzer.comparison_summary.iloc[0]
        
        best_frame = ttk.LabelFrame(parent, text="BEST CONFIGURATION", padding="15")
        best_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        best_info = f"""Sheet: {best_config['SOM_Config']}
Classification Accuracy: {best_config['Global_Fit']:.1f}%
Association Strength (Cramer's V): {best_config['Cramers_V']:.3f}
Neuron Utilization: {best_config['Utilization']:.1f}%
Total Samples: {best_config['Total_Samples']:,}"""
        
        ttk.Label(best_frame, text=best_info, font=('Arial', 12), 
                 foreground='darkgreen').pack()
        
        # Summary table
        table_frame = ttk.LabelFrame(parent, text="ALL CONFIGURATIONS", padding="15")
        table_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Create treeview for better table display
        columns = ['Rank', 'Sheet', 'Classification Accuracy', 'Association Strength (Cramer\'s V)', 'Neuron Utilization', 'Samples']
        tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=12)  # Increased height to show all rows
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor='center')
        
        # Add data
        for _, row in self.analyzer.comparison_summary.iterrows():
            tree.insert('', 'end', values=(
                int(row['Rank']),
                row['SOM_Config'],
                f"{row['Global_Fit']:.1f}%",
                f"{row['Cramers_V']:.3f}",
                f"{row['Utilization']:.1f}%",
                f"{row['Total_Samples']:,}"
            ))
        
        tree.pack(fill=tk.X)
        
        # Add scrollbar for table
        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_performance_comparison_in_window(self):
        """Create performance comparison charts"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Performance Comparison")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Create figure with subplots
        fig = Figure(figsize=(15, 10), dpi=100, facecolor='white')
        
        # Accuracy comparison
        ax1 = fig.add_subplot(2, 2, 1)
        sheets = self.analyzer.comparison_summary['SOM_Config']
        accuracies = self.analyzer.comparison_summary['Global_Fit']
        
        bars = ax1.bar(range(len(sheets)), accuracies, color='skyblue', edgecolor='navy')
        ax1.set_title('Classification Accuracy by Sheet', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Classification Accuracy (%)')
        ax1.set_xticks(range(len(sheets)))
        ax1.set_xticklabels(sheets, rotation=45, ha='right')
        ax1.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bar, acc in zip(bars, accuracies):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f'{acc:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        # Cramer's V comparison
        ax2 = fig.add_subplot(2, 2, 2)
        cramers_v = self.analyzer.comparison_summary['Cramers_V']
        
        bars2 = ax2.bar(range(len(sheets)), cramers_v, color='lightcoral', edgecolor='darkred')
        ax2.set_title('Association Strength (Cramer\'s V)', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Cramer\'s V')
        ax2.set_xticks(range(len(sheets)))
        ax2.set_xticklabels(sheets, rotation=45, ha='right')
        ax2.grid(True, alpha=0.3)
        
        # Utilization comparison
        ax3 = fig.add_subplot(2, 2, 3)
        utilization = self.analyzer.comparison_summary['Utilization']
        
        bars3 = ax3.bar(range(len(sheets)), utilization, color='lightgreen', edgecolor='darkgreen')
        ax3.set_title('Neuron Utilization', fontsize=14, fontweight='bold')
        ax3.set_ylabel('Neuron Utilization (%)')
        ax3.set_xticks(range(len(sheets)))
        ax3.set_xticklabels(sheets, rotation=45, ha='right')
        ax3.grid(True, alpha=0.3)
        
        # Combined scatter plot
        ax4 = fig.add_subplot(2, 2, 4)
        scatter = ax4.scatter(cramers_v, accuracies, c=utilization, 
                             cmap='viridis', s=100, alpha=0.7, edgecolors='black')
        ax4.set_xlabel('Cramer\'s V (Association Strength)')
        ax4.set_ylabel('Classification Accuracy (%)')
        ax4.set_title('Performance Overview', fontsize=14, fontweight='bold')
        ax4.grid(True, alpha=0.3)
        
        # Add colorbar
        cbar = fig.colorbar(scatter, ax=ax4)
        cbar.set_label('Neuron Utilization (%)')
        
        # Add sheet labels to scatter points
        for i, sheet in enumerate(sheets):
            ax4.annotate(sheet, (cramers_v.iloc[i], accuracies.iloc[i]), 
                        xytext=(5, 5), textcoords='offset points', 
                        fontsize=8, alpha=0.8)
        
        fig.tight_layout()
        
        canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
        canvas_fig.draw()
        canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
        for child in scrollable_frame.winfo_children():
            try:
                if hasattr(child, 'bind'):
                    child.bind("<MouseWheel>", _on_mousewheel)
                    child.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
                    child.bind("<Button-4>", _on_mousewheel)
                    child.bind("<Button-5>", _on_mousewheel)
                    child.bind("<Shift-Button-4>", _on_shift_mousewheel)
                    child.bind("<Shift-Button-5>", _on_shift_mousewheel)
            except Exception:
                pass
    
    def create_individual_sheets_in_window(self):
        """Create individual sheet details"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Individual Sheets")
        
        # Create scrollable canvas for the entire tab
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Sheet selector
        selector_frame = ttk.Frame(scrollable_frame)
        selector_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(selector_frame, text="Select Sheet:", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        sheet_var = tk.StringVar()
        sheet_names = list(self.analyzer.batch_results.keys())
        sheet_combo = ttk.Combobox(selector_frame, textvariable=sheet_var, 
                                  values=sheet_names, state="readonly", width=30)
        sheet_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        if sheet_names:
            sheet_combo.set(sheet_names[0])
        
        # Content frame
        content_frame = ttk.Frame(scrollable_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def update_sheet_display(*args):
            # Clear existing content
            for widget in content_frame.winfo_children():
                widget.destroy()
            
            selected_sheet = sheet_var.get()
            if selected_sheet and selected_sheet in self.analyzer.batch_results:
                self.create_sheet_detail_content(content_frame, selected_sheet)
        
        sheet_var.trace('w', update_sheet_display)
        update_sheet_display()  # Initial load
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_sheet_detail_content(self, parent, sheet_name):
        """Create detailed content for a specific sheet"""
        sheet_data = self.analyzer.batch_results[sheet_name]
        
        # Sheet info
        info_frame = ttk.LabelFrame(parent, text=f"SHEET: {sheet_name}", padding="15")
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        info_text = f"""Total Observations: {sheet_data['total_observations']:,}
Total Neurons: {sheet_data['total_neurons']}
Active Neurons: {sheet_data['active_neurons']}
Classification Accuracy: {sheet_data['global_fit']:.2f}%
Association Strength (Cramer's V): {sheet_data['cramers_v']:.4f}
Inactive Neurons: {sheet_data['percent_undefined']:.1f}%"""
        
        ttk.Label(info_frame, text=info_text, font=('Arial', 11)).pack(anchor='w')
        
        # Confusion matrix visualization
        if 'confusion_matrix' in sheet_data:
            matrix_frame = ttk.LabelFrame(parent, text="CONFUSION MATRIX", padding="15")
            matrix_frame.pack(fill=tk.X, padx=10, pady=10)
            
            self.create_mini_heatmap(matrix_frame, sheet_data['confusion_matrix'], sheet_name)
    
    def create_mini_heatmap(self, parent, confusion_matrix, sheet_name=None):
        """Create a small heatmap for the confusion matrix with improved visibility"""
        try:
            # Apply normalization if checkbox is checked
            display_matrix = confusion_matrix
            matrix_title = 'Confusion Matrix Heatmap'
            
            if hasattr(self.analyzer, 'normalize_confusion_matrices') and self.analyzer.normalize_confusion_matrices.get():
                try:
                    display_matrix = self.analyzer.normalize_confusion_matrix(confusion_matrix)
                    matrix_title = 'Normalized Confusion Matrix Heatmap (Row %)'
                except Exception as norm_error:
                    logger.warning(f"Failed to normalize matrix for heatmap: {norm_error}")
                    display_matrix = confusion_matrix
                    matrix_title = 'Confusion Matrix Heatmap (Normalization Failed)'
            
            # Add sheet name to title if provided
            if sheet_name:
                matrix_title = f"{matrix_title} - {sheet_name}"
            
            fig = Figure(figsize=(10, 8), dpi=100, facecolor='white')
            ax = fig.add_subplot(111)
            
            # Create heatmap with improved visibility
            im = ax.imshow(display_matrix.values, cmap='Blues', aspect='auto')
            
            # Set ticks and labels with better formatting
            ax.set_xticks(range(len(display_matrix.columns)))
            ax.set_yticks(range(len(display_matrix.index)))
            ax.set_xticklabels(display_matrix.columns, rotation=45, ha='right', fontsize=10)
            ax.set_yticklabels(display_matrix.index, fontsize=10)
            
            # Add text annotations with better contrast
            for i in range(len(display_matrix.index)):
                for j in range(len(display_matrix.columns)):
                    value = display_matrix.iloc[i, j]
                    # Determine text color based on background intensity
                    text_color = 'white' if value > display_matrix.values.max() * 0.5 else 'black'
                    
                    if hasattr(self.analyzer, 'normalize_confusion_matrices') and self.analyzer.normalize_confusion_matrices.get():
                        # Show as percentage with 1 decimal place
                        text = ax.text(j, i, f"{value:.1f}%",
                                      ha="center", va="center", color=text_color, 
                                      fontweight='bold', fontsize=10)
                    else:
                        # Show as integer count
                        text = ax.text(j, i, f"{int(value)}",
                                      ha="center", va="center", color=text_color, 
                                      fontweight='bold', fontsize=10)
            
            # Set title with better formatting
            ax.set_title(matrix_title, fontsize=14, fontweight='bold', pad=20, color='#2E86AB')
            ax.set_xlabel('Predicted', fontsize=12, fontweight='bold')
            ax.set_ylabel('Actual', fontsize=12, fontweight='bold')
            
            # Add colorbar with better formatting
            cbar = fig.colorbar(im, ax=ax, shrink=0.8)
            cbar.set_label('Count' if 'Normalized' not in matrix_title else 'Percentage', 
                          fontsize=11, fontweight='bold')
            
            fig.tight_layout(pad=2.0)
            
            canvas = FigureCanvasTkAgg(fig, parent)
            canvas.draw()
            canvas.get_tk_widget().pack()
            
        except Exception as e:
            logger.error(f"Error creating mini heatmap: {e}")
            # Create error message
            error_label = ttk.Label(parent, text=f"Failed to create heatmap: {str(e)}", 
                                   font=('Arial', 10), foreground='red')
            error_label.pack(pady=10)
    
    def create_multi_sheet_side_by_side_view(self):
        """Create side-by-side view of multiple sheets simultaneously"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Multi-Sheet View")
        
        # Create main scrollable canvas
        main_canvas = tk.Canvas(frame, bg='white')
        main_scrollbar_v = ttk.Scrollbar(frame, orient="vertical", command=main_canvas.yview)
        main_scrollbar_h = ttk.Scrollbar(frame, orient="horizontal", command=main_canvas.xview)
        main_scrollable_frame = ttk.Frame(main_canvas)
        
        main_scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=main_scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar_v.set, xscrollcommand=main_scrollbar_h.set)
        
        # Title
        title_label = ttk.Label(main_scrollable_frame, text="ALL SHEETS SIDE-BY-SIDE COMPARISON", 
                               font=('Arial', 16, 'bold'), foreground='darkblue')
        title_label.pack(pady=(10, 20))
        
        # Create grid of sheets (2 columns)
        sheets_frame = ttk.Frame(main_scrollable_frame)
        sheets_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        sheet_names = list(self.analyzer.batch_results.keys())
        cols = 2
        rows = (len(sheet_names) + cols - 1) // cols
        
        for i, sheet_name in enumerate(sheet_names):
            row = i // cols
            col = i % cols
            
            # Create frame for each sheet
            sheet_frame = ttk.LabelFrame(sheets_frame, text=f"SHEET: {sheet_name}", padding="10")
            sheet_frame.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            
            # Configure grid weights
            sheets_frame.grid_rowconfigure(row, weight=1)
            sheets_frame.grid_columnconfigure(col, weight=1)
            
            # Add sheet content
            self.create_sheet_summary_content(sheet_frame, sheet_name)
        
        # Configure canvas scrolling
        main_canvas.pack(side="left", fill="both", expand=True)
        main_scrollbar_v.pack(side="right", fill="y")
        main_scrollbar_h.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling (vertical and horizontal)
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            main_canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        main_canvas.bind("<MouseWheel>", _on_mousewheel)
        main_scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        main_canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        main_scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        # Linux support
        main_canvas.bind("<Button-4>", _on_mousewheel)
        main_canvas.bind("<Button-5>", _on_mousewheel)
        main_scrollable_frame.bind("<Button-4>", _on_mousewheel)
        main_scrollable_frame.bind("<Button-5>", _on_mousewheel)
        main_canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        main_canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        main_scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        main_scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_sheet_summary_content(self, parent, sheet_name):
        """Create summary content for a single sheet in multi-view"""
        sheet_data = self.analyzer.batch_results[sheet_name]
        
        # Sheet metrics
        metrics_text = f"""Classification Accuracy: {sheet_data['global_fit']:.1f}%
Association Strength (Cramer's V): {sheet_data['cramers_v']:.3f}
Samples: {sheet_data['total_observations']:,}
Active Neurons: {sheet_data['active_neurons']}/{sheet_data['total_neurons']}
Neuron Utilization: {(sheet_data['active_neurons']/sheet_data['total_neurons']*100):.1f}%"""
        
        metrics_label = ttk.Label(parent, text=metrics_text, font=('Arial', 10), 
                                 foreground='darkgreen', justify='left')
        metrics_label.pack(anchor='w', pady=(0, 10))
        
        # Mini confusion matrix heatmap
        if 'confusion_matrix' in sheet_data:
            self.create_mini_confusion_heatmap(parent, sheet_data['confusion_matrix'], sheet_name)
    
    def create_mini_confusion_heatmap(self, parent, confusion_matrix, sheet_name=None):
        """Create a mini heatmap for side-by-side view with improved visibility"""
        try:
            # Apply normalization if checkbox is checked
            display_matrix = confusion_matrix
            matrix_title = 'Confusion Matrix'
            
            if hasattr(self.analyzer, 'normalize_confusion_matrices') and self.analyzer.normalize_confusion_matrices.get():
                try:
                    display_matrix = self.analyzer.normalize_confusion_matrix(confusion_matrix)
                    matrix_title = 'Normalized Confusion Matrix (Row %)'
                except Exception as norm_error:
                    logger.warning(f"Failed to normalize matrix for mini heatmap: {norm_error}")
                    display_matrix = confusion_matrix
                    matrix_title = 'Confusion Matrix (Normalization Failed)'
            
            # Add sheet name to title if provided
            if sheet_name:
                matrix_title = f"{matrix_title} - {sheet_name}"
            
            fig = Figure(figsize=(6, 4), dpi=100, facecolor='white')
            ax = fig.add_subplot(111)
            
            # Create heatmap with improved visibility
            im = ax.imshow(display_matrix.values, cmap='Blues', aspect='auto')
            
            # Improved labels for mini view
            if len(display_matrix.columns) <= 8:
                ax.set_xticks(range(len(display_matrix.columns)))
                ax.set_yticks(range(len(display_matrix.index)))
                ax.set_xticklabels([str(c)[:10] for c in display_matrix.columns], rotation=45, ha='right', fontsize=9)
                ax.set_yticklabels([str(i)[:10] for i in display_matrix.index], fontsize=9)
            else:
                ax.set_xticks([])
                ax.set_yticks([])
            
            # Add text annotations for small matrices with better contrast
            if display_matrix.shape[0] <= 6 and display_matrix.shape[1] <= 6:
                for i in range(len(display_matrix.index)):
                    for j in range(len(display_matrix.columns)):
                        value = display_matrix.iloc[i, j]
                        # Determine text color based on background intensity
                        text_color = 'white' if value > display_matrix.values.max() * 0.5 else 'black'
                        
                        if hasattr(self.analyzer, 'normalize_confusion_matrices') and self.analyzer.normalize_confusion_matrices.get():
                            # Show as percentage with 1 decimal place
                            ax.text(j, i, f"{value:.1f}%",
                                   ha="center", va="center", color=text_color, fontsize=8, fontweight='bold')
                        else:
                            # Show as integer count
                            ax.text(j, i, f"{int(value)}",
                                   ha="center", va="center", color=text_color, fontsize=8, fontweight='bold')
            
            ax.set_title(matrix_title, fontsize=10, fontweight='bold')
            
            fig.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, parent)
            canvas.draw()
            canvas.get_tk_widget().pack()
            
        except Exception as e:
            logger.error(f"Error creating mini confusion heatmap: {e}")
            # Create error message
            error_label = ttk.Label(parent, text=f"Failed to create heatmap: {str(e)}", 
                                   font=('Arial', 10), foreground='red')
            error_label.pack(pady=10)
    
    def create_all_sheets_combined_view(self):
        """Create performance matrix heatmap showing all sheets comparison"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Performance Matrix")
        
        # Create scrollable canvas for controls and heatmap
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Title and description
        title_label = ttk.Label(scrollable_frame, text="PERFORMANCE MATRIX - ALL METRICS", 
                               font=('Arial', 16, 'bold'), foreground='darkblue')
        title_label.pack(pady=(20, 10))
        
        subtitle_label = ttk.Label(scrollable_frame, text="Color: Normalized Performance (0=Worst, 1=Best)", 
                                  font=('Arial', 12), foreground='darkgreen')
        subtitle_label.pack(pady=(0, 10))
        
        # Note about the new heatmap view
        note_label = ttk.Label(scrollable_frame, text="Note: This tab has been enhanced with a performance matrix heatmap for better visualization and comparison.", 
                              font=('Arial', 10), foreground='darkorange')
        note_label.pack(pady=(0, 20))
        
        # Check if we have comparison data
        if not hasattr(self.analyzer, 'comparison_summary') or self.analyzer.comparison_summary is None:
            # Create comparison summary if it doesn't exist
            if hasattr(self.analyzer, 'create_comparison_summary'):
                self.analyzer.create_comparison_summary()
        
        if hasattr(self.analyzer, 'comparison_summary') and self.analyzer.comparison_summary is not None:
            # Check if we have enough data for a meaningful heatmap
            if len(self.analyzer.comparison_summary) > 1:
                # Create the performance matrix heatmap
                self.create_performance_matrix_heatmap(scrollable_frame)
            else:
                # Show message for single configuration
                single_config_label = ttk.Label(scrollable_frame, text="Single configuration detected. Heatmap requires multiple configurations for comparison.", 
                                              font=('Arial', 12), foreground='orange')
                single_config_label.pack(pady=20)
                
                # Show the single configuration data
                self.create_single_config_display(scrollable_frame)
        else:
            # Show error message if no data available
            error_label = ttk.Label(scrollable_frame, text="No comparison data available. Please run analysis on multiple sheets first.", 
                                   font=('Arial', 12), foreground='red')
            error_label.pack(pady=50)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
    
    def create_detailed_sheet_content(self, parent, sheet_name):
        """Create detailed content for each sheet in combined view"""
        sheet_data = self.analyzer.batch_results[sheet_name]
        
        # Sheet header
        header_frame = ttk.LabelFrame(parent, text=f"SHEET: {sheet_name}", padding="15")
        header_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        # Create two-column layout
        content_frame = ttk.Frame(header_frame)
        content_frame.pack(fill=tk.X)
        
        # Left column - metrics
        left_frame = ttk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        metrics_text = f"""PERFORMANCE METRICS:
- Classification Accuracy: {sheet_data['global_fit']:.2f}%
- Association Strength (Cramer's V): {sheet_data['cramers_v']:.4f}
- Total Observations: {sheet_data['total_observations']:,}
- Total Neurons: {sheet_data['total_neurons']}
- Active Neurons: {sheet_data['active_neurons']}
- Inactive Neurons: {sheet_data['total_neurons'] - sheet_data['active_neurons']}
- Neuron Utilization: {(sheet_data['active_neurons']/sheet_data['total_neurons']*100):.1f}%
- Zero Entries Percentage: {sheet_data['percent_undefined']:.1f}%"""
        
        metrics_label = ttk.Label(left_frame, text=metrics_text, font=('Arial', 11), 
                                 foreground='darkgreen', justify='left')
        metrics_label.pack(anchor='w')
        
        # Right column - confusion matrix
        right_frame = ttk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        if 'confusion_matrix' in sheet_data:
            matrix_label = ttk.Label(right_frame, text="CONFUSION MATRIX:", 
                                   font=('Arial', 11, 'bold'), foreground='darkblue')
            matrix_label.pack(anchor='w', pady=(0, 5))
            
            self.create_detailed_heatmap(right_frame, sheet_data['confusion_matrix'], sheet_name)
    
    def create_detailed_heatmap(self, parent, confusion_matrix, sheet_name=None):
        """Create a detailed heatmap for the combined view with improved visibility"""
        try:
            # Apply normalization if checkbox is checked
            display_matrix = confusion_matrix
            matrix_title = 'Confusion Matrix'
            fmt_param = 'd'
            
            if hasattr(self.analyzer, 'normalize_confusion_matrices') and self.analyzer.normalize_confusion_matrices.get():
                try:
                    display_matrix = self.analyzer.normalize_confusion_matrix(confusion_matrix)
                    matrix_title = 'Normalized Confusion Matrix (Row %)'
                    fmt_param = '.1f'
                except Exception as norm_error:
                    logger.warning(f"Failed to normalize matrix for detailed heatmap: {norm_error}")
                    display_matrix = confusion_matrix
                    matrix_title = 'Confusion Matrix (Normalization Failed)'
                    fmt_param = 'd'
            
            # Add sheet name to title if provided
            if sheet_name:
                matrix_title = f"{matrix_title} - {sheet_name}"
            
            fig = Figure(figsize=(8, 6), dpi=100, facecolor='white')
            ax = fig.add_subplot(111)
            
            # Create heatmap with improved visibility
            import seaborn as sns
            sns.heatmap(display_matrix, annot=True, fmt=fmt_param, cmap='Blues', 
                       ax=ax, cbar_kws={'shrink': 0.8, 'label': 'Count' if fmt_param == 'd' else 'Percentage'},
                       square=True, linewidths=1.0, annot_kws={'fontsize': 10, 'fontweight': 'bold'})
            
            # Set title with better formatting
            ax.set_title(matrix_title, fontsize=14, fontweight='bold', pad=20, color='#2E86AB')
            ax.set_xlabel('Predicted', fontsize=12, fontweight='bold')
            ax.set_ylabel('Actual', fontsize=12, fontweight='bold')
            
            # Improve tick label visibility
            ax.tick_params(axis='both', labelsize=10, colors='#495057')
            
            fig.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, parent)
            canvas.draw()
            canvas.get_tk_widget().pack()
            
        except Exception as e:
            logger.error(f"Error creating detailed heatmap: {e}")
            # Create error message
            error_label = ttk.Label(parent, text=f"Failed to create heatmap: {str(e)}", 
                                   font=('Arial', 10), foreground='red')
            error_label.pack(pady=10)
    
    def create_performance_matrix_heatmap(self, parent):
        """Create a comprehensive performance matrix heatmap following industry standards"""
        try:
            # Prepare data for heatmap
            df = self.analyzer.comparison_summary.copy()
            
            # Handle any NaN values
            df = df.fillna(0)  # Replace NaN with 0 for visualization
            
            # Select key metrics for visualization - performance metrics first, then reference metrics
            performance_metrics = ['Global_Fit', 'Cramers_V', 'Utilization', 'Active_Neurons']
            performance_labels = ['Classification Accuracy (%)', 'Association Strength (Cramer\'s V)', 'Neuron Utilization (%)', 'Active Neurons']
            
            # Reference metrics (will be shown at bottom)
            reference_metrics = ['Total_Samples']
            reference_labels = ['Total Samples']
            
            # Combine for plotting
            metrics_to_plot = performance_metrics + reference_metrics
            metric_labels = performance_labels + reference_labels
            
            # Verify all required columns exist
            missing_columns = [col for col in metrics_to_plot if col not in df.columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Prepare data matrix
            plot_data = df[metrics_to_plot].copy()
            
            # Check for empty or invalid data
            if plot_data.empty or plot_data.isnull().all().all():
                raise ValueError("No valid data available for visualization")
            
            # Normalize data for better visualization (0-1 scale)
            normalized_data = plot_data.copy()
            
            # Normalize each metric appropriately with safety checks
            # Classification Accuracy: higher is better, normalize to 0-1
            if plot_data['Global_Fit'].max() != plot_data['Global_Fit'].min():
                normalized_data['Global_Fit'] = (plot_data['Global_Fit'] - plot_data['Global_Fit'].min()) / (plot_data['Global_Fit'].max() - plot_data['Global_Fit'].min())
            else:
                normalized_data['Global_Fit'] = 0.5  # Neutral if all values are the same
            
            # Cramer's V: higher is better, normalize to 0-1
            if plot_data['Cramers_V'].max() != plot_data['Cramers_V'].min():
                normalized_data['Cramers_V'] = (plot_data['Cramers_V'] - plot_data['Cramers_V'].min()) / (plot_data['Cramers_V'].max() - plot_data['Cramers_V'].min())
            else:
                normalized_data['Cramers_V'] = 0.5  # Neutral if all values are the same
            
            # Neuron Utilization: higher is better, normalize to 0-1
            if plot_data['Utilization'].max() != plot_data['Utilization'].min():
                normalized_data['Utilization'] = (plot_data['Utilization'] - plot_data['Utilization'].min()) / (plot_data['Utilization'].max() - plot_data['Utilization'].min())
            else:
                normalized_data['Utilization'] = 0.5  # Neutral if all values are the same
            
            # Total Samples: reference metric, set to neutral (0.5) since it's not a performance indicator
            normalized_data['Total_Samples'] = 0.5  # Always neutral for reference
            
            # Active Neurons: lower is better (more efficient), invert normalization
            if plot_data['Active_Neurons'].max() != plot_data['Active_Neurons'].min():
                active_neurons_normalized = (plot_data['Active_Neurons'] - plot_data['Active_Neurons'].min()) / (plot_data['Active_Neurons'].max() - plot_data['Active_Neurons'].min())
                normalized_data['Active_Neurons'] = 1 - active_neurons_normalized  # Invert so lower = better
            else:
                normalized_data['Active_Neurons'] = 0.5  # Neutral if all values are the same
            
            # Final validation of normalized data
            if normalized_data.isnull().any().any() or (normalized_data < 0).any().any() or (normalized_data > 1).any().any():
                # Clean up any invalid values
                normalized_data = normalized_data.fillna(0.5)
                normalized_data = normalized_data.clip(0, 1)
            
            # Create the heatmap
            fig = Figure(figsize=(14, 10), dpi=100, facecolor='white')
            ax = fig.add_subplot(111)
            
            # Create heatmap using seaborn
            import seaborn as sns
            
            # Set up the heatmap with proper formatting
            heatmap = sns.heatmap(
                normalized_data.T,  # Transpose to show metrics as rows, configs as columns
                annot=plot_data.T,  # Show actual values
                fmt='.1f',  # Consistent formatting for better readability
                cmap='RdYlGn',  # Red-Yellow-Green colormap (industry standard for performance)
                ax=ax,
                cbar_kws={
                    'label': 'Normalized Performance\n(0=Worst, 1=Best)',
                    'shrink': 0.8,
                    'aspect': 20
                },
                linewidths=0.5,
                linecolor='white',
                square=False,
                xticklabels=df['SOM_Config'].tolist(),  # Ensure it's a list
                yticklabels=metric_labels,
                annot_kws={'size': 9}  # Adjust annotation font size
            )
            
            # Customize the heatmap appearance
            ax.set_title('Performance Matrix - Performance Metrics\n(Color: Normalized Performance)', 
                        fontsize=14, fontweight='bold', pad=20)
            ax.set_xlabel('SOM Configuration', fontsize=12, fontweight='bold', labelpad=10)
            ax.set_ylabel('Performance Metrics', fontsize=12, fontweight='bold', labelpad=10)
            
            # Rotate x-axis labels for better readability
            try:
                plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
            except Exception as label_error:
                logger.warning(f"Could not rotate x-axis labels: {label_error}")
            
            # Adjust layout
            try:
                fig.tight_layout()
            except Exception as layout_error:
                logger.warning(f"Could not adjust layout: {layout_error}")
            
                        # Create canvas and display
            try:
                canvas = FigureCanvasTkAgg(fig, parent)
                canvas.draw()
                canvas.get_tk_widget().pack(pady=20)
                
                # Add interpretation guide
                try:
                    self.create_heatmap_interpretation_guide(parent)
                except Exception as guide_error:
                    logger.error(f"Error creating interpretation guide: {guide_error}")
                    # Continue without the guide
            except Exception as canvas_error:
                logger.error(f"Error creating canvas: {canvas_error}")
                # Fallback: create a simple text display
                fallback_label = ttk.Label(parent, text="Heatmap created successfully but display failed. Check console for details.", 
                                         font=('Arial', 10), foreground='orange')
                fallback_label.pack(pady=20)
            
        except Exception as e:
            logger.error(f"Error creating performance matrix heatmap: {e}")
            # Create error message
            error_label = ttk.Label(parent, text=f"Failed to create heatmap: {str(e)}", 
                                   font=('Arial', 10), foreground='red')
            error_label.pack(pady=10)
    
    def create_heatmap_interpretation_guide(self, parent):
        """Create interpretation guide for the heatmap"""
        guide_frame = ttk.LabelFrame(parent, text="HEATMAP INTERPRETATION GUIDE", padding="15")
        guide_frame.pack(fill=tk.X, padx=20, pady=20)
        
        # Create two-column layout for the guide
        guide_content = ttk.Frame(guide_frame)
        guide_content.pack(fill=tk.X)
        
        # Left column - Color interpretation
        left_frame = ttk.Frame(guide_content)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        color_text = """COLOR INTERPRETATION:
• Dark Green: Excellent performance (0.8-1.0)
• Light Green: Good performance (0.6-0.8)
• Yellow: Moderate performance (0.4-0.6)
• Orange: Below average (0.2-0.4)
• Red: Poor performance (0.0-0.2)

PERFORMANCE METRICS:
• Classification Accuracy (%): Classification accuracy (higher = better)
• Association Strength (Cramer's V): Cramer's V correlation strength (higher = better)
• Neuron Utilization (%): Neuron utilization efficiency (higher = better)
• Total Samples: Data volume (neutral metric)
• Active Neurons: Efficiency indicator (lower = better)"""
        
        color_label = ttk.Label(left_frame, text=color_text, font=('Arial', 10), 
                               foreground='darkblue', justify='left')
        color_label.pack(anchor='w')
        
        # Right column - Recommendations
        right_frame = ttk.Frame(guide_content)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        if hasattr(self.analyzer, 'comparison_summary') and self.analyzer.comparison_summary is not None:
            df = self.analyzer.comparison_summary
            best_config = df.iloc[0]
            
            rec_text = f"""TOP PERFORMING CONFIGURATION:
• Configuration: {best_config['SOM_Config']}
• Classification Accuracy: {best_config['Global_Fit']:.1f}%
• Association Strength (Cramer's V): {best_config['Cramers_V']:.4f}
• Neuron Utilization: {best_config['Utilization']:.1f}%

RECOMMENDATIONS:
• Green cells indicate optimal performance
• Red cells suggest areas for improvement
• Consider configuration trade-offs
• Balance accuracy vs. efficiency"""
        else:
            rec_text = """RECOMMENDATIONS:
• Green cells indicate optimal performance
• Red cells suggest areas for improvement
• Consider configuration trade-offs
• Balance accuracy vs. efficiency"""
        
        rec_label = ttk.Label(right_frame, text=rec_text, font=('Arial', 10), 
                             foreground='darkgreen', justify='left')
        rec_label.pack(anchor='w')
    
    def create_single_config_display(self, parent):
        """Create display for single configuration when heatmap is not applicable"""
        try:
            df = self.analyzer.comparison_summary
            config_data = df.iloc[0]
            
            # Create summary frame
            summary_frame = ttk.LabelFrame(parent, text="SINGLE CONFIGURATION SUMMARY", padding="15")
            summary_frame.pack(fill=tk.X, padx=20, pady=20)
            
            # Create two-column layout
            content_frame = ttk.Frame(summary_frame)
            content_frame.pack(fill=tk.X)
            
            # Left column - key metrics
            left_frame = ttk.Frame(content_frame)
            left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
            
            metrics_text = f"""CONFIGURATION: {config_data['SOM_Config']}

PERFORMANCE METRICS:
• Classification Accuracy: {config_data['Global_Fit']:.2f}%
• Association Strength (Cramer's V): {config_data['Cramers_V']:.4f}
• Neuron Utilization: {config_data['Utilization']:.1f}%
• Total Samples: {int(config_data['Total_Samples']):,}
• Active Neurons: {int(config_data['Active_Neurons'])}
• Total Neurons: {int(config_data['Total_Neurons'])}"""
            
            metrics_label = ttk.Label(left_frame, text=metrics_text, font=('Arial', 11), 
                                     foreground='darkgreen', justify='left')
            metrics_label.pack(anchor='w')
            
            # Right column - performance assessment
            right_frame = ttk.Frame(content_frame)
            right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
            
            # Performance assessment
            accuracy_grade = "Excellent" if config_data['Global_Fit'] > 75 else "Good" if config_data['Global_Fit'] > 60 else "Poor"
            association_grade = "Strong" if config_data['Cramers_V'] > 0.5 else "Moderate" if config_data['Cramers_V'] > 0.3 else "Weak"
            
            assessment_text = f"""PERFORMANCE ASSESSMENT:

Classification Accuracy Grade: {accuracy_grade}
• {config_data['Global_Fit']:.1f}% classification accuracy
• {'Excellent' if config_data['Global_Fit'] > 75 else 'Good' if config_data['Global_Fit'] > 60 else 'Poor'} performance level

Association Strength Grade: {association_grade}
• Cramer's V: {config_data['Cramers_V']:.4f}
• {'Strong' if config_data['Cramers_V'] > 0.5 else 'Moderate' if config_data['Cramers_V'] > 0.3 else 'Weak'} correlation strength

Neuron Utilization: {config_data['Utilization']:.1f}%"""
            
            assessment_label = ttk.Label(right_frame, text=assessment_text, font=('Arial', 11), 
                                        foreground='darkblue', justify='left')
            assessment_label.pack(anchor='w')
            
        except Exception as e:
            logger.error(f"Error creating single config display: {e}")
            error_label = ttk.Label(parent, text=f"Failed to create single configuration display: {str(e)}", 
                                   font=('Arial', 10), foreground='red')
            error_label.pack(pady=10)
    
    def create_multi_sheet_radar_analysis_in_window(self):
        """Create comprehensive radar chart analysis for multi-sheet comparison"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Multi-Sheet Radar Analysis")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            if hasattr(self.analyzer, 'comparison_summary') and self.analyzer.comparison_summary is not None:
                # Create figure with subplots for different radar analyses
                fig = Figure(figsize=(15, 10), dpi=100, facecolor='white')
                
                # Performance comparison radar
                ax1 = fig.add_subplot(2, 2, 1, projection='polar')
                sheets = self.analyzer.comparison_summary['SOM_Config']
                accuracies = self.analyzer.comparison_summary['Global_Fit'] / 100  # Normalize to 0-1
                cramers_v = self.analyzer.comparison_summary['Cramers_V']
                utilization = self.analyzer.comparison_summary['Utilization'] / 100  # Normalize to 0-1
                
                # Create radar for top 6 sheets
                top_sheets = sheets.head(6)
                top_accuracies = accuracies.head(6)
                top_cramers = cramers_v.head(6)
                top_utilization = utilization.head(6)
                
                angles = [n / float(len(top_sheets)) * 2 * pi for n in range(len(top_sheets))]
                angles += angles[:1]
                
                # Plot accuracy
                acc_values = list(top_accuracies.values) + [top_accuracies.iloc[0]]
                ax1.plot(angles, acc_values, 'o-', linewidth=2, label='Classification Accuracy', color='blue')
                ax1.fill(angles, acc_values, alpha=0.15, color='blue')
                
                ax1.set_xticks(angles[:-1])
                ax1.set_xticklabels([str(name)[:8] for name in top_sheets], fontsize=8)
                ax1.set_ylim(0, 1)
                ax1.set_title('Sheet Classification Accuracy Comparison', fontsize=12, fontweight='bold', pad=20)
                ax1.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                ax1.grid(True)
                
                # Association strength radar
                ax2 = fig.add_subplot(2, 2, 2, projection='polar')
                cramers_values = list(top_cramers.values) + [top_cramers.iloc[0]]
                ax2.plot(angles, cramers_values, 'o-', linewidth=2, label='Association Strength (Cramer\'s V)', color='red')
                ax2.fill(angles, cramers_values, alpha=0.15, color='red')
                
                ax2.set_xticks(angles[:-1])
                ax2.set_xticklabels([str(name)[:8] for name in top_sheets], fontsize=8)
                ax2.set_ylim(0, 1)
                ax2.set_title('Association Strength (Cramer\'s V) Comparison', fontsize=12, fontweight='bold', pad=20)
                ax2.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                ax2.grid(True)
                
                # Utilization radar
                ax3 = fig.add_subplot(2, 2, 3, projection='polar')
                util_values = list(top_utilization.values) + [top_utilization.iloc[0]]
                ax3.plot(angles, util_values, 'o-', linewidth=2, label='Neuron Utilization', color='green')
                ax3.fill(angles, util_values, alpha=0.15, color='green')
                
                ax3.set_xticks(angles[:-1])
                ax3.set_xticklabels([str(name)[:8] for name in top_sheets], fontsize=8)
                ax3.set_ylim(0, 1)
                ax3.set_title('Neuron Utilization Comparison', fontsize=12, fontweight='bold', pad=20)
                ax3.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                ax3.grid(True)
                
                # Overall performance radar
                ax4 = fig.add_subplot(2, 2, 4, projection='polar')
                # Calculate composite score for each sheet
                composite_scores = []
                for i in range(len(top_sheets)):
                    score = (top_accuracies.iloc[i] * 0.4 + 
                            top_cramers.iloc[i] * 0.3 + 
                            top_utilization.iloc[i] * 0.3)
                    composite_scores.append(score)
                
                composite_scores += [composite_scores[0]]
                ax4.plot(angles, composite_scores, 'o-', linewidth=2, label='Composite Score', color='purple')
                ax4.fill(angles, composite_scores, alpha=0.15, color='purple')
                
                ax4.set_xticks(angles[:-1])
                ax4.set_xticklabels([str(name)[:8] for name in top_sheets], fontsize=8)
                ax4.set_ylim(0, 1)
                ax4.set_title('Overall Performance Score', fontsize=12, fontweight='bold', pad=20)
                ax4.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                ax4.grid(True)
                
            else:
                # No comparison data available
                fig = Figure(figsize=(12, 8), dpi=100, facecolor='white')
                ax = fig.add_subplot(111)
                ax.text(0.5, 0.5, 'No multi-sheet comparison data available for radar analysis', 
                       ha='center', va='center', fontsize=14, transform=ax.transAxes)
                ax.set_title('Multi-Sheet Radar Analysis', fontsize=14, fontweight='bold')
            
            fig.tight_layout()
            
            canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
            canvas_fig.draw()
            canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating multi-sheet radar analysis: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_multi_sheet_pie_chart_analysis_in_window(self):
        """Create comprehensive pie chart analysis for multi-sheet comparison"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Multi-Sheet Pie Analysis")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            if hasattr(self.analyzer, 'comparison_summary') and self.analyzer.comparison_summary is not None:
                # Create figure with subplots for different pie analyses (wider to accommodate left legends)
                fig = Figure(figsize=(16, 10), dpi=100, facecolor='white')
                
                # Performance distribution pie chart
                ax1 = fig.add_subplot(2, 2, 1)
                accuracies = self.analyzer.comparison_summary['Global_Fit']
                
                # Categorize performance levels
                excellent = len(accuracies[accuracies >= 80])
                good = len(accuracies[(accuracies >= 60) & (accuracies < 80)])
                fair = len(accuracies[(accuracies >= 40) & (accuracies < 60)])
                poor = len(accuracies[accuracies < 40])
                
                performance_data = [excellent, good, fair, poor]
                performance_labels = ['Excellent (≥80%)', 'Good (60-79%)', 'Fair (40-59%)', 'Poor (<40%)']
                performance_colors = ['#2E7D32', '#388E3C', '#F57C00', '#D32F2F']
                
                # Filter out zero values for cleaner visualization
                filtered_data = [(data, label, color) for data, label, color in zip(performance_data, performance_labels, performance_colors) if data > 0]
                if filtered_data:
                    data_values, data_labels, data_colors = zip(*filtered_data)
                    
                    wedges, texts, autotexts = ax1.pie(data_values, autopct='%1.1f%%', 
                                                       colors=data_colors, startangle=90,
                                                       pctdistance=0.85)
                    
                    # Improve percentage text formatting
                    for autotext in autotexts:
                        autotext.set_color('white')
                        autotext.set_fontweight('bold')
                        autotext.set_fontsize(10)
                    
                    # Create legend positioned to the left to avoid cutoff
                    ax1.legend(wedges, data_labels, loc="center left", bbox_to_anchor=(-0.1, 0.5), 
                              fontsize=9, title="Performance Levels", title_fontsize=10)
                
                ax1.set_title('Performance Distribution Across Sheets', fontsize=12, fontweight='bold')
                
                # Association strength distribution pie chart
                ax2 = fig.add_subplot(2, 2, 2)
                cramers_v = self.analyzer.comparison_summary['Cramers_V']
                
                # Categorize association strength
                strong = len(cramers_v[cramers_v >= 0.7])
                moderate = len(cramers_v[(cramers_v >= 0.5) & (cramers_v < 0.7)])
                weak = len(cramers_v[(cramers_v >= 0.3) & (cramers_v < 0.5)])
                negligible = len(cramers_v[cramers_v < 0.3])
                
                association_data = [strong, moderate, weak, negligible]
                association_labels = ['Strong (≥0.7)', 'Moderate (0.5-0.7)', 'Weak (0.3-0.5)', 'Negligible (<0.3)']
                association_colors = ['#1976D2', '#42A5F5', '#90CAF9', '#E3F2FD']
                
                # Filter out zero values for cleaner visualization
                filtered_data = [(data, label, color) for data, label, color in zip(association_data, association_labels, association_colors) if data > 0]
                if filtered_data:
                    data_values, data_labels, data_colors = zip(*filtered_data)
                    
                    wedges, texts, autotexts = ax2.pie(data_values, autopct='%1.1f%%', 
                                                       colors=data_colors, startangle=90,
                                                       pctdistance=0.85)
                    
                    # Improve percentage text formatting
                    for autotext in autotexts:
                        autotext.set_color('white')
                        autotext.set_fontweight('bold')
                        autotext.set_fontsize(10)
                    
                    # Create legend
                    ax2.legend(wedges, data_labels, loc="center left", bbox_to_anchor=(-0.1, 0.5), 
                              fontsize=9, title="Association Strength", title_fontsize=10)
                
                ax2.set_title('Association Strength Distribution', fontsize=12, fontweight='bold')
                
                # Neuron utilization distribution pie chart
                ax3 = fig.add_subplot(2, 2, 3)
                utilization = self.analyzer.comparison_summary['Utilization']
                
                # Categorize utilization levels
                high_util = len(utilization[utilization >= 80])
                medium_util = len(utilization[(utilization >= 50) & (utilization < 80)])
                low_util = len(utilization[utilization < 50])
                
                utilization_data = [high_util, medium_util, low_util]
                utilization_labels = ['High (≥80%)', 'Medium (50-79%)', 'Low (<50%)']
                utilization_colors = ['#4CAF50', '#8BC34A', '#CDDC39']
                
                # Filter out zero values for cleaner visualization
                filtered_data = [(data, label, color) for data, label, color in zip(utilization_data, utilization_labels, utilization_colors) if data > 0]
                if filtered_data:
                    data_values, data_labels, data_colors = zip(*filtered_data)
                    
                    wedges, texts, autotexts = ax3.pie(data_values, autopct='%1.1f%%', 
                                                       colors=data_colors, startangle=90,
                                                       pctdistance=0.85)
                    
                    # Improve percentage text formatting
                    for autotext in autotexts:
                        autotext.set_color('white')
                        autotext.set_fontweight('bold')
                        autotext.set_fontsize(10)
                    
                    # Create legend
                    ax3.legend(wedges, data_labels, loc="center left", bbox_to_anchor=(-0.1, 0.5), 
                              fontsize=9, title="Utilization Levels", title_fontsize=10)
                
                ax3.set_title('Neuron Utilization Distribution', fontsize=12, fontweight='bold')
                
                # Sample size distribution pie chart
                ax4 = fig.add_subplot(2, 2, 4)
                sample_sizes = self.analyzer.comparison_summary['Total_Samples']
                
                # Categorize sample sizes
                large = len(sample_sizes[sample_sizes >= 1000])
                medium = len(sample_sizes[(sample_sizes >= 100) & (sample_sizes < 1000)])
                small = len(sample_sizes[sample_sizes < 100])
                
                sample_data = [large, medium, small]
                sample_labels = ['Large (≥1000)', 'Medium (100-999)', 'Small (<100)']
                sample_colors = ['#FF9800', '#FFB74D', '#FFCC02']
                
                # Filter out zero values for cleaner visualization
                filtered_data = [(data, label, color) for data, label, color in zip(sample_data, sample_labels, sample_colors) if data > 0]
                if filtered_data:
                    data_values, data_labels, data_colors = zip(*filtered_data)
                    
                    wedges, texts, autotexts = ax4.pie(data_values, autopct='%1.1f%%', 
                                                       colors=data_colors, startangle=90,
                                                       pctdistance=0.85)
                    
                    # Improve percentage text formatting
                    for autotext in autotexts:
                        autotext.set_color('white')
                        autotext.set_fontweight('bold')
                        autotext.set_fontsize(10)
                    
                    # Create legend
                    ax4.legend(wedges, data_labels, loc="center left", bbox_to_anchor=(-0.1, 0.5), 
                              fontsize=9, title="Sample Sizes", title_fontsize=10)
                
                ax4.set_title('Sample Size Distribution', fontsize=12, fontweight='bold')
                
            else:
                # No comparison data available
                fig = Figure(figsize=(12, 8), dpi=100, facecolor='white')
                ax = fig.add_subplot(111)
                ax.text(0.5, 0.5, 'No multi-sheet comparison data available for pie chart analysis', 
                       ha='center', va='center', fontsize=14, transform=ax.transAxes)
                ax.set_title('Multi-Sheet Pie Chart Analysis', fontsize=14, fontweight='bold')
            
            fig.tight_layout()
            
            canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
            canvas_fig.draw()
            canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating multi-sheet pie chart analysis: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    

    
    def create_confusion_heatmap_in_window(self):
        """Create confusion matrix heatmap for single sheet"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Confusion Heatmap")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            if hasattr(self.analyzer, 'confusion_matrix') and self.analyzer.confusion_matrix is not None:
                # Apply normalization if checkbox is checked
                display_matrix = self.analyzer.confusion_matrix
                matrix_title = 'Confusion Matrix Heatmap'
                fmt_param = 'd'
                
                if hasattr(self.analyzer, 'normalize_confusion_matrices') and self.analyzer.normalize_confusion_matrices.get():
                    try:
                        display_matrix = self.analyzer.normalize_confusion_matrix(self.analyzer.confusion_matrix)
                        matrix_title = 'Normalized Confusion Matrix Heatmap (Row %)'
                        fmt_param = '.1f'
                    except Exception as norm_error:
                        logger.warning(f"Failed to normalize matrix for window heatmap: {norm_error}")
                        display_matrix = self.analyzer.confusion_matrix
                        matrix_title = 'Confusion Matrix Heatmap (Normalization Failed)'
                        fmt_param = 'd'
                
                fig = Figure(figsize=(12, 8), dpi=100, facecolor='white')
                ax = fig.add_subplot(111)
                
                # Create heatmap
                import seaborn as sns
                sns.heatmap(display_matrix, annot=True, fmt=fmt_param, 
                           cmap='Blues', ax=ax, cbar_kws={'shrink': 0.8})
                
                ax.set_title(matrix_title, fontsize=14, fontweight='bold')
                ax.set_xlabel('Actual')
                ax.set_ylabel('Predicted')
                
                fig.tight_layout()
                
                canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
                canvas_fig.draw()
                canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            else:
                ttk.Label(scrollable_frame, text="No confusion matrix data available", 
                         font=('Arial', 14)).pack(pady=50)
                
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating heatmap: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_distribution_charts_in_window(self):
        """Create distribution charts"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Distributions")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            if hasattr(self.analyzer, 'confusion_matrix') and self.analyzer.confusion_matrix is not None:
                fig = Figure(figsize=(15, 8), dpi=100, facecolor='white')
                
                # Actual distribution
                ax1 = fig.add_subplot(1, 2, 1)
                actual_counts = self.analyzer.confusion_matrix.sum(axis=0)
                ax1.bar(range(len(actual_counts)), actual_counts.values, color='skyblue', edgecolor='navy')
                ax1.set_title('Actual Type Distribution', fontsize=14, fontweight='bold')
                ax1.set_ylabel('Count')
                ax1.set_xticks(range(len(actual_counts)))
                ax1.set_xticklabels(actual_counts.index, rotation=45, ha='right')
                ax1.grid(True, alpha=0.3)
                
                # Predicted distribution
                ax2 = fig.add_subplot(1, 2, 2)
                predicted_counts = self.analyzer.confusion_matrix.sum(axis=1)
                ax2.bar(range(len(predicted_counts)), predicted_counts.values, color='lightcoral', edgecolor='darkred')
                ax2.set_title('Predicted Type Distribution', fontsize=14, fontweight='bold')
                ax2.set_ylabel('Count')
                ax2.set_xticks(range(len(predicted_counts)))
                ax2.set_xticklabels(predicted_counts.index, rotation=45, ha='right')
                ax2.grid(True, alpha=0.3)
                
                fig.tight_layout()
                
                canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
                canvas_fig.draw()
                canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            else:
                ttk.Label(scrollable_frame, text="No distribution data available", 
                         font=('Arial', 14)).pack(pady=50)
                
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating distributions: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_metrics_comparison_in_window(self):
        """Create metrics comparison chart"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Metrics Comparison")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            if hasattr(self.analyzer, 'results') and 'class_metrics' in self.analyzer.results:
                fig = Figure(figsize=(12, 8), dpi=100, facecolor='white')
                ax = fig.add_subplot(111)
                
                # Prepare data
                classes = list(self.analyzer.results['class_metrics'].keys())
                precisions = [self.analyzer.results['class_metrics'][c]['precision'] for c in classes]
                recalls = [self.analyzer.results['class_metrics'][c]['recall'] for c in classes]
                f1_scores = [self.analyzer.results['class_metrics'][c]['f1_score'] for c in classes]
                
                x = np.arange(len(classes))
                width = 0.25
                
                ax.bar(x - width, precisions, width, label='Precision', color='skyblue', edgecolor='navy')
                ax.bar(x, recalls, width, label='Recall', color='lightgreen', edgecolor='darkgreen')
                ax.bar(x + width, f1_scores, width, label='F1-Score', color='lightcoral', edgecolor='darkred')
                
                ax.set_title('Performance Metrics by Class', fontsize=14, fontweight='bold')
                ax.set_ylabel('Score')
                ax.set_xlabel('Classes')
                ax.set_xticks(x)
                ax.set_xticklabels(classes, rotation=45, ha='right')
                ax.legend()
                ax.grid(True, alpha=0.3)
                ax.set_ylim(0, 1.1)
                
                fig.tight_layout()
                
                canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
                canvas_fig.draw()
                canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            else:
                ttk.Label(scrollable_frame, text="No metrics data available", 
                         font=('Arial', 14)).pack(pady=50)
                
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating metrics comparison: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_radar_analysis_in_window(self):
        """Create comprehensive radar chart analysis for single sheet"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Radar Analysis")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            # Create figure with subplots for different radar analyses
            fig = Figure(figsize=(15, 10), dpi=100, facecolor='white')
            
            if hasattr(self.analyzer, 'results') and 'class_metrics' in self.analyzer.results:
                if len(self.analyzer.results['class_metrics']) >= 3:
                    # Performance metrics radar
                    ax1 = fig.add_subplot(2, 2, 1, projection='polar')
                    classes = list(self.analyzer.results['class_metrics'].keys())[:6]
                    metrics = ['Precision', 'Recall', 'F1-Score']
                    
                    angles = [n / float(len(metrics)) * 2 * pi for n in range(len(metrics))]
                    angles += angles[:1]
                    
                    colors = plt.cm.tab10(np.linspace(0, 1, len(classes)))
                    
                    for i, (class_name, color) in enumerate(zip(classes, colors)):
                        class_data = self.analyzer.results['class_metrics'][class_name]
                        values = [class_data['precision'], class_data['recall'], class_data['f1_score']]
                        values += values[:1]
                        
                        ax1.plot(angles, values, 'o-', linewidth=2, label=str(class_name), color=color)
                        ax1.fill(angles, values, alpha=0.15, color=color)
                    
                    ax1.set_xticks(angles[:-1])
                    ax1.set_xticklabels(metrics)
                    ax1.set_ylim(0, 1)
                    ax1.set_title('Performance Metrics Radar', fontsize=12, fontweight='bold', pad=20)
                    ax1.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                    ax1.grid(True)
                    
                    # Statistical significance radar
                    ax2 = fig.add_subplot(2, 2, 2, projection='polar')
                    if hasattr(self.analyzer, 'confusion_matrix') and self.analyzer.confusion_matrix is not None:
                        # Calculate statistical metrics for each class
                        actual_counts = self.analyzer.confusion_matrix.sum(axis=0)
                        predicted_counts = self.analyzer.confusion_matrix.sum(axis=1)
                        
                        # Normalize counts for radar display
                        max_count = max(actual_counts.max(), predicted_counts.max())
                        actual_norm = actual_counts / max_count
                        predicted_norm = predicted_counts / max_count
                        
                        # Create radar for first 6 classes
                        class_names = list(actual_counts.index)[:6]
                        angles = [n / float(len(class_names)) * 2 * pi for n in range(len(class_names))]
                        angles += angles[:1]
                        
                        actual_values = [actual_norm[name] for name in class_names]
                        predicted_values = [predicted_norm[name] for name in class_names]
                        actual_values += actual_values[:1]
                        predicted_values += predicted_values[:1]
                        
                        ax2.plot(angles, actual_values, 'o-', linewidth=2, label='Actual Distribution', color='blue')
                        ax2.fill(angles, actual_values, alpha=0.15, color='blue')
                        ax2.plot(angles, predicted_values, 'o-', linewidth=2, label='Predicted Distribution', color='red')
                        ax2.fill(angles, predicted_values, alpha=0.15, color='red')
                        
                        ax2.set_xticks(angles[:-1])
                        ax2.set_xticklabels([str(name)[:8] for name in class_names], fontsize=8)
                        ax2.set_ylim(0, 1)
                        ax2.set_title('Distribution Comparison Radar', fontsize=12, fontweight='bold', pad=20)
                        ax2.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                        ax2.grid(True)
                    
                    # Quality metrics radar
                    ax3 = fig.add_subplot(2, 2, 3, projection='polar')
                    if hasattr(self.analyzer, 'confusion_matrix') and self.analyzer.confusion_matrix is not None:
                        # Calculate quality metrics for each class
                        quality_metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Support']
                        
                        angles = [n / float(len(quality_metrics)) * 2 * pi for n in range(len(quality_metrics))]
                        angles += angles[:1]
                        
                        # Use first class as representative
                        first_class = list(self.analyzer.results['class_metrics'].keys())[0]
                        class_data = self.analyzer.results['class_metrics'][first_class]
                        
                        values = [
                            class_data.get('accuracy', 0),
                            class_data.get('precision', 0),
                            class_data.get('recall', 0),
                            class_data.get('f1_score', 0),
                            min(class_data.get('support', 0) / 100, 1.0)  # Normalize support
                        ]
                        values += values[:1]
                        
                        ax3.plot(angles, values, 'o-', linewidth=2, label=first_class, color='green')
                        ax3.fill(angles, values, alpha=0.15, color='green')
                        
                        ax3.set_xticks(angles[:-1])
                        ax3.set_xticklabels(quality_metrics)
                        ax3.set_ylim(0, 1)
                        ax3.set_title('Quality Metrics Radar', fontsize=12, fontweight='bold', pad=20)
                        ax3.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                        ax3.grid(True)
                    
                    # Overall performance radar
                    ax4 = fig.add_subplot(2, 2, 4, projection='polar')
                    overall_metrics = ['Global Accuracy', 'Association Strength', 'Neuron Utilization', 'Data Quality']
                    
                    angles = [n / float(len(overall_metrics)) * 2 * pi for n in range(len(overall_metrics))]
                    angles += angles[:1]
                    
                    # Calculate overall metrics
                    if hasattr(self.analyzer, 'batch_results') and self.analyzer.batch_results:
                        sheet_name = list(self.analyzer.batch_results.keys())[0]
                        sheet_data = self.analyzer.batch_results[sheet_name]
                        
                        overall_values = [
                            min(sheet_data.get('global_fit', 0) / 100, 1.0),  # Normalize accuracy
                            min(sheet_data.get('cramers_v', 0) * 2, 1.0),     # Scale Cramer's V
                            min(sheet_data.get('active_neurons', 0) / sheet_data.get('total_neurons', 1), 1.0),
                            min(sheet_data.get('data_completeness', 0) / 100, 1.0)  # Normalize completeness
                        ]
                    else:
                        overall_values = [0.5, 0.5, 0.5, 0.5]  # Default values
                    
                    overall_values += overall_values[:1]
                    
                    ax4.plot(angles, overall_values, 'o-', linewidth=2, label='Overall Performance', color='purple')
                    ax4.fill(angles, overall_values, alpha=0.15, color='purple')
                    
                    ax4.set_xticks(angles[:-1])
                    ax4.set_xticklabels(overall_metrics)
                    ax4.set_ylim(0, 1)
                    ax4.set_title('Overall Performance Radar', fontsize=12, fontweight='bold', pad=20)
                    ax4.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)
                    ax4.grid(True)
                    
                else:
                    # Not enough classes for radar
                    ax = fig.add_subplot(111)
                    ax.text(0.5, 0.5, 'Radar analysis requires at least 3 classes', 
                           ha='center', va='center', fontsize=14, transform=ax.transAxes)
                    ax.set_title('Radar Analysis', fontsize=14, fontweight='bold')
            else:
                ax = fig.add_subplot(111)
                ax.text(0.5, 0.5, 'No analysis data available for radar charts', 
                       ha='center', va='center', fontsize=14, transform=ax.transAxes)
                ax.set_title('Radar Analysis', fontsize=14, fontweight='bold')
            
            fig.tight_layout()
            
            canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
            canvas_fig.draw()
            canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating radar analysis: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_pie_chart_analysis_in_window(self):
        """Create comprehensive pie chart analysis for single sheet"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Pie Chart Analysis")
        
        # Create scrollable canvas
        canvas = tk.Canvas(frame, bg='white')
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        try:
            # Create figure with subplots for different pie analyses
            fig = Figure(figsize=(15, 10), dpi=100, facecolor='white')
            
            if hasattr(self.analyzer, 'confusion_matrix') and self.analyzer.confusion_matrix is not None:
                # Class distribution pie chart
                ax1 = fig.add_subplot(2, 2, 1)
                actual_counts = self.analyzer.confusion_matrix.sum(axis=0)
                
                # Limit to top 8 classes for readability
                top_classes = actual_counts.nlargest(8)
                other_count = actual_counts.sum() - top_classes.sum()
                
                if other_count > 0:
                    pie_data = list(top_classes.values) + [other_count]
                    pie_labels = list(top_classes.index) + ['Others']
                else:
                    pie_data = list(top_classes.values)
                    pie_labels = list(top_classes.index)
                
                colors = plt.cm.tab10(np.linspace(0, 1, len(pie_data)))
                wedges, texts, autotexts = ax1.pie(pie_data, labels=pie_labels, autopct='%1.1f%%', 
                                                   colors=colors, startangle=90)
                
                # Enhance text readability
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')
                
                ax1.set_title('Actual Class Distribution', fontsize=12, fontweight='bold')
                
                # Predicted distribution pie chart
                ax2 = fig.add_subplot(2, 2, 2)
                predicted_counts = self.analyzer.confusion_matrix.sum(axis=1)
                
                # Limit to top 8 classes for readability
                top_predicted = predicted_counts.nlargest(8)
                other_predicted = predicted_counts.sum() - top_predicted.sum()
                
                if other_predicted > 0:
                    pie_data_pred = list(top_predicted.values) + [other_predicted]
                    pie_labels_pred = list(top_predicted.index) + ['Others']
                else:
                    pie_data_pred = list(top_predicted.values)
                    pie_labels_pred = list(top_predicted.index)
                
                colors_pred = plt.cm.tab20(np.linspace(0, 1, len(pie_data_pred)))
                wedges, texts, autotexts = ax2.pie(pie_data_pred, labels=pie_labels_pred, autopct='%1.1f%%', 
                                                   colors=colors_pred, startangle=90)
                
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')
                
                ax2.set_title('Predicted Class Distribution', fontsize=12, fontweight='bold')
                
                # Performance metrics pie chart
                ax3 = fig.add_subplot(2, 2, 3)
                if hasattr(self.analyzer, 'results') and 'class_metrics' in self.analyzer.results:
                    # Calculate average performance metrics
                    classes = list(self.analyzer.results['class_metrics'].keys())
                    avg_precision = np.mean([self.analyzer.results['class_metrics'][c]['precision'] for c in classes])
                    avg_recall = np.mean([self.analyzer.results['class_metrics'][c]['recall'] for c in classes])
                    avg_f1 = np.mean([self.analyzer.results['class_metrics'][c]['f1_score'] for c in classes])
                    
                    # Calculate remaining as "Other Metrics"
                    remaining = 3 - (avg_precision + avg_recall + avg_f1)
                    
                    performance_data = [avg_precision, avg_recall, avg_f1, remaining]
                    performance_labels = ['Avg Precision', 'Avg Recall', 'Avg F1-Score', 'Other Metrics']
                    performance_colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
                    
                    wedges, texts, autotexts = ax3.pie(performance_data, labels=performance_labels, autopct='%1.1f%%', 
                                                       colors=performance_colors, startangle=90)
                    
                    for autotext in autotexts:
                        autotext.set_color('white')
                        autotext.set_fontweight('bold')
                    
                    ax3.set_title('Average Performance Metrics', fontsize=12, fontweight='bold')
                
                # Data quality pie chart
                ax4 = fig.add_subplot(2, 2, 4)
                if hasattr(self.analyzer, 'batch_results') and self.analyzer.batch_results:
                    sheet_name = list(self.analyzer.batch_results.keys())[0]
                    sheet_data = self.analyzer.batch_results[sheet_name]
                    
                    # Calculate quality metrics
                    accuracy = sheet_data.get('global_fit', 0)
                    association = sheet_data.get('cramers_v', 0) * 100  # Convert to percentage
                    utilization = sheet_data.get('active_neurons', 0) / sheet_data.get('total_neurons', 1) * 100
                    completeness = sheet_data.get('data_completeness', 0)
                    
                    # Normalize to percentages that sum to 100
                    total = accuracy + association + utilization + completeness
                    if total > 0:
                        accuracy_norm = (accuracy / total) * 100
                        association_norm = (association / total) * 100
                        utilization_norm = (utilization / total) * 100
                        completeness_norm = (completeness / total) * 100
                    else:
                        accuracy_norm = association_norm = utilization_norm = completeness_norm = 25
                    
                    quality_data = [accuracy_norm, association_norm, utilization_norm, completeness_norm]
                    quality_labels = ['Accuracy', 'Association', 'Utilization', 'Completeness']
                    quality_colors = ['#FFD93D', '#6BCF7F', '#4D96FF', '#FF6B9D']
                    
                    wedges, texts, autotexts = ax4.pie(quality_data, labels=quality_labels, autopct='%1.1f%%', 
                                                       colors=quality_colors, startangle=90)
                    
                    for autotext in autotexts:
                        autotext.set_color('white')
                        autotext.set_fontweight('bold')
                    
                    ax4.set_title('Data Quality Metrics', fontsize=12, fontweight='bold')
                
            else:
                # No data available
                ax = fig.add_subplot(111)
                ax.text(0.5, 0.5, 'No confusion matrix data available for pie charts', 
                       ha='center', va='center', fontsize=14, transform=ax.transAxes)
                ax.set_title('Pie Chart Analysis', fontsize=14, fontweight='bold')
            
            fig.tight_layout()
            
            canvas_fig = FigureCanvasTkAgg(fig, scrollable_frame)
            canvas_fig.draw()
            canvas_fig.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            ttk.Label(scrollable_frame, text=f"Error creating pie chart analysis: {str(e)}", 
                     font=('Arial', 12)).pack(pady=50)
        
        # Configure scrolling
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _on_shift_mousewheel(event):
            canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel)
        canvas.bind("<Button-5>", _on_mousewheel)
        scrollable_frame.bind("<Button-4>", _on_mousewheel)
        scrollable_frame.bind("<Button-5>", _on_mousewheel)
        canvas.bind("<Shift-Button-4>", _on_shift_mousewheel)
        canvas.bind("<Shift-Button-5>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-4>", _on_shift_mousewheel)
        scrollable_frame.bind("<Shift-Button-5>", _on_shift_mousewheel)
    
    def create_placeholder(self):
        """Create placeholder when no data is available"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="No Data")
        
        ttk.Label(frame, text="No analysis data available.\nPlease run an analysis first.", 
                 font=('Arial', 16), foreground='gray').pack(expand=True)
    
    def create_error_tab(self, error_message):
        """Create error tab when visualization fails"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Error")
        
        error_text = f"Error creating visualizations:\n\n{error_message}"
        ttk.Label(frame, text=error_text, font=('Arial', 12), 
                 foreground='red', wraplength=600).pack(expand=True, padx=20, pady=20)
    
    def export_all_charts(self):
        """Export all charts from the visualization window"""
        try:
            self.analyzer.export_charts()
            messagebox.showinfo("Export Complete", "All charts exported successfully!")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export charts: {str(e)}")
    
    def refresh_visualizations(self):
        """Refresh all visualizations"""
        # Clear existing tabs
        for tab in self.notebook.tabs():
            self.notebook.forget(tab)
        
        # Reload visualizations
        self.load_visualizations()
        
        messagebox.showinfo("Refresh Complete", "Visualizations refreshed!")
    
    def on_close(self):
        """Handle window close event"""
        self.window.destroy()
        self.window = None

# Enhanced dependency management
def check_dependencies():
    """Enhanced dependency checking with detailed reporting and user guidance"""
    logger.info("Checking system dependencies...")
    
    # Check if running as frozen executable
    is_frozen = getattr(sys, 'frozen', False)
    
    if is_frozen:
        # When frozen, all dependencies should be bundled
        # Just verify they can be imported
        logger.info("Running as compiled executable - verifying bundled dependencies...")
        
        required_modules = {
            'numpy': 'numpy',
            'pandas': 'pandas',
            'scipy': 'scipy',
            'matplotlib': 'matplotlib',
            'seaborn': 'seaborn',
            'openpyxl': 'openpyxl',
            'requests': 'requests'
        }
        
        missing_deps = []
        for package_name, module_name in required_modules.items():
            try:
                __import__(module_name)
                logger.debug(f"{package_name}: OK (bundled)")
            except ImportError as e:
                missing_deps.append(package_name)
                logger.error(f"Required package {package_name} cannot be imported: {e}")
        
        if missing_deps:
            error_msg = "Missing Required Dependencies:\n\n"
            error_msg += "Missing packages:\n"
            for pkg in missing_deps:
                error_msg += f"  • {pkg}\n"
            error_msg += "\n"
            error_msg += "These packages should be bundled in the executable.\n"
            error_msg += "Please rebuild the executable with all dependencies included."
            
            try:
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror("Dependency Error", error_msg)
                root.destroy()
            except Exception as e:
                logger.error(f"Failed to show dependency error dialog: {e}")
                logger.error(error_msg)
            
            return False
        
        logger.info("All bundled dependencies verified")
        return True
    
    # For non-frozen execution (development/testing), check versions
    dependencies = {
        'numpy': '1.24.0',
        'pandas': '2.0.0', 
        'scipy': '1.10.0',
        'matplotlib': '3.7.0',
        'seaborn': '0.12.0',
        'openpyxl': '3.1.0',
        'requests': '2.28.0'
    }
    
    # Optional dependencies
    optional_dependencies = {
        'adjustText': '1.3.0'
    }
    
    missing_deps = []
    version_issues = []
    optional_missing = []
    
    # Check required dependencies
    for package, min_version in dependencies.items():
        try:
            # Use modern importlib.metadata
            try:
                from importlib import metadata
            except ImportError:
                import importlib_metadata as metadata
            
            try:
                installed_version = metadata.version(package)
                logger.debug(f"{package}: {installed_version} (required: {min_version})")
                
                # Simple version comparison
                if installed_version < min_version:
                    version_issues.append({
                        'package': package,
                        'installed': installed_version,
                        'required': min_version
                    })
                    logger.warning(f"{package} version {installed_version} is below required {min_version}")
                    
            except metadata.PackageNotFoundError:
                missing_deps.append(package)
                logger.error(f"Required package {package} is not installed")
                
        except ImportError as e:
            missing_deps.append(package)
            logger.error(f"Failed to check {package}: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error checking {package}: {e}")
    
    # Check optional dependencies
    for package, min_version in optional_dependencies.items():
        try:
            try:
                from importlib import metadata
            except ImportError:
                import importlib_metadata as metadata
                
            installed_version = metadata.version(package)
            logger.debug(f"Optional {package}: {installed_version}")
            
        except metadata.PackageNotFoundError:
            optional_missing.append(package)
            logger.info(f"Optional package {package} not found (features may be limited)")
        except Exception:
            pass
    
    # Report results
    if missing_deps or version_issues:
        logger.error("Dependency check failed!")
        
        error_msg = "Missing Required Dependencies:\n\n"
        
        if missing_deps:
            error_msg += "Missing packages:\n"
            for pkg in missing_deps:
                error_msg += f"  • {pkg} (>= {dependencies[pkg]})\n"
            error_msg += "\n"
        
        if version_issues:
            error_msg += "Version conflicts:\n"
            for issue in version_issues:
                error_msg += f"  • {issue['package']}: installed {issue['installed']}, need >= {issue['required']}\n"
            error_msg += "\n"
        
        error_msg += "Installation command:\n"
        error_msg += f"pip install " + " ".join([f"{pkg}>={ver}" for pkg, ver in dependencies.items()])
        
        # Show error dialog
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Dependency Error", error_msg)
            root.destroy()
        except Exception as e:
            logger.error(f"Failed to show dependency error dialog: {e}")
            logger.error(error_msg)
        
        return False
    
    if optional_missing:
        logger.info(f"Optional dependencies missing: {', '.join(optional_missing)}")
        logger.info("Some advanced features may not be available")
    
    logger.info("All required dependencies satisfied")
    return True

# Try to import adjustText for better label positioning
try:
    from adjustText import adjust_text  # type: ignore
    ADJUST_TEXT_AVAILABLE = True
except ImportError:
    ADJUST_TEXT_AVAILABLE = False

class ProfessionalVisualizationDesigner:
    """Professional visualization designer for client-ready charts"""
    
    def __init__(self):
        # Standardized chart dimensions for consistency
        self.standard_width = 12.0
        self.standard_height = 8.0
        self.dpi = 100
        self.facecolor = 'white'
        
        # Professional color palette
        self.colors = {
            'primary': '#2E86AB',      # Professional blue
            'secondary': '#A23B72',    # Professional purple
            'accent': '#F18F01',       # Professional orange
            'success': '#C73E1D',      # Professional red
            'neutral': '#6C757D',      # Professional gray
            'light_blue': '#E3F2FD',
            'light_green': '#E8F5E8',
            'light_orange': '#FFF3E0',
            'light_red': '#FFEBEE'
        }
        
        # Performance color mapping
        self.performance_colors = {
            'excellent': '#2E7D32',    # Dark green
            'good': '#388E3C',         # Green
            'fair': '#F57C00',         # Orange
            'poor': '#D32F2F'          # Red
        }
        
        # Font settings for professional appearance
        self.font_settings = {
            'title': {'fontsize': 14, 'fontweight': 'bold', 'color': '#2E86AB'},
            'subtitle': {'fontsize': 12, 'fontweight': 'bold', 'color': '#6C757D'},
            'axis_label': {'fontsize': 11, 'fontweight': 'normal', 'color': '#495057'},
            'tick_label': {'fontsize': 9, 'fontweight': 'normal', 'color': '#495057'},
            'legend': {'fontsize': 10, 'fontweight': 'normal', 'color': '#495057'},
            'annotation': {'fontsize': 8, 'fontweight': 'bold', 'color': '#212529'}
        }
        
        # Standard margins and spacing
        self.margins = {
            'left': 0.12,
            'right': 0.95,
            'top': 0.92,
            'bottom': 0.15
        }
        
        # Legend positioning
        self.legend_positions = {
            'right': 'upper right',
            'left': 'upper left', 
            'bottom': 'lower center',
            'top': 'upper center'
        }
    
    def create_standard_figure(self, width=None, height=None, subplot_layout=(1, 1)):
        """Create a standardized figure with consistent sizing"""
        if width is None:
            width = self.standard_width
        if height is None:
            height = self.standard_height
            
        fig = Figure(figsize=(width, height), dpi=self.dpi, facecolor=self.facecolor)
        
        # Set standard margins
        fig.subplots_adjust(
            left=self.margins['left'],
            right=self.margins['right'],
            top=self.margins['top'],
            bottom=self.margins['bottom']
        )
        
        return fig
    
    def create_subplot_grid(self, fig, rows, cols, **kwargs):
        """Create a grid of subplots with consistent spacing"""
        gs = fig.add_gridspec(rows, cols, **kwargs)
        return gs
    
    def format_axis_labels(self, ax, xlabel=None, ylabel=None, title=None, 
                          xlabel_rotation=45, ylabel_rotation=0):
        """Format axis labels with consistent styling and text wrapping"""
        
        if title:
            # Wrap long titles
            wrapped_title = self.wrap_text(title, max_length=60)
            ax.set_title(wrapped_title, **self.font_settings['title'], pad=20)
        
        if xlabel:
            wrapped_xlabel = self.wrap_text(xlabel, max_length=40)
            ax.set_xlabel(wrapped_xlabel, **self.font_settings['axis_label'])
        
        if ylabel:
            wrapped_ylabel = self.wrap_text(ylabel, max_length=30)
            ax.set_ylabel(wrapped_ylabel, **self.font_settings['axis_label'])
        
        # Format tick labels
        ax.tick_params(axis='both', labelsize=self.font_settings['tick_label']['fontsize'])
        
        # Rotate x-axis labels if needed
        if xlabel_rotation != 0:
            ax.set_xticklabels(ax.get_xticklabels(), rotation=xlabel_rotation, 
                              ha='right', fontsize=self.font_settings['tick_label']['fontsize'])
        
        if ylabel_rotation != 0:
            ax.set_yticklabels(ax.get_yticklabels(), rotation=ylabel_rotation, 
                              fontsize=self.font_settings['tick_label']['fontsize'])
    
    def wrap_text(self, text, max_length=50):
        """Wrap text to prevent overflow"""
        if len(text) <= max_length:
            return text
        
        words = text.split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line + " " + word) <= max_length:
                current_line += (" " + word if current_line else word)
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        
        if current_line:
            lines.append(current_line)
        
        return '\n'.join(lines)
    
    def create_legend(self, ax, legend_data, position='right', title=None, 
                     max_items_per_column=10):
        """Create a professional legend with proper positioning and formatting"""
        
        if not legend_data:
            return
        
        # Determine legend position
        if position in self.legend_positions:
            loc = self.legend_positions[position]
        else:
            loc = position
        
        # Create legend
        legend = ax.legend(
            loc=loc,
            fontsize=self.font_settings['legend']['fontsize'],
            title=title,
            title_fontsize=self.font_settings['subtitle']['fontsize'],
            frameon=True,
            fancybox=True,
            shadow=True,
            ncol=1 if len(legend_data) <= max_items_per_column else 2
        )
        
        # Style the legend
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.9)
        legend.get_frame().set_edgecolor('#E0E0E0')
        
        return legend
    
    def create_color_mapping(self, labels, color_scheme='professional'):
        """Create consistent color mapping for labels"""
        if color_scheme == 'professional':
            base_colors = [self.colors['primary'], self.colors['secondary'], 
                          self.colors['accent'], self.colors['success']]
        elif color_scheme == 'performance':
            base_colors = list(self.performance_colors.values())
        else:
            base_colors = plt.cm.tab10.colors
        
        # Extend colors if needed
        while len(base_colors) < len(labels):
            base_colors.extend(base_colors)
        
        return {label: base_colors[i % len(base_colors)] for i, label in enumerate(labels)}
    
    def create_performance_color_mapping(self, values, metric_type):
        """Create color mapping based on performance thresholds"""
        colors = []
        
        for val in values:
            if metric_type == 'accuracy':
                if val >= 80:
                    colors.append(self.performance_colors['excellent'])
                elif val >= 60:
                    colors.append(self.performance_colors['good'])
                elif val >= 40:
                    colors.append(self.performance_colors['fair'])
                else:
                    colors.append(self.performance_colors['poor'])
            elif metric_type == 'association':
                if val >= 0.7:
                    colors.append(self.performance_colors['excellent'])
                elif val >= 0.5:
                    colors.append(self.performance_colors['good'])
                elif val >= 0.3:
                    colors.append(self.performance_colors['fair'])
                else:
                    colors.append(self.performance_colors['poor'])
            else:  # Lower is better (e.g., PZE)
                if val <= 10:
                    colors.append(self.performance_colors['excellent'])
                elif val <= 25:
                    colors.append(self.performance_colors['good'])
                elif val <= 40:
                    colors.append(self.performance_colors['fair'])
                else:
                    colors.append(self.performance_colors['poor'])
        
        return colors
    
    def add_value_labels(self, ax, bars, format_func=None, offset=3):
        """Add value labels to bars with consistent formatting"""
        for bar in bars:
            height = bar.get_height()
            if format_func:
                label = format_func(height)
            else:
                label = f'{height:.1f}'
            
            ax.annotate(
                label,
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, offset),
                textcoords="offset points",
                ha='center', va='bottom',
                **self.font_settings['annotation']
            )
    
    def create_key_legend(self, ax, key_mapping, title="Legend", position='right'):
        """Create a key legend for abbreviated labels"""
        if not key_mapping:
            return
        
        # Create legend text
        legend_text = []
        for short_name, full_name in key_mapping.items():
            legend_text.append(f"{short_name}: {full_name}")
        
        # Add text box with legend
        legend_str = '\n'.join(legend_text)
        
        if position == 'right':
            bbox_props = dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.9, edgecolor='#E0E0E0')
            ax.text(1.02, 0.98, legend_str, transform=ax.transAxes, fontsize=8,
                   verticalalignment='top', bbox=bbox_props)
        elif position == 'bottom':
            bbox_props = dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.9, edgecolor='#E0E0E0')
            ax.text(0.5, -0.15, legend_str, transform=ax.transAxes, fontsize=8,
                   horizontalalignment='center', bbox=bbox_props)
    
    def optimize_label_rotation(self, labels, max_length=15):
        """Automatically determine optimal label rotation"""
        max_label_length = max(len(str(label)) for label in labels)
        
        if max_label_length <= max_length:
            return 0
        elif max_label_length <= max_length * 1.5:
            return 45
        else:
            return 90
    
    def create_consistent_heatmap(self, data, ax, title=None, xlabel=None, ylabel=None,
                                 colorbar_label="Count", cmap='Blues', annotate=True):
        """Create a consistently styled heatmap"""
        
        # Create heatmap
        im = sns.heatmap(
            data,
            annot=annotate,
            fmt='d' if annotate else None,
            cmap=cmap,
            ax=ax,
            cbar_kws={'label': colorbar_label},
            square=True,
            linewidths=0.5,
            annot_kws={'fontsize': 8, 'fontweight': 'bold'}
        )
        
        # Format labels
        self.format_axis_labels(ax, xlabel, ylabel, title)
        
        # Optimize label rotation
        if len(data.columns) > 0:
            x_rotation = self.optimize_label_rotation(data.columns)
            ax.set_xticklabels(ax.get_xticklabels(), rotation=x_rotation, ha='right')
        
        if len(data.index) > 0:
            y_rotation = self.optimize_label_rotation(data.index)
            ax.set_yticklabels(ax.get_yticklabels(), rotation=y_rotation)
        
        return im
    
    def finalize_figure(self, fig, tight_layout=True):
        """Finalize figure with consistent formatting"""
        if tight_layout:
            fig.tight_layout(pad=2.0)
        
        return fig
    
    def create_confusion_matrix_heatmap(self, confusion_matrix, sheet_name):
        """Create a professional confusion matrix heatmap with sheet name in title"""
        try:
            fig = self.create_standard_figure(width=10, height=8)
            ax = fig.add_subplot(111)
            
            # Create heatmap with improved visibility
            im = sns.heatmap(
                confusion_matrix,
                annot=True,
                fmt='d',
                cmap='Blues',
                ax=ax,
                cbar_kws={'label': 'Count', 'shrink': 0.8},
                square=True,
                linewidths=1.0,
                annot_kws={'fontsize': 10, 'fontweight': 'bold', 'color': 'white'}
            )
            
            # Set title with sheet name
            title = f"Confusion Matrix - {sheet_name}"
            ax.set_title(title, **self.font_settings['title'], pad=20)
            ax.set_xlabel('Predicted', **self.font_settings['axis_label'])
            ax.set_ylabel('Actual', **self.font_settings['axis_label'])
            
            # Improve tick label visibility
            ax.tick_params(axis='both', labelsize=10, colors='#495057')
            
            # Add value annotations with better contrast
            for i in range(confusion_matrix.shape[0]):
                for j in range(confusion_matrix.shape[1]):
                    value = confusion_matrix.iloc[i, j]
                    text_color = 'white' if value > confusion_matrix.values.max() * 0.5 else 'black'
                    ax.text(j + 0.5, i + 0.5, str(value), 
                           ha='center', va='center', 
                           fontsize=10, fontweight='bold', color=text_color)
            
            return self.finalize_figure(fig)
            
        except Exception as e:
            logger.error(f"Error creating confusion matrix heatmap: {e}")
            return None
    
    def create_correlation_matrix(self, correlation_matrix, sheet_name):
        """Create a professional correlation matrix with sheet name in title"""
        try:
            fig = self.create_standard_figure(width=10, height=8)
            ax = fig.add_subplot(111)
            
            # Create heatmap with improved visibility
            im = sns.heatmap(
                correlation_matrix,
                annot=True,
                fmt='.2f',
                cmap='RdBu_r',
                center=0,
                ax=ax,
                cbar_kws={'label': 'Correlation Coefficient', 'shrink': 0.8},
                square=True,
                linewidths=1.0,
                annot_kws={'fontsize': 9, 'fontweight': 'bold'}
            )
            
            # Set title with sheet name
            title = f"Correlation Matrix - {sheet_name}"
            ax.set_title(title, **self.font_settings['title'], pad=20)
            ax.set_xlabel('Variables', **self.font_settings['axis_label'])
            ax.set_ylabel('Variables', **self.font_settings['axis_label'])
            
            # Improve tick label visibility
            ax.tick_params(axis='both', labelsize=9, colors='#495057')
            
            return self.finalize_figure(fig)
            
        except Exception as e:
            logger.error(f"Error creating correlation matrix: {e}")
            return None
    
    def create_statistical_summary_chart(self, statistics, sheet_name):
        """Create a professional statistical summary chart with sheet name in title"""
        try:
            fig = self.create_standard_figure(width=12, height=8)
            
            # Create 2x2 subplot grid for better organization
            gs = fig.add_gridspec(2, 2, hspace=0.3, wspace=0.3)
            
            # Extract key statistics
            metrics = {
                'Classification Accuracy': statistics.get('global_fit', 0),
                'Cramer\'s V': statistics.get('cramers_v', 0),
                'Chi-Square P-Value': statistics.get('chi2_pvalue', 1),
                'Sample Size': statistics.get('total_observations', 0)
            }
            
            # 1. Bar chart for main metrics
            ax1 = fig.add_subplot(gs[0, 0])
            bars = ax1.bar(range(len(metrics)), list(metrics.values()), 
                          color=[self.colors['primary'], self.colors['secondary'], 
                                self.colors['accent'], self.colors['success']])
            ax1.set_title('Key Performance Metrics', **self.font_settings['subtitle'])
            ax1.set_xticks(range(len(metrics)))
            ax1.set_xticklabels(list(metrics.keys()), rotation=45, ha='right')
            ax1.set_ylabel('Value', **self.font_settings['axis_label'])
            
            # Add value labels on bars
            self.add_value_labels(ax1, bars, format_func=lambda x: f'{x:.2f}')
            
            # 2. Pie chart for accuracy distribution
            ax2 = fig.add_subplot(gs[0, 1])
            accuracy = statistics.get('global_fit', 0)
            accuracy_data = [accuracy, 100 - accuracy]
            labels = ['Correct', 'Incorrect']
            colors = [self.colors['success'], self.colors['neutral']]
            
            wedges, texts, autotexts = ax2.pie(accuracy_data, labels=labels, colors=colors, 
                                              autopct='%1.1f%%', startangle=90)
            ax2.set_title('Classification Accuracy Distribution', **self.font_settings['subtitle'])
            
            # 3. Performance indicators
            ax3 = fig.add_subplot(gs[1, :])
            
            # Create performance indicators
            indicators = {
                'Sample Size': statistics.get('total_observations', 0),
                'Matrix Size': f"{statistics.get('matrix_shape', 'N/A')}",
                'Effect Size': statistics.get('cramers_v', 0),
                'Significance': 'Yes' if statistics.get('chi2_pvalue', 1) < 0.05 else 'No'
            }
            
            y_pos = range(len(indicators))
            ax3.barh(y_pos, [1] * len(indicators), color=self.colors['light_blue'], alpha=0.7)
            ax3.set_yticks(y_pos)
            ax3.set_yticklabels(list(indicators.keys()))
            ax3.set_xlabel('Status', **self.font_settings['axis_label'])
            ax3.set_title('Analysis Summary', **self.font_settings['subtitle'])
            
            # Add values as text
            for i, (key, value) in enumerate(indicators.items()):
                ax3.text(0.5, i, str(value), ha='center', va='center', 
                        fontweight='bold', fontsize=10)
            
            # Set main title with sheet name
            fig.suptitle(f"Statistical Analysis Summary - {sheet_name}", 
                        **self.font_settings['title'], y=0.95)
            
            return self.finalize_figure(fig)
            
        except Exception as e:
            logger.error(f"Error creating statistical summary chart: {e}")
            return None

# Global designer instance
designer = ProfessionalVisualizationDesigner()

class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder for numpy types"""
    def default(self, obj):
        if hasattr(obj, 'item'):
            return obj.item()  # Convert numpy scalars to Python types
        elif hasattr(obj, 'tolist'):
            return obj.tolist()  # Convert numpy arrays to lists
        return super().default(obj)


class SheetSelectionConfig:
    """Configuration for sheet selection dialog"""
    def __init__(self):
        self.dialog_size = (900, 1000)  # Match main window height
        self.min_size = (800, 800)
        self.max_size = (1200, 1200)
        self.preview_rows = 5
        self.auto_select_valid = True
        self.show_preview_info = True

# Security and resource configuration
MAX_MEMORY_MB = 512
OPERATION_TIMEOUT = 300
MAX_CELLS = 1000000

# Data management configuration
PROJECTS_DIR = Path.home() / "deltaV solutions_Projects"
BACKUPS_DIR = PROJECTS_DIR / "Backups"
SETTINGS_FILE = PROJECTS_DIR / "settings.json"
MAX_BACKUPS = 10

class StatisticalAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Statistical Contingency Analysis Platform v1.0 - Ready")
        # Let window size to content instead of fixed size
        self.root.geometry("1800x900")  # Reasonable starting size
        self.root.configure(bg='#f5f5f5')
        
        # Allow window to resize to content
        self.root.minsize(1200, 700)  # Minimum usable size
        self.root.maxsize(2500, 1500)  # Maximum before it gets unwieldy
        
        # Data storage - removed redundant variables
        self.confusion_matrix = None
        self.results = {}
        self.excel_file = None
        
        # NEW: Batch processing data storage
        self.batch_results = {}  # Store results for all sheets
        self.comparison_summary = None  # Summary comparison table
        
        # Visualization window
        self.viz_window = None
        
        # Data management
        self.current_project = None
        self.project_metadata = {}
        self.ensure_project_directories()
        
        # Thread safety
        self.data_lock = threading.Lock()
        
        # Threading infrastructure with comprehensive safety
        self.thread_manager = SafeThreadPoolManager(max_workers=MAX_WORKERS)
        self.current_tasks = []
        self.cancel_event = threading.Event()
        self.progress_queue = Queue()
        
        # UI state management
        self.processing_state = False
        self.button_states = {}
        
        self.setup_ui()
        self.setup_menu_bar()
        self.start_progress_monitor()
        
        # Show initial ready state and resize to content
        self.root.after(1000, lambda: self.show_ready_state())
        self.root.after(1500, self.auto_resize_to_content)  # Auto-resize after UI is ready
    
    def ensure_project_directories(self):
        """Create project directories if they don't exist"""
        try:
            PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
            BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            pass
    
    def show_message_safely(self, message_type, title, message):
        """Thread-safe message box display"""
        try:
            # Check if root window exists and is valid
            if not hasattr(self, 'root') or not self.root or not self.root.winfo_exists():
                logger.error(f"Cannot show message - root window not available: {title}: {message}")
                return None
            
            # Check if we're on main thread
            if threading.current_thread() is threading.main_thread():
                try:
                    if message_type == "error":
                        return messagebox.showerror(title, message)
                    elif message_type == "warning":
                        return messagebox.showwarning(title, message)
                    elif message_type == "info":
                        return messagebox.showinfo(title, message)
                    else:
                        return messagebox.showinfo(title, message)
                except RuntimeError as e:
                    if "main thread is not in main loop" in str(e):
                        logger.error(f"Tkinter mainloop not running: {title}: {message}")
                        return None
                    raise
            else:
                result_container = []
                completed = threading.Event()
                
                def show_on_main():
                    try:
                        # Double-check root is still valid
                        if not hasattr(self, 'root') or not self.root or not self.root.winfo_exists():
                            logger.error(f"Cannot show message - root window not available: {title}: {message}")
                            return
                        
                        if message_type == "error":
                            result = messagebox.showerror(title, message)
                        elif message_type == "warning":
                            result = messagebox.showwarning(title, message)
                        elif message_type == "info":
                            result = messagebox.showinfo(title, message)
                        else:
                            result = messagebox.showinfo(title, message)
                        result_container.append(result)
                    except RuntimeError as e:
                        if "main thread is not in main loop" in str(e):
                            logger.error(f"Tkinter mainloop not running: {title}: {message}")
                        else:
                            logger.error(f"Error showing message box: {e}")
                    except Exception as e:
                        logger.error(f"Error showing message box: {e}")
                    finally:
                        completed.set()
                
                try:
                    self.root.after(0, show_on_main)
                    completed.wait(timeout=5.0)  # Prevent deadlock
                    return result_container[0] if result_container else None
                except RuntimeError as e:
                    if "main thread is not in main loop" in str(e):
                        logger.error(f"Cannot schedule message - mainloop not running: {title}: {message}")
                        return None
                    raise
        except Exception as e:
            logger.error(f"Failed to show message safely: {title}: {message} - Error: {e}")
            return None
    
    def auto_resize_to_content(self):
        """Automatically resize window to fit content optimally"""
        try:
            # Force update of all widgets to get accurate sizes
            self.root.update_idletasks()
            
            # Get the actual content size needed
            content_width = self.root.winfo_reqwidth()
            content_height = self.root.winfo_reqheight()
            
            # Add some padding for window chrome (title bar, borders, etc.)
            padding_width = 50
            padding_height = 100
            
            # Calculate optimal window size
            optimal_width = min(max(content_width + padding_width, 1200), 2500)
            optimal_height = min(max(content_height + padding_height, 700), 1500)
            
            # Only resize if significantly different from current size
            current_width = self.root.winfo_width()
            current_height = self.root.winfo_height()
            
            width_diff = abs(optimal_width - current_width)
            height_diff = abs(optimal_height - current_height)
            
            # Resize if difference is more than 50 pixels in either direction
            if width_diff > 50 or height_diff > 50:
                self.root.geometry(f"{optimal_width}x{optimal_height}")
                
        except Exception as e:
            logger.warning(f"Failed to auto-resize window: {e}")
    
    def process_data_placeholder(self):
        """Process single sheet analysis using unified batch architecture"""
        try:
            # Validate inputs
            if not self.file_path.get():
                messagebox.showerror("No File Selected", "Please select an Excel file first.")
                return
                
            if not self.sheet_var.get():
                messagebox.showerror("No Sheet Selected", "Please select a sheet to analyze.")
                return
            
            # Ensure Excel file is loaded
            if not self.excel_file:
                # Load the Excel file if not already loaded
                try:
                    file_path = self.file_path.get()
                    if not os.path.exists(file_path):
                        messagebox.showerror("File Not Found", f"File not found: {file_path}")
                        return
                    
                    self.excel_file = pd.ExcelFile(file_path)
                    # Update sheet combo if needed
                    if not self.sheet_combo['values']:
                        sheet_names = self.excel_file.sheet_names
                        self.sheet_combo['values'] = sheet_names
                        if sheet_names:
                            self.sheet_combo.set(sheet_names[0])
                            self.sheet_var.set(sheet_names[0])
                except Exception as e:
                    messagebox.showerror("File Loading Error", f"Failed to load Excel file: {str(e)}")
                    return
            
            # Use the existing batch processing core logic for single sheet
            selected_sheets = [self.sheet_var.get()]
            self.batch_process_sheets_directly(selected_sheets)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start analysis: {str(e)}")
    
    def batch_process_sheets_directly(self, selected_sheets):
        """Process sheets without showing selection dialog"""
        if not self.excel_file:
            # Try to load the Excel file if not already loaded
            try:
                file_path = self.file_path.get()
                if not os.path.exists(file_path):
                    messagebox.showerror("File Not Found", f"File not found: {file_path}")
                    return
                
                self.excel_file = pd.ExcelFile(file_path)
            except Exception as e:
                messagebox.showerror("File Loading Error", f"Failed to load Excel file: {str(e)}")
                return
            
        if self.processing_state:
            return
            
        self.set_processing_state(True)
        self.safe_update_mode_label("Mode: Processing Analysis...", 'orange')
        self.update_progress_status('Starting analysis...', 0)
        
        # Show processing overlay immediately
        self.show_processing_overlay(f"Starting analysis of {len(selected_sheets)} sheet(s)...")
        self.root.update()  # Force update to show overlay
        
        def batch_worker():
            try:
                # Clear previous batch results
                with self.data_lock:
                    self.batch_results = {}
                    self.comparison_summary = None
                
                total_sheets = len(selected_sheets)
                processed_count = 0
                skipped_count = 0
                
                self.update_progress_status(f'Processing {total_sheets} sheet(s)...', 5)
                self.root.after(0, lambda: self.show_processing_overlay(f"Starting analysis of {total_sheets} sheet(s)..."))
                
                # Process each selected sheet
                for i, sheet_name in enumerate(selected_sheets):
                    if self.cancel_event.is_set():
                        return
                    
                    progress = 10 + (i / total_sheets) * 70  # 10-80% for processing
                    self.update_progress_status(f'Analyzing sheet: {sheet_name} ({i+1}/{total_sheets})', progress)
                    self.root.after(0, lambda name=sheet_name, idx=i+1, total=total_sheets: 
                                  self.show_processing_overlay(f"Analyzing sheet {idx}/{total}: {name}"))
                    
                    try:
                        # Process single sheet
                        sheet_results = self.process_single_sheet_for_batch(sheet_name)
                        
                        if sheet_results and isinstance(sheet_results, dict):
                            with self.data_lock:
                                self.batch_results[sheet_name] = sheet_results
                                processed_count += 1
                        else:
                            skipped_count += 1
                                
                    except Exception as e:
                        skipped_count += 1
                        continue
                
                # Create comparison summary if multiple sheets
                if len(selected_sheets) > 1:
                    self.update_progress_status('Creating comparison summary...', 85)
                    self.root.after(0, lambda: self.show_processing_overlay("Creating comparison summary..."))
                    self.create_comparison_summary()
                
                # Update UI with results
                self.update_progress_status('Finalizing results...', 95)
                self.root.after(0, lambda: self.show_processing_overlay("Finalizing results..."))
                
                def update_ui():
                    # Update the textual results area for batch processing
                    try:
                        if len(selected_sheets) == 1:
                            # For single sheet, show detailed results
                            sheet_name = selected_sheets[0]
                            if sheet_name in self.batch_results:
                                self.confusion_matrix = self.batch_results[sheet_name].get('confusion_matrix')
                                # Populate results dictionary with class metrics for visualization
                                if 'class_metrics' in self.batch_results[sheet_name]:
                                    self.results['class_metrics'] = self.batch_results[sheet_name]['class_metrics']
                                # Display single sheet results
                                self.update_single_sheet_results_display(sheet_name)
                        else:
                            # For multiple sheets, show comparison
                            self.update_batch_results_display()
                    except Exception:
                        pass
                    
                    self.update_progress_status(
                        f'Analysis complete - Processed: {processed_count} sheet(s), Skipped: {skipped_count} sheet(s)',
                        100,
                        True,
                    )
                    
                    # Update QC Results Panel with new data
                    self.update_qc_results_panel()
                    
                    # Update confusion matrix display
                    self.update_confusion_matrix_display()
                    
                    # Open the external visualization window
                    self.open_visualization_window()
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.handle_error(str(e), e, "Analysis processing")
            finally:
                # Always reset processing state
                self.root.after(0, lambda: self.set_processing_state(False))
        
        # Use the safe thread manager for execution
        try:
            future = self.thread_manager.submit_task(batch_worker)
            self.current_tasks.append(future)
        except Exception as e:
            self.handle_error(f"Failed to start batch processing: {str(e)}", e, "Thread submission")
            self.set_processing_state(False)
    
    def batch_process_selected_sheets(self, selected_sheets):
        """The missing method that provides robust batch processing with thread safety"""
        if not self.excel_file:
            self.show_message_safely("error", "Error", "Please load an Excel file first.")
            return
            
        if self.processing_state:
            return
            
        self.set_processing_state(True)
        self.safe_update_mode_label("Mode: Processing Analysis...", 'orange')
        self.update_progress_status('Starting analysis...', 0)
        
        # Show processing overlay immediately
        self.show_processing_overlay(f"Starting analysis of {len(selected_sheets)} sheet(s)...")
        self.root.update()  # Force update to show overlay
        
        def batch_worker():
            try:
                # Clear previous batch results
                with self.data_lock:
                    self.batch_results = {}
                    self.comparison_summary = None
                
                total_sheets = len(selected_sheets)
                processed_count = 0
                skipped_count = 0
                
                self.update_progress_status(f'Processing {total_sheets} sheet(s)...', 5)
                self.root.after(0, lambda: self.show_processing_overlay(f"Starting analysis of {total_sheets} sheet(s)..."))
                
                # Process each selected sheet
                for i, sheet_name in enumerate(selected_sheets):
                    if self.cancel_event.is_set():
                        return
                    
                    progress = 10 + (i / total_sheets) * 70  # 10-80% for processing
                    self.update_progress_status(f'Analyzing sheet: {sheet_name} ({i+1}/{total_sheets})', progress)
                    self.root.after(0, lambda name=sheet_name, idx=i+1, total=total_sheets: 
                                  self.show_processing_overlay(f"Analyzing sheet {idx}/{total}: {name}"))
                    
                    try:
                        # Process single sheet
                        sheet_results = self.process_single_sheet_for_batch(sheet_name)
                        
                        if sheet_results and isinstance(sheet_results, dict):
                            with self.data_lock:
                                self.batch_results[sheet_name] = sheet_results
                                processed_count += 1
                        else:
                            skipped_count += 1
                                
                    except Exception as e:
                        skipped_count += 1
                        continue
                
                # Create comparison summary if multiple sheets
                if len(selected_sheets) > 1:
                    self.update_progress_status('Creating comparison summary...', 85)
                    self.root.after(0, lambda: self.show_processing_overlay("Creating comparison summary..."))
                    self.create_comparison_summary()
                
                # Update UI with results
                self.update_progress_status('Finalizing results...', 95)
                self.root.after(0, lambda: self.show_processing_overlay("Finalizing results..."))
                
                def update_ui():
                    # Update the textual results area
                    try:
                        if len(selected_sheets) == 1:
                            # For single sheet, show detailed results
                            sheet_name = selected_sheets[0]
                            if sheet_name in self.batch_results:
                                self.confusion_matrix = self.batch_results[sheet_name].get('confusion_matrix')
                                # Populate results dictionary with class metrics for visualization
                                if 'class_metrics' in self.batch_results[sheet_name]:
                                    self.results['class_metrics'] = self.batch_results[sheet_name]['class_metrics']
                        else:
                            # For multiple sheets, show comparison
                            self.update_batch_results_display()
                    except Exception:
                        pass
                    
                    self.update_progress_status(
                        f'Analysis complete - Processed: {processed_count} sheet(s), Skipped: {skipped_count} sheet(s)',
                        100,
                        True,
                    )
                    
                    # Update QC Results Panel with new data
                    self.update_qc_results_panel()
                    
                    # Update confusion matrix display
                    self.update_confusion_matrix_display()
                    
                    # Open the external visualization window
                    self.open_visualization_window()
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.handle_error(str(e), e, "Analysis processing")
            finally:
                # Always reset processing state
                self.root.after(0, lambda: self.set_processing_state(False))
        
        # Use the safe thread manager for execution
        try:
            future = self.thread_manager.submit_task(batch_worker)
            self.current_tasks.append(future)
        except Exception as e:
            self.handle_error(f"Failed to start batch processing: {str(e)}", e, "Thread submission")
            self.set_processing_state(False)
    
    def _process_single_sheet(self, sheet_name):
        """Process a single sheet with comprehensive error handling"""
        try:
            if not self.excel_file:
                return None
                
            # Load sheet data
            sheet_data = pd.read_excel(self.excel_file, sheet_name=sheet_name)
            
            if sheet_data.empty:
                logger.warning(f"Sheet {sheet_name} is empty")
                return None
            
            # Perform analysis (this would call your existing analysis methods)
            # For now, return a placeholder result structure
            results = {
                'sheet_name': sheet_name,
                'data_shape': sheet_data.shape,
                'confusion_matrix': None,  # Would be populated by actual analysis
                'timestamp': datetime.now().isoformat()
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing sheet {sheet_name}: {e}")
            return None
    
    def export_results(self):
        """Export analysis results to various formats"""
        try:
            # Check if we have results to export
            if not hasattr(self, 'batch_results') or not self.batch_results:
                messagebox.showwarning("No Results", "No analysis results available to export.\nPlease run an analysis first.")
                return
            
            from tkinter import filedialog
            import csv
            import os
            
            # Get save location
            filename = filedialog.asksaveasfilename(
                title="Export Analysis Results",
                defaultextension=".csv",
                filetypes=[
                    ("CSV files", "*.csv"),
                    ("Excel files", "*.xlsx"),
                    ("Text files", "*.txt"),
                    ("All files", "*.*")
                ],
                initialdir=os.path.expanduser("~/Desktop")
            )
            
            if not filename:
                return
            
            self.update_activity_indicator("Exporting results...")
            
            # Prepare export data
            export_data = []
            
            # Header row
            headers = [
                "Sheet Name", "Status", "QC Grade", "Rows", "Columns", 
                "Completeness %", "Accuracy Score", "Effect Size", 
                "Chi-Square", "P-Value", "Sample Size", "Warnings"
            ]
            export_data.append(headers)
            
            # Data rows
            for sheet_name, result in self.batch_results.items():
                if result.get('status') == 'success':
                    stats = result.get('statistics', {})
                    qc_summary = self.get_chi_square_qc_summary(result)
                    
                    row = [
                        sheet_name,
                        "Success",
                        qc_summary.get('qc_grade', 'N/A'),
                        result.get('total_rows', 'N/A'),
                        result.get('total_cols', 'N/A'),
                        f"{result.get('data_completeness', 0):.1f}%" if result.get('data_completeness') else 'N/A',
                        f"{qc_summary.get('accuracy_score', 0):.2f}",
                        f"{stats.get('cramers_v', 0):.3f}" if stats.get('cramers_v') else 'N/A',
                        f"{stats.get('chi2', 0):.2f}" if stats.get('chi2') else 'N/A',
                        f"{stats.get('p_value', 0):.4f}" if stats.get('p_value') else 'N/A',
                        stats.get('sample_size', 'N/A'),
                        "; ".join(result.get('warnings', []))
                    ]
                else:
                    row = [
                        sheet_name,
                        "Failed",
                        "F",
                        "N/A", "N/A", "N/A", "0", "N/A", "N/A", "N/A", "N/A",
                        result.get('error', 'Unknown error')
                    ]
                
                export_data.append(row)
            
            # Write file based on extension
            file_ext = filename.lower().split('.')[-1]
            
            if file_ext == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerows(export_data)
                    
            elif file_ext in ['xlsx', 'xls']:
                # Export to Excel
                try:
                    df = pd.DataFrame(export_data[1:], columns=export_data[0])
                    df.to_excel(filename, index=False, engine='openpyxl')
                except ImportError:
                    messagebox.showerror("Export Error", "openpyxl is required for Excel export. Please install it with: pip install openpyxl")
                    return
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to save Excel file: {str(e)}")
                    return
                
            else:  # Text file
                with open(filename, 'w', encoding='utf-8') as f:
                    for row in export_data:
                        f.write('\t'.join(str(cell) for cell in row) + '\n')
            
            self.update_activity_indicator("Export complete!")
            messagebox.showinfo("Export Complete", 
                              f"Results exported successfully to:\n{filename}\n\n"
                              f"Exported {len(self.batch_results)} sheet(s) of analysis data.")
            
        except Exception as e:
            self.update_activity_indicator("Export failed")
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def export_charts(self):
        """Export all generated charts and visualizations"""
        try:
            # Check if we have results to export
            if not hasattr(self, 'batch_results') or not self.batch_results:
                messagebox.showwarning("No Charts", "No analysis results available to export charts.\nPlease run an analysis first.")
                return
            
            from tkinter import filedialog
            import os
            
            # Get save directory
            save_dir = filedialog.askdirectory(
                title="Select Directory to Save Charts",
                initialdir=os.path.expanduser("~/Desktop")
            )
            
            if not save_dir:
                return
            
            self.update_activity_indicator("Exporting charts...")
            self.start_activity_animation()
            
            def export_worker():
                try:
                    # Create subdirectory for this export
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    chart_dir = os.path.join(save_dir, f"StatisticalCharts_{timestamp}")
                    os.makedirs(chart_dir, exist_ok=True)
                    
                    exported_count = 0
                    designer = ProfessionalVisualizationDesigner()
                    
                    # Export charts for each successful analysis
                    for sheet_name, result in self.batch_results.items():
                        if result.get('status') != 'success':
                            continue
                            
                        try:
                            # Create sheet-specific directory
                            safe_sheet_name = sheet_name.replace('/', '_').replace('\\', '_')
                            sheet_dir = os.path.join(chart_dir, "Sheet_" + safe_sheet_name)
                            os.makedirs(sheet_dir, exist_ok=True)
                            
                            # Export confusion matrix heatmap
                            if 'confusion_matrix' in result:
                                matrix = result['confusion_matrix']
                                fig = designer.create_confusion_matrix_heatmap(matrix, sheet_name)
                                fig.savefig(os.path.join(sheet_dir, f"{sheet_name}_confusion_matrix.png"), 
                                          dpi=300, bbox_inches='tight')
                                plt.close(fig)
                                exported_count += 1
                            
                            # Export correlation matrix
                            if 'correlation_matrix' in result:
                                corr_matrix = result['correlation_matrix']
                                fig = designer.create_correlation_matrix(corr_matrix, sheet_name)
                                fig.savefig(os.path.join(sheet_dir, f"{sheet_name}_correlation_matrix.png"), 
                                          dpi=300, bbox_inches='tight')
                                plt.close(fig)
                                exported_count += 1
                            
                            # Export statistical summary chart
                            stats = result.get('statistics', {})
                            if stats:
                                fig = designer.create_statistical_summary_chart(stats, sheet_name)
                                fig.savefig(os.path.join(sheet_dir, f"{sheet_name}_statistics.png"), 
                                          dpi=300, bbox_inches='tight')
                                plt.close(fig)
                                exported_count += 1
                                
                        except Exception as e:
                            logger.error(f"Error exporting charts for {sheet_name}: {e}")
                            # Show user-friendly error message
                            messagebox.showerror("Export Error", f"Failed to export charts for {sheet_name}: {str(e)}")
                            continue
                    
                    # Create summary report
                    summary_path = os.path.join(chart_dir, "export_summary.txt")
                    with open(summary_path, 'w') as f:
                        f.write(f"Statistical Analysis Charts Export Summary\n")
                        f.write(f"{'='*50}\n")
                        f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total Sheets Analyzed: {len(self.batch_results)}\n")
                        f.write(f"Total Charts Exported: {exported_count}\n")
                        f.write(f"Export Directory: {chart_dir}\n\n")
                        
                        f.write("Exported Charts by Sheet:\n")
                        f.write("-" * 30 + "\n")
                        for sheet_name, result in self.batch_results.items():
                            status = "Success" if result.get('status') == 'success' else "Failed"
                            f.write(f"{sheet_name}: {status}\n")
                    
                    def show_success():
                        self.stop_activity_animation()
                        self.update_activity_indicator("Charts exported!")
                        messagebox.showinfo("Export Complete", 
                                          f"Charts exported successfully!\n\n"
                                          f"Location: {chart_dir}\n"
                                          f"Charts exported: {exported_count}\n"
                                          f"Sheets processed: {len([r for r in self.batch_results.values() if r.get('status') == 'success'])}")
                    
                    self.root.after(0, show_success)
                    
                except Exception as e:
                    def show_error():
                        self.stop_activity_animation()
                        self.update_activity_indicator("Export failed")
                        messagebox.showerror("Export Error", f"Failed to export charts:\n{str(e)}")
                    self.root.after(0, show_error)
            
            # Submit the export task
            self.submit_task(export_worker)
            
        except Exception as e:
            self.stop_activity_animation()
            self.update_activity_indicator("Export failed")
            messagebox.showerror("Export Error", f"Failed to start chart export:\n{str(e)}")
    
    def export_comparison(self):
        """Export comparison analysis between multiple sheets"""
        try:
            # Check if we have multiple results to compare
            if not hasattr(self, 'batch_results') or len(self.batch_results) < 2:
                messagebox.showwarning("Insufficient Data", 
                                     "Need at least 2 analyzed sheets to export comparison.\n"
                                     "Please run multi-sheet analysis first.")
                return
            
            from tkinter import filedialog
            import csv
            
            # Get save location
            filename = filedialog.asksaveasfilename(
                title="Export Comparison Analysis",
                defaultextension=".xlsx",
                filetypes=[
                    ("Excel files", "*.xlsx"),
                    ("CSV files", "*.csv"),
                    ("Text files", "*.txt"),
                    ("All files", "*.*")
                ],
                initialdir=os.path.expanduser("~/Desktop")
            )
            
            if not filename:
                return
            
            self.update_activity_indicator("Exporting comparison...")
            
            # Generate comparison data
            comparison_data = []
            
            # Header
            headers = [
                "Comparison Metric", "Sheet 1", "Sheet 2", "Difference", "Interpretation"
            ]
            
            # Get successful results
            successful_results = {name: result for name, result in self.batch_results.items() 
                                if result.get('status') == 'success'}
            
            if len(successful_results) < 2:
                messagebox.showwarning("Insufficient Data", 
                                     "Need at least 2 successful analyses for comparison.")
                return
            
            # Take first two successful sheets for comparison
            sheet_names = list(successful_results.keys())[:2]
            sheet1_name, sheet2_name = sheet_names
            sheet1_data = successful_results[sheet1_name]
            sheet2_data = successful_results[sheet2_name]
            
            # Compare key metrics
            comparisons = []
            
            # Sample size comparison
            size1 = sheet1_data.get('statistics', {}).get('sample_size', 0)
            size2 = sheet2_data.get('statistics', {}).get('sample_size', 0)
            size_diff = size2 - size1
            size_interp = "Larger dataset" if size_diff > 0 else "Smaller dataset" if size_diff < 0 else "Equal size"
            comparisons.append(["Sample Size", str(size1), str(size2), str(size_diff), size_interp])
            
            # Effect size comparison (Cramer's V)
            effect1 = sheet1_data.get('statistics', {}).get('cramers_v', 0)
            effect2 = sheet2_data.get('statistics', {}).get('cramers_v', 0)
            effect_diff = effect2 - effect1
            effect_interp = "Stronger effect" if effect_diff > 0.1 else "Weaker effect" if effect_diff < -0.1 else "Similar effect"
            comparisons.append(["Effect Size (Cramer's V)", f"{effect1:.3f}", f"{effect2:.3f}", f"{effect_diff:.3f}", effect_interp])
            
            # Chi-square comparison
            chi1 = sheet1_data.get('statistics', {}).get('chi2', 0)
            chi2 = sheet2_data.get('statistics', {}).get('chi2', 0)
            chi_diff = chi2 - chi1
            chi_interp = "Stronger association" if chi_diff > 10 else "Weaker association" if chi_diff < -10 else "Similar association"
            comparisons.append(["Chi-Square", f"{chi1:.2f}", f"{chi2:.2f}", f"{chi_diff:.2f}", chi_interp])
            
            # P-value comparison
            p1 = sheet1_data.get('statistics', {}).get('p_value', 1.0)
            p2 = sheet2_data.get('statistics', {}).get('p_value', 1.0)
            p_diff = p2 - p1
            p_interp = "More significant" if p1 < 0.05 and p2 >= 0.05 else "Less significant" if p1 >= 0.05 and p2 < 0.05 else "Similar significance"
            comparisons.append(["P-Value", f"{p1:.4f}", f"{p2:.4f}", f"{p_diff:.4f}", p_interp])
            
            # Data completeness comparison
            comp1 = sheet1_data.get('data_completeness', 0)
            comp2 = sheet2_data.get('data_completeness', 0)
            comp_diff = comp2 - comp1
            comp_interp = "Better quality" if comp_diff > 5 else "Lower quality" if comp_diff < -5 else "Similar quality"
            comparisons.append(["Data Completeness (%)", f"{comp1:.1f}", f"{comp2:.1f}", f"{comp_diff:.1f}", comp_interp])
            
            # QC Grade comparison
            qc1_summary = self.get_chi_square_qc_summary(sheet1_data)
            qc2_summary = self.get_chi_square_qc_summary(sheet2_data)
            qc1_grade = qc1_summary.get('qc_grade', 'F')
            qc2_grade = qc2_summary.get('qc_grade', 'F')
            
            grade_order = {'A': 4, 'B': 3, 'C': 2, 'D': 1, 'F': 0}
            qc1_score = grade_order.get(qc1_grade, 0)
            qc2_score = grade_order.get(qc2_grade, 0)
            qc_diff = qc2_score - qc1_score
            qc_interp = "Higher grade" if qc_diff > 0 else "Lower grade" if qc_diff < 0 else "Same grade"
            comparisons.append(["QC Grade", qc1_grade, qc2_grade, f"{qc_diff:+d}", qc_interp])
            
            # Combine headers and data
            comparison_data = [headers] + comparisons
            
            # Add summary section
            comparison_data.append([])  # Empty row
            comparison_data.append(["SUMMARY", "", "", "", ""])
            comparison_data.append([f"Sheet 1: {sheet1_name}", "", "", "", ""])
            comparison_data.append([f"Sheet 2: {sheet2_name}", "", "", "", ""])
            comparison_data.append([f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "", "", "", ""])
            
            # Write file based on extension
            file_ext = filename.lower().split('.')[-1]
            
            if file_ext == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerows(comparison_data)
                    
            elif file_ext in ['xlsx', 'xls']:
                try:
                    df = pd.DataFrame(comparison_data[1:], columns=comparison_data[0])
                    df.to_excel(filename, index=False, sheet_name='Sheet Comparison', engine='openpyxl')
                except ImportError:
                    messagebox.showerror("Export Error", "openpyxl is required for Excel export. Please install it with: pip install openpyxl")
                    return
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to save Excel file: {str(e)}")
                    return
                
            else:  # Text file
                with open(filename, 'w', encoding='utf-8') as f:
                    for row in comparison_data:
                        f.write('\t'.join(str(cell) for cell in row) + '\n')
            
            self.update_activity_indicator("Comparison exported!")
            messagebox.showinfo("Export Complete", 
                              f"Comparison analysis exported successfully!\n\n"
                              f"File: {filename}\n"
                              f"Comparing: {sheet1_name} vs {sheet2_name}\n"
                              f"Metrics compared: {len(comparisons)}")
            
        except Exception as e:
            self.update_activity_indicator("Export failed")
            messagebox.showerror("Export Error", f"Failed to export comparison:\n{str(e)}")
    
    def open_visualization_window(self):
        """Open the interactive visualization window"""
        try:
            # Check if we have results to visualize
            if not hasattr(self, 'batch_results') or not self.batch_results:
                messagebox.showwarning("No Data", "No analysis results available to visualize.\nPlease run an analysis first.")
                return
            
            # Check if window is already open
            if hasattr(self, 'viz_window') and self.viz_window and self.viz_window.window and self.viz_window.window.winfo_exists():
                # Bring existing window to front
                self.viz_window.window.lift()
                self.viz_window.window.focus_force()
                return
            
            # Create new visualization window
            self.update_activity_indicator("Opening visualizations...")
            
            try:
                self.viz_window = VisualizationWindow(self.root, self)
                window = self.viz_window.create_window()
                
                if window:
                    # Load visualizations into the window
                    self.viz_window.load_visualizations()
                    
                    self.update_activity_indicator("Visualizations loaded!")
                    
                    # Show success message briefly
                    self.root.after(2000, lambda: self.update_activity_indicator("Ready"))
                else:
                    raise Exception("Failed to create visualization window")
                    
            except Exception as e:
                self.update_activity_indicator("Visualization failed")
                messagebox.showerror("Visualization Error", 
                                   f"Failed to open visualization window:\n{str(e)}\n\n"
                                   "This may be due to display issues or missing data.")
            
        except Exception as e:
            self.update_activity_indicator("Error occurred")
            messagebox.showerror("Error", f"Failed to initialize visualization window:\n{str(e)}")
    
    def save_project(self):
        """Save current project analysis to a file"""
        try:
            # Check if we have data to save
            if not hasattr(self, 'batch_results') or not self.batch_results:
                messagebox.showwarning("No Data", "No analysis data available to save.\nPlease run an analysis first.")
                return
            
            from tkinter import filedialog
            import json
            import pickle
            
            # Get save location
            filename = filedialog.asksaveasfilename(
                title="Save Project",
                defaultextension=".cap",  # TraceSeis, Inc. Analysis Project
                filetypes=[
                    ("CONFIRM Project", "*.tsgp"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*")
                ],
                initialdir="C:/Users/Desktop"
            )
            
            if not filename:
                return
            
            self.update_activity_indicator("Saving project...")
            
            # Prepare project data
            project_data = {
                'project_info': {
                    'name': os.path.basename(filename).replace('.tsgp', '').replace('.json', ''),
                    'version': '1.0',
                    'created': datetime.now().isoformat(),
                    'application': 'TraceSeis, Inc. Statistical Analysis Tool v1.0',
                    'original_file': self.file_path.get() if hasattr(self, 'file_path') else None
                },
                'analysis_results': {},
                'metadata': {
                    'total_sheets': len(self.batch_results),
                    'successful_analyses': len([r for r in self.batch_results.values() if r.get('status') == 'success']),
                    'failed_analyses': len([r for r in self.batch_results.values() if r.get('status') != 'success'])
                },
                'ui_settings': {
                    'normalize_confusion_matrices': self.normalize_confusion_matrices.get() if hasattr(self, 'normalize_confusion_matrices') else False
                }
            }
            
            # Process each analysis result for saving
            for sheet_name, result in self.batch_results.items():
                # Create a JSON-serializable version of the result
                serializable_result = {
                    'status': result.get('status'),
                    'sheet_name': sheet_name,
                    'total_rows': result.get('total_rows'),
                    'total_cols': result.get('total_cols'),
                    'data_completeness': result.get('data_completeness'),
                    'warnings': result.get('warnings', []),
                    'error': result.get('error'),
                    'timestamp': result.get('timestamp', datetime.now().isoformat())
                }
                
                # Include statistics if available
                if 'statistics' in result:
                    stats = result['statistics']
                    serializable_result['statistics'] = {
                        'chi2': float(stats.get('chi2', 0)),
                        'p_value': float(stats.get('p_value', 1.0)),
                        'degrees_of_freedom': int(stats.get('degrees_of_freedom', 0)),
                        'cramers_v': float(stats.get('cramers_v', 0)),
                        'sample_size': int(stats.get('sample_size', 0)),
                        'expected_freq_ok': bool(stats.get('expected_freq_ok', False))
                    }
                
                # Include confusion matrix if available (convert to list for JSON)
                if 'confusion_matrix' in result and result['confusion_matrix'] is not None:
                    try:
                        matrix = result['confusion_matrix']
                        if hasattr(matrix, 'tolist'):  # numpy array
                            serializable_result['confusion_matrix'] = matrix.tolist()
                        else:
                            serializable_result['confusion_matrix'] = matrix
                    except Exception:
                        pass  # Skip if can't serialize matrix
                
                # Add QC summary
                try:
                    qc_summary = self.get_chi_square_qc_summary(result)
                    serializable_result['qc_summary'] = {
                        'qc_grade': qc_summary.get('qc_grade', 'F'),
                        'accuracy_score': float(qc_summary.get('accuracy_score', 0)),
                        'recommendations': qc_summary.get('recommendations', [])
                    }
                except Exception:
                    pass  # Skip QC summary if error
                
                project_data['analysis_results'][sheet_name] = serializable_result
            
            # Save the file
            file_ext = filename.lower().split('.')[-1]
            
            if file_ext == 'json':
                # Save as JSON
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(project_data, f, indent=2, ensure_ascii=False)
            else:
                # Save as deltaV solutions project file (JSON format)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(project_data, f, indent=2, ensure_ascii=False)
            
            # Update current project reference
            self.current_project = filename
            self.project_metadata = project_data['project_info']
            
            self.update_activity_indicator("Project saved!")
            messagebox.showinfo("Save Complete", 
                              f"Project saved successfully!\n\n"
                              f"File: {filename}\n"
                              f"Sheets saved: {len(self.batch_results)}\n"
                              f"Successful analyses: {project_data['metadata']['successful_analyses']}")
            
        except Exception as e:
            self.update_activity_indicator("Save failed")
            messagebox.showerror("Save Error", f"Failed to save project:\n{str(e)}")
    
    def load_project(self):
        """Load a saved project file"""
        try:
            from tkinter import filedialog
            import json
            
            # Get file to load
            filename = filedialog.askopenfilename(
                title="Load Project",
                filetypes=[
                    ("CONFIRM Project", "*.tsgp"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*")
                ],
                initialdir="C:/Users/Desktop"
            )
            
            if not filename:
                return
            
            self.update_activity_indicator("Loading project...")
            
            # Load and parse the file
            with open(filename, 'r', encoding='utf-8') as f:
                project_data = json.load(f)
            
            # Validate project structure
            if 'analysis_results' not in project_data:
                raise ValueError("Invalid project file: missing analysis results")
            
            # Clear existing results
            self.batch_results = {}
            
            # Load analysis results
            loaded_count = 0
            for sheet_name, result_data in project_data['analysis_results'].items():
                try:
                    # Reconstruct the result object
                    result = {
                        'status': result_data.get('status', 'unknown'),
                        'sheet_name': sheet_name,
                        'total_rows': result_data.get('total_rows'),
                        'total_cols': result_data.get('total_cols'),
                        'data_completeness': result_data.get('data_completeness'),
                        'warnings': result_data.get('warnings', []),
                        'error': result_data.get('error'),
                        'timestamp': result_data.get('timestamp')
                    }
                    
                    # Reconstruct statistics
                    if 'statistics' in result_data:
                        stats = result_data['statistics']
                        result['statistics'] = {
                            'chi2': stats.get('chi2', 0),
                            'p_value': stats.get('p_value', 1.0),
                            'degrees_of_freedom': stats.get('degrees_of_freedom', 0),
                            'cramers_v': stats.get('cramers_v', 0),
                            'sample_size': stats.get('sample_size', 0),
                            'expected_freq_ok': stats.get('expected_freq_ok', False)
                        }
                    
                    # Reconstruct confusion matrix
                    if 'confusion_matrix' in result_data:
                        matrix_data = result_data['confusion_matrix']
                        if matrix_data:
                            result['confusion_matrix'] = np.array(matrix_data)
                    
                    # Store QC summary if available
                    if 'qc_summary' in result_data:
                        result['qc_summary'] = result_data['qc_summary']
                    
                    self.batch_results[sheet_name] = result
                    loaded_count += 1
                    
                except Exception as e:
                    logger.warning(f"Could not load sheet '{sheet_name}': {e}")
                    continue
            
            if loaded_count == 0:
                raise ValueError("No valid analysis results found in project file")
            
            # Update project metadata
            if 'project_info' in project_data:
                self.current_project = filename
                self.project_metadata = project_data['project_info']
                
                # Update original file path if available
                original_file = project_data['project_info'].get('original_file')
                if original_file and hasattr(self, 'file_path'):
                    self.file_path.set(original_file)
            
            # Restore UI settings if available
            if 'ui_settings' in project_data:
                ui_settings = project_data['ui_settings']
                if hasattr(self, 'normalize_confusion_matrices') and 'normalize_confusion_matrices' in ui_settings:
                    self.normalize_confusion_matrices.set(ui_settings['normalize_confusion_matrices'])
            
            # Update UI
            def update_ui():
                # Update QC results panel
                try:
                    self.update_qc_results_panel()
                except Exception as e:
                    logger.warning(f"Could not update QC panel: {e}")
                
                # Show success message
                project_info = project_data.get('project_info', {})
                project_name = project_info.get('name', 'Unknown')
                created_date = project_info.get('created', 'Unknown')
                
                messagebox.showinfo("Load Complete", 
                                  f"Project loaded successfully!\n\n"
                                  f"Project: {project_name}\n"
                                  f"File: {os.path.basename(filename)}\n"
                                  f"Created: {created_date[:10] if created_date != 'Unknown' else 'Unknown'}\n"
                                  f"Sheets loaded: {loaded_count}")
                
                self.update_activity_indicator("Project loaded!")
                
                # Update window title
                self.root.title(f"Statistical Analysis Tool - {project_name}")
            
            self.root.after(0, update_ui)
            
        except FileNotFoundError:
            self.update_activity_indicator("File not found")
            messagebox.showerror("File Error", "The selected project file could not be found.")
        except json.JSONDecodeError as e:
            self.update_activity_indicator("Load failed")
            messagebox.showerror("Format Error", f"Invalid project file format:\n{str(e)}")
        except Exception as e:
            self.update_activity_indicator("Load failed")
            messagebox.showerror("Load Error", f"Failed to load project:\n{str(e)}")
    
    def show_ready_state(self):
        """Show the application is ready for use"""
        if hasattr(self, 'overlay_frame'):
            # Create a brief "Ready" message
            self.overlay_status.config(text="Application ready! Select an Excel file to begin analysis.")
            self.overlay_message.config(text="Ready", foreground='green')
            self.overlay_spinner.config(text="OK")
            self.overlay_frame.pack(expand=True, fill=tk.BOTH)
            
            # Hide after 2 seconds
            self.root.after(2000, self.hide_processing_overlay)
    
    def update_window_title(self, status="Ready"):
        """Update the window title with current status"""
        base_title = "Statistical Contingency Analysis Platform v1.0"
        if status == "Ready":
            self.root.title(f"{base_title} - Ready")
        elif status == "Processing":
            self.root.title(f"{base_title} - Processing...")
        elif status == "Complete":
            self.root.title(f"{base_title} - Analysis Complete")
        else:
            self.root.title(f"{base_title} - {status}")
    
    def safe_update_mode_label(self, text, color='black'):
        """Safely update the mode label with enhanced visual feedback"""
        try:
            if hasattr(self, 'mode_label') and self.mode_label.winfo_exists():
                # Map color names to background colors for the new boxed design
                color_map = {
                    'green': '#28a745',
                    'red': '#dc3545', 
                    'orange': '#fd7e14',
                    'blue': '#007bff',
                    'purple': '#6f42c1',
                    'black': '#6c757d'
                }
                
                bg_color = color_map.get(color, '#28a745')
                text_color = 'white' if color != 'black' else 'white'
                
                self.mode_label.config(text=text.upper(), foreground=text_color, bg=bg_color)
        except tk.TclError:
            pass  # Widget was destroyed, ignore the error
        
    def setup_ui(self):
        """Setup the user interface"""
        # Create scrollable main container with both vertical and horizontal scrolling
        main_canvas = tk.Canvas(self.root, bg='white')
        v_scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=main_canvas.yview)
        h_scrollbar = ttk.Scrollbar(self.root, orient="horizontal", command=main_canvas.xview)
        scrollable_frame = ttk.Frame(main_canvas)
        
        # Force the scrollable frame to be wider than the canvas to enable horizontal scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        # Create the window in the canvas and force it to be wider
        canvas_window = main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Make the scrollable frame wider to enable horizontal scrolling
        def configure_scroll_region(event):
            bbox = main_canvas.bbox("all")
            if bbox:
                canvas_width = main_canvas.winfo_width()
                canvas_height = main_canvas.winfo_height()
                content_width = bbox[2] - bbox[0]
                content_height = bbox[3] - bbox[1]
                
                # Always ensure scrollable area is larger than canvas
                scroll_width = max(content_width + 400, canvas_width + 400)
                scroll_height = max(content_height + 100, canvas_height + 100)
                
                main_canvas.configure(scrollregion=(0, 0, scroll_width, scroll_height))
        
        scrollable_frame.bind("<Configure>", configure_scroll_region)
        
        # Pack canvas and scrollbars
        main_canvas.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        v_scrollbar.pack(side="right", fill="y", pady=10)
        h_scrollbar.pack(side="bottom", fill="x", padx=(10, 0))
        
        # Add scroll indicators
        self.add_scroll_indicators(main_canvas)
        
        # Top section - File selection and sheet selection
        self.setup_file_section(scrollable_frame)
        
        # Middle section - Results and visualizations
        self.setup_analysis_section(scrollable_frame)
        
        # Bottom section - Data preview
        self.setup_data_section(scrollable_frame)
        
        # Status bar with progress
        self.setup_status_bar(scrollable_frame)
        
        # Create processing overlay (initially hidden)
        self.create_processing_overlay()
        
        # Bind mouse wheel scrolling for both vertical and horizontal
        def _on_mousewheel(event):
            # Vertical scrolling with mouse wheel
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _on_shift_mousewheel(event):
            # Horizontal scrolling with Shift + mouse wheel
            main_canvas.xview_scroll(int(-1*(event.delta/120)), "units")
        
        main_canvas.bind("<MouseWheel>", _on_mousewheel)
        main_canvas.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
    
    def add_scroll_indicators(self, canvas):
        """Add visual scroll indicators to show users they can scroll"""
        # Top scroll indicator
        top_indicator = tk.Label(canvas, text="↑ SCROLL UP FOR MORE OPTIONS", 
                                font=('Arial', 8, 'bold'), bg='#e3f2fd', 
                                fg='#1976d2', relief='raised', bd=1)
        
        # Bottom scroll indicator  
        bottom_indicator = tk.Label(canvas, text="↓ SCROLL DOWN FOR QC CONTROLS", 
                                   font=('Arial', 8, 'bold'), bg='#e8f5e8', 
                                   fg='#388e3c', relief='raised', bd=1)
        
        # Remove the orange horizontal scroll indicator as requested
        
        # Position indicators
        def position_indicators():
            try:
                canvas.update_idletasks()
                canvas_width = canvas.winfo_width()
                canvas_height = canvas.winfo_height()
                if canvas_width > 100 and canvas_height > 100:  # Only show if canvas is wide enough
                    # Position top indicator
                    canvas.coords(top_indicator, canvas_width//2, 20)
                    canvas.coords(bottom_indicator, canvas_width//2, canvas_height-30)
                else:
                    # Hide indicators if canvas too small
                    canvas.coords(top_indicator, -100, -100)
                    canvas.coords(bottom_indicator, -100, -100)
            except tk.TclError:
                pass  # Canvas destroyed
        
        # Add indicators to canvas
        canvas.create_window(0, 0, window=top_indicator, anchor="center")
        canvas.create_window(0, 0, window=bottom_indicator, anchor="center")
        
        # Update positions when canvas resizes
        canvas.bind("<Configure>", lambda e: position_indicators())
        self.root.after(100, position_indicators)  # Initial positioning
        
    def setup_file_section(self, parent):
        """Setup file selection section"""
        file_frame = ttk.LabelFrame(parent, text="Data Input", padding="15")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File selection row
        file_row = ttk.Frame(file_frame)
        file_row.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(file_row, text="Excel File:", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(file_row, textvariable=self.file_path, width=60, font=('Arial', 10))
        self.file_entry.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        
        # Enable drag and drop on the file entry
        self.setup_drag_and_drop()
        
        self.browse_btn = ttk.Button(file_row, text="Browse", command=self.browse_file, width=10)
        self.browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Sheet selection row
        sheet_row = ttk.Frame(file_frame)
        sheet_row.pack(fill=tk.X)
        
        ttk.Label(sheet_row, text="Sheet:", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        self.sheet_var = tk.StringVar()
        self.sheet_combo = ttk.Combobox(sheet_row, textvariable=self.sheet_var, width=30, 
                                       state="readonly", font=('Arial', 10))
        self.sheet_combo.pack(side=tk.LEFT, padx=(10, 5))
        
        # Analysis buttons row - moved to top
        analysis_buttons_row = ttk.Frame(file_frame)
        analysis_buttons_row.pack(fill=tk.X, pady=(10, 0))
        
        self.analyze_btn = ttk.Button(analysis_buttons_row, text="Single Sheet", command=self.process_data_placeholder, 
                                     width=15)
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # NEW: Batch processing button with better labeling
        self.batch_analyze_btn = ttk.Button(analysis_buttons_row, text="Multi-Sheet Analysis", 
                                           command=self.batch_analyze_selected_sheets_threaded, 
                                           width=18)
        self.batch_analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Export and control buttons - create a separate row to prevent cutoff
        export_row = ttk.Frame(analysis_buttons_row)
        export_row.pack(fill=tk.X, pady=(5, 0))
        
        # First row of buttons
        row1_frame = ttk.Frame(export_row)
        row1_frame.pack(fill=tk.X)
        
        self.export_results_btn = ttk.Button(row1_frame, text="Export Results", 
                                           command=self.export_results, width=12)
        self.export_results_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.export_charts_btn = ttk.Button(row1_frame, text="Export Charts", 
                                          command=self.export_charts, width=12)
        self.export_charts_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.export_comparison_btn = ttk.Button(row1_frame, text="Export Comparison", 
                                              command=self.export_comparison, width=15)
        self.export_comparison_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.open_viz_btn = ttk.Button(row1_frame, text="Open Viz Window", 
                                     command=self.open_visualization_window, width=15)
        self.open_viz_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Second row of buttons
        row2_frame = ttk.Frame(export_row)
        row2_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.save_project_btn = ttk.Button(row2_frame, text="Save Project", 
                                         command=self.save_project, width=12)
        self.save_project_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.load_project_btn = ttk.Button(row2_frame, text="Load Project", 
                                         command=self.load_project, width=12)
        self.load_project_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.cancel_btn = ttk.Button(row2_frame, text="Cancel", command=self.cancel_operations, 
                                   width=10, state='disabled')
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # NEW: Matrix normalization option
        normalization_frame = ttk.Frame(file_frame)
        normalization_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.normalize_confusion_matrices = tk.BooleanVar()
        self.normalize_checkbox = ttk.Checkbutton(
            normalization_frame, 
            text="Normalize confusion matrices", 
            variable=self.normalize_confusion_matrices,
            command=self.on_normalization_changed
        )
        self.normalize_checkbox.pack(side=tk.LEFT)
        
        # Add explanation tooltip
        normalize_info_label = ttk.Label(
            normalization_frame, 
            text="ⓘ Convert counts to percentages (each row sums to 100%)",
            font=('Arial', 9), 
            foreground='blue'
        )
        normalize_info_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Add instruction text
        instruction_frame = ttk.Frame(file_frame)
        instruction_frame.pack(fill=tk.X, pady=(10, 0))
        
        instruction_text = "TIP: Use 'Single Sheet' for detailed analysis of one sheet, or 'Multi-Sheet Analysis' to compare multiple sheets"
        ttk.Label(instruction_frame, text=instruction_text, 
                 font=('Arial', 9), foreground='blue', wraplength=600).pack()
        
        # Add prominent status indicator with boxed design
        status_frame = ttk.Frame(instruction_frame)
        status_frame.pack(pady=(10, 0))
        
        # Create a bordered status indicator
        self.mode_label = tk.Label(status_frame, text="MODE: READY", 
                                  font=('Arial', 12, 'bold'), foreground='white', 
                                  bg='#28a745', relief='raised', bd=2, 
                                  padx=15, pady=8)
        self.mode_label.pack()
        
        # Store button references for state management
        self.button_states = {
            'browse': self.browse_btn,
            'analyze': self.analyze_btn,
            'batch_analyze': self.batch_analyze_btn,  # NEW
            'export_results': self.export_results_btn,
            'export_charts': self.export_charts_btn,
            'export_comparison': self.export_comparison_btn,  # NEW
            'open_viz': self.open_viz_btn,  # NEW
            'save_project': self.save_project_btn,
            'load_project': self.load_project_btn,
            'cancel': self.cancel_btn
        }
    
    def on_normalization_changed(self):
        """Handle normalization checkbox change"""
        try:
            if hasattr(self, 'batch_results') and self.batch_results:
                # Update existing visualizations if data is available
                try:
                    self.update_confusion_matrix_display()
                    if hasattr(self, 'viz_window') and self.viz_window and self.viz_window.window:
                        self.viz_window.load_visualizations()
                except Exception as viz_error:
                    logger.warning(f"Failed to update visualizations: {viz_error}")
            else:
                # No data available, just update the tree view to show the current state
                try:
                    self.update_confusion_matrix_display()
                except Exception as tree_error:
                    logger.warning(f"Failed to update tree view: {tree_error}")
        except Exception as e:
            logger.warning(f"Error in normalization callback: {e}")
            # Try to at least update the tree view
            try:
                self.update_confusion_matrix_display()
            except:
                pass
    
    def create_processing_overlay(self):
        """Create a processing overlay that shows during analysis"""
        # Create overlay frame that covers the main content area
        self.overlay_frame = tk.Frame(self.root, bg='white', relief=tk.RAISED, bd=3)
        self.overlay_frame.configure(bg='#f0f8ff')  # Light blue background
        
        # Create main content area within overlay
        content_frame = ttk.Frame(self.overlay_frame)
        content_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
        
        # Processing title
        title_label = ttk.Label(content_frame, text="ANALYSIS IN PROGRESS", 
                               font=('Arial', 16, 'bold'), foreground='darkblue')
        title_label.pack(pady=(0, 20))
        
        # Processing animation frame
        anim_frame = ttk.Frame(content_frame)
        anim_frame.pack(pady=(0, 20))
        
        # Large animated spinner
        self.overlay_spinner = ttk.Label(anim_frame, text="Processing", font=('Arial', 24))
        self.overlay_spinner.pack()
        
        # Processing message
        self.overlay_message = ttk.Label(content_frame, text="Initializing analysis...", 
                                        font=('Arial', 12), foreground='darkgreen')
        self.overlay_message.pack(pady=(0, 10))
        
        # Progress bar in overlay
        self.overlay_progress = ttk.Progressbar(content_frame, mode='indeterminate', 
                                               length=400)
        self.overlay_progress.pack(pady=(0, 20))
        
        # Status text
        self.overlay_status = ttk.Label(content_frame, text="Please wait while we process your data...", 
                                       font=('Arial', 10), foreground='gray')
        self.overlay_status.pack()
        
        # Add cancel button
        cancel_button = tk.Button(content_frame, text="Cancel Processing", 
                                 command=self.cancel_operations,
                                 bg='#ff4444', fg='white', font=('Arial', 10, 'bold'),
                                 relief=tk.RAISED, bd=2)
        cancel_button.pack(pady=(20, 0))
        
        # Initially hide the overlay
        self.overlay_frame.pack_forget()
        
        # Start overlay animation
        self.start_overlay_animation()
    
    def start_overlay_animation(self):
        """Start the overlay animation"""
        self.overlay_animation_running = True
        self.overlay_animation_frame = 0
        self.animate_overlay()
    
    def stop_overlay_animation(self):
        """Stop the overlay animation"""
        self.overlay_animation_running = False
    
    def animate_overlay(self):
        """Animate the overlay spinner and messages"""
        if not self.overlay_animation_running:
            return
        
        # Check if root window still exists
        try:
            if not self.root.winfo_exists():
                self.overlay_animation_running = False
                return
        except tk.TclError:
            self.overlay_animation_running = False
            return
        
        # Rotating spinner animation (using simple ASCII characters)
        spinners = ['|', '/', '-', '\\', '|', '/', '-', '\\']
        current_spinner = spinners[self.overlay_animation_frame % len(spinners)]
        
        try:
            if hasattr(self, 'overlay_spinner') and self.overlay_spinner.winfo_exists():
                self.overlay_spinner.config(text=current_spinner)
        except tk.TclError:
            self.overlay_animation_running = False
            return
        
        # Rotating processing messages
        messages = [
            "Analyzing data structure...",
            "Processing analysis units...",
            "Calculating statistics...",
            "Generating visualizations...",
            "Creating comparison charts...",
            "Finalizing results..."
        ]
        current_message = messages[self.overlay_animation_frame // 10 % len(messages)]
        
        try:
            if hasattr(self, 'overlay_message') and self.overlay_message.winfo_exists():
                self.overlay_message.config(text=current_message)
        except tk.TclError:
            self.overlay_animation_running = False
            return
        
        self.overlay_animation_frame += 1
        
        # Schedule next animation frame
        try:
            self.root.after(200, self.animate_overlay)
        except tk.TclError:
            self.overlay_animation_running = False
    
    def show_processing_overlay(self, message="Analysis in progress..."):
        """Show the processing overlay with enhanced visual feedback"""
        if hasattr(self, 'overlay_frame'):
            self.overlay_status.config(text=message)
            self.overlay_progress.start(10)
            self.overlay_frame.pack(expand=True, fill=tk.BOTH)
            
            # Add pulsing effect to make it more noticeable
            self.pulse_overlay()
            
            # Bring overlay to front and force update
            self.overlay_frame.lift()
            self.overlay_frame.focus_force()
            self.root.update()
            
            # Start timeout monitoring
            self.start_timeout_monitor()
    
    def pulse_overlay(self):
        """Add a subtle pulsing effect to the processing overlay"""
        if hasattr(self, 'overlay_frame') and self.overlay_frame.winfo_exists():
            try:
                # Alternate between normal and slightly lighter background
                current_bg = self.overlay_frame.cget('bg')
                if current_bg == '#f0f0f0':
                    new_bg = '#f8f8f8'
                else:
                    new_bg = '#f0f0f0'
                
                self.overlay_frame.configure(bg=new_bg)
                
                # Schedule next pulse
                self.root.after(1000, self.pulse_overlay)
            except tk.TclError:
                # Widget was destroyed, stop pulsing
                pass
    
    def start_timeout_monitor(self):
        """Start monitoring for processing timeouts"""
        self.processing_start_time = time.time()
        self.timeout_monitor_running = True
        self.check_processing_timeout()
    
    def stop_timeout_monitor(self):
        """Stop timeout monitoring"""
        self.timeout_monitor_running = False
    
    def check_processing_timeout(self):
        """Check if processing is taking too long"""
        if not self.timeout_monitor_running:
            return
        
        if hasattr(self, 'processing_start_time'):
            elapsed_time = time.time() - self.processing_start_time
            
            # Show timeout warning after 30 seconds
            if elapsed_time > 30 and not hasattr(self, 'timeout_warning_shown'):
                self.timeout_warning_shown = True
                self.overlay_status.config(text="Processing is taking longer than expected. This is normal for large datasets.")
                self.overlay_message.config(text="Please wait...", foreground='orange')
            
            # Show critical timeout after 2 minutes
            if elapsed_time > 120 and not hasattr(self, 'critical_timeout_shown'):
                self.critical_timeout_shown = True
                self.overlay_status.config(text="Processing is taking a very long time. You may cancel if needed.")
                self.overlay_message.config(text="Long processing time", foreground='red')
        
        # Schedule next check
        if self.timeout_monitor_running:
            self.root.after(5000, self.check_processing_timeout)  # Check every 5 seconds
    
    def hide_processing_overlay(self):
        """Hide the processing overlay"""
        if hasattr(self, 'overlay_frame'):
            self.overlay_progress.stop()
            self.overlay_frame.pack_forget()
            self.root.update()
        
        # Stop timeout monitoring
        self.stop_timeout_monitor()
        
        # Reset timeout flags
        if hasattr(self, 'timeout_warning_shown'):
            delattr(self, 'timeout_warning_shown')
        if hasattr(self, 'critical_timeout_shown'):
            delattr(self, 'critical_timeout_shown')
        
    def setup_drag_and_drop(self):
        """Setup drag and drop functionality for Excel files"""
        # Enable drag and drop on the main window and file entry
        def handle_drop(event):
            try:
                # Get the dropped file path
                files = event.data
                if files:
                    # Handle multiple formats (Windows, Linux, etc.)
                    if isinstance(files, str):
                        file_path = files.strip('{}').replace('\\', '/')
                    else:
                        file_path = str(files[0]).strip('{}').replace('\\', '/')
                    
                    # Validate it's an Excel file
                    if file_path.lower().endswith(('.xlsx', '.xls')):
                        self.file_path.set(file_path)
                        self.update_activity_indicator("File dropped successfully!")
                        # Auto-load the file
                        self.load_excel_sheets_threaded()
                    else:
                        messagebox.showerror("Invalid File", "Please drop an Excel file (.xlsx or .xls)")
                        
            except Exception as e:
                messagebox.showerror("Drop Error", f"Error processing dropped file: {str(e)}")
        
        def handle_drag_enter(event):
            self.update_activity_indicator("Drop Excel file here...")
            self.file_entry.configure(style="DragOver.TEntry")
            return event.action
            
        def handle_drag_leave(event):
            self.update_activity_indicator("Ready")
            self.file_entry.configure(style="TEntry")
            
        # Try to enable drag and drop (tkinterdnd2 if available, otherwise basic)
        try:
            # Basic drag and drop using built-in tk features
            self.root.drop_target_register('DND_Files')
            self.file_entry.drop_target_register('DND_Files')
            
            self.root.dnd_bind('<<Drop>>', handle_drop)
            self.file_entry.dnd_bind('<<Drop>>', handle_drop)
            self.file_entry.dnd_bind('<<DragEnter>>', handle_drag_enter)
            self.file_entry.dnd_bind('<<DragLeave>>', handle_drag_leave)
            
        except AttributeError:
            # Fallback: Just add visual hint for drag and drop
            self.file_entry.insert(0, "Browse or drag Excel file here...")
            self.file_entry.bind('<Button-1>', lambda e: self.file_entry.delete(0, tk.END) if self.file_entry.get().startswith("Browse") else None)
    
    def update_activity_indicator(self, message="Working..."):
        """Update the status to show program activity with enhanced visual feedback"""
        if hasattr(self, 'status_label'):
            self.status_label.configure(text=f"Status: {message}")
            self.root.update_idletasks()
            
            # Add visual feedback with color coding
            if "failed" in message.lower() or "error" in message.lower():
                self.status_label.configure(foreground='red')
            elif "complete" in message.lower() or "success" in message.lower() or "ready" in message.lower():
                self.status_label.configure(foreground='green')
            elif "processing" in message.lower() or "working" in message.lower() or "loading" in message.lower() or "analyzing" in message.lower():
                self.status_label.configure(foreground='blue')
                # Start activity animation for processing states
                self.start_activity_animation()
            else:
                self.status_label.configure(foreground='black')
                # Stop activity animation for non-processing states
                self.stop_activity_animation()
            
        # Update window title to show activity
        current_title = self.root.title()
        if "Working" not in current_title and message != "Ready":
            self.root.title(f"Statistical Analysis Tool - {message}")
        elif message == "Ready":
            self.root.title("Statistical Contingency Analysis Platform v1.0 - Ready")
    
    def start_activity_animation(self):
        """Start the activity animation"""
        if hasattr(self, 'activity_progress'):
            self.activity_progress.pack(side=tk.RIGHT, padx=(5, 0))
            self.activity_progress.start(10)  # Animation speed
            
        # Start dots animation
        self.animation_step = 0
        self.animate_activity_dots()
        
    def stop_activity_animation(self):
        """Stop the activity animation"""
        if hasattr(self, 'activity_progress'):
            self.activity_progress.stop()
            self.activity_progress.pack_forget()
            
        # Stop dots animation
        if hasattr(self, 'animation_after_id'):
            self.root.after_cancel(self.animation_after_id)
            
        if hasattr(self, 'processing_dots'):
            self.processing_dots.configure(text="")
            
    def animate_activity_dots(self):
        """Animate the activity dots"""
        if not hasattr(self, 'processing_dots'):
            return
            
        dots = ["", ".", "..", "..."]
        if hasattr(self, 'animation_step'):
            self.processing_dots.configure(text=dots[self.animation_step % 4])
            self.animation_step += 1
            self.animation_after_id = self.root.after(500, self.animate_activity_dots)
            
    def setup_analysis_section(self, parent):
        """Setup analysis results and visualization section"""
        analysis_frame = ttk.Frame(parent)
        analysis_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create a PanedWindow for resizable left/right panels
        paned_window = ttk.PanedWindow(analysis_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)  # Allow expansion to show all content
        
        # Left side - Results (fixed size)
        left_frame = ttk.LabelFrame(paned_window, text="Statistical Analysis", padding="15")
        paned_window.add(left_frame, weight=1)
        
        # Results text with fixed height
        self.results_text = tk.Text(left_frame, height=20, width=45, wrap=tk.NONE,
                                   font=('Consolas', 10), bg='white', relief=tk.SUNKEN, bd=2)
        results_scroll_y = ttk.Scrollbar(left_frame, orient="vertical", command=self.results_text.yview)
        results_scroll_x = ttk.Scrollbar(left_frame, orient="horizontal", command=self.results_text.xview)
        self.results_text.configure(yscrollcommand=results_scroll_y.set, xscrollcommand=results_scroll_x.set)
        
        # Grid layout for text and scrollbars
        self.results_text.grid(row=0, column=0, sticky='nsew')
        results_scroll_y.grid(row=0, column=1, sticky='ns')
        results_scroll_x.grid(row=1, column=0, sticky='ew')
        
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)
        
        # Right side - QC Results Panel (fixed height)
        qc_frame = ttk.LabelFrame(paned_window, text="QC Results & Sheet Comparison", padding="15")
        paned_window.add(qc_frame, weight=2)
        
        # Create QC Results Panel
        self.setup_qc_results_panel(qc_frame)
        
    def setup_data_section(self, parent):
        """Setup data preview section"""
        data_frame = ttk.LabelFrame(parent, text="Confusion Matrix", padding="15")
        data_frame.pack(fill=tk.X)
        
        # Create treeview with scrollbars - size to content, not full width
        tree_frame = ttk.Frame(data_frame, height=300)
        tree_frame.pack()  # Let it size to content instead of fill=tk.X
        
        # Configure the tree frame to allow proper column sizing
        tree_frame.grid_columnconfigure(0, weight=1)
        
        self.tree = ttk.Treeview(tree_frame, show='tree headings', height=12)  # Fixed height
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Grid layout for scrollbars - tree sizes to content
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=0)  # Don't expand tree columns unnecessarily
        
    def setup_qc_results_panel(self, parent):
        """Setup comprehensive QC Results & Sheet Comparison panel"""
        # Create main scrollable container
        canvas = tk.Canvas(parent, bg='white')
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # ADD THESE LINES IMMEDIATELY AFTER:
        def update_scroll():
            canvas.update_idletasks()
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.yview_moveto(0)  # Reset to top

        # Force initial scroll region update
        canvas.after(100, update_scroll)
        canvas.after(500, update_scroll)  # Second update for delayed content
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # === TOP SECTION: Overall Batch Summary ===
        summary_frame = ttk.LabelFrame(scrollable_frame, text="📊 Batch Analysis Summary", padding="10")
        summary_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        self.batch_summary_text = tk.Text(summary_frame, height=4, width=50, wrap=tk.WORD,
                                        font=('Consolas', 9), bg='#f8f9fa', relief=tk.FLAT)
        self.batch_summary_text.pack(fill=tk.X)
        self.batch_summary_text.insert('1.0', 'No batch analysis data available. Run Multi-Sheet Analysis to see results.')
        self.batch_summary_text.config(state=tk.DISABLED)
        
        # === MIDDLE SECTION: Per-Sheet QC Details Table ===
        details_frame = ttk.LabelFrame(scrollable_frame, text="🔍 Sheet Quality Control Details", padding="10")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # QC Details Treeview
        qc_columns = ("Sheet", "Status", "QC Grade", "Rows", "Completeness", "Accuracy", "Effect Size", "Warnings")
        self.qc_tree = ttk.Treeview(details_frame, columns=qc_columns, show='headings', height=8)
        
        # Configure column headings and widths
        column_widths = [120, 80, 60, 60, 80, 70, 80, 150]
        for i, (col, width) in enumerate(zip(qc_columns, column_widths)):
            self.qc_tree.heading(col, text=col)
            self.qc_tree.column(col, width=width, minwidth=50)
        
        # Add scrollbars for QC table
        qc_v_scroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.qc_tree.yview)
        qc_h_scroll = ttk.Scrollbar(details_frame, orient="horizontal", command=self.qc_tree.xview)
        self.qc_tree.configure(yscrollcommand=qc_v_scroll.set, xscrollcommand=qc_h_scroll.set)
        
        # Grid layout for QC table
        self.qc_tree.grid(row=0, column=0, sticky='nsew')
        qc_v_scroll.grid(row=0, column=1, sticky='ns')
        qc_h_scroll.grid(row=1, column=0, sticky='ew')
        
        details_frame.grid_rowconfigure(0, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)
        
        # === BOTTOM SECTION: Comparison Readiness & Action Buttons ===
        actions_frame = ttk.LabelFrame(scrollable_frame, text="🚀 Comparison Readiness & Actions", padding="10")
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Readiness status row
        readiness_row = ttk.Frame(actions_frame)
        readiness_row.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(readiness_row, text="Comparison Readiness:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        self.readiness_label = ttk.Label(readiness_row, text="No data analyzed", foreground='gray')
        self.readiness_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Quality groups row
        groups_row = ttk.Frame(actions_frame)
        groups_row.pack(fill=tk.X, pady=(0, 10))
        
        self.high_quality_label = ttk.Label(groups_row, text="High Quality: 0", foreground='green')
        self.high_quality_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.medium_quality_label = ttk.Label(groups_row, text="Medium Quality: 0", foreground='orange')
        self.medium_quality_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.low_quality_label = ttk.Label(groups_row, text="Low Quality: 0", foreground='red')
        self.low_quality_label.pack(side=tk.LEFT)
        
        # Action buttons row with visual indicator
        buttons_row = ttk.Frame(actions_frame)
        buttons_row.pack(fill=tk.X, pady=(10, 0))
        
        # Add subtle hint for QC controls location
        hint_frame = ttk.Frame(buttons_row)
        hint_frame.pack(fill=tk.X, pady=(0, 5))
        
        hint_label = ttk.Label(hint_frame, text="Click buttons below to open analysis windows with charts and comparisons", 
                              font=('Arial', 9, 'italic'), foreground='#666666')
        hint_label.pack(anchor=tk.CENTER)
        
        self.compare_high_btn = ttk.Button(buttons_row, text="Open High-Quality Analysis Window", 
                                         command=self.launch_high_quality_comparison, state=tk.DISABLED)
        self.compare_high_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.compare_all_btn = ttk.Button(buttons_row, text="Open Full Analysis Window", 
                                        command=self.launch_all_comparison, state=tk.DISABLED)
        self.compare_all_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_qc_btn = ttk.Button(buttons_row, text="Export QC Report", 
                                      command=self.export_qc_report, state=tk.DISABLED)
        self.export_qc_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.refresh_qc_btn = ttk.Button(buttons_row, text="Refresh QC Analysis", 
                                       command=self.refresh_qc_analysis)
        self.refresh_qc_btn.pack(side=tk.RIGHT)
        
        # Initialize with empty state
        self.update_qc_results_panel()
    
    def setup_status_bar(self, parent):
        """Setup status bar with progress indication"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        # Status text
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Select an Excel file to begin")
        
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, 
                                anchor=tk.W, font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Consolidated progress indicators
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                          length=200, mode='determinate')
        
        self.activity_progress = ttk.Progressbar(status_frame, mode='indeterminate', length=50)
        
        # Add processing animation frame
        self.processing_frame = ttk.Frame(status_frame)
        self.processing_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Processing animation label
        self.processing_label = ttk.Label(self.processing_frame, text="", font=('Arial', 9))
        self.processing_label.pack(side=tk.LEFT)
        
        # Processing animation dots
        self.processing_dots = ttk.Label(self.processing_frame, text="", font=('Arial', 12, 'bold'))
        self.processing_dots.pack(side=tk.LEFT, padx=(5, 0))
        
        # Initially hide processing animation
        self.processing_frame.pack_forget()
        
    def setup_menu_bar(self):
        """Setup menu bar with Help and About options"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        help_menu.add_command(label="User Guide", command=self.show_help)
        help_menu.add_separator()
        help_menu.add_command(label="Terms of Service", command=self.show_terms)
        help_menu.add_separator()
        help_menu.add_command(label="About deltaV solutions", command=self.show_about)
    
    def show_about(self):
        """Show About dialog"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About CONFIRM Statistical Analysis")
        about_window.geometry("450x350")
        about_window.resizable(False, False)
        about_window.grab_set()  # Make modal
        
        # Center the window
        about_window.transient(self.root)
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 225
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 175
        about_window.geometry(f"+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(about_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Company logo area
        logo_frame = ttk.Frame(main_frame)
        logo_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(logo_frame, text="deltaV solutions®", font=('Arial', 24, 'bold'), 
                 foreground='#2E86AB').pack()
        ttk.Label(logo_frame, text="STATISTICAL ANALYSIS TOOL", 
                 font=('Arial', 10, 'bold'), foreground='#555').pack()
        
        # Product info
        info_text = f"""Statistical Contingency Analysis Platform
Version {__version__}

© 2025 TraceSeis, Inc. All rights reserved.
Developed by deltaV solutions, the non-geoscience division of TraceSeis, Inc.
TraceSeis, Inc.® is a registered trademark of TraceSeis, Inc.

STATISTICAL ANALYSIS SOFTWARE
SOM-based categories classification and statistical analysis 
for statistical research and analysis.

This software transforms clustering analysis results into 
traditional confusion matrices, providing comprehensive statistical 
analysis of categories classification performance.

FEATURES:
- Excel data import and validation
- Automated SOM-to-confusion matrix transformation  
- Statistical analysis (Chi-square, Cramer's V)
- Multiple visualization types
- Project save/load functionality
- Data integrity verification

This software is licensed under the TraceSeis, Inc. Commercial License Agreement.
Unauthorized copying, distribution, or modification is prohibited.

COMPANY STRUCTURE:
TraceSeis, Inc. - Parent company specializing in geophysical analysis
deltaV solutions - Non-geoscience division for general statistical analysis

CONTACT:
For support and inquiries: info@traceseis.com"""
        
        text_widget = tk.Text(main_frame, height=12, width=50, wrap=tk.WORD, 
                             font=('Arial', 9), bg='#f8f9fa', relief=tk.FLAT,
                             borderwidth=1, highlightthickness=1)
        text_widget.insert(1.0, info_text)
        text_widget.configure(state='disabled')
        text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Close button
        ttk.Button(main_frame, text="Close", command=about_window.destroy, 
                  width=15).pack()
    
    def show_help(self):
        """Show Help dialog"""
        help_window = tk.Toplevel(self.root)
        help_window.title("deltaV solutions User Guide")
        help_window.geometry("700x600")
        help_window.grab_set()  # Make modal
        
        # Center the window
        help_window.transient(self.root)
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 350
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 300
        help_window.geometry(f"+{x}+{y}")
        
        # Main frame with scrollbar
        main_frame = ttk.Frame(help_window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="TraceSeis, Inc.® Geophysics Analysis - User Guide", 
                 font=('Arial', 14, 'bold')).pack(pady=(0, 15))
        
        # Help content with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        help_text = """QUICK START GUIDE

1. LOADING DATA
   - Click "Browse" to select an Excel file (.xlsx or .xls)
   - Choose the worksheet containing your analysis unit data
   - Data format: First column = Unit IDs, Other columns = Category types
   - Click "Analyze" to process the data

2. UNDERSTANDING THE ANALYSIS
   This tool transforms clustering analysis results into traditional confusion matrices:
   - Each neuron is assigned the categories type it contains most samples of
   - All samples in a neuron inherit that categories type as their "prediction"
   - The confusion matrix compares SOM predictions vs actual categories types

3. INTERPRETING RESULTS
   
   GLOBAL STATISTICS:
   • Global Fit: Overall classification accuracy (higher = better)
   • Cramer's V: Association strength between predicted and actual types
   • Chi-square test: Statistical significance of the association
   
   PER-CLASS PERFORMANCE:
   • Precision: How often predictions for this type are correct
   • Recall: How often actual samples of this type are correctly identified
   • F1-Score: Balanced measure combining precision and recall
   
   SOM EFFECTIVENESS:
   • Evaluates how well the SOM separated different categories types
   • Based on classification accuracy and unit utilization

4. VISUALIZATIONS
   
   DISTRIBUTION: Shows how samples are distributed among predicted types
   PERFORMANCE: Radar chart comparing precision, recall, and F1-scores
   HEATMAP: Visual confusion matrix showing prediction patterns
   METRICS: Bar chart comparing performance across categories types
   ACTUAL TYPES: Distribution of true categories types in your data
   PREDICTED TYPES: Distribution of SOM-derived predictions

5. DATA MANAGEMENT
   
   SAVING PROJECTS:
   • Save complete analysis sessions including all results and visualizations
   • Projects saved as .tsp files with automatic backups
   • Auto-save feature prevents data loss
   
   LOADING PROJECTS:
   • Restore previous analysis sessions
   • Data integrity verification ensures file authenticity
   • Project metadata tracks analysis history

6. EXPORTING RESULTS
   
   EXPORT RESULTS: Save statistical analysis as text or CSV files
   EXPORT CHARTS: Save all visualizations as high-resolution PNG images

7. DATA REQUIREMENTS
   
   EXCEL FORMAT:
   • First column: Neuron identifiers (can be numbers or text)
   • Subsequent columns: Category type names as headers
   • Cell values: Number of samples of each type assigned to each neuron
   • No empty rows/columns in the data area
   
   EXAMPLE DATA STRUCTURE:
   Unit_ID  | Category_A | Category_B | Category_C | Category_D
   -----------|-----------|-----------|-------|--------
   Unit_001 |    45     |     12    |   3   |    0
   Neuron_002 |     8     |     67    |  15   |    2
   Neuron_003 |     2     |      5    |  89   |    1

8. TROUBLESHOOTING
   
   COMMON ISSUES:
   • "No data to analyze": Check that your Excel sheet contains numeric data
   • "Data too large": Reduce dataset size or close other applications
   • "Invalid file structure": Ensure Excel file is not corrupted
   • Visualization errors: Try reducing the number of categories types
   
   PERFORMANCE TIPS:
   • Close other memory-intensive applications before analysis
   • Use Excel files rather than CSV for better compatibility
   • Keep categories type names short for better chart readability

© 2025 TraceSeis, Inc. All rights reserved."""
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Arial', 9), 
                             bg='white', relief=tk.SUNKEN, borderwidth=1)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.insert(1.0, help_text)
        text_widget.configure(state='disabled')
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=help_window.destroy, 
                  width=15).pack(pady=(15, 0))
    
    def show_terms(self):
        """Show Terms of Service dialog"""
        terms_window = tk.Toplevel(self.root)
        terms_window.title("TraceSeis, Inc. Terms of Service")
        terms_window.geometry("650x550")
        terms_window.grab_set()  # Make modal
        
        # Center the window
        terms_window.transient(self.root)
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 325
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 275
        terms_window.geometry(f"+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(terms_window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="TraceSeis, Inc.® Commercial License Agreement", 
                 font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        # Terms content with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        terms_text = """TraceSeis, Inc.® COMMERCIAL LICENSE AGREEMENT
(deltaV solutions division)

IMPORTANT: READ CAREFULLY BEFORE USING THIS SOFTWARE

This Commercial License Agreement ("Agreement") is a legal agreement between you (either an individual or a single entity) and TraceSeis, Inc. ("TraceSeis, Inc.") for the TraceSeis, Inc. software product identified above, developed by deltaV solutions (the non-geoscience division of TraceSeis, Inc.), which includes computer software and associated documentation ("Software").

BY CLICKING "I ACCEPT" BELOW, YOU AGREE TO BE BOUND BY THE TERMS OF THIS AGREEMENT.

1. GRANT OF LICENSE
TraceSeis, Inc. grants you a non-exclusive, non-transferable license to use the Software in accordance with the terms of this Agreement. You may:
• Use the Software on computers owned or controlled by you
• Make one backup copy of the Software for archival purposes
• Use the Software for categories analysis and research

2. RESTRICTIONS
You may NOT:
• Copy the Software except as specified above
• Distribute, rent, lease, or sublicense the Software
• Reverse engineer, decompile, or disassemble the Software
• Remove or alter any copyright notices or labels
• Use the Software to develop competing products
• Share license keys with unauthorized users

3. OWNERSHIP
The Software is protected by copyright laws and international copyright treaties. TraceSeis, Inc. retains all ownership rights in the Software. TraceSeis, Inc.® is a registered trademark of TraceSeis, Inc.

4. WARRANTY DISCLAIMER
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. TraceSeis, Inc. DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

5. LIMITATION OF LIABILITY
IN NO EVENT SHALL TraceSeis, Inc. BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THE SOFTWARE, EVEN IF TraceSeis, Inc. HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. TraceSeis, Inc.' TOTAL LIABILITY SHALL NOT EXCEED THE AMOUNT PAID FOR THE SOFTWARE LICENSE.

6. DATA PRIVACY
TraceSeis, Inc. respects your privacy. The Software operates locally on your computer and does not transmit categories data or personally identifiable information to external servers without your explicit consent.

7. EXPORT RESTRICTIONS
You acknowledge that the Software may be subject to export restrictions. You agree to comply with all applicable export laws and regulations.

8. TERMINATION
This license is effective until terminated. Your rights under this license will terminate automatically without notice if you fail to comply with any term of this Agreement. Upon termination, you must destroy all copies of the Software.

9. GOVERNING LAW
This Agreement is governed by the laws of the United States, without regard to conflict of law principles.

10. ENTIRE AGREEMENT
This Agreement constitutes the entire agreement between you and TraceSeis, Inc. regarding the Software and supersedes all prior agreements and understandings.

By clicking "I Accept" below, you acknowledge that you have read and understood this Agreement and agree to be bound by its terms.

© 2025 TraceSeis, Inc. All rights reserved.
TraceSeis, Inc.® is a registered trademark of TraceSeis, Inc."""
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Courier', 8), 
                             bg='#f8f9fa', relief=tk.SUNKEN, borderwidth=1)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.insert(1.0, terms_text)
        text_widget.configure(state='disabled')
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="Print Terms", command=self.print_terms, 
                  width=15).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Close", command=terms_window.destroy, 
                  width=15).pack(side=tk.RIGHT)
    
    def print_terms(self):
        """Handle printing of terms (placeholder)"""
        messagebox.showinfo("Print Terms", 
                           "Terms of Service can be saved or printed using your system's\n"
                           "standard print functionality from this dialog window.")
        
    def start_progress_monitor(self):
        """Start the progress monitoring system"""
        def check_progress():
            try:
                # Check if root window still exists
                if not self.root.winfo_exists():
                    return
            except tk.TclError:
                return
            
            try:
                while True:
                    progress_data = self.progress_queue.get_nowait()
                    self.update_progress(progress_data)
            except Empty:
                pass
            finally:
                # Schedule next check only if window still exists
                try:
                    if self.root.winfo_exists():
                        self.root.after(100, check_progress)
                except tk.TclError:
                    return
        
        # Start the monitoring loop
        try:
            self.root.after(100, check_progress)
        except tk.TclError:
            return
        
        # Start processing animation
        self.start_processing_animation()
    
    def start_processing_animation(self):
        """Start the processing animation with rotating dots"""
        self.animation_running = True
        self.animation_frame = 0
        self.animate_processing()
    
    def stop_processing_animation(self):
        """Stop the processing animation"""
        self.animation_running = False
        if hasattr(self, 'processing_frame'):
            self.processing_frame.pack_forget()
    
    def animate_processing(self):
        """Animate the processing indicator with rotating dots"""
        if not self.animation_running:
            return
        
        # Check if root window still exists
        try:
            if not self.root.winfo_exists():
                self.animation_running = False
                return
        except tk.TclError:
            self.animation_running = False
            return
        
        # Rotating dots animation
        dots = ['|', '/', '-', '\\', '|', '/', '-', '\\', '|', '/']
        current_dot = dots[self.animation_frame % len(dots)]
        
        try:
            if hasattr(self, 'processing_dots') and self.processing_dots.winfo_exists():
                self.processing_dots.config(text=current_dot)
        except tk.TclError:
            self.animation_running = False
            return
        
        self.animation_frame += 1
        
        # Schedule next animation frame
        try:
            self.root.after(100, self.animate_processing)
        except tk.TclError:
            self.animation_running = False
        
    def update_progress(self, progress_data):
        """Update progress indicators from worker threads"""
        if isinstance(progress_data, dict):
            if 'status' in progress_data:
                self.status_var.set(progress_data['status'])
            
            if 'progress' in progress_data:
                progress = progress_data['progress']
                if progress == -1:  # Indeterminate
                    self.progress_bar.pack_forget()
                    self.activity_progress.pack(side=tk.RIGHT, padx=(10, 0))
                    self.activity_progress.start(10)
                    # Show processing animation
                    if hasattr(self, 'processing_frame'):
                        self.processing_frame.pack(side=tk.RIGHT, padx=(10, 0))
                        self.processing_label.config(text="Processing")
                else:  # Determinate
                    self.activity_progress.stop()
                    self.activity_progress.pack_forget()
                    self.progress_bar.pack(side=tk.RIGHT, padx=(10, 0))
                    self.progress_var.set(min(progress, 100))  # Cap at 100%
                    # Show processing animation with progress
                    if hasattr(self, 'processing_frame'):
                        self.processing_frame.pack(side=tk.RIGHT, padx=(10, 0))
                        self.processing_label.config(text=f"Processing {progress:.0f}%")
            
            if 'complete' in progress_data and progress_data['complete']:
                self.activity_progress.stop()
                self.activity_progress.pack_forget()
                self.progress_bar.pack_forget()
                # Hide processing animation
                if hasattr(self, 'processing_frame'):
                    self.processing_frame.pack_forget()
                self.set_processing_state(False)
    
    # CONSOLIDATED: Button state management
    def set_processing_state(self, processing):
        """Enable/disable UI elements based on processing state"""
        self.processing_state = processing
        
        states = {
            'browse': 'disabled' if processing else 'normal',
            'analyze': 'disabled' if processing else 'normal', 
            'batch_analyze': 'disabled' if processing else 'normal',  # NEW
            'export_results': 'disabled' if processing else 'normal',
            'export_charts': 'disabled' if processing else 'normal',
            'export_comparison': 'disabled' if processing else 'normal',  # NEW
            'open_viz': 'disabled' if processing else 'normal',  # NEW
            'save_project': 'disabled' if processing else 'normal',
            'load_project': 'disabled' if processing else 'normal',
            'cancel': 'normal' if processing else 'disabled'
        }
        
        for btn_name, state in states.items():
            if btn_name in self.button_states:  # Check if button exists
                self.button_states[btn_name].config(state=state)
        
        # Show/hide processing overlay
        if processing:
            self.show_processing_overlay("Starting analysis...")
            self.update_window_title("Processing")
        else:
            self.hide_processing_overlay()
            self.update_window_title("Ready")
            
        if not processing:
            self.cancel_event.clear()
    
    # CONSOLIDATED: Progress update method
    def update_progress_status(self, status, progress=None, complete=False):
        """Unified progress update method"""
        progress_data = {'status': status}
        if progress is not None:
            progress_data['progress'] = progress
        if complete:
            progress_data['complete'] = True
        self.progress_queue.put(progress_data)
    
    # CONSOLIDATED: Error handling method  
    def handle_error(self, error_msg, exception=None, context="Operation"):
        """Unified error handling method"""
        full_msg = f"{context} failed: {error_msg}"
        logger.error(f"{context} error: {error_msg}", exc_info=exception)
        
        def show_error():
            try:
                self.show_message_safely("error", "Error", full_msg)
                self.update_progress_status(f"{context} failed", complete=True)
            except Exception as e:
                logger.error(f"Failed to display error message: {e}")
        
        try:
            # Check if root exists and mainloop might be running
            if hasattr(self, 'root') and self.root and self.root.winfo_exists():
                try:
                    self.root.after(0, show_error)
                except RuntimeError as e:
                    if "main thread is not in main loop" in str(e):
                        logger.error(f"Cannot display error - mainloop not running: {full_msg}")
                        # Try to log to file instead
                        logger.critical(f"CRITICAL ERROR (mainloop not running): {full_msg}")
                    else:
                        raise
            else:
                logger.error(f"Cannot display error - root window not available: {full_msg}")
        except Exception as e:
            logger.error(f"Error in handle_error: {e}")
            logger.critical(f"CRITICAL ERROR: {full_msg}")
        
    def cancel_operations(self):
        """Cancel current operations"""
        self.cancel_event.set()
        self.update_progress_status('Cancelling operations...', -1)
        
        # Cancel futures
        for task in self.current_tasks:
            if not task.done():
                task.cancel()
        self.current_tasks.clear()
        
        # Reset UI state after a short delay
        def reset_ui():
            self.set_processing_state(False)
            self.update_progress_status('Operations cancelled', complete=True)
        
        self.root.after(1000, reset_ui)
        
    def submit_task(self, func, *args, **kwargs):
        """Submit a task to the thread pool"""
        # Show activity indicator
        self.update_activity_indicator("Processing...")
        self.start_activity_animation()
        
        future = self.thread_manager.submit_task(func, *args, **kwargs)
        self.current_tasks.append(future)
        
        # Add callback to stop animation when done
        def on_complete(fut):
            self.root.after(0, self.stop_activity_animation)
            self.root.after(0, lambda: self.update_activity_indicator("Ready"))
        
        future.add_done_callback(on_complete)
        return future
    
    # SECURITY FIX: Enhanced file validation
    def validate_file_security(self, filename):
        """Enhanced security validation for Excel files"""
        try:
            # Basic file checks
            if not os.path.exists(filename):
                raise FileNotFoundError("Selected file does not exist")
            
            if not os.access(filename, os.R_OK):
                raise PermissionError("Cannot read the selected file")
            
            # Validate extension
            valid_extensions = ['.xlsx', '.xls']
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in valid_extensions:
                raise ValueError("Please select a valid Excel file (.xlsx or .xls)")
            
            # Check file size
            file_size = os.path.getsize(filename)
            max_size = 100 * 1024 * 1024  # 100MB
            if file_size > max_size:
                raise ValueError(f"File too large. Maximum size allowed is {max_size // (1024*1024)}MB")
            
            # SECURITY: Enhanced path validation
            abs_path = os.path.abspath(filename)
            real_path = os.path.realpath(filename)
            
            # Check for symlink attacks
            if abs_path != real_path:
                raise ValueError("Symbolic links not allowed")
            
            # Check for device files or network paths
            if not os.path.isfile(real_path):
                raise ValueError("Invalid file type")
            
            # SECURITY: Basic Excel file structure validation
            self.validate_excel_structure(filename)
            
            return True
            
        except Exception as e:
            raise ValueError(str(e))
    
    def validate_excel_structure(self, filename):
        """Basic Excel file security validation"""
        try:
            # Check if file is actually a zip (Excel format)
            with zipfile.ZipFile(filename, 'r') as zip_file:
                file_list = zip_file.namelist()
                
                # Check for suspicious files
                suspicious_files = [f for f in file_list if f.endswith(('.exe', '.bat', '.cmd', '.vbs'))]
                if suspicious_files:
                    raise ValueError("Excel file contains suspicious embedded files")
                
                # Basic structure validation
                required_files = ['_rels/', 'xl/']
                if not any(f.startswith(req) for req in required_files for f in file_list):
                    raise ValueError("Invalid Excel file structure")
                    
        except zipfile.BadZipFile:
            # Older .xls files are not zip format, this is OK
            pass
        except Exception as e:
            raise ValueError(f"Excel file validation failed: {str(e)}")
    
    def validate_contingency_format(self, filename):
        """Validate that the file contains properly formatted contingency tables"""
        try:
            # Read first sheet to check format
            excel_file = pd.ExcelFile(filename)
            if not excel_file.sheet_names:
                raise ValueError("Excel file contains no sheets")
            
            # Check first sheet
            first_sheet = excel_file.sheet_names[0]
            df = pd.read_excel(filename, sheet_name=first_sheet, header=None)
            
            # Check if we have enough data
            if df.shape[0] < 2:
                raise ValueError(
                    "Invalid format: Contingency table must have at least 2 rows of data.\n\n"
                    "Expected format:\n"
                    "Row 1: [empty cells]\n"
                    "Row 2+: Numeric data only"
                )
            
            # Check if first column (after header row) contains text labels
            # Start checking from row 1 (index 1) since row 0 may be empty
            if df.shape[0] > 1:
                first_data_row = df.iloc[1]
                
                # Check if first column is text (not numeric)
                if first_data_row.iloc[0] is not None and not isinstance(first_data_row.iloc[0], (int, float)):
                    raise ValueError(
                        "Invalid format: First column contains text labels.\n\n"
                        "CONFIRM expects contingency tables in this format:\n"
                        "  Row 1: [empty cells]\n"
                        "  Row 2: 1  [data]  [data]  [data]\n"
                        "  Row 3: 2  [data]  [data]  [data]\n"
                        "  Row 4: 3  [data]  [data]  [data]\n"
                        "  Last:  Category names (optional)\n\n"
                        "Your file has text labels like row names in the first column.\n"
                        "Please use numeric IDs (1, 2, 3...) instead.\n\n"
                        "Need help? Contact support@traceseis.com"
                    )
            
            return True
            
        except ValueError:
            # Re-raise our formatted errors
            raise
        except Exception as e:
            # Generic error for other issues
            raise ValueError(f"Unable to read contingency table format: {str(e)}")
        
    def browse_file(self):
        """Browse and select Excel file with enhanced security"""
        filename = filedialog.askopenfilename(
            title="Select Excel File with Contingency Tables",
            filetypes=[("Excel files", "*.xlsx *.xls"), ("All files", "*.*")],
            initialdir="C:/Users",
            defaultextension=".xlsx"
        )
        
        if filename:
            try:
                self.validate_file_security(filename)
                self.validate_contingency_format(filename)
                self.file_path.set(filename)
                self.load_excel_sheets_threaded()
                
            except Exception as e:
                self.handle_error(str(e), e, "File validation")
            
    def load_excel_sheets_threaded(self):
        """Load Excel sheets in background thread"""
        if self.processing_state:
            return
        
        # CRITICAL: Get file path from tkinter variable on MAIN THREAD before starting worker
        try:
            file_path = self.file_path.get()
        except RuntimeError:
            self.show_message_safely("error", "Error", "Cannot access file path. Please try again.")
            return
        
        # Validate file path exists before starting thread
        if not file_path or not os.path.exists(file_path):
            self.show_message_safely("error", "Error", "Please select a valid Excel file first.")
            return
            
        self.set_processing_state(True)
        self.update_progress_status('Loading Excel file structure...', -1)
        self.update_window_title("Loading File")
        
        def load_sheets_worker(file_path_param):
            try:
                file_path = file_path_param
                
                # Validate file exists
                if not os.path.exists(file_path):
                    raise FileNotFoundError(f"File not found: {file_path}")
                
                self.update_progress_status('Reading Excel file headers...', 25)
                
                # Check for cancellation
                if self.cancel_event.is_set():
                    return
                
                # SECURITY: Monitor memory during Excel loading
                initial_memory_check = True  # Placeholder for memory monitoring
                
                # Read Excel file to get sheet names
                # Wrap in try-except to catch any tkinter-related errors from openpyxl
                try:
                    excel_file = pd.ExcelFile(file_path)
                    sheet_names = excel_file.sheet_names
                except Exception as excel_error:
                    # Log the actual Excel error
                    logger.error(f"Excel file read error: {excel_error}", exc_info=excel_error)
                    raise FileNotFoundError(f"Failed to read Excel file: {str(excel_error)}")
                
                # SECURITY: Check for reasonable file size (basic validation)
                if len(sheet_names) > 100:  # Sanity check
                    raise ValueError("Excel file has too many sheets (possible corruption)")
                
                # FIX: Set excel_file IMMEDIATELY so buttons work right away
                with self.data_lock:
                    self.excel_file = excel_file
                
                self.update_progress_status('Processing sheet information...', 75)
                
                # Check for cancellation
                if self.cancel_event.is_set():
                    return
                
                # Update UI from main thread
                def update_ui():
                    try:
                        if hasattr(self, 'sheet_combo') and self.sheet_combo:
                            self.sheet_combo['values'] = sheet_names
                            
                            if sheet_names:
                                self.sheet_combo.set(sheet_names[0])
                                # FIX: Also set the variable explicitly
                                self.sheet_var.set(sheet_names[0])
                        
                        self.update_progress_status(f'Loaded {len(sheet_names)} sheets. Select a sheet to analyze.', 100, True)
                    except Exception as ui_error:
                        logger.error(f"Error updating UI after Excel load: {ui_error}")
                
                # Safely schedule UI update
                try:
                    if hasattr(self, 'root') and self.root and self.root.winfo_exists():
                        self.root.after(0, update_ui)
                    else:
                        logger.error("Cannot update UI - root window not available")
                except RuntimeError as e:
                    if "main thread is not in main loop" in str(e):
                        logger.error("Cannot schedule UI update - mainloop not running")
                    else:
                        raise
                
            except Exception as e:
                logger.error(f"Excel file loading error: {e}", exc_info=e)
                # Use handle_error which now has proper mainloop checking
                self.handle_error(str(e), e, "Excel file loading")
                # Also reset processing state
                def reset_state():
                    try:
                        self.set_processing_state(False)
                        self.update_progress_status("File loading failed", complete=True)
                    except:
                        pass
                
                try:
                    if hasattr(self, 'root') and self.root and self.root.winfo_exists():
                        self.root.after(0, reset_state)
                except:
                    pass
        
        # Pass file_path as parameter to avoid accessing tkinter from worker thread
        self.submit_task(load_sheets_worker, file_path)

    # =============== NEW: BATCH PROCESSING METHODS ===============
    
    def show_sheet_selection_dialog(self):
        """Show dialog for selecting which sheets to analyze"""
        if not self.excel_file:
            self.show_message_safely("error", "Error", "Please load an Excel file first.")
            return None
        
        # Create dialog with configuration
        config = SheetSelectionConfig()
        dialog = self._create_selection_dialog(config)
        
        # Setup content and get references
        tree, checked_items, status_label, analyze_button, instruction_label = self._setup_dialog_content(dialog, config)
        
        # Setup keyboard shortcuts and event handlers
        self._setup_keyboard_shortcuts(dialog, tree, checked_items, analyze_button)
        self._setup_event_handlers(tree, checked_items, status_label, analyze_button, instruction_label)
        
        # Load sheet previews asynchronously
        self._load_sheet_previews_async(tree, checked_items, status_label)
        
        # Wait for user action
        dialog.wait_window()
        
        # Return selected sheets
        return self._get_selected_sheets(tree, checked_items)

    def _create_selection_dialog(self, config):
        """Create and configure the selection dialog window"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Sheets for Multi-Sheet Analysis")
        
        # Configure dialog properties
        dialog.geometry(f"{config.dialog_size[0]}x{config.dialog_size[1]}")
        dialog.minsize(*config.min_size)
        dialog.maxsize(*config.max_size)
        dialog.resizable(True, True)
        dialog.grab_set()  # Make modal
        dialog.transient(self.root)
        
        # Center the dialog on screen
        self._center_dialog(dialog, config.dialog_size)
        
        # Configure styling
        dialog.configure(bg='#f0f0f0')
        
        return dialog

    def _center_dialog(self, dialog, size):
        """Center the dialog on screen"""
        dialog.update_idletasks()
        
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        
        x = (screen_width - size[0]) // 2
        y = (screen_height - size[1]) // 2
        
        # Ensure dialog doesn't go off-screen
        x = max(0, min(x, screen_width - size[0]))
        y = max(0, min(y, screen_height - size[1]))
        
        dialog.geometry(f"{size[0]}x{size[1]}+{x}+{y}")

    def _setup_dialog_content(self, dialog, config):
        """Setup all content within the dialog"""
        # Main frame
        main_frame = ttk.Frame(dialog, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Setup header
        self._setup_header(main_frame)
        
        # Setup control buttons FIRST (at the top)
        tree, checked_items = self._setup_sheet_list(main_frame, config)
        self._setup_control_buttons(main_frame, tree, checked_items)
        
        # Setup status display
        status_label = self._setup_status_display(main_frame, tree, checked_items)
        
        return tree, checked_items, status_label, self._analyze_button, None

    def _setup_header(self, main_frame):
        """Setup the header section with title and instructions"""
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Main title
        title_label = ttk.Label(header_frame, text="MULTI-SHEET ANALYSIS", 
                               font=('Arial', 18, 'bold'), foreground='darkblue')
        title_label.pack(pady=(0, 5))
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame, text="Select which sheets to analyze and compare", 
                                  font=('Arial', 12), foreground='darkgreen')
        subtitle_label.pack(pady=(0, 10))
        
        # File information
        file_frame = ttk.Frame(header_frame)
        file_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(file_frame, text="Excel File:", 
                 font=('Arial', 11, 'bold')).pack(side=tk.LEFT)
        ttk.Label(file_frame, text=f"{os.path.basename(self.file_path.get())}", 
                 font=('Arial', 11), foreground='blue').pack(side=tk.LEFT, padx=(5, 0))
        
        # Instructions
        instructions_frame = ttk.Frame(header_frame)
        instructions_frame.pack(fill=tk.X, pady=(0, 10))
        
        instructions_text = "Click sheet names to select/deselect - Choose any sheets you want to analyze"
        instructions_label = ttk.Label(instructions_frame, text=instructions_text, 
                                      font=('Arial', 9), foreground='darkblue')
        instructions_label.pack()
        
        # Status indicator (use different variable name to avoid conflict with main UI)
        self.dialog_mode_label = ttk.Label(instructions_frame, text="Mode: Ready", 
                                          font=('Arial', 9), foreground='green')

    def _setup_sheet_list(self, main_frame, config):
        """Setup the sheet list with Treeview"""
        list_frame = ttk.LabelFrame(main_frame, text="AVAILABLE SHEETS", padding="10")
        list_frame.pack(fill=tk.X, pady=(0, 15))  # Fixed height, no expand
        
        # Create scrollable listbox
        listbox_frame = ttk.Frame(list_frame)
        listbox_frame.pack(fill=tk.X)  # Fixed height, no expand
        
        # Use Treeview for better checkbox support
        tree = ttk.Treeview(listbox_frame, columns=('status', 'info'), show='tree headings', height=15)
        tree.heading('#0', text='Sheet Name')
        tree.heading('status', text='Status')
        tree.heading('info', text='Preview Info')
        tree.column('#0', width=300)
        tree.column('status', width=120)
        tree.column('info', width=400)
        
        # Configure highlighting tags
        tree.tag_configure('selected', background='lightgreen', foreground='black')
        tree.tag_configure('error', background='lightcoral', foreground='black')
        tree.tag_configure('invalid', background='lightyellow', foreground='black')
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(listbox_frame, orient="vertical", command=tree.yview)
        h_scroll = ttk.Scrollbar(listbox_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        listbox_frame.grid_rowconfigure(0, weight=1)
        listbox_frame.grid_columnconfigure(0, weight=1)
        
        # Track checked items
        checked_items = set()
        
        return tree, checked_items

    def _setup_control_buttons(self, main_frame, tree, checked_items):
        """Setup quick selection control buttons"""
        button_frame = ttk.LabelFrame(main_frame, text="QUICK SELECTION", padding="10")
        button_frame.pack(fill=tk.X, pady=(0, 15))  # Move to top, add padding below
        
        def select_all():
            checked_items.clear()
            for item in tree.get_children():
                checked_items.add(item)
                tree.set(item, 'status', "Selected")
                # Highlight selected items
                tree.item(item, tags=('selected',))
        
        def select_none():
            checked_items.clear()
            for item in tree.get_children():
                tree.set(item, 'status', "Available")
                # Remove highlighting
                tree.item(item, tags=())
        
        # Control buttons
        ttk.Button(button_frame, text="Select All Sheets", command=select_all, 
                  width=20).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Clear All", command=select_none, 
                  width=15).pack(side=tk.LEFT, padx=10)
        
        # Add cancel and analyze buttons to the right side - MADE MORE PROMINENT
        cancel_button = tk.Button(button_frame, text="CANCEL", 
                                 command=lambda: self._cancel_selection(tree), 
                                 width=15, height=2, bg='#f44336', fg='white',
                                 font=('Arial', 10, 'bold'), relief=tk.RAISED, bd=3)
        cancel_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        analyze_button = tk.Button(button_frame, 
                                  text=f"START ANALYSIS ({len(checked_items)} sheets)", 
                                  command=lambda: self._analyze_selected(tree, checked_items), 
                                  width=35, height=2, bg='#4CAF50', fg='white',
                                  font=('Arial', 10, 'bold'), relief=tk.RAISED, bd=3)
        analyze_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Store reference for updates
        self._analyze_button = analyze_button

    def _setup_status_display(self, main_frame, tree, checked_items):
        """Setup status display with real-time updates"""
        status_frame = ttk.LabelFrame(main_frame, text="SELECTION STATUS", padding="10")
        status_frame.pack(fill=tk.X, pady=(15, 20))
        
        status_label = ttk.Label(status_frame, text=f"Selected: {len(checked_items)} of {len(self.excel_file.sheet_names)} sheets", 
                                font=('Arial', 11, 'bold'))
        status_label.pack(side=tk.LEFT)
        
        return status_label



    def _setup_keyboard_shortcuts(self, dialog, tree, checked_items, analyze_button):
        """Setup keyboard shortcuts for better accessibility"""
        def on_key_press(event):
            if event.keysym == 'Return':
                # Select/deselect current item
                current = tree.selection()
                if current:
                    self._toggle_item_selection(tree, current[0], checked_items)
            elif event.keysym == 'a' and event.state & 4:  # Ctrl+A
                self._select_all_items(tree, checked_items)
            elif event.keysym == 'Escape':
                dialog.destroy()
        
        dialog.bind('<Key>', on_key_press)

    def _setup_event_handlers(self, tree, checked_items, status_label, analyze_button, instruction_label):
        """Setup event handlers for the tree and buttons"""
        def on_item_click(event):
            item = tree.selection()[0] if tree.selection() else None
            if item:
                self._toggle_item_selection(tree, item, checked_items)
        
        tree.bind('<Button-1>', on_item_click)
        tree.bind('<Return>', on_item_click)
        tree.bind('<space>', on_item_click)
        
        # Setup status updates
        def update_status():
            if checked_items:
                selected_names = [tree.item(item, 'text') for item in checked_items]
                preview_text = f"Will analyze: {', '.join(selected_names[:3])}"
                if len(selected_names) > 3:
                    preview_text += f" and {len(selected_names)-3} more..."
            else:
                preview_text = "No sheets selected"
            
            status_label.config(text=f"Selected: {len(checked_items)} of {len(self.excel_file.sheet_names)} sheets | {preview_text}")
            
            # Update button text
            if checked_items:
                analyze_button.config(text=f"START MULTI-SHEET ANALYSIS ({len(checked_items)} sheets)")
            else:
                analyze_button.config(text="START ANALYSIS (No Sheets Selected)")
            
            # Schedule next update
            tree.after(100, update_status)
        
        update_status()

    def _load_sheet_previews_async(self, tree, checked_items, status_label):
        """Load sheet previews asynchronously to avoid blocking the UI"""
        sheet_names = self.excel_file.sheet_names
        
        def preview_worker():
            for i, sheet_name in enumerate(sheet_names):
                try:
                    # Load preview with timeout
                    preview_data = self._load_sheet_preview(sheet_name)
                    if preview_data is not None:
                        status, preview_info, is_valid = self._validate_sheet_data(preview_data, sheet_name)
                        
                        # Update UI safely
                        self._update_ui_safely(lambda: self._add_sheet_to_tree(
                            tree, sheet_name, status, preview_info, is_valid, checked_items))
                        
                        # Update progress
                        progress = (i + 1) / len(sheet_names) * 100
                        self._update_ui_safely(lambda: status_label.config(
                            text=f"Loading sheets... {progress:.0f}%"))
                    
                except Exception as e:
                    # Add error entry
                    self._update_ui_safely(lambda: self._add_sheet_to_tree(
                        tree, sheet_name, "Error", f"Error: {str(e)[:30]}...", False, checked_items))
            
            # Final status update
            self._update_ui_safely(lambda: status_label.config(
                text=f"Ready - {len(checked_items)} sheets selected"))
        
        # Start preview loading in background thread
        threading.Thread(target=preview_worker, daemon=True).start()

    def _load_sheet_preview(self, sheet_name):
        """Load preview data for a single sheet with memory management"""
        try:
            # Use the already-loaded excel_file if available (thread-safe)
            # Otherwise, we shouldn't be in a thread - use excel_file attribute
            if self.excel_file:
                df_preview = pd.read_excel(self.excel_file, sheet_name=sheet_name, nrows=5)
                return df_preview
            else:
                # If excel_file not loaded, we can't safely access file_path from thread
                # This should not happen if load_excel_sheets_threaded was called first
                logger.warning(f"Cannot load preview - excel_file not loaded for sheet: {sheet_name}")
                return None
        except Exception as e:
            logger.error(f"Error loading sheet preview for {sheet_name}: {e}")
            return None

    def _validate_sheet_data(self, df_preview, sheet_name):
        """Validate sheet data and return detailed status"""
        try:
            if df_preview.empty:
                return "Empty", "No data found", False
            
            if len(df_preview.columns) < 2:
                return "Invalid", "Insufficient columns", False
            
            numeric_cols = df_preview.select_dtypes(include=[np.number]).shape[1]
            if numeric_cols == 0:
                return "No Numeric", "No numeric data found", False
            
            rows, cols = df_preview.shape
            preview_info = f"{rows}+ rows, {cols} cols, {numeric_cols} numeric columns"
            return "Valid", preview_info, True
            
        except Exception as e:
            return "Error", f"Error: {str(e)[:30]}...", False

    def _add_sheet_to_tree(self, tree, sheet_name, status, preview_info, is_valid, checked_items):
        """Add a sheet to the tree with proper status"""
        item_id = tree.insert('', 'end', text=sheet_name, values=(status, preview_info))
        
        # Apply appropriate highlighting based on status
        if "Error" in status:
            tree.item(item_id, tags=('error',))
        elif "Empty" in status or "No Numeric" in status or "Invalid" in status:
            tree.item(item_id, tags=('invalid',))
        
        # Don't auto-select - let user choose manually
        # All sheets start as unselected regardless of validity

    def _toggle_item_selection(self, tree, item, checked_items):
        """Toggle selection state of an item"""
        if item in checked_items:
            # Deselect
            checked_items.remove(item)
            tree.set(item, 'status', "Available")
            # Remove highlighting and restore original status-based highlighting
            status = tree.item(item, 'values')[0]
            if "Error" in status:
                tree.item(item, tags=('error',))
            elif "Empty" in status or "No Numeric" in status or "Invalid" in status:
                tree.item(item, tags=('invalid',))
            else:
                tree.item(item, tags=())
        else:
            # Select - allow selection of any sheet regardless of status
            checked_items.add(item)
            tree.set(item, 'status', "Selected")
            # Apply selection highlighting
            tree.item(item, tags=('selected',))

    def _select_all_items(self, tree, checked_items):
        """Select all items in the tree"""
        checked_items.clear()
        for item in tree.get_children():
            checked_items.add(item)
            tree.set(item, 'status', "Selected")
            # Apply selection highlighting
            tree.item(item, tags=('selected',))

    def _update_ui_safely(self, func):
        """Execute UI updates safely from background threads"""
        if threading.current_thread() is threading.main_thread():
            func()
        else:
            self.root.after(0, func)

    def _analyze_selected(self, tree, checked_items):
        """Handle analyze button click"""
        if not checked_items:
            self.show_message_safely("warning", "No Selection", "Please select at least one sheet to analyze.")
            return
        
        # Get selected sheet names
        selected_sheets = []
        for item in checked_items:
            sheet_name = tree.item(item, 'text')
            selected_sheets.append(sheet_name)
        
        # Show immediate feedback that button was clicked
        dialog = tree.winfo_toplevel()
        
        # Change button text to show processing
        for widget in dialog.winfo_children():
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.LabelFrame):
                        for button in child.winfo_children():
                            if isinstance(button, tk.Button) and "START ANALYSIS" in button.cget('text'):
                                button.config(text="PROCESSING...", bg='#FF9800', state='disabled')
                                button.update()
                                break
        
        # Store selected sheets and close dialog immediately
        self._selected_sheets = selected_sheets
        dialog.destroy()
        
        # Start batch processing with selected sheets
        self.batch_process_selected_sheets(selected_sheets)

    def validate_and_clean_data(self, df):
        """
        Consolidated data validation and cleaning with comprehensive quality checks.
        
        Args:
            df (pd.DataFrame): Input dataframe to validate and clean
            
        Returns:
            pd.DataFrame: Cleaned and validated dataframe
            
        Raises:
            ValueError: If data fails validation criteria
        """
        if df is None:
            raise ValueError("Input dataframe is None - cannot process empty data.")
            
        if df.empty:
            raise ValueError("The selected sheet appears to be empty.")
        
        # Store original dimensions for reporting
        original_shape = df.shape
        original_columns = list(df.columns)
        
        # Remove completely empty rows and columns
        df_cleaned = df.dropna(how='all').dropna(axis=1, how='all')
        
        if df_cleaned.empty:
            raise ValueError(
                f"Sheet contains no valid data after removing empty rows/columns. "
                f"Original shape: {original_shape}, cleaned shape: {df_cleaned.shape}"
            )
        
        # Check minimum structural requirements
        if len(df_cleaned.columns) < 2:
            raise ValueError(
                f"Data must have at least 2 columns (unit IDs + categories data). "
                f"Found: {len(df_cleaned.columns)} columns"
            )
        
        # Check for reasonable data dimensions
        if df_cleaned.shape[0] < 5:
            raise ValueError(
                f"Insufficient data rows for meaningful analysis. "
                f"Minimum required: 5 rows, found: {df_cleaned.shape[0]} rows"
            )
        
        # Validate column names (should not be empty or purely numeric)
        invalid_cols = []
        for col in df_cleaned.columns:
            if pd.isna(col) or str(col).strip() == '' or str(col).isdigit():
                invalid_cols.append(col)
        
        if invalid_cols:
            # Try to fix column names
            df_cleaned.columns = [f"Column_{i}" if pd.isna(col) or str(col).strip() == '' or str(col).isdigit() 
                                else col for i, col in enumerate(df_cleaned.columns)]
        
        # Report cleaning results
        rows_removed = original_shape[0] - df_cleaned.shape[0]
        cols_removed = original_shape[1] - df_cleaned.shape[1]
        
        # Note: rows_removed and cols_removed are calculated but not displayed to avoid logging
        
        return df_cleaned
    
    def convert_to_numeric_safe(self, matrix_data):
        """
        Convert data to numeric with comprehensive safety checks and data quality validation.
        
        Args:
            matrix_data (pd.DataFrame): Input matrix data to convert
            
        Returns:
            pd.DataFrame: Numeric matrix with safety validations applied
            
        Raises:
            ValueError: If data fails safety criteria or is unsuitable for analysis
        """
        if matrix_data is None or matrix_data.empty:
            raise ValueError("Matrix data is empty or None - cannot convert to numeric.")
        
        # Store original info for reporting
        original_dtypes = matrix_data.dtypes.value_counts()
        original_shape = matrix_data.shape
        
        # Convert to numeric with error handling
        numeric_matrix = matrix_data.apply(pd.to_numeric, errors='coerce')
        nan_count = numeric_matrix.isnull().sum().sum()
        total_cells = numeric_matrix.size
        
        # Comprehensive data quality assessment
        if nan_count > 0:
            nan_percentage = (nan_count / total_cells) * 100
            
            # Note: Data quality issues are detected but not logged to avoid excessive output
            
            # Warn user about significant data quality issues
            if nan_percentage > 50:
                def warn_quality():
                    messagebox.showwarning(
                        "Data Quality Warning", 
                        f"{nan_percentage:.1f}% of data cells are non-numeric.\n"
                        f"This may affect analysis reliability. Consider reviewing your data source."
                    )
                self.root.after(0, warn_quality)
            elif nan_percentage > 20:
                def warn_moderate():
                    messagebox.showwarning(
                        "Data Quality Notice", 
                        f"{nan_percentage:.1f}% of data cells are non-numeric.\n"
                        f"These will be converted to zero for analysis."
                    )
                self.root.after(0, warn_moderate)
        
        # SECURITY: Comprehensive bounds checking and data sanitization
        numeric_matrix = numeric_matrix.fillna(0)
        
        # Check for negative values and convert to absolute values
        negative_count = (numeric_matrix < 0).sum().sum()
        if negative_count > 0:
            # Note: Negative values are converted but not logged to avoid excessive output
            numeric_matrix = numeric_matrix.abs()
        
        # Check for unreasonably large values that could cause overflow or computational issues
        max_val = numeric_matrix.max().max()
        if max_val > 1e10:
            raise ValueError(
                f"Data contains extremely large values (max: {max_val:.2e}) that could cause "
                f"computational overflow. Please review your data source."
            )
        elif max_val > 1e6:
            # Note: Large values are detected but not logged to avoid excessive output
            logger.warning(f"Large values detected (max: {max_val:.2e}) - monitoring for potential issues")
        
        # Check for unreasonably small values that might be floating point errors
        min_val = numeric_matrix[numeric_matrix > 0].min().min() if (numeric_matrix > 0).any().any() else 0
        if 0 < min_val < 1e-10:
            # Note: Very small values are detected but not logged to avoid excessive output
            pass
        
        # Convert to integer for contingency analysis
        try:
            numeric_matrix = numeric_matrix.astype(int)
        except (ValueError, OverflowError) as e:
            raise ValueError(
                f"Failed to convert data to integers: {str(e)}. "
                f"Data may contain values outside integer range."
            )
        
        # Final validation: ensure we have meaningful data for analysis
        total_sum = numeric_matrix.sum().sum()
        if total_sum == 0:
            raise ValueError(
                "All categories data values are zero - no samples available for analysis. "
                "Please check your data source and selection criteria."
            )
        
        # Report conversion results
        # Note: Conversion results are calculated but not displayed to avoid logging
        
        return numeric_matrix

    def normalize_confusion_matrix(self, confusion_matrix):
        """
        Normalize confusion matrix rows to percentages.
        Each row will sum to 100% (or 1.0 in decimal form).
        
        Args:
            confusion_matrix (pd.DataFrame): Original confusion matrix with counts
            
        Returns:
            pd.DataFrame: Normalized confusion matrix with percentages
        """
        if confusion_matrix is None or confusion_matrix.empty:
            return confusion_matrix
        
        try:
            # Validate input matrix
            if not hasattr(confusion_matrix, 'values') or not hasattr(confusion_matrix, 'shape'):
                logger.warning("Invalid confusion matrix format for normalization")
                return confusion_matrix
            
            # Create a copy to avoid modifying original
            normalized_matrix = confusion_matrix.copy()
            
            # Calculate row sums
            row_sums = normalized_matrix.sum(axis=1)
            
            # Check for all-zero rows and handle them
            zero_rows = row_sums == 0
            if zero_rows.any():
                logger.warning(f"Found {zero_rows.sum()} rows with no observations - keeping as 0%")
            
            # Normalize each row (avoid division by zero)
            for idx in normalized_matrix.index:
                if row_sums[idx] > 0:
                    normalized_matrix.loc[idx] = (normalized_matrix.loc[idx] / row_sums[idx]) * 100
                else:
                    # If row sum is 0, keep as 0
                    normalized_matrix.loc[idx] = 0
            
            # Validate output
            if not normalized_matrix.isna().any().any():
                return normalized_matrix
            else:
                logger.warning("Normalization produced NaN values, returning original matrix")
                return confusion_matrix
            
        except Exception as e:
            logger.warning(f"Failed to normalize confusion matrix: {e}")
            return confusion_matrix

    def _cancel_selection(self, tree):
        """Handle cancel button click"""
        self._selected_sheets = None
        tree.winfo_toplevel().destroy()

    def _get_selected_sheets(self, tree, checked_items):
        """Get the selected sheets from the dialog"""
        if hasattr(self, '_selected_sheets'):
            return self._selected_sheets
        return None

    def batch_analyze_selected_sheets_threaded(self):
        """Process selected sheets with improved UI"""
        if not self.excel_file:
            self.show_message_safely("error", "Error", "Please load an Excel file first.")
            return
        
        # Show sheet selection dialog
        selected_sheets = self.show_sheet_selection_dialog()
        
        if not selected_sheets:
            return  # User cancelled or no sheets selected
            
        if self.processing_state:
            return
            
        self.set_processing_state(True)
        self.safe_update_mode_label("Mode: Processing Multi-Sheet Analysis...", 'orange')
        self.update_activity_indicator("Starting multi-sheet analysis...")
        self.update_progress_status('Starting selective batch analysis...', 0)
        
        # Show processing overlay immediately
        self.show_processing_overlay(f"Starting batch analysis of {len(selected_sheets)} sheets...")
        self.root.update()  # Force update to show overlay
        
        def batch_worker():
            try:
                # Clear previous batch results
                with self.data_lock:
                    self.batch_results = {}
                    self.comparison_summary = None
                
                total_sheets = len(selected_sheets)
                processed_count = 0
                skipped_count = 0
                
                self.update_progress_status(f'Processing {total_sheets} selected sheets...', 5)
                self.root.after(0, lambda: self.show_processing_overlay(f"Starting batch analysis of {total_sheets} sheets..."))
                self.root.after(0, lambda: self.update_activity_indicator(f"Processing {total_sheets} sheets..."))
                
                # Process each selected sheet
                for i, sheet_name in enumerate(selected_sheets):
                    if self.cancel_event.is_set():
                        return
                    
                    progress = 10 + (i / total_sheets) * 70  # 10-80% for processing
                    self.update_progress_status(f'Analyzing sheet: {sheet_name} ({i+1}/{total_sheets})', progress)
                    self.root.after(0, lambda name=sheet_name, idx=i+1, total=total_sheets: 
                                  self.show_processing_overlay(f"Analyzing sheet {idx}/{total}: {name}"))
                    
                    try:
                        # Process single sheet
                        sheet_results = self.process_single_sheet_for_batch(sheet_name)
                        
                        if sheet_results and isinstance(sheet_results, dict):
                            with self.data_lock:
                                self.batch_results[sheet_name] = sheet_results
                                processed_count += 1
                        else:
                            skipped_count += 1
                                
                    except Exception as e:
                        skipped_count += 1
                        continue
                
                # Create comparison summary
                self.update_progress_status('Creating comparison summary...', 85)
                self.root.after(0, lambda: self.show_processing_overlay("Creating comparison summary..."))
                self.root.after(0, lambda: self.update_activity_indicator("Creating comparison summary..."))
                self.create_comparison_summary()
                
                # Update UI with comparison results
                self.update_progress_status('Creating enhanced visualizations...', 95)
                self.root.after(0, lambda: self.show_processing_overlay("Creating enhanced visualizations..."))
                self.root.after(0, lambda: self.update_activity_indicator("Creating enhanced visualizations..."))
                
                def update_ui():
                    # Clear any existing tabs in the in-app notebook and keep it empty
                    if hasattr(self, 'notebook') and self.notebook:
                        for tab in self.notebook.tabs():
                            self.notebook.forget(tab)

                    # Update the textual results area
                    try:
                        self.update_batch_results_display()
                    except Exception:
                        try:
                            self.create_basic_results_display()
                        except Exception:
                            pass

                    # Do NOT create in-app notebook visualizations anymore.
                    # Show everything in the separate Visualization Window instead.
                    self.update_progress_status(
                        f'Analysis complete - {processed_count}/{total_sheets} sheets processed successfully',
                        100,
                        True,
                    )

                    # Update window title and mode
                    self.root.title(
                        f"Statistical Analysis Tool - Batch Comparison ({len(self.batch_results)} sheets)"
                    )
                    if len(self.batch_results) > 1:
                        self.update_activity_indicator(f"Multi-sheet analysis complete! {len(self.batch_results)} sheets processed.")
                        self.safe_update_mode_label(
                            f"Mode: Multi-Sheet Comparison ({len(self.batch_results)} sheets)", 'purple'
                        )
                    else:
                        self.safe_update_mode_label("Mode: Single Sheet Analysis", 'blue')
                        # For single sheet, populate results for visualization
                        if len(self.batch_results) == 1:
                            sheet_name = list(self.batch_results.keys())[0]
                            if 'class_metrics' in self.batch_results[sheet_name]:
                                self.results['class_metrics'] = self.batch_results[sheet_name]['class_metrics']
                            if 'confusion_matrix' in self.batch_results[sheet_name]:
                                self.confusion_matrix = self.batch_results[sheet_name]['confusion_matrix']

                    # Update QC Results Panel with new data
                    self.update_qc_results_panel()
                    
                    # Open visualization window only if we have valid data
                    if hasattr(self, 'batch_results') and self.batch_results:
                        self.open_visualization_window()
                    else:
                        self.show_message_safely("error", "No Valid Data", "No sheets contained valid data for analysis.")
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.handle_error(str(e), e, "Selective batch processing")
        
        self.submit_task(batch_worker)

    def batch_process_all_sheets_threaded(self):
        """Process all sheets in the Excel file and create comparison analysis"""
        if not self.excel_file:
            self.show_message_safely("error", "Error", "Please load an Excel file first.")
            return
            
        if self.processing_state:
            return
            
        self.set_processing_state(True)
        self.update_progress_status('Starting batch analysis...', 0)
        
        def batch_worker():
            try:
                # Clear previous batch results
                with self.data_lock:
                    self.batch_results = {}
                    self.comparison_summary = None
                
                # Get all sheet names
                sheet_names = self.excel_file.sheet_names
                total_sheets = len(sheet_names)
                processed_count = 0
                skipped_count = 0
                
                self.update_progress_status(f'Processing {total_sheets} sheets...', 5)
                
                # Process each sheet
                for i, sheet_name in enumerate(sheet_names):
                    if self.cancel_event.is_set():
                        return
                    
                    progress = 10 + (i / total_sheets) * 70  # 10-80% for processing
                    self.update_progress_status(f'Analyzing sheet: {sheet_name}', progress)
                    
                    try:
                        # Process single sheet
                        sheet_results = self.process_single_sheet_for_batch(sheet_name)
                        
                        if sheet_results and isinstance(sheet_results, dict):
                            with self.data_lock:
                                self.batch_results[sheet_name] = sheet_results
                                processed_count += 1
                        else:
                            skipped_count += 1
                                
                    except Exception as e:
                        skipped_count += 1
                        # Continue with other sheets
                        continue
                
                # Create comparison summary
                self.update_progress_status('Creating comparison summary...', 85)
                self.create_comparison_summary()
                
                # Update UI with comparison results
                self.update_progress_status('Updating comparison displays...', 95)
                
                def update_ui():
                    # Update textual results; do not populate in-app notebook tabs
                    try:
                        self.update_batch_results_display()
                    except Exception:
                        pass
                    self.update_progress_status(
                        f'Batch analysis complete - Processed: {processed_count} sheets, Skipped: {skipped_count} sheets',
                        100,
                        True,
                    )
                    
                    # For single sheet, populate results for visualization
                    if len(self.batch_results) == 1:
                        sheet_name = list(self.batch_results.keys())[0]
                        if 'class_metrics' in self.batch_results[sheet_name]:
                            self.results['class_metrics'] = self.batch_results[sheet_name]['class_metrics']
                        if 'confusion_matrix' in self.batch_results[sheet_name]:
                            self.confusion_matrix = self.batch_results[sheet_name]['confusion_matrix']
                    
                    # Update QC Results Panel with new data
                    self.update_qc_results_panel()
                    
                    # Open the external visualization window instead of tabs
                    self.open_visualization_window()
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.handle_error(str(e), e, "Batch processing")
        
        self.submit_task(batch_worker)
    
    def process_single_sheet_for_batch(self, sheet_name, df=None):
        """Process a single sheet and return key metrics for comparison"""
        try:
            # Read the sheet data if not provided
            if df is None:
                # Always use the loaded Excel file (thread-safe)
                # self.file_path.get() cannot be called from worker threads
                if self.excel_file:
                    df = pd.read_excel(self.excel_file, sheet_name=sheet_name)
                else:
                    # If excel_file not loaded, we can't safely access file_path from thread
                    logger.error(f"Cannot process sheet {sheet_name} - excel_file not loaded")
                    return None
            
            # Check if sheet is empty before validation
            if df.empty:
                return None
            
            # Check for minimum data requirements
            if len(df.columns) < 2 or len(df) < 1:
                return None
            
            # Validate and clean data (reuse existing method)
            try:
                df = self.validate_and_clean_data(df)
            except ValueError as e:
                return None
            
            # Extract matrix data
            row_labels = df.iloc[:, 0].astype(str)
            col_labels = df.columns[1:].astype(str)
            matrix_data = df.iloc[:, 1:]
            
            # Convert to numeric (reuse existing method)
            numeric_matrix = self.convert_to_numeric_safe(matrix_data)
            
            # Create confusion matrix
            analysis_matrix = pd.DataFrame(
                numeric_matrix.values,
                index=row_labels,
                columns=col_labels
            )
            
            # Transform SOM to confusion matrix
            unit_assignments = {}
            for unit_id in analysis_matrix.index:
                neuron_counts = analysis_matrix.loc[unit_id]
                if neuron_counts.sum() > 0:
                    winning_type = neuron_counts.idxmax()
                    unit_assignments[unit_id] = winning_type
                else:
                    unit_assignments[unit_id] = None
            
            # Create sample records
            sample_records = []
            for unit_id in analysis_matrix.index:
                neuron_counts = analysis_matrix.loc[unit_id]
                predicted_type = unit_assignments[unit_id]
                
                if predicted_type is not None:
                    for actual_type, count in neuron_counts.items():
                        for _ in range(int(count)):
                            sample_records.append({
                                'neuron': unit_id,
                                'predicted': predicted_type,
                                'actual': actual_type
                            })
            
            # Create traditional confusion matrix
            categories_types = list(analysis_matrix.columns)
            confusion_matrix = pd.DataFrame(
                0, 
                index=categories_types,
                columns=categories_types
            )
            
            for record in sample_records:
                predicted = record['predicted']
                actual = record['actual']
                confusion_matrix.loc[predicted, actual] += 1
            
            # Calculate key metrics
            matrix = confusion_matrix.values
            total_observations = np.sum(matrix)
            
            if total_observations == 0:
                return None  # Skip sheets with no data
            
            # Global fit (accuracy)
            if matrix.shape[0] == matrix.shape[1]:
                diagonal_sum = np.trace(matrix)
                global_fit = (diagonal_sum / total_observations) * 100
            else:
                min_dim = min(matrix.shape)
                diagonal_sum = sum(matrix[i, i] for i in range(min_dim))
                global_fit = (diagonal_sum / total_observations) * 100
            
            # Cramer's V
            try:
                chi2, p_value, dof, expected = chi2_contingency(matrix)
                n = total_observations
                min_dim = min(matrix.shape) - 1
                
                if min_dim > 0 and n > 0:
                    cramers_v = np.sqrt(chi2 / (n * min_dim))
                else:
                    cramers_v = 0
            except:
                cramers_v = 0
                p_value = 1
            
            # Percent Zero Entries (inactive units)
            total_neurons = len(analysis_matrix)
            active_neurons = len([w for w in unit_assignments.values() if w is not None])
            inactive_neurons = total_neurons - active_neurons
            percent_undefined = (inactive_neurons / total_neurons) * 100
            
            # Calculate per-class metrics (precision, recall, f1-score)
            class_metrics = {}
            for class_name in confusion_matrix.index:
                # True Positives: correct predictions for this class
                tp = confusion_matrix.loc[class_name, class_name]
                
                # False Positives: predictions as this class that were wrong
                fp = confusion_matrix.loc[class_name, :].sum() - tp
                
                # False Negatives: actual class items predicted as other classes
                fn = confusion_matrix.loc[:, class_name].sum() - tp
                
                # True Negatives: correct predictions for other classes
                tn = confusion_matrix.values.sum() - tp - fp - fn
                
                # Calculate metrics
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                support = confusion_matrix.loc[:, class_name].sum()
                accuracy = (tp + tn) / confusion_matrix.values.sum() if confusion_matrix.values.sum() > 0 else 0
                
                class_metrics[class_name] = {
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1_score,
                    'support': support,
                    'accuracy': accuracy
                }
            
            # Return summary results
            return {
                'sheet_name': sheet_name,
                'total_observations': total_observations,
                'total_neurons': total_neurons,
                'active_neurons': active_neurons,
                'global_fit': global_fit,
                'cramers_v': cramers_v,
                'percent_undefined': percent_undefined,
                'chi2_p_value': p_value,
                'matrix_shape': confusion_matrix.shape,
                'confusion_matrix': confusion_matrix,
                'analysis_matrix': analysis_matrix,
                'unit_assignments': unit_assignments,
                'class_metrics': class_metrics
            }
            
        except Exception as e:
            return None
    
    def create_comparison_summary(self):
        """Create a summary table comparing all processed sheets"""
        if not self.batch_results:
            return
        
        summary_data = []
        
        for sheet_name, results in self.batch_results.items():
            summary_data.append({
                'SOM_Config': sheet_name,
                'Global_Fit': results['global_fit'],
                'Cramers_V': results['cramers_v'],
                'Percent_Zero_Entries': results['percent_undefined'],
                'Total_Samples': results['total_observations'],
                'Active_Neurons': results['active_neurons'],
                'Total_Neurons': results['total_neurons'],
                'Utilization': (results['active_neurons'] / results['total_neurons']) * 100,
                'P_Value': results['chi2_p_value']
            })
        
        # Create DataFrame and sort by Global Fit (descending)
        self.comparison_summary = pd.DataFrame(summary_data)
        self.comparison_summary = self.comparison_summary.sort_values('Global_Fit', ascending=False)
        
        # Add ranking
        self.comparison_summary['Rank'] = range(1, len(self.comparison_summary) + 1)
        
        # Reorder columns for better display
        column_order = ['Rank', 'SOM_Config', 'Global_Fit', 'Cramers_V', 
                       'Percent_Zero_Entries', 'Total_Samples', 'Active_Neurons', 
                       'Total_Neurons', 'Utilization', 'P_Value']
        self.comparison_summary = self.comparison_summary[column_order]
    
    def update_single_sheet_results_display(self, sheet_name):
        """Update the results display to show single sheet analysis results"""
        try:
            if sheet_name not in self.batch_results:
                return
                
            sheet_results = self.batch_results[sheet_name]
            self.results_text.delete(1.0, tk.END)
            
            # Header
            header = f"""SINGLE SHEET ANALYSIS RESULTS
{'='*60}

SHEET: {sheet_name}
File: {os.path.basename(self.file_path.get())}

ANALYSIS SUMMARY:
Total Observations: {sheet_results['total_observations']:,}
Total Neurons: {sheet_results['total_neurons']}
Active Neurons: {sheet_results['active_neurons']}
Inactive Neurons: {sheet_results['total_neurons'] - sheet_results['active_neurons']}

PERFORMANCE METRICS:
Global Fit (Classification Accuracy): {sheet_results['global_fit']:.2f}%
Association Strength (Cramer's V): {sheet_results['cramers_v']:.4f}
Chi-Square P-Value: {sheet_results['chi2_p_value']:.6f}
Neuron Utilization: {(sheet_results['active_neurons'] / sheet_results['total_neurons'] * 100):.1f}%

PERFORMANCE INTERPRETATION:
"""
            
            # Performance interpretation
            if sheet_results['global_fit'] >= 75:
                accuracy_grade = "EXCELLENT"
                accuracy_desc = "High classification accuracy indicates effective analysis configuration"
            elif sheet_results['global_fit'] >= 60:
                accuracy_grade = "GOOD"
                accuracy_desc = "Good classification accuracy with room for improvement"
            else:
                accuracy_grade = "POOR"
                accuracy_desc = "Low classification accuracy - consider reviewing SOM parameters"
            
            if sheet_results['cramers_v'] >= 0.5:
                association_grade = "STRONG"
                association_desc = "Strong association between predicted and actual categories"
            elif sheet_results['cramers_v'] >= 0.3:
                association_grade = "MODERATE"
                association_desc = "Moderate association strength"
            else:
                association_grade = "WEAK"
                association_desc = "Weak association - SOM may not be effectively separating categories"
            
            interpretation = f"""Classification Accuracy: {accuracy_grade}
• {accuracy_desc}
• Score: {sheet_results['global_fit']:.2f}%

Association Strength: {association_grade}
• {association_desc}
• Cramer's V: {sheet_results['cramers_v']:.4f}

Neuron Utilization: {(sheet_results['active_neurons'] / sheet_results['total_neurons'] * 100):.1f}%
• {sheet_results['active_neurons']} out of {sheet_results['total_neurons']} neurons are active
• Higher utilization indicates more efficient analysis configuration

Statistical Significance:
• Chi-Square P-Value: {sheet_results['chi2_p_value']:.6f}
• {'Statistically significant' if sheet_results['chi2_p_value'] < 0.05 else 'Not statistically significant'} at α=0.05
"""
            
            full_text = header + interpretation
            self.results_text.insert(1.0, full_text)
            
            # Update window title
            self.root.title(f"Statistical Analysis Tool - {sheet_name} Analysis")
            
        except Exception as e:
            logger.warning(f"Failed to update single sheet results display: {e}")
            # Show error in results text
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, f"Error displaying results: {str(e)}")
    
    def update_batch_results_display(self):
        """Update the results display to show batch comparison"""
        if not self.comparison_summary is None:
            self.results_text.delete(1.0, tk.END)
            
            # Header
            header = f"""SOM CONFIGURATION COMPARISON
{'='*60}

BATCH ANALYSIS SUMMARY:
Total Configurations Analyzed: {len(self.batch_results)}
File: {os.path.basename(self.file_path.get())}

PERFORMANCE RANKING:
(Ranked by Global Fit - Classification Accuracy)

"""
            
            # Create formatted table
            table_header = f"{'Rank':<4} {'SOM Config':<15} {'Global Fit':<12} {'Cramer V':<10} {'PZE%':<8} {'Samples':<10} {'Neurons':<8}\n"
            table_header += f"{'-'*75}\n"
            
            table_content = ""
            for _, row in self.comparison_summary.iterrows():
                table_content += f"{int(row['Rank']):<4} "
                table_content += f"{row['SOM_Config']:<15} "
                table_content += f"{row['Global_Fit']:<12.2f} "
                table_content += f"{row['Cramers_V']:<10.4f} "
                table_content += f"{row['Percent_Zero_Entries']:<8.1f} "
                table_content += f"{int(row['Total_Samples']):<10} "
                table_content += f"{int(row['Active_Neurons']):<8}\n"
            
            # Recommendations
            best_config = self.comparison_summary.iloc[0]
            recommendations = f"""

RECOMMENDATIONS:

Best Overall Configuration: {best_config['SOM_Config']}
• Highest Classification Accuracy: {best_config['Global_Fit']:.2f}%
• Association Strength (Cramer's V): {best_config['Cramers_V']:.4f}
• Neuron Utilization: {best_config['Utilization']:.1f}%

PERFORMANCE INTERPRETATION:
• Global Fit >75%: Excellent classification
• Global Fit 60-75%: Good classification  
• Global Fit <60%: Poor classification

• Cramer's V >0.5: Strong association
• Cramer's V 0.3-0.5: Moderate association
• Cramer's V <0.3: Weak association

• Lower PZE% indicates better unit utilization
"""
            
            full_text = header + table_header + table_content + recommendations
            self.results_text.insert(1.0, full_text)
            
            # Update window title
            self.root.title(f"Statistical Analysis Tool - Batch Comparison ({len(self.batch_results)} configs)")
    
    def update_confusion_matrix_display(self):
        """Update the confusion matrix display in the tree view"""
        try:
            # Clear existing tree items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Get the current confusion matrix
            current_matrix = None
            if hasattr(self, 'batch_results') and self.batch_results:
                # Get matrix from first available result
                for sheet_name, result in self.batch_results.items():
                    if 'confusion_matrix' in result:
                        current_matrix = result['confusion_matrix']
                        break
            elif hasattr(self, 'confusion_matrix') and self.confusion_matrix is not None:
                current_matrix = self.confusion_matrix
            
            if current_matrix is None:
                return
            
            # Apply normalization if checkbox is checked
            display_matrix = current_matrix
            matrix_title = "Confusion Matrix (Counts)"
            
            if hasattr(self, 'normalize_confusion_matrices') and self.normalize_confusion_matrices.get():
                try:
                    display_matrix = self.normalize_confusion_matrix(current_matrix)
                    matrix_title = "Normalized Confusion Matrix (Row Percentages)"
                except Exception as norm_error:
                    logger.warning(f"Failed to normalize matrix for tree display: {norm_error}")
                    display_matrix = current_matrix
                    matrix_title = "Confusion Matrix (Normalization Failed)"
            
            # Update the tree display
            self.populate_tree_with_matrix(display_matrix, matrix_title)
            
        except Exception as e:
            logger.warning(f"Failed to update confusion matrix display: {e}")
            # Show error in tree view
            try:
                self.tree.heading('#0', text="Error: Failed to update display")
                for item in self.tree.get_children():
                    self.tree.delete(item)
                self.tree.insert('', 'end', text="Error occurred", values=("Failed to update confusion matrix display",))
            except:
                pass
    
    def populate_tree_with_matrix(self, matrix, title):
        """Populate the tree view with matrix data"""
        try:
            # Validate matrix
            if matrix is None or matrix.empty:
                logger.warning("Cannot populate tree with empty matrix")
                return
            
            # Configure tree columns
            columns = [''] + list(matrix.columns)
            self.tree['columns'] = columns[1:]  # Exclude the first empty column for row labels
            self.tree['show'] = 'tree headings'
            
            # Set up column headings
            self.tree.heading('#0', text=title)
            for col in matrix.columns:
                self.tree.heading(col, text=str(col))
                self.tree.column(col, width=120, anchor='center')  # Increased width to show all content
            
            # Add matrix data rows
            for idx in matrix.index:
                row_values = []
                for col in matrix.columns:
                    try:
                        value = matrix.loc[idx, col]
                        if hasattr(self, 'normalize_confusion_matrices') and self.normalize_confusion_matrices.get():
                            # Show as percentage with 1 decimal place
                            if pd.isna(value) or not np.isfinite(value):
                                row_values.append("N/A")
                            else:
                                row_values.append(f"{value:.1f}%")
                        else:
                            # Show as integer count
                            if pd.isna(value) or not np.isfinite(value):
                                row_values.append("N/A")
                            else:
                                row_values.append(f"{int(value)}")
                    except Exception as val_error:
                        logger.warning(f"Error formatting value at [{idx}, {col}]: {val_error}")
                        row_values.append("Error")
                
                self.tree.insert('', 'end', text=str(idx), values=tuple(row_values))
                
        except Exception as e:
            logger.warning(f"Failed to populate tree with matrix: {e}")
            # Show error in tree
            try:
                self.tree.heading('#0', text="Error: Failed to populate matrix")
                for item in self.tree.get_children():
                    self.tree.delete(item)
                self.tree.insert('', 'end', text="Error occurred", values=("Failed to populate matrix data",))
            except:
                pass
    
    # =============== QC ORCHESTRATION METHODS ===============
    
    def get_chi_square_qc_summary(self, sheet_data):
        """
        Generate comprehensive Chi-square test QC summary with statistical validation
        and quality assessment.
        
        Args:
            sheet_data (dict): Dictionary containing sheet analysis results
            
        Returns:
            dict: Comprehensive QC summary with statistical metrics and quality indicators
        """
        # Input validation
        if not sheet_data or not isinstance(sheet_data, dict):
            return self._get_default_qc_result("Invalid sheet data format")
        
        if 'confusion_matrix' not in sheet_data:
            return self._get_default_qc_result("Missing confusion matrix data")
        
        try:
            matrix = sheet_data['confusion_matrix']
            
            # Validate matrix structure
            if not hasattr(matrix, 'values') or not hasattr(matrix, 'shape'):
                return self._get_default_qc_result("Invalid confusion matrix format")
            
            matrix_values = matrix.values
            matrix_shape = matrix.shape
            
            # Check matrix dimensions
            if len(matrix_shape) != 2:
                return self._get_default_qc_result(f"Invalid matrix dimensions: {matrix_shape}")
            
            if matrix_shape[0] < 2 or matrix_shape[1] < 2:
                return self._get_default_qc_result(f"Matrix too small for chi-square test: {matrix_shape}")
            
            total_observations = np.sum(matrix_values)
            
            if total_observations == 0:
                return self._get_default_qc_result("No observations in confusion matrix")
            
            # Check for minimum sample size requirements
            if total_observations < 20:
                return self._get_default_qc_result(
                    f"Insufficient sample size for reliable chi-square test: {total_observations} observations"
                )
            
            # Calculate chi-square test with error handling
            try:
                chi2, p_value, dof, expected = chi2_contingency(matrix_values)
            except Exception as chi_error:
                return self._get_default_qc_result(f"Chi-square calculation failed: {str(chi_error)}")
            
            # Validate chi-square results
            if not np.isfinite(chi2) or not np.isfinite(p_value):
                return self._get_default_qc_result("Chi-square test produced invalid results")
            
            # Calculate Cramer's V (effect size) with validation
            min_dim = min(matrix_shape) - 1
            if min_dim > 0 and total_observations > 0 and chi2 > 0:
                cramers_v = np.sqrt(chi2 / (total_observations * min_dim))
                # Clamp Cramer's V to valid range [0, 1]
                cramers_v = max(0.0, min(1.0, cramers_v))
            else:
                cramers_v = 0.0
            
            # Comprehensive expected frequency validation
            expected_freq_ok = True
            expected_freq_warnings = []
            
            if expected is not None:
                # Check for cells with expected frequency < 5 (chi-square assumption violation)
                low_freq_cells = expected < 5
                low_freq_count = np.sum(low_freq_cells)
                
                if low_freq_count > 0:
                    low_freq_percentage = (low_freq_count / expected.size) * 100
                    expected_freq_ok = low_freq_percentage < 20  # Allow up to 20% low frequency cells
                    
                    if low_freq_percentage > 50:
                        expected_freq_warnings.append(f"Severe: {low_freq_percentage:.1f}% of cells have expected frequency < 5")
                    elif low_freq_percentage > 20:
                        expected_freq_warnings.append(f"Moderate: {low_freq_percentage:.1f}% of cells have expected frequency < 5")
            
            # Calculate accuracy score with validation
            diagonal_sum = np.trace(matrix_values)
            accuracy_score = (diagonal_sum / total_observations) if total_observations > 0 else 0.0
            
            # Validate accuracy score
            if not np.isfinite(accuracy_score) or accuracy_score < 0 or accuracy_score > 1:
                accuracy_score = 0.0
            
            # Determine QC grade based on multiple criteria
            qc_grade = self._calculate_qc_grade(p_value, cramers_v, accuracy_score, expected_freq_ok)
            
            # Enhanced QC status with confidence levels
            if p_value < 0.001:
                qc_status = "Highly significant association (p < 0.001)"
                confidence_level = "99.9%"
            elif p_value < 0.01:
                qc_status = "Very significant association (p < 0.01)"
                confidence_level = "99%"
            elif p_value < 0.05:
                qc_status = "Significant association (p < 0.05)"
                confidence_level = "95%"
            else:
                qc_status = "No significant association (p >= 0.05)"
                confidence_level = "Not applicable"
            
            # Calculate additional quality metrics
            matrix_density = np.count_nonzero(matrix_values) / matrix_values.size
            row_balance = np.std(np.sum(matrix_values, axis=1)) / np.mean(np.sum(matrix_values, axis=1)) if np.mean(np.sum(matrix_values, axis=1)) > 0 else 0
            col_balance = np.std(np.sum(matrix_values, axis=0)) / np.mean(np.sum(matrix_values, axis=0)) if np.mean(np.sum(matrix_values, axis=0)) > 0 else 0
            
            # Determine overall quality assessment
            quality_assessment = self._assess_overall_quality(
                p_value, cramers_v, accuracy_score, expected_freq_ok, 
                matrix_density, row_balance, col_balance
            )
            
            return {
                'test_valid': True,
                'chi2_statistic': float(chi2),
                'p_value': float(p_value),
                'effect_size': float(cramers_v),
                'expected_freq_ok': expected_freq_ok,
                'expected_freq_warnings': expected_freq_warnings,
                'qc_status': qc_status,
                'confidence_level': confidence_level,
                'qc_grade': qc_grade,
                'accuracy_score': float(accuracy_score),
                'total_observations': int(total_observations),
                'matrix_dimensions': matrix_shape,
                'matrix_density': float(matrix_density),
                'row_balance': float(row_balance),
                'col_balance': float(col_balance),
                'quality_assessment': quality_assessment,
                'degrees_of_freedom': int(dof),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error in QC analysis: {str(e)}"
            logger.error(f"QC analysis error: {error_msg}")
            return self._get_default_qc_result(error_msg)
    
    def _get_default_qc_result(self, error_message):
        """Generate default QC result for error cases"""
        return {
            'test_valid': False,
            'chi2_statistic': 0.0,
            'p_value': 1.0,
            'effect_size': 0.0,
            'expected_freq_ok': False,
            'expected_freq_warnings': [error_message],
            'qc_status': 'Analysis failed',
            'confidence_level': 'Not applicable',
            'qc_grade': 'F',
            'accuracy_score': 0.0,
            'total_observations': 0,
            'matrix_dimensions': (0, 0),
            'matrix_density': 0.0,
            'row_balance': 0.0,
            'col_balance': 0.0,
            'quality_assessment': 'Unable to assess',
            'degrees_of_freedom': 0,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _assess_overall_quality(self, p_value, cramers_v, accuracy_score, expected_freq_ok, 
                               matrix_density, row_balance, col_balance):
        """Assess overall data quality based on multiple metrics"""
        quality_score = 0
        max_score = 100
        
        # Statistical significance (25 points)
        if p_value < 0.001:
            quality_score += 25
        elif p_value < 0.01:
            quality_score += 20
        elif p_value < 0.05:
            quality_score += 15
        elif p_value < 0.1:
            quality_score += 10
        
        # Effect size (25 points)
        if cramers_v >= 0.7:
            quality_score += 25
        elif cramers_v >= 0.5:
            quality_score += 20
        elif cramers_v >= 0.3:
            quality_score += 15
        elif cramers_v >= 0.1:
            quality_score += 10
        
        # Accuracy (20 points)
        if accuracy_score >= 0.9:
            quality_score += 20
        elif accuracy_score >= 0.8:
            quality_score += 18
        elif accuracy_score >= 0.7:
            quality_score += 15
        elif accuracy_score >= 0.6:
            quality_score += 12
        elif accuracy_score >= 0.5:
            quality_score += 8
        
        # Expected frequency validity (15 points)
        if expected_freq_ok:
            quality_score += 15
        
        # Matrix quality (15 points)
        if matrix_density >= 0.8:
            quality_score += 15
        elif matrix_density >= 0.6:
            quality_score += 12
        elif matrix_density >= 0.4:
            quality_score += 8
        
        # Balance assessment (bonus/penalty)
        balance_penalty = min(10, (row_balance + col_balance) * 5)
        quality_score = max(0, quality_score - balance_penalty)
        
        # Convert to quality level
        if quality_score >= 85:
            return "Excellent"
        elif quality_score >= 70:
            return "Good"
        elif quality_score >= 55:
            return "Fair"
        elif quality_score >= 40:
            return "Poor"
        else:
            return "Very Poor"
    
    def get_comparison_readiness_status(self, sheet_results_dict):
        """Sheet comparison readiness analysis"""
        if not sheet_results_dict:
            return {
                'total_sheets': 0,
                'comparable_sheets': 0,
                'readiness_score': 0.0,
                'comparison_groups': {'high_quality': [], 'medium_quality': [], 'low_quality': []},
                'readiness_warnings': ['No sheets available']
            }
        
        try:
            total_sheets = len(sheet_results_dict)
            comparable_sheets = 0
            comparison_groups = {'high_quality': [], 'medium_quality': [], 'low_quality': []}
            readiness_warnings = []
            
            for sheet_name, sheet_data in sheet_results_dict.items():
                if not sheet_data:
                    continue
                    
                global_fit = sheet_data.get('global_fit', 0)
                cramers_v = sheet_data.get('cramers_v', 0)
                total_observations = sheet_data.get('total_observations', 0)
                percent_undefined = sheet_data.get('percent_undefined', 100)
                
                quality_score = (
                    (global_fit / 100) * 0.4 +
                    cramers_v * 0.3 +
                    min(total_observations / 1000, 1.0) * 0.2 +
                    (100 - percent_undefined) / 100 * 0.1
                ) * 100
                
                if quality_score >= 75:
                    comparison_groups['high_quality'].append(sheet_name)
                    comparable_sheets += 1
                elif quality_score >= 50:
                    comparison_groups['medium_quality'].append(sheet_name)
                    comparable_sheets += 1
                else:
                    comparison_groups['low_quality'].append(sheet_name)
                
                if total_observations < 100:
                    readiness_warnings.append(f'{sheet_name}: Small sample size')
                if percent_undefined > 50:
                    readiness_warnings.append(f'{sheet_name}: High undefined neurons')
                if global_fit < 50:
                    readiness_warnings.append(f'{sheet_name}: Low accuracy')
            
            readiness_score = (comparable_sheets / total_sheets * 100) if total_sheets > 0 else 0
            
            return {
                'total_sheets': total_sheets,
                'comparable_sheets': comparable_sheets,
                'readiness_score': readiness_score,
                'comparison_groups': comparison_groups,
                'readiness_warnings': readiness_warnings
            }
            
        except Exception as e:
            return {
                'total_sheets': len(sheet_results_dict) if sheet_results_dict else 0,
                'comparable_sheets': 0,
                'readiness_score': 0.0,
                'comparison_groups': {'high_quality': [], 'medium_quality': [], 'low_quality': []},
                'readiness_warnings': [f'Analysis error: {str(e)[:50]}']
            }
    
    # =============== QC PANEL METHODS ===============
    
    def update_qc_results_panel(self):
        """Update the QC Results Panel with current batch analysis data"""
        try:
            # Update batch summary
            self.update_batch_summary()
            
            # Update per-sheet QC details table
            self.update_qc_details_table()
            
            # Update comparison readiness status
            self.update_comparison_readiness()
            
            # ADD THIS AT THE VERY END:
            self.root.after(100, self.force_update_scroll_regions)
            self.root.after(500, self.force_update_scroll_regions)
            self.root.after(750, self.auto_resize_to_content)  # Auto-resize after content updates
        except Exception as e:
            logger.warning(f"Failed to update QC panel: {e}")
    
    def update_batch_summary(self):
        """Update the batch analysis summary section"""
        try:
            self.batch_summary_text.config(state=tk.NORMAL)
            self.batch_summary_text.delete('1.0', tk.END)
            
            if not hasattr(self, 'batch_results') or not self.batch_results:
                self.batch_summary_text.insert('1.0', 'No batch analysis data available. Run Multi-Sheet Analysis to see results.')
            else:
                # Generate summary using existing comparison logic
                readiness_status = self.get_comparison_readiness_status(self.batch_results)
                
                summary_text = f"""BATCH ANALYSIS SUMMARY
{'='*50}
File: {os.path.basename(self.file_path.get()) if hasattr(self, 'file_path') and self.file_path.get() else 'No file loaded'}
Total Sheets Processed: {readiness_status['total_sheets']}
Sheets Ready for Comparison: {readiness_status['comparable_sheets']}
Overall Readiness Score: {readiness_status['readiness_score']:.1f}%

QUALITY DISTRIBUTION:
• High Quality Sheets: {len(readiness_status['comparison_groups']['high_quality'])}
• Medium Quality Sheets: {len(readiness_status['comparison_groups']['medium_quality'])}
• Low Quality Sheets: {len(readiness_status['comparison_groups']['low_quality'])}"""
                
                self.batch_summary_text.insert('1.0', summary_text)
            
            self.batch_summary_text.config(state=tk.DISABLED)
        
        except Exception as e:
            self.batch_summary_text.config(state=tk.NORMAL)
            self.batch_summary_text.delete('1.0', tk.END)
            self.batch_summary_text.insert('1.0', f'Error updating batch summary: {str(e)}')
            self.batch_summary_text.config(state=tk.DISABLED)
    
    def update_qc_details_table(self):
        """Update the per-sheet QC details table"""
        try:
            # Clear existing items
            for item in self.qc_tree.get_children():
                self.qc_tree.delete(item)
            
            if not hasattr(self, 'batch_results') or not self.batch_results:
                # Add placeholder row
                self.qc_tree.insert('', 'end', values=('No data', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'Run analysis first'))
                return
            
            # Process each sheet using orchestration methods
            for sheet_name, sheet_data in self.batch_results.items():
                if not sheet_data:
                    continue
                
                try:
                    # Get QC metrics using orchestration methods
                    chi_square_qc = self.get_chi_square_qc_summary(sheet_data)
                    
                    # Extract key metrics
                    status = 'Valid' if chi_square_qc['test_valid'] else 'Warning'
                    qc_grade = self.calculate_qc_grade(sheet_data, chi_square_qc)
                    rows = sheet_data.get('total_observations', 0)
                    completeness = f"{((sheet_data.get('total_observations', 0) / max(sheet_data.get('total_neurons', 1), 1)) * 100):.1f}%"
                    accuracy = f"{sheet_data.get('global_fit', 0):.1f}%"
                    effect_size = f"{sheet_data.get('cramers_v', 0):.3f}"
                    
                    # Generate warnings
                    warnings = []
                    if not chi_square_qc['test_valid']:
                        warnings.append('Low expected freq')
                    if sheet_data.get('global_fit', 0) < 50:
                        warnings.append('Low accuracy')
                    if sheet_data.get('total_observations', 0) < 100:
                        warnings.append('Small sample')
                    
                    warnings_text = ', '.join(warnings[:2]) if warnings else 'None'
                    
                    # Add row with color coding
                    item = self.qc_tree.insert('', 'end', values=(
                        sheet_name,
                        status,
                        qc_grade,
                        f"{rows:,}",
                        completeness,
                        accuracy,
                        effect_size,
                        warnings_text
                    ))
                    
                    # Color code by QC grade
                    if qc_grade in ['A', 'B']:
                        self.qc_tree.set(item, 'QC Grade', qc_grade)
                    elif qc_grade == 'C':
                        pass  # Default color
                    else:
                        pass  # Could add red highlighting for D/F grades
                
                except Exception as e:
                    # Add error row for this sheet
                    self.qc_tree.insert('', 'end', values=(
                        sheet_name, 'Error', 'F', 'N/A', 'N/A', 'N/A', 'N/A', f'Analysis failed: {str(e)[:30]}'
                    ))
        
        except Exception as e:
            logger.warning(f"Failed to update QC details table: {e}")
    
    def calculate_qc_grade(self, sheet_data, chi_square_qc):
        """Calculate overall QC grade for a sheet"""
        try:
            # Weight different factors
            accuracy_score = min(sheet_data.get('global_fit', 0) / 100, 1.0)  # 0-1 scale
            effect_size_score = min(sheet_data.get('cramers_v', 0), 1.0)      # 0-1 scale
            sample_size_score = min(sheet_data.get('total_observations', 0) / 1000, 1.0)  # 0-1 scale
            validity_score = 1.0 if chi_square_qc.get('test_valid', False) else 0.5  # Valid test or not
            
            # Weighted overall score
            overall_score = (
                accuracy_score * 0.4 +     # Classification accuracy (40%)
                effect_size_score * 0.3 +  # Effect size strength (30%)
                sample_size_score * 0.2 +  # Sample adequacy (20%)
                validity_score * 0.1       # Test validity (10%)
            ) * 100
            
            # Grade assignment
            if overall_score >= 85:
                return 'A'
            elif overall_score >= 75:
                return 'B'
            elif overall_score >= 65:
                return 'C'
            elif overall_score >= 50:
                return 'D'
            else:
                return 'F'
                
        except Exception:
            return 'F'
    
    def update_comparison_readiness(self):
        """Update the comparison readiness status and buttons"""
        try:
            if not hasattr(self, 'batch_results') or not self.batch_results:
                # No data state
                self.readiness_label.config(text="No data analyzed", foreground='gray')
                self.high_quality_label.config(text="High Quality: 0")
                self.medium_quality_label.config(text="Medium Quality: 0")
                self.low_quality_label.config(text="Low Quality: 0")
                
                # Disable action buttons
                self.compare_high_btn.config(state=tk.DISABLED)
                self.compare_all_btn.config(state=tk.DISABLED)
                self.export_qc_btn.config(state=tk.DISABLED)
                return
            
            # Get readiness status using orchestration method
            readiness_status = self.get_comparison_readiness_status(self.batch_results)
            
            # Update readiness label
            readiness_score = readiness_status['readiness_score']
            if readiness_score >= 80:
                self.readiness_label.config(text=f"Excellent ({readiness_score:.0f}%)", foreground='green')
            elif readiness_score >= 60:
                self.readiness_label.config(text=f"Good ({readiness_score:.0f}%)", foreground='orange')
            else:
                self.readiness_label.config(text=f"Needs Improvement ({readiness_score:.0f}%)", foreground='red')
            
            # Update quality group counts
            high_count = len(readiness_status['comparison_groups']['high_quality'])
            medium_count = len(readiness_status['comparison_groups']['medium_quality'])
            low_count = len(readiness_status['comparison_groups']['low_quality'])
            
            self.high_quality_label.config(text=f"High Quality: {high_count}")
            self.medium_quality_label.config(text=f"Medium Quality: {medium_count}")
            self.low_quality_label.config(text=f"Low Quality: {low_count}")
            
            # Enable/disable action buttons based on data availability
            has_high_quality = high_count > 1
            has_any_data = (high_count + medium_count) > 1
            
            self.compare_high_btn.config(state=tk.NORMAL if has_high_quality else tk.DISABLED)
            self.compare_all_btn.config(state=tk.NORMAL if has_any_data else tk.DISABLED)
            self.export_qc_btn.config(state=tk.NORMAL)
            
        except Exception as e:
            self.readiness_label.config(text="Error analyzing readiness", foreground='red')
            logger.warning(f"Failed to update comparison readiness: {e}")
    
    def launch_high_quality_comparison(self):
        """Launch comparison analysis for high quality sheets only"""
        try:
            readiness_status = self.get_comparison_readiness_status(self.batch_results)
            high_quality_sheets = readiness_status['comparison_groups']['high_quality']
            
            if len(high_quality_sheets) < 2:
                messagebox.showwarning("Insufficient Data", "Need at least 2 high quality sheets for comparison.")
                return
            
            # Create filtered batch results for high quality sheets only
            filtered_results = {sheet: self.batch_results[sheet] for sheet in high_quality_sheets if sheet in self.batch_results}
            
            # Perform comparison analysis on high-quality sheets only
            comparison_results = self.perform_comprehensive_comparison(filtered_results)
            
            # Store original results and temporarily replace with filtered ones
            original_results = self.batch_results.copy()
            self.batch_results = filtered_results
            
            # Update UI to show filtered results
            self.update_batch_results_display()
            self.update_qc_results_panel()
            
            # Generate comparison summary for high-quality sheets
            self.display_comparison_summary(comparison_results, "High-Quality Sheets")
            
            # Open visualization window with filtered results
            self.open_visualization_window()
            
            # Show detailed comparison results
            self.show_comparison_details(comparison_results, "High-Quality Analysis")
            
            # Restore original results after a delay to allow visualization to load
            self.root.after(5000, lambda: setattr(self, 'batch_results', original_results))
            
            messagebox.showinfo("High-Quality Analysis Window Opened", 
                              f"ANALYSIS WINDOW LAUNCHED!\n\n" +
                              f"Filtered to show only {len(high_quality_sheets)} high-quality sheets\n" +
                              f"Multiple analysis tabs now available:\n" +
                              f"   - Performance comparisons\n" +
                              f"   - Side-by-side visualizations\n" +
                              f"   - Radar charts\n" +
                              f"   - Statistical rankings\n\n" +
                              f"High-Quality Sheets: {', '.join(high_quality_sheets[:3])}\n" +
                              (f"   ... and {len(high_quality_sheets)-3} more" if len(high_quality_sheets) > 3 else "") +
                              "\n\nCheck the analysis window for detailed comparisons!")
        
        except Exception as e:
            messagebox.showerror("Comparison Error", f"Failed to launch high quality comparison: {str(e)}")
    
    def launch_all_comparison(self):
        """Launch comprehensive comparison analysis for all available sheets"""
        try:
            readiness_status = self.get_comparison_readiness_status(self.batch_results)
            total_comparable = readiness_status['comparable_sheets']
            
            if total_comparable < 2:
                messagebox.showwarning("Insufficient Data", "Need at least 2 sheets ready for comparison.")
                return
            
            # Perform actual comparison analysis
            comparison_results = self.perform_comprehensive_comparison(self.batch_results)
            
            # Generate comparison summary in the main window
            self.display_comparison_summary(comparison_results, "All Sheets")
            
            # Open visualization window with all results
            self.open_visualization_window()
            
            # Show detailed comparison results
            self.show_comparison_details(comparison_results, "All Sheets Analysis")
            
            messagebox.showinfo("Full Comparison Analysis Complete", 
                              f"COMPREHENSIVE ANALYSIS COMPLETED!\n\n" +
                              f"Analyzed {total_comparable} sheets\n" +
                              f"Generated comparison rankings\n" +
                              f"Performance metrics calculated\n" +
                              f"Best configuration identified\n\n" +
                              f"Check the analysis window for detailed charts and rankings!")
        
        except Exception as e:
            messagebox.showerror("Comparison Error", f"Failed to launch full comparison: {str(e)}")
    
    def export_qc_report(self):
        """Export comprehensive QC report to file"""
        try:
            if not hasattr(self, 'batch_results') or not self.batch_results:
                messagebox.showwarning("No Data", "No QC data available to export.")
                return
            
            from tkinter import filedialog
            
            # Get save location
            filename = filedialog.asksaveasfilename(
                title="Export QC Report",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
                initialdir=os.path.expanduser("~/Desktop")
            )
            
            if not filename:
                return
            
            # Generate comprehensive QC report
            readiness_status = self.get_comparison_readiness_status(self.batch_results)
            
            report_content = f"""STATISTICAL QC ANALYSIS REPORT
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
File: {os.path.basename(self.file_path.get()) if hasattr(self, 'file_path') and self.file_path.get() else 'Unknown'}

EXECUTIVE SUMMARY:
Total Sheets Analyzed: {readiness_status['total_sheets']}
Sheets Ready for Comparison: {readiness_status['comparable_sheets']}
Overall Readiness Score: {readiness_status['readiness_score']:.1f}%

QUALITY DISTRIBUTION:
High Quality (Grade A/B): {len(readiness_status['comparison_groups']['high_quality'])}
Medium Quality (Grade C): {len(readiness_status['comparison_groups']['medium_quality'])}
Low Quality (Grade D/F): {len(readiness_status['comparison_groups']['low_quality'])}

DETAILED SHEET ANALYSIS:
{'='*60}
"""
            
            # Add detailed sheet information
            for sheet_name, sheet_data in self.batch_results.items():
                chi_square_qc = self.get_chi_square_qc_summary(sheet_data)
                qc_grade = self.calculate_qc_grade(sheet_data, chi_square_qc)
                
                report_content += f"""
Sheet: {sheet_name}
QC Grade: {qc_grade}
Observations: {sheet_data.get('total_observations', 0):,}
Classification Accuracy: {sheet_data.get('global_fit', 0):.2f}%
Effect Size (Cramer's V): {sheet_data.get('cramers_v', 0):.4f}
Chi-square Valid: {'Yes' if chi_square_qc.get('test_valid') else 'No'}
Statistical Significance: {chi_square_qc.get('qc_status', 'Unknown')}
Matrix Dimensions: {sheet_data.get('matrix_shape', 'Unknown')}
{'-'*40}"""
            
            # Add warnings section
            if readiness_status['readiness_warnings']:
                report_content += f"""

QUALITY WARNINGS:
{'='*30}
"""
                for warning in readiness_status['readiness_warnings']:
                    report_content += f"• {warning}\n"
            
            # Write to file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            messagebox.showinfo("Export Complete", f"QC report exported to: {filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export QC report: {str(e)}")
    
    def refresh_qc_analysis(self):
        """Refresh the QC analysis panel"""
        self.update_qc_results_panel()
        messagebox.showinfo("Refresh Complete", "QC analysis refreshed!")

    def force_update_scroll_regions(self):
        """Force update all scroll regions - call this after UI updates"""
        try:
            # Update main canvas
            if hasattr(self, 'root'):
                self.root.update_idletasks()
                
            # Find and update all canvas widgets
            def update_canvas_recursive(widget):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Canvas):
                        try:
                            bbox = child.bbox("all")
                            if bbox and len(bbox) == 4:  # Ensure bbox is valid
                                # Add generous padding
                                width = bbox[2] - bbox[0] + 400
                                height = bbox[3] - bbox[1] + 200
                                child.configure(scrollregion=(0, 0, width, height))
                        except:
                            pass
                    try:
                        update_canvas_recursive(child)
                    except:
                        pass
            
            update_canvas_recursive(self.root)
        except Exception as e:
            logger.warning(f"Failed to update scroll regions: {e}")

    def perform_comprehensive_comparison(self, batch_results):
        """Perform comprehensive statistical comparison analysis"""
        try:
            if not batch_results or len(batch_results) < 2:
                return None
            
            comparison_results = {
                'total_sheets': len(batch_results),
                'rankings': [],
                'best_configuration': None,
                'statistical_summary': {},
                'performance_metrics': {}
            }
            
            # Calculate performance metrics for each sheet
            sheet_metrics = []
            for sheet_name, result in batch_results.items():
                if result.get('status') == 'success':
                    stats = result.get('statistics', {})
                    qc_summary = self.get_chi_square_qc_summary(result)
                    
                    metrics = {
                        'sheet_name': sheet_name,
                        'global_fit': stats.get('global_fit', 0),
                        'cramers_v': stats.get('cramers_v', 0),
                        'accuracy': qc_summary.get('accuracy_score', 0),
                        'qc_grade': qc_summary.get('qc_grade', 'F'),
                        'p_value': stats.get('p_value', 1),
                        'sample_size': stats.get('sample_size', 0),
                        'total_score': 0  # Will calculate below
                    }
                    
                    # Calculate composite score (higher is better)
                    metrics['total_score'] = (
                        metrics['global_fit'] * 0.3 +  # 30% weight
                        metrics['cramers_v'] * 100 * 0.25 +  # 25% weight (scaled up)
                        metrics['accuracy'] * 0.25 +  # 25% weight
                        (1 - metrics['p_value']) * 20 * 0.2  # 20% weight (lower p-value is better)
                    )
                    
                    sheet_metrics.append(metrics)
            
            # Sort by total score (descending)
            sheet_metrics.sort(key=lambda x: x['total_score'], reverse=True)
            
            # Generate rankings
            for i, metrics in enumerate(sheet_metrics):
                ranking = {
                    'rank': i + 1,
                    'sheet_name': metrics['sheet_name'],
                    'total_score': round(metrics['total_score'], 2),
                    'global_fit': round(metrics['global_fit'], 2),
                    'cramers_v': round(metrics['cramers_v'], 3),
                    'accuracy': round(metrics['accuracy'], 3),
                    'qc_grade': metrics['qc_grade']
                }
                comparison_results['rankings'].append(ranking)
            
            # Set best configuration
            if sheet_metrics:
                comparison_results['best_configuration'] = {
                    'sheet_name': sheet_metrics[0]['sheet_name'],
                    'total_score': round(sheet_metrics[0]['total_score'], 2),
                    'reason': f"Highest composite score based on global fit, accuracy, and statistical significance"
                }
            
            # Calculate statistical summary
            if sheet_metrics:
                comparison_results['statistical_summary'] = {
                    'average_score': round(sum(m['total_score'] for m in sheet_metrics) / len(sheet_metrics), 2),
                    'score_range': round(max(m['total_score'] for m in sheet_metrics) - min(m['total_score'] for m in sheet_metrics), 2),
                    'high_quality_count': len([m for m in sheet_metrics if m['qc_grade'] in ['A', 'B']]),
                    'total_analyzed': len(sheet_metrics)
                }
            
            return comparison_results
            
        except Exception as e:
            logger.error(f"Failed to perform comprehensive comparison: {e}")
            return None

    def display_comparison_summary(self, comparison_results, analysis_type):
        """Display comparison summary in a separate popup window instead of overwriting main results"""
        try:
            if not comparison_results:
                return
            
            # Create a separate popup window for comparison results instead of overwriting main results
            self.show_comparison_summary_popup(comparison_results, analysis_type)
            
        except Exception as e:
            logger.error(f"Failed to display comparison summary: {e}")

    def show_comparison_summary_popup(self, comparison_results, analysis_type):
        """Show comparison summary in a popup window without affecting main results"""
        try:
            # Create popup window
            summary_window = tk.Toplevel(self.root)
            summary_window.title(f"Comparison Summary - {analysis_type}")
            summary_window.geometry("900x700")
            summary_window.grab_set()  # Modal
            
            # Center the window
            summary_window.transient(self.root)
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 450
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 350
            summary_window.geometry(f"+{x}+{y}")
            
            # Create scrollable text area
            text_frame = ttk.Frame(summary_window)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
            
            text_area = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 10), bg='#f8f9fa')
            scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_area.yview)
            text_area.configure(yscrollcommand=scrollbar.set)
            
            text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Generate summary text
            summary_text = f"""COMPREHENSIVE COMPARISON ANALYSIS - {analysis_type.upper()}
{'='*70}

ANALYSIS SUMMARY:
Total Sheets Analyzed: {comparison_results['total_sheets']}
Analysis Type: {analysis_type}

TOP PERFORMING CONFIGURATIONS:
"""
            
            # Add top 5 rankings
            for ranking in comparison_results['rankings'][:5]:
                summary_text += f"""
Rank {ranking['rank']}: {ranking['sheet_name']}
   - Composite Score: {ranking['total_score']}
   - Global Fit: {ranking['global_fit']}%
   - Cramer's V: {ranking['cramers_v']}
   - Accuracy: {ranking['accuracy']:.3f}
   - QC Grade: {ranking['qc_grade']}
"""
            
            if comparison_results['best_configuration']:
                best = comparison_results['best_configuration']
                summary_text += f"""
RECOMMENDED CONFIGURATION:
   {best['sheet_name']} (Score: {best['total_score']})
   {best['reason']}
"""
            
            if comparison_results['statistical_summary']:
                stats = comparison_results['statistical_summary']
                summary_text += f"""
STATISTICAL SUMMARY:
   - Average Performance Score: {stats['average_score']}
   - Performance Range: {stats['score_range']}
   - High-Quality Sheets: {stats['high_quality_count']}/{stats['total_analyzed']}
"""
            
            summary_text += f"""
INTERPRETATION:
   - Higher composite scores indicate better overall performance
   - Global Fit shows how well the SOM matches your data
   - Cramer's V indicates association strength (0-1, higher is better)
   - QC Grades A-B are recommended for production use

NEXT STEPS:
   1. Review detailed charts in the analysis window
   2. Consider the top 2-3 configurations for your specific needs
   3. Validate results with additional data if available
"""
            
            text_area.insert('1.0', summary_text)
            text_area.config(state=tk.DISABLED)
            
            # Add close button
            button_frame = ttk.Frame(summary_window)
            button_frame.pack(pady=10)
            ttk.Button(button_frame, text="Close", command=summary_window.destroy).pack()
            
        except Exception as e:
            logger.error(f"Failed to show comparison summary popup: {e}")

    def show_comparison_details(self, comparison_results, title):
        """Show detailed comparison results in a popup window"""
        try:
            if not comparison_results:
                return
            
            # Create popup window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Detailed {title}")
            details_window.geometry("800x600")
            details_window.grab_set()  # Modal
            
            # Center the window
            details_window.transient(self.root)
            x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 400
            y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 300
            details_window.geometry(f"+{x}+{y}")
            
            # Create scrollable text area
            text_frame = ttk.Frame(details_window)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text_area = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 10))
            scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_area.yview)
            text_area.configure(yscrollcommand=scrollbar.set)
            
            text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Generate detailed text
            details_text = f"DETAILED {title.upper()}\n{'='*80}\n\n"
            
            details_text += f"ANALYSIS OVERVIEW:\n"
            details_text += f"Total Sheets: {comparison_results['total_sheets']}\n"
            details_text += f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            details_text += f"COMPLETE RANKINGS:\n{'-'*50}\n"
            for ranking in comparison_results['rankings']:
                details_text += f"""
Rank {ranking['rank']}: {ranking['sheet_name']}
   Composite Score: {ranking['total_score']}
   Global Fit: {ranking['global_fit']}%
   Cramer's V: {ranking['cramers_v']}
   Accuracy: {ranking['accuracy']:.3f}
   QC Grade: {ranking['qc_grade']}
"""
            
            details_text += f"\nSTATISTICAL DETAILS:\n{'-'*50}\n"
            if comparison_results['statistical_summary']:
                stats = comparison_results['statistical_summary']
                details_text += f"Average Score: {stats['average_score']}\n"
                details_text += f"Score Range: {stats['score_range']}\n"
                details_text += f"High-Quality Count: {stats['high_quality_count']}\n"
                details_text += f"Total Analyzed: {stats['total_analyzed']}\n"
            
            text_area.insert('1.0', details_text)
            text_area.config(state=tk.DISABLED)
            
            # Add close button
            button_frame = ttk.Frame(details_window)
            button_frame.pack(pady=10)
            ttk.Button(button_frame, text="Close", command=details_window.destroy).pack()
            
        except Exception as e:
            logger.error(f"Failed to show comparison details: {e}")
    
    # =============== END QC PANEL METHODS ===============

    def get_chi_square_qc_summary(self, sheet_data):
        """Chi-square test QC summary - reuses existing chi2_contingency results"""
        if not sheet_data or 'confusion_matrix' not in sheet_data:
            return {
                'test_valid': False,
                'chi2_statistic': 0,
                'p_value': 1.0,
                'effect_size': 0.0,
                'expected_freq_ok': False,
                'qc_status': 'No data available',
                'qc_grade': 'F',
                'accuracy_score': 0.0
            }
        
        try:
            matrix = sheet_data['confusion_matrix'].values
            total_observations = np.sum(matrix)
            
            if total_observations == 0:
                return {
                    'test_valid': False,
                    'chi2_statistic': 0,
                    'p_value': 1.0,
                    'effect_size': 0.0,
                    'expected_freq_ok': False,
                    'qc_status': 'No observations in confusion matrix',
                    'qc_grade': 'F',
                    'accuracy_score': 0.0
                }
            
            # Calculate chi-square test
            chi2, p_value, dof, expected = chi2_contingency(matrix)
            
            # Calculate Cramer's V (effect size)
            min_dim = min(matrix.shape) - 1
            if min_dim > 0 and total_observations > 0:
                cramers_v = np.sqrt(chi2 / (total_observations * min_dim))
            else:
                cramers_v = 0
            
            # Check expected frequencies (should be >= 5 for chi-square validity)
            expected_freq_ok = np.all(expected >= 5)
            
            # Calculate accuracy score
            diagonal_sum = np.trace(matrix)
            accuracy_score = (diagonal_sum / total_observations) if total_observations > 0 else 0
            
            # Determine QC grade based on multiple criteria
            qc_grade = self._calculate_qc_grade(p_value, cramers_v, accuracy_score, expected_freq_ok)
            
            # Determine QC status
            if p_value < 0.001:
                qc_status = "Highly significant association"
            elif p_value < 0.01:
                qc_status = "Very significant association"
            elif p_value < 0.05:
                qc_status = "Significant association"
            else:
                qc_status = "No significant association"
            
            return {
                'test_valid': True,
                'chi2_statistic': chi2,
                'p_value': p_value,
                'effect_size': cramers_v,
                'expected_freq_ok': expected_freq_ok,
                'qc_status': qc_status,
                'qc_grade': qc_grade,
                'accuracy_score': accuracy_score
            }
            
        except Exception as e:
            return {
                'test_valid': False,
                'chi2_statistic': 0,
                'p_value': 1.0,
                'effect_size': 0.0,
                'expected_freq_ok': False,
                'qc_status': f'Error in analysis: {str(e)[:50]}',
                'qc_grade': 'F',
                'accuracy_score': 0.0
            }
    
    def _calculate_qc_grade(self, p_value, cramers_v, accuracy_score, expected_freq_ok):
        """
        Calculate comprehensive QC grade based on multiple statistical and quality criteria.
        
        Args:
            p_value (float): Statistical significance p-value
            cramers_v (float): Cramer's V effect size measure
            accuracy_score (float): Classification accuracy (0-1)
            expected_freq_ok (bool): Whether expected frequencies meet chi-square assumptions
            
        Returns:
            str: Letter grade (A, B, C, D, F) with detailed explanation
        """
        grade_points = 0
        max_points = 15
        grade_details = []
        
        # P-value scoring (0-5 points) - Statistical significance
        if p_value < 0.001:
            grade_points += 5
            grade_details.append("Excellent statistical significance (p < 0.001)")
        elif p_value < 0.01:
            grade_points += 4
            grade_details.append("Very good statistical significance (p < 0.01)")
        elif p_value < 0.05:
            grade_points += 3
            grade_details.append("Good statistical significance (p < 0.05)")
        elif p_value < 0.1:
            grade_points += 2
            grade_details.append("Moderate statistical significance (p < 0.1)")
        elif p_value < 0.2:
            grade_points += 1
            grade_details.append("Weak statistical significance (p < 0.2)")
        else:
            grade_details.append("No statistical significance (p >= 0.2)")
        
        # Effect size scoring (0-5 points) - Practical significance
        if cramers_v >= 0.7:
            grade_points += 5
            grade_details.append("Very large effect size (Cramer's V ≥ 0.7)")
        elif cramers_v >= 0.5:
            grade_points += 4
            grade_details.append("Large effect size (Cramer's V ≥ 0.5)")
        elif cramers_v >= 0.3:
            grade_points += 3
            grade_details.append("Medium effect size (Cramer's V ≥ 0.3)")
        elif cramers_v >= 0.1:
            grade_points += 2
            grade_details.append("Small effect size (Cramer's V ≥ 0.1)")
        elif cramers_v > 0:
            grade_points += 1
            grade_details.append("Minimal effect size (Cramer's V > 0)")
        else:
            grade_details.append("No effect size (Cramer's V = 0)")
        
        # Accuracy scoring (0-3 points) - Classification performance
        if accuracy_score >= 0.9:
            grade_points += 3
            grade_details.append("Excellent classification accuracy (≥ 90%)")
        elif accuracy_score >= 0.8:
            grade_points += 2.5
            grade_details.append("Very good classification accuracy (≥ 80%)")
        elif accuracy_score >= 0.7:
            grade_points += 2
            grade_details.append("Good classification accuracy (≥ 70%)")
        elif accuracy_score >= 0.6:
            grade_points += 1.5
            grade_details.append("Fair classification accuracy (≥ 60%)")
        elif accuracy_score >= 0.5:
            grade_points += 1
            grade_details.append("Poor classification accuracy (≥ 50%)")
        else:
            grade_details.append("Very poor classification accuracy (< 50%)")
        
        # Expected frequency validity (0-2 points) - Statistical assumptions
        if expected_freq_ok:
            grade_points += 2
            grade_details.append("Chi-square assumptions met (expected frequencies ≥ 5)")
        else:
            grade_details.append("Chi-square assumptions violated (some expected frequencies < 5)")
        
        # Calculate percentage score
        percentage_score = (grade_points / max_points) * 100
        
        # Convert to letter grade with detailed explanation
        if percentage_score >= 90:
            grade = 'A'
            grade_explanation = "Excellent quality - Results are highly reliable and statistically robust"
        elif percentage_score >= 80:
            grade = 'B'
            grade_explanation = "Very good quality - Results are reliable with minor limitations"
        elif percentage_score >= 70:
            grade = 'C'
            grade_explanation = "Good quality - Results are acceptable but with some limitations"
        elif percentage_score >= 60:
            grade = 'D'
            grade_explanation = "Fair quality - Results have significant limitations and should be interpreted with caution"
        else:
            grade = 'F'
            grade_explanation = "Poor quality - Results are unreliable and should not be used for decision making"
        
        # Store grade details for potential display
        grade_summary = {
            'letter_grade': grade,
            'percentage_score': percentage_score,
            'points_earned': grade_points,
            'max_points': max_points,
            'explanation': grade_explanation,
            'details': grade_details
        }
        
        # Store in instance for potential access by other methods
        if not hasattr(self, '_last_qc_grade_details'):
            self._last_qc_grade_details = {}
        self._last_qc_grade_details = grade_summary
        
        return grade

    def cleanup_resources(self):
        """
        Comprehensive cleanup of application resources before shutdown.
        Ensures graceful termination and prevents resource leaks.
        """
        # Note: Application cleanup is initiated silently to avoid excessive logging
        
        try:
            # Cancel any ongoing operations
            if hasattr(self, 'cancel_event'):
                self.cancel_event.set()
                # Note: Operations are cancelled silently to avoid excessive logging
            
            # Stop processing state
            if hasattr(self, 'processing_state'):
                self.processing_state = False
                # Note: Processing state is stopped silently to avoid excessive logging
            
            # Stop animations and visual effects
            if hasattr(self, 'animation_running'):
                self.animation_running = False
                # Note: Animations are stopped silently to avoid excessive logging
            
            # Stop any running timers
            if hasattr(self, 'root') and self.root:
                try:
                    self.root.after_cancel('all')
                    # Note: Scheduled tasks are cancelled silently to avoid excessive logging
                except:
                    pass
            
            # Close thread pool gracefully using safe manager
            if hasattr(self, 'thread_manager'):
                try:
                    logger.info("Shutting down thread pool...")
                    success = self.thread_manager.shutdown(wait=True, timeout=THREAD_POOL_TIMEOUT)
                    if success:
                        logger.info("Thread pool shutdown complete")
                    else:
                        logger.warning("Thread pool shutdown encountered issues")
                except Exception as e:
                    logger.warning(f"Thread pool shutdown error: {str(e)}")
            
            # Close visualization window if open
            if hasattr(self, 'viz_window') and self.viz_window and self.viz_window.window:
                try:
                    logger.info("Closing visualization window...")
                    self.viz_window.window.destroy()
                    self.viz_window = None
                    logger.info("Visualization window closed")
                except Exception as e:
                    logger.warning(f"Error closing visualization window: {str(e)}")
            
            # Close any other open windows
            if hasattr(self, 'root') and self.root:
                try:
                    # Find and close all toplevel windows
                    for widget in self.root.winfo_children():
                        if isinstance(widget, tk.Toplevel):
                            try:
                                widget.destroy()
                            except:
                                pass
                    logger.info("Closed additional windows")
                except Exception as e:
                    logger.warning(f"Error closing additional windows: {str(e)}")
            
            # Clear data structures
            with self.data_lock:
                try:
                    if hasattr(self, 'batch_results'):
                        self.batch_results.clear()
                    if hasattr(self, 'comparison_summary'):
                        self.comparison_summary.clear()
                    if hasattr(self, 'confusion_matrix'):
                        self.confusion_matrix = None
                    if hasattr(self, 'results'):
                        self.results.clear()
                    if hasattr(self, 'excel_file'):
                        self.excel_file = None
                    logger.info("Cleared data structures")
                except Exception as e:
                    logger.warning(f"Error clearing data: {str(e)}")
            
            # Close file handles
            if hasattr(self, 'excel_file') and self.excel_file:
                try:
                    self.excel_file.close()
                    logger.info("Closed Excel file")
                except Exception as e:
                    logger.warning(f"Error closing Excel file: {str(e)}")
            
            # Clear matplotlib figures to prevent memory leaks
            try:
                import matplotlib.pyplot as plt
                plt.close('all')
                logger.info("Cleared matplotlib figures")
            except Exception as e:
                logger.warning(f"Error clearing matplotlib figures: {str(e)}")
            
            # Force garbage collection
            try:
                import gc
                gc.collect()
                logger.info("Forced garbage collection")
            except Exception as e:
                logger.warning(f"Error during garbage collection: {str(e)}")
            
            logger.info("Application cleanup completed successfully")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            # Don't let cleanup errors prevent shutdown
            pass
        
        finally:
            # Final cleanup actions
            try:
                # Ensure all threads are terminated
                if hasattr(self, 'cancel_event'):
                    self.cancel_event.set()
                
                # Clear any remaining references
                if hasattr(self, 'root') and self.root:
                    try:
                        self.root.quit()
                    except:
                        pass
                
                logger.info("Final cleanup actions completed")
                
            except Exception as e:
                logger.warning(f"Error in final cleanup: {str(e)}")
                pass
    
    def cleanup(self):
        """Comprehensive cleanup method for application shutdown"""
        try:
            logger.info("Starting comprehensive cleanup...")
            
            # Stop any running analysis
            if hasattr(self, 'processing_state'):
                self.processing_state = False
            
            # Cancel any ongoing operations
            if hasattr(self, 'cancel_event'):
                self.cancel_event.set()
            
            # Clean up thread manager
            if hasattr(self, 'thread_manager'):
                logger.info("Shutting down thread manager...")
                success = self.thread_manager.shutdown(wait=True, timeout=THREAD_POOL_TIMEOUT)
                if not success:
                    logger.warning("Thread manager did not shut down cleanly")
            
            # Clean up matplotlib
            try:
                import matplotlib.pyplot as plt
                plt.close('all')
            except:
                pass
            
            # Force garbage collection
            try:
                gc.collect()
            except:
                pass
            
            logger.info("Comprehensive cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup error (non-fatal): {e}")
    
    def __del__(self):
        """Backup cleanup during garbage collection"""
        try:
            self.cleanup()
        except:
            pass  # Avoid errors during garbage collection

def check_terms_acceptance():
    """Check if terms have been previously accepted"""
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                settings = json.load(f)
                terms_accepted = settings.get('terms_accepted', False)
                if terms_accepted:
                    logger.debug(f"Terms were previously accepted on {settings.get('terms_accepted_date', 'unknown date')}")
                return terms_accepted
    except Exception as e:
        logger.warning(f"Error checking terms acceptance: {e}")
    return False

def show_terms_acceptance_dialog():
    """Show Terms of Service acceptance dialog"""
    # Create terms acceptance dialog
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    terms_dialog = tk.Toplevel(root)
    terms_dialog.title("TraceSeis, Inc.® Terms of Service Agreement")
    terms_dialog.geometry("700x550")
    terms_dialog.resizable(False, False)
    terms_dialog.grab_set()  # Make modal
    
    # Center the dialog
    terms_dialog.update_idletasks()
    x = (terms_dialog.winfo_screenwidth() - 700) // 2
    y = (terms_dialog.winfo_screenheight() - 550) // 2
    terms_dialog.geometry(f"+{x}+{y}")
    
    # Variables to track user choice
    terms_accepted = False
    remember_choice = tk.BooleanVar()
    
    # Main frame
    main_frame = ttk.Frame(terms_dialog, padding="15")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Header
    header_frame = ttk.Frame(main_frame)
    header_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(header_frame, text="Welcome to TraceSeis, Inc.®", 
             font=('Arial', 16, 'bold')).pack()
    ttk.Label(header_frame, text="deltaV solutions division", 
             font=('Arial', 10), foreground='#666').pack()
    ttk.Label(header_frame, text="Please read and accept the Terms of Service to continue", 
             font=('Arial', 10)).pack()
    
    # Terms text with scrollbar
    text_frame = ttk.Frame(main_frame)
    text_frame.pack(fill=tk.BOTH, expand=True)
    
    terms_text = """TraceSeis, Inc.® COMMERCIAL LICENSE AGREEMENT
(deltaV solutions division)

IMPORTANT: READ CAREFULLY BEFORE USING THIS SOFTWARE

This Commercial License Agreement ("Agreement") is a legal agreement between you (either an individual or a single entity) and TraceSeis, Inc. ("TraceSeis, Inc.") for the TraceSeis, Inc. software product identified above, developed by deltaV solutions (the non-geoscience division of TraceSeis, Inc.), which includes computer software and associated documentation ("Software").

BY CLICKING "I ACCEPT" BELOW, YOU AGREE TO BE BOUND BY THE TERMS OF THIS AGREEMENT.

1. GRANT OF LICENSE
TraceSeis, Inc. grants you a non-exclusive, non-transferable license to use the Software in accordance with the terms of this Agreement. You may:
• Use the Software on computers owned or controlled by you
• Make one backup copy of the Software for archival purposes
• Use the Software for categories analysis and research

2. RESTRICTIONS
You may NOT:
• Copy the Software except as specified above
• Distribute, rent, lease, or sublicense the Software
• Reverse engineer, decompile, or disassemble the Software
• Remove or alter any copyright notices or labels
• Use the Software to develop competing products
• Share license keys with unauthorized users

3. OWNERSHIP
The Software is protected by copyright laws and international copyright treaties. TraceSeis, Inc. retains all ownership rights in the Software. TraceSeis, Inc.® is a registered trademark of TraceSeis, Inc.

4. WARRANTY DISCLAIMER
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. TraceSeis, Inc. DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

5. LIMITATION OF LIABILITY
IN NO EVENT SHALL TraceSeis, Inc. BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THE SOFTWARE, EVEN IF TraceSeis, Inc. HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. TraceSeis, Inc.' TOTAL LIABILITY SHALL NOT EXCEED THE AMOUNT PAID FOR THE SOFTWARE LICENSE.

6. DATA PRIVACY
TraceSeis, Inc. respects your privacy. The Software operates locally on your computer and does not transmit categories data or personally identifiable information to external servers without your explicit consent.

7. EXPORT RESTRICTIONS
You acknowledge that the Software may be subject to export restrictions. You agree to comply with all applicable export laws and regulations.

8. TERMINATION
This license is effective until terminated. Your rights under this license will terminate automatically without notice if you fail to comply with any term of this Agreement. Upon termination, you must destroy all copies of the Software.

9. GOVERNING LAW
This Agreement is governed by the laws of the United States, without regard to conflict of law principles.

10. ENTIRE AGREEMENT
This Agreement constitutes the entire agreement between you and TraceSeis, Inc. regarding the Software and supersedes all prior agreements and understandings.

By clicking "I Accept" below, you acknowledge that you have read and understood this Agreement and agree to be bound by its terms.

© 2025 TraceSeis, Inc. All rights reserved.
TraceSeis, Inc.® is a registered trademark of TraceSeis, Inc."""
    
    text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Courier', 8), 
                         bg='#f8f9fa', relief=tk.SUNKEN, borderwidth=1)
    scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    
    text_widget.insert(1.0, terms_text)
    text_widget.configure(state='disabled')
    
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Checkbox frame
    checkbox_frame = ttk.Frame(main_frame)
    checkbox_frame.pack(fill=tk.X, pady=(10, 5))
    
    ttk.Checkbutton(checkbox_frame, text="Remember my choice (don't show this again)", 
                   variable=remember_choice).pack(anchor=tk.W)
    
    # Buttons frame
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(fill=tk.X, pady=(5, 0))
    
    def accept_terms():
        nonlocal terms_accepted
        terms_accepted = True
        # Always save terms acceptance (not just when checkbox is checked)
        # The checkbox is for "don't show again" preference, but acceptance should always be saved
        try:
            SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
            # Read existing settings first
            settings = {}
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
            # Update with terms acceptance (always save, regardless of checkbox)
            settings['terms_accepted'] = True
            settings['terms_accepted_date'] = datetime.now().isoformat()
            # Also save the "don't show again" preference if checkbox is checked
            if remember_choice.get():
                settings['terms_dont_show_again'] = True
            # Save back
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2)
            logger.info("Terms acceptance saved successfully")
        except Exception as e:
            logger.error(f"Failed to save terms acceptance: {e}")
        terms_dialog.destroy()
        root.destroy()
    
    def decline_terms():
        nonlocal terms_accepted
        terms_accepted = False
        terms_dialog.destroy()
        root.destroy()
    
    ttk.Button(button_frame, text="I Decline", command=decline_terms, 
              width=15).pack(side=tk.LEFT)
    ttk.Button(button_frame, text="I Accept", command=accept_terms, 
              width=15).pack(side=tk.RIGHT)
    
    # Handle window close button (treat as decline)
    def on_close():
        nonlocal terms_accepted
        terms_accepted = False
        terms_dialog.destroy()
        root.destroy()
    
    terms_dialog.protocol("WM_DELETE_WINDOW", on_close)
    
    # Wait for user choice
    root.mainloop()
    
    return terms_accepted

def initialize_application():
    """Complete application initialization with comprehensive error handling"""
    logger.info("=" * 60)
    logger.info(f"Initializing {APP_NAME} v{APP_VERSION}")
    logger.info("=" * 60)
    
    initialization_steps = [
        ("System Dependencies", check_dependencies),
        ("License Validation", validate_license_activation),
        ("Terms Acceptance", check_and_handle_terms),
        ("System Resources", verify_system_resources),
        ("Application Setup", None)  # Handled separately
    ]
    
    try:
        # Step 1: Check dependencies
        logger.info("Step 1/5: Checking system dependencies...")
        if not check_dependencies():
            logger.critical("Dependency check failed - cannot continue")
            return False
        
        # Step 2: Validate license
        logger.info("Step 2/5: Validating software license...")
        license_result = validate_license_activation()
        if not license_result:
            logger.critical("License validation failed - cannot continue")
            return False
        
        logger.info(f"License valid - Tier: {license_result.get('tier', 'unknown')}, "
                   f"Days remaining: {license_result.get('days_remaining', 'unknown')}")
        
        # Step 3: Check terms acceptance
        logger.info("Step 3/5: Checking terms acceptance...")
        if not check_and_handle_terms():
            logger.info("User declined terms - exiting gracefully")
            return False
        
        # Step 4: Verify system resources
        logger.info("Step 4/5: Verifying system resources...")
        if not verify_system_resources():
            logger.warning("System resource check failed - continuing with warnings")
        
        # Step 5: Application setup
        logger.info("Step 5/5: Setting up application environment...")
        setup_application_environment()
        
        logger.info("Application initialization completed successfully")
        return True
        
    except Exception as e:
        logger.critical(f"Critical error during initialization: {e}")
        logger.critical("Application cannot start safely")
        
        try:
            # Show error to user
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Initialization Error", 
                               f"Failed to initialize application:\n\n{str(e)}\n\n"
                               f"Check log file: {LOG_FILE}")
            root.destroy()
        except:
            pass
        
        return False

def check_and_handle_terms():
    """Check and handle terms acceptance with proper error handling"""
    try:
        if not check_terms_acceptance():
            logger.info("Terms not previously accepted, showing dialog...")
            if not show_terms_acceptance_dialog():
                return False
        
        logger.info("Terms acceptance verified")
        return True
        
    except Exception as e:
        logger.error(f"Error checking terms acceptance: {e}")
        return False

def verify_system_resources():
    """Verify system has adequate resources for operation"""
    try:
        logger.debug("Checking system resources...")
        
        # Check available memory (basic check)
        import psutil
        memory = psutil.virtual_memory()
        available_gb = memory.available / (1024**3)
        
        logger.info(f"Available memory: {available_gb:.1f} GB")
        
        if available_gb < 1.0:
            logger.warning("Low available memory - performance may be affected")
        
        # Check disk space in config directory
        config_disk = psutil.disk_usage(str(CONFIG_DIR))
        available_disk_gb = config_disk.free / (1024**3)
        
        logger.info(f"Available disk space: {available_disk_gb:.1f} GB")
        
        if available_disk_gb < 0.5:
            logger.warning("Low disk space - may affect data export capabilities")
        
        return True
        
    except ImportError:
        logger.debug("psutil not available - skipping detailed resource check")
        return True
    except Exception as e:
        logger.warning(f"System resource check failed: {e}")
        return True  # Non-critical, continue anyway

def setup_application_environment():
    """Setup application environment and signal handlers"""
    try:
        logger.debug("Setting up application environment...")
        
        # Setup emergency exit handlers
        def emergency_exit(signum=None, frame=None):
            """Emergency exit handler for critical failures"""
            logger.critical("Emergency exit triggered!")
            try:
                # Force cleanup
                import gc
                gc.collect()
                plt.close('all')
            except:
                pass
            sys.exit(1)
        
        # Register signal handlers
        signal.signal(signal.SIGABRT, emergency_exit)
        if hasattr(signal, 'SIGFPE'):
            signal.signal(signal.SIGFPE, emergency_exit)
        
        # Setup cleanup on normal exit
        def cleanup_on_exit():
            logger.info("Application exiting - performing cleanup...")
            try:
                plt.close('all')
                import gc
                gc.collect()
            except:
                pass
        
        atexit.register(cleanup_on_exit)
        
        logger.debug("Application environment setup completed")
        
    except Exception as e:
        logger.warning(f"Environment setup warning: {e}")

def main():
    """Enhanced main application entry point with comprehensive initialization"""
    try:
        # Initialize commercial protection
        is_compiled = getattr(sys, 'frozen', False)
        
        if not PROTECTION_AVAILABLE:
            if PROTECTION_ERROR:
                logger.warning(f"Protection module unavailable: {PROTECTION_ERROR}")
                logger.warning("Application will run without commercial protection features")
            else:
                logger.warning("Protection module not available - running without protection")
        elif PROTECTION_AVAILABLE:
            # Try to initialize protection regardless of compilation status
            # (can be useful for testing protection during development)
            try:
                protection = initialize_protection()
                if is_compiled:
                    logger.info("Commercial protection initialized (compiled .exe mode)")
                else:
                    logger.info("Commercial protection initialized (development/testing mode)")
            except Exception as e:
                logger.error(f"Protection initialization failed: {e}")
                logger.error(f"Error type: {type(e).__name__}")
                import traceback
                logger.debug(f"Protection initialization traceback: {traceback.format_exc()}")
                logger.warning("Application will continue without protection - this may indicate a configuration issue")
        
        # Run complete initialization
        if not initialize_application():
            logger.critical("Application initialization failed - exiting")
            sys.exit(1)
        
        # Create main application window
        logger.info("Creating main application window...")
        root = tk.Tk()
        
        # Configure main window
        root.title(f"{APP_NAME} v{APP_VERSION}")
        root.minsize(1200, 800)
        
        # Center window on screen
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2
        y = (root.winfo_screenheight() - root.winfo_reqheight()) // 2
        root.geometry(f"+{x}+{y}")
        
        # Create the application instance
        logger.info("Initializing main application components...")
        app = StatisticalAnalyzer(root)
        
        def on_closing():
            """Enhanced window closing handler with comprehensive cleanup"""
            logger.info("Application closing - starting cleanup sequence...")
            
            import threading
            close_completed = threading.Event()
            
            def do_cleanup():
                try:
                    # Stop any running analysis
                    if hasattr(app, 'processing_state'):
                        app.processing_state = False
                    
                    # Cancel any ongoing operations
                    if hasattr(app, 'cancel_event'):
                        app.cancel_event.set()
                    
                    # Cleanup commercial protection
                    if PROTECTION_AVAILABLE:
                        try:
                            cleanup_protection()
                            logger.info("Commercial protection cleaned up")
                        except Exception as e:
                            logger.warning(f"Protection cleanup warning: {e}")
                    
                    # Perform comprehensive cleanup
                    app.cleanup()
                    
                    # Update configuration with last run info
                    try:
                        app_config["license_info"]["last_run"] = datetime.now().isoformat()
                        save_config(app_config)
                    except:
                        pass
                    
                    close_completed.set()
                    logger.info("Cleanup completed successfully")
                    
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")
                    close_completed.set()
            
            # Start cleanup in background thread with timeout
            cleanup_thread = threading.Thread(target=do_cleanup, daemon=True)
            cleanup_thread.start()
            
            # Wait max 5 seconds for cleanup to complete
            if not close_completed.wait(timeout=5.0):
                logger.warning("Cleanup timed out - forcing exit")
            
            # Always destroy the window
            try:
                root.destroy()
            except Exception as e:
                logger.error(f"Window destruction error: {e}")
                sys.exit(0)
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the application
        logger.info("Starting main application loop...")
        logger.info("Application ready for user interaction")
        
        root.mainloop()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        try:
            root.quit()
        except:
            pass
    except Exception as e:
        logger.critical(f"Critical application error: {e}")
        try:
            messagebox.showerror("Critical Error", 
                               f"A critical error occurred:\n\n{str(e)}\n\n"
                               f"Please check the log file: {LOG_FILE}")
        except:
            pass
        sys.exit(1)
    finally:
        logger.info("Application shutdown complete")
        logger.info("=" * 60)

if __name__ == "__main__":
    main()
