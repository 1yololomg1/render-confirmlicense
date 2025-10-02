#!/usr/bin/env python3
"""
CONFIRM - Professional Statistical Analysis Suite
Integrated with new license management system
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
from tkinter import messagebox, simpledialog, ttk, scrolledtext
import sys
import logging
from pathlib import Path
import signal
import atexit
import secrets
from typing import Optional
import threading
import subprocess
import re

# Import your existing dependencies
try:
    import pandas as pd
    import numpy as np
    from scipy import stats
    from sklearn.metrics import confusion_matrix, accuracy_score
    from sklearn.preprocessing import LabelEncoder
    import matplotlib.pyplot as plt
    import seaborn as sns
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import warnings
    warnings.filterwarnings('ignore')
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install required packages: pip install pandas numpy scipy scikit-learn matplotlib seaborn")
    sys.exit(1)

# Configuration and Constants
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

def get_computer_fingerprint():
    """Generate a unique computer fingerprint for license binding"""
    try:
        # Get system information
        system_info = []
        
        # CPU information
        try:
            if platform.system() == "Windows":
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

def bind_license_to_computer(license_key, computer_id, email):
    """Bind license to computer using new server"""
    try:
        response = requests.post(
            f"{LICENSE_SERVER_URL}/activate",
            headers={'Content-Type': 'application/json'},
            json={
                'license_key': license_key,
                'machine_id': computer_id,
                'email': email
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

class LicenseDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CONFIRM - Professional License Activation")
        self.root.geometry("650x450")  # Slightly taller for email field
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
        self.email.trace('w', self.on_license_changed)
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
                    success, message = bind_license_to_computer(license_key, get_computer_fingerprint(), email)
                    
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

# Simplified Statistical Analyzer for demonstration
class StatisticalAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("CONFIRM - Professional Statistical Analysis Suite")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f8f9fa')
        
        # Variables
        self.excel_file = None
        self.sheet_data = {}
        self.results = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the main UI"""
        # Header
        header_frame = tk.Frame(self.root, bg="#1a365d", height=80)
        header_frame.pack(fill="x", pady=0)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="CONFIRM Statistical Analysis Suite", 
                font=("Arial", 18, "bold"), fg="#ffffff", bg="#1a365d").pack(pady=15)
        tk.Label(header_frame, text="Professional Statistical Validation Engine", 
                font=("Arial", 10), fg="#a0aec0", bg="#1a365d").pack()
        
        # Main content
        main_frame = tk.Frame(self.root, bg="#f8f9fa")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # File selection
        file_frame = tk.LabelFrame(main_frame, text="Data Input", 
                                 font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                 padx=20, pady=15)
        file_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(file_frame, text="Select Excel file for analysis:", 
                font=("Arial", 11), bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        file_input_frame = tk.Frame(file_frame, bg="#f8f9fa")
        file_input_frame.pack(fill="x", pady=(10, 0))
        
        self.file_entry = tk.Entry(file_input_frame, font=("Arial", 12), 
                                  width=60, bg="#ffffff", fg="#2d3748", 
                                  relief="solid", bd=1)
        self.file_entry.pack(side="left", padx=(0, 10), ipady=8, fill="x", expand=True)
        
        tk.Button(file_input_frame, text="Browse", command=self.browse_file,
                 font=("Arial", 11), bg="#2b6cb0", fg="white",
                 padx=15, pady=8, relief="flat", cursor="hand2").pack(side="right")
        
        # Analysis button
        analyze_frame = tk.Frame(main_frame, bg="#f8f9fa")
        analyze_frame.pack(fill="x", pady=(0, 20))
        
        tk.Button(analyze_frame, text="Start Analysis", command=self.start_analysis,
                 font=("Arial", 12, "bold"), bg="#059669", fg="white",
                 padx=30, pady=10, relief="flat", cursor="hand2").pack()
        
        # Results area
        results_frame = tk.LabelFrame(main_frame, text="Analysis Results", 
                                    font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                    padx=20, pady=15)
        results_frame.pack(fill="both", expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                     font=("Consolas", 10), 
                                                     bg="#ffffff", fg="#2d3748",
                                                     height=20, wrap=tk.WORD)
        self.results_text.pack(fill="both", expand=True)
        
    def browse_file(self):
        """Browse for Excel file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select Excel File",
            filetypes=[("Excel files", "*.xlsx *.xls"), ("All files", "*.*")]
        )
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
    
    def start_analysis(self):
        """Start statistical analysis"""
        filename = self.file_entry.get().strip()
        if not filename:
            messagebox.showerror("Error", "Please select an Excel file")
            return
        
        if not os.path.exists(filename):
            messagebox.showerror("Error", "File not found")
            return
        
        try:
            # Load Excel file
            self.excel_file = pd.ExcelFile(filename)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Loading Excel file: {filename}\n")
            self.results_text.insert(tk.END, f"Found {len(self.excel_file.sheet_names)} sheets\n\n")
            
            # Analyze each sheet
            for sheet_name in self.excel_file.sheet_names:
                self.results_text.insert(tk.END, f"Analyzing sheet: {sheet_name}\n")
                self.results_text.insert(tk.END, "-" * 50 + "\n")
                
                try:
                    df = pd.read_excel(filename, sheet_name=sheet_name)
                    self.analyze_sheet(sheet_name, df)
                except Exception as e:
                    self.results_text.insert(tk.END, f"Error analyzing {sheet_name}: {str(e)}\n")
                
                self.results_text.insert(tk.END, "\n")
            
            self.results_text.insert(tk.END, "Analysis complete!\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load Excel file: {str(e)}")
    
    def analyze_sheet(self, sheet_name, df):
        """Analyze a single sheet"""
        try:
            # Basic statistics
            self.results_text.insert(tk.END, f"Shape: {df.shape[0]} rows, {df.shape[1]} columns\n")
            self.results_text.insert(tk.END, f"Columns: {list(df.columns)}\n")
            
            # Data types
            self.results_text.insert(tk.END, f"Data types:\n")
            for col, dtype in df.dtypes.items():
                self.results_text.insert(tk.END, f"  {col}: {dtype}\n")
            
            # Missing values
            missing = df.isnull().sum()
            if missing.sum() > 0:
                self.results_text.insert(tk.END, f"Missing values:\n")
                for col, count in missing.items():
                    if count > 0:
                        self.results_text.insert(tk.END, f"  {col}: {count}\n")
            else:
                self.results_text.insert(tk.END, "No missing values\n")
            
            # Basic statistics for numeric columns
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                self.results_text.insert(tk.END, f"Numeric statistics:\n")
                stats = df[numeric_cols].describe()
                self.results_text.insert(tk.END, str(stats) + "\n")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"Error in analysis: {str(e)}\n")

def check_license():
    """Check if license is valid"""
    try:
        # Try to load saved license
        saved_license = get_saved_license()
        if saved_license:
            license_key = saved_license.get('license_key')
            if license_key:
                validation_result = check_license_with_fingerprint(license_key)
                if validation_result.get('valid'):
                    logger.info("Valid license found")
                    return True, "License is valid"
                else:
                    logger.warning("Saved license is invalid")
                    return False, validation_result.get('reason', 'License invalid')
        
        # No valid license found
        return False, "No valid license found"
        
    except Exception as e:
        logger.error(f"License check error: {e}")
        return False, f"License check error: {str(e)}"

def show_license_dialog():
    """Show license activation dialog"""
    dialog = LicenseDialog()
    result = dialog.show()
    return result

def main():
    """Main application entry point"""
    try:
        # Check license first
        is_licensed, message = check_license()
        
        if not is_licensed:
            # Show license dialog
            result = show_license_dialog()
            if not result:
                print("License activation cancelled")
                return
            
            # Verify license again
            is_licensed, message = check_license()
            if not is_licensed:
                messagebox.showerror("License Error", f"License activation failed: {message}")
                return
        
        # License is valid, start the application
        print(f"License check passed: {message}")
        
        # Create and run the main application
        root = tk.Tk()
        app = StatisticalAnalyzer(root)
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Application error: {e}")
        messagebox.showerror("Error", f"Application error: {str(e)}")

if __name__ == "__main__":
    main()
