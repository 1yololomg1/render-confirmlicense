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

License Management GUI
Connects to existing license API endpoints without creating new databases
Uses existing admin key system and API structure
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json
import threading
from datetime import datetime, timedelta
import hashlib
import platform
import subprocess
import re
import os
import base64
from cryptography.fernet import Fernet
from pathlib import Path

class LicenseManagerGUI:
    # File paths for saved credentials
    # Use %LOCALAPPDATA% on Windows, fallback to home directory on other platforms
    _local_app_data = os.getenv("LOCALAPPDATA")
    if _local_app_data and platform.system() == "Windows":
        CREDENTIALS_DIR = Path(_local_app_data) / "CONFIRM_LicenseManager"
    else:
        CREDENTIALS_DIR = Path.home() / ".confirm_license_manager"
    ADMIN_KEY_FILE = CREDENTIALS_DIR / "admin_key.enc"
    MASTER_KEY_FILE = CREDENTIALS_DIR / "master_key.key"
    
    def __init__(self, root):
        self.root = root
        self.root.title("CONFIRM License Management System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f8f9fa')
        
        # API Configuration - load from environment or config
        self.api_base_url = os.getenv('LICENSE_API_URL', 'http://localhost:3000')
        self.admin_key = None
        self.saved_admin_key = None
        self.licenses_data = []
        self.local_mode = True  # Enable local testing mode
        
        # Create credentials directory if it doesn't exist
        self.CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Try to load saved admin key
        self.load_saved_admin_key()
        
        # Create the interface
        self.create_widgets()
        
        # Pre-populate admin key entry if saved key exists
        if self.saved_admin_key:
            self.admin_key_entry.insert(0, self.saved_admin_key)
        
    def get_or_create_master_key(self):
        """Get or create the master encryption key"""
        if self.MASTER_KEY_FILE.exists():
            with open(self.MASTER_KEY_FILE, 'rb') as f:
                return f.read()
        else:
            # Generate new master key
            key = Fernet.generate_key()
            with open(self.MASTER_KEY_FILE, 'wb') as f:
                f.write(key)
            return key
    
    def save_admin_key(self, admin_key):
        """Save admin key to encrypted file
        
        Returns:
            bool: True if save succeeded, False otherwise
        """
        try:
            master_key = self.get_or_create_master_key()
            cipher = Fernet(master_key)
            encrypted_key = cipher.encrypt(admin_key.encode())
            
            with open(self.ADMIN_KEY_FILE, 'wb') as f:
                f.write(encrypted_key)
            self.saved_admin_key = admin_key
            return True
        except Exception as e:
            print(f"Failed to save admin key: {e}")
            return False
    
    def load_saved_admin_key(self):
        """Load saved admin key from encrypted file"""
        try:
            if self.ADMIN_KEY_FILE.exists() and self.MASTER_KEY_FILE.exists():
                master_key = self.get_or_create_master_key()
                cipher = Fernet(master_key)
                
                with open(self.ADMIN_KEY_FILE, 'rb') as f:
                    encrypted_key = f.read()
                
                decrypted_key = cipher.decrypt(encrypted_key).decode()
                self.saved_admin_key = decrypted_key
        except Exception as e:
            print(f"Failed to load saved admin key: {e}")
            self.saved_admin_key = None
    
    def clear_saved_credentials(self):
        """Clear saved admin credentials"""
        try:
            if self.ADMIN_KEY_FILE.exists():
                self.ADMIN_KEY_FILE.unlink()
            if self.MASTER_KEY_FILE.exists():
                self.MASTER_KEY_FILE.unlink()
            self.saved_admin_key = None
            self.admin_key_entry.delete(0, tk.END)
            self.creds_status_label.config(text="")  # Clear status label
            messagebox.showinfo("Success", "Saved credentials cleared")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear credentials: {e}")
        
    def create_widgets(self):
        """Create the main interface widgets"""
        # Header
        header_frame = tk.Frame(self.root, bg="#1a365d", height=80)
        header_frame.pack(fill="x", pady=0)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="CONFIRM License Management", 
                font=("Arial", 18, "bold"), fg="#ffffff", bg="#1a365d").pack(pady=15)
        tk.Label(header_frame, text="Professional Statistical Analysis Suite - License Administration", 
                font=("Arial", 10), fg="#a0aec0", bg="#1a365d").pack()
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg="#f8f9fa")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Create tabs
        self.create_overview_tab()
        self.create_licenses_tab()
        self.create_verify_tab()
        self.create_create_tab()
        self.create_revoke_tab()
        
    def create_overview_tab(self):
        """Create the overview/analytics tab"""
        overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(overview_frame, text="System Overview")
        
        # Admin key section
        key_frame = tk.LabelFrame(overview_frame, text="Authentication", 
                                 font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                 padx=20, pady=15)
        key_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(key_frame, text="Admin Key:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        self.admin_key_entry = tk.Entry(key_frame, font=("Consolas", 12), 
                                       width=50, show="*", bg="#ffffff", 
                                       fg="#2d3748", relief="solid", bd=1)
        self.admin_key_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Button frame
        button_frame = tk.Frame(key_frame, bg="#f8f9fa")
        button_frame.pack(fill="x")
        
        tk.Button(button_frame, text="Load System Statistics", 
                 command=self.load_system_stats,
                 font=("Arial", 11, "bold"), bg="#2b6cb0", fg="white",
                 padx=20, pady=8, relief="flat", cursor="hand2").pack(side="left", padx=(0, 10))
        
        # Clear saved credentials button
        tk.Button(button_frame, text="Clear Saved Credentials", 
                 command=self.clear_saved_credentials,
                 font=("Arial", 10), bg="#e2e8f0", fg="#4a5568",
                 padx=15, pady=8, relief="flat", cursor="hand2").pack(side="left")
        
        # Show status if credentials are saved
        self.creds_status_label = tk.Label(key_frame, text="", 
                                          font=("Arial", 9, "italic"), 
                                          bg="#f8f9fa", fg="#059669")
        self.creds_status_label.pack(anchor="w", pady=(5, 0))
        
        # Update status label if credentials are saved
        if self.saved_admin_key:
            self.creds_status_label.config(text="Using saved credentials")
        
        # Statistics display
        self.stats_frame = tk.LabelFrame(overview_frame, text="System Statistics", 
                                        font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                        padx=20, pady=15)
        self.stats_frame.pack(fill="both", expand=True)
        
        self.stats_text = scrolledtext.ScrolledText(self.stats_frame, 
                                                   font=("Consolas", 10), 
                                                   bg="#ffffff", fg="#2d3748",
                                                   height=15, wrap=tk.WORD)
        self.stats_text.pack(fill="both", expand=True)
        
    def create_licenses_tab(self):
        """Create the licenses management tab"""
        licenses_frame = ttk.Frame(self.notebook)
        self.notebook.add(licenses_frame, text="License Management")
        
        # Search section
        search_frame = tk.LabelFrame(licenses_frame, text="Search Licenses", 
                                   font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                   padx=20, pady=15)
        search_frame.pack(fill="x", pady=(0, 20))
        
        # Search by fingerprint
        tk.Label(search_frame, text="Search by Machine Fingerprint:", 
                font=("Arial", 11, "bold"), bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        search_input_frame = tk.Frame(search_frame, bg="#f8f9fa")
        search_input_frame.pack(fill="x", pady=(5, 10))
        
        self.fingerprint_search = tk.Entry(search_input_frame, font=("Consolas", 12), 
                                          width=40, bg="#ffffff", fg="#2d3748", 
                                          relief="solid", bd=1)
        self.fingerprint_search.pack(side="left", padx=(0, 10), ipady=8, fill="x", expand=True)
        
        tk.Button(search_input_frame, text="Search Licenses", 
                 command=self.search_licenses,
                 font=("Arial", 11, "bold"), bg="#059669", fg="white",
                 padx=15, pady=8, relief="flat", cursor="hand2").pack(side="right")
        
        # Licenses table
        table_frame = tk.LabelFrame(licenses_frame, text="License Results", 
                                   font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                   padx=20, pady=15)
        table_frame.pack(fill="both", expand=True)
        
        # Create treeview for licenses
        columns = ("Fingerprint", "Type", "Status", "Expires", "Days Left", "Last Verified")
        self.licenses_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.licenses_tree.heading("Fingerprint", text="Machine Fingerprint")
        self.licenses_tree.heading("Type", text="License Type")
        self.licenses_tree.heading("Status", text="Status")
        self.licenses_tree.heading("Expires", text="Expires")
        self.licenses_tree.heading("Days Left", text="Days Left")
        self.licenses_tree.heading("Last Verified", text="Last Verified")
        
        # Set column widths
        self.licenses_tree.column("Fingerprint", width=200)
        self.licenses_tree.column("Type", width=120)
        self.licenses_tree.column("Status", width=80)
        self.licenses_tree.column("Expires", width=100)
        self.licenses_tree.column("Days Left", width=80)
        self.licenses_tree.column("Last Verified", width=120)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.licenses_tree.yview)
        self.licenses_tree.configure(yscrollcommand=scrollbar.set)
        
        self.licenses_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_verify_tab(self):
        """Create the license verification tab"""
        verify_frame = ttk.Frame(self.notebook)
        self.notebook.add(verify_frame, text="Verify License")
        
        # Hardware info section
        hw_frame = tk.LabelFrame(verify_frame, text="Hardware Information", 
                                font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                padx=20, pady=15)
        hw_frame.pack(fill="x", pady=(0, 20))
        
        # CPU ID
        tk.Label(hw_frame, text="CPU ID:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.cpu_id_entry = tk.Entry(hw_frame, font=("Consolas", 12), 
                                    width=50, bg="#ffffff", fg="#2d3748", 
                                    relief="solid", bd=1)
        self.cpu_id_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Motherboard ID
        tk.Label(hw_frame, text="Motherboard ID:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.motherboard_id_entry = tk.Entry(hw_frame, font=("Consolas", 12), 
                                            width=50, bg="#ffffff", fg="#2d3748", 
                                            relief="solid", bd=1)
        self.motherboard_id_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # BIOS Serial
        tk.Label(hw_frame, text="BIOS Serial (optional):", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.bios_serial_entry = tk.Entry(hw_frame, font=("Consolas", 12), 
                                         width=50, bg="#ffffff", fg="#2d3748", 
                                         relief="solid", bd=1)
        self.bios_serial_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # MAC Address
        tk.Label(hw_frame, text="MAC Address (optional):", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.mac_address_entry = tk.Entry(hw_frame, font=("Consolas", 12), 
                                         width=50, bg="#ffffff", fg="#2d3748", 
                                         relief="solid", bd=1)
        self.mac_address_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # License Key
        tk.Label(hw_frame, text="License Key:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.license_key_entry = tk.Entry(hw_frame, font=("Consolas", 12), 
                                         width=50, bg="#ffffff", fg="#2d3748", 
                                         relief="solid", bd=1)
        self.license_key_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Buttons
        button_frame = tk.Frame(hw_frame, bg="#f8f9fa")
        button_frame.pack(fill="x", pady=(15, 0))
        
        tk.Button(button_frame, text="Get Current Hardware Info", 
                 command=self.get_current_hardware,
                 font=("Arial", 11, "bold"), bg="#6b7280", fg="white",
                 padx=15, pady=8, relief="flat", cursor="hand2").pack(side="left", padx=(0, 10))
        
        tk.Button(button_frame, text="Verify License", 
                 command=self.verify_license,
                 font=("Arial", 11, "bold"), bg="#059669", fg="white",
                 padx=15, pady=8, relief="flat", cursor="hand2").pack(side="left")
        
        # Results section
        results_frame = tk.LabelFrame(verify_frame, text="Verification Results", 
                                    font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                    padx=20, pady=15)
        results_frame.pack(fill="both", expand=True)
        
        self.verify_results = scrolledtext.ScrolledText(results_frame, 
                                                       font=("Consolas", 10), 
                                                       bg="#ffffff", fg="#2d3748",
                                                       height=10, wrap=tk.WORD)
        self.verify_results.pack(fill="both", expand=True)
        
    def create_create_tab(self):
        """Create the manual license creation tab"""
        create_frame = ttk.Frame(self.notebook)
        self.notebook.add(create_frame, text="Create License")
        
        # License creation form
        form_frame = tk.LabelFrame(create_frame, text="Create New License", 
                                  font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                  padx=20, pady=15)
        form_frame.pack(fill="x", pady=(0, 20))
        
        # Email address
        tk.Label(form_frame, text="Customer Email:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.create_fingerprint_entry = tk.Entry(form_frame, font=("Consolas", 12), 
                                                 width=50, bg="#ffffff", fg="#2d3748", 
                                                 relief="solid", bd=1)
        self.create_fingerprint_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # License type
        tk.Label(form_frame, text="License Type:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.license_type_var = tk.StringVar(value="student")
        license_type_combo = ttk.Combobox(form_frame, textvariable=self.license_type_var,
                                         values=["student", "startup", "professional", 
                                                "professional_yearly", "enterprise", "enterprise_yearly"],
                                         font=("Arial", 12), width=47)
        license_type_combo.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Expiration date
        tk.Label(form_frame, text="Expiration Date (YYYY-MM-DD):", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.expires_date_entry = tk.Entry(form_frame, font=("Consolas", 12), 
                                          width=50, bg="#ffffff", fg="#2d3748", 
                                          relief="solid", bd=1)
        self.expires_date_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Notes
        tk.Label(form_frame, text="Notes (optional):", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.notes_entry = tk.Text(form_frame, font=("Arial", 12), 
                                  width=50, height=3, bg="#ffffff", fg="#2d3748", 
                                  relief="solid", bd=1)
        self.notes_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Create button
        tk.Button(form_frame, text="Create License", 
                 command=self.create_license,
                 font=("Arial", 11, "bold"), bg="#059669", fg="white",
                 padx=20, pady=8, relief="flat", cursor="hand2").pack(pady=(15, 0))
        
        # Results
        create_results_frame = tk.LabelFrame(create_frame, text="Creation Results", 
                                           font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                           padx=20, pady=15)
        create_results_frame.pack(fill="both", expand=True)
        
        self.create_results = scrolledtext.ScrolledText(create_results_frame, 
                                                       font=("Consolas", 10), 
                                                       bg="#ffffff", fg="#2d3748",
                                                       height=10, wrap=tk.WORD)
        self.create_results.pack(fill="both", expand=True)
        
    def create_revoke_tab(self):
        """Create the license revocation tab"""
        revoke_frame = ttk.Frame(self.notebook)
        self.notebook.add(revoke_frame, text="Revoke License")
        
        # Revocation form
        revoke_form_frame = tk.LabelFrame(revoke_frame, text="Revoke License", 
                                         font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                         padx=20, pady=15)
        revoke_form_frame.pack(fill="x", pady=(0, 20))
        
        # License ID
        tk.Label(revoke_form_frame, text="License ID (or Email to search):", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        
        search_frame = tk.Frame(revoke_form_frame, bg="#f8f9fa")
        search_frame.pack(fill="x", pady=(5, 10))
        
        self.revoke_fingerprint_entry = tk.Entry(search_frame, font=("Consolas", 12), 
                                                width=40, bg="#ffffff", fg="#2d3748", 
                                                relief="solid", bd=1)
        self.revoke_fingerprint_entry.pack(side="left", padx=(0, 10), ipady=8, fill="x", expand=True)
        
        tk.Button(search_frame, text="Search", 
                 command=self.search_license_for_revoke,
                 font=("Arial", 11, "bold"), bg="#6b7280", fg="white",
                 padx=15, pady=8, relief="flat", cursor="hand2").pack(side="right")
        
        # Reason
        tk.Label(revoke_form_frame, text="Revocation Reason:", font=("Arial", 11, "bold"), 
                bg="#f8f9fa", fg="#2d3748").pack(anchor="w")
        self.revoke_reason_entry = tk.Text(revoke_form_frame, font=("Arial", 12), 
                                          width=50, height=3, bg="#ffffff", fg="#2d3748", 
                                          relief="solid", bd=1)
        self.revoke_reason_entry.pack(pady=(5, 10), ipady=8, fill="x")
        
        # Revoke button
        tk.Button(revoke_form_frame, text="Revoke License", 
                 command=self.revoke_license,
                 font=("Arial", 11, "bold"), bg="#dc2626", fg="white",
                 padx=20, pady=8, relief="flat", cursor="hand2").pack(pady=(15, 0))
        
        # Results
        revoke_results_frame = tk.LabelFrame(revoke_frame, text="Revocation Results", 
                                           font=("Arial", 12, "bold"), bg="#f8f9fa", fg="#1a365d",
                                           padx=20, pady=15)
        revoke_results_frame.pack(fill="both", expand=True)
        
        self.revoke_results = scrolledtext.ScrolledText(revoke_results_frame, 
                                                       font=("Consolas", 10), 
                                                       bg="#ffffff", fg="#2d3748",
                                                       height=10, wrap=tk.WORD)
        self.revoke_results.pack(fill="both", expand=True)
    
    def load_system_stats(self):
        """Load system statistics from the API"""
        admin_key = self.admin_key_entry.get().strip()
        if not admin_key:
            messagebox.showerror("Error", "Please enter admin key")
            return
        
        self.admin_key = admin_key
        
        def load_stats_thread():
            try:
                # Use Render API endpoints
                response = requests.get(
                    f"{self.api_base_url}/admin/recent-licenses",
                    headers={
                        'x-app-secret': admin_key
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    # Your API returns licenses directly, not wrapped in success/stats
                    if 'licenses' in result:
                        # Save admin key after successful authentication
                        save_success = self.save_admin_key(admin_key)
                        if save_success:
                            self.root.after(0, lambda: self.creds_status_label.config(text="Using saved credentials"))
                        else:
                            self.root.after(0, lambda: self.creds_status_label.config(text="WARNING: Credentials not saved (check permissions)"))
                        self.root.after(0, lambda: self.display_stats_from_licenses(result['licenses']))
                    else:
                        self.root.after(0, lambda: messagebox.showerror("Error", "No licenses data received"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API Error: {response.status_code}"))
                    
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: messagebox.showerror("Network Error", str(e)))
        
        threading.Thread(target=load_stats_thread, daemon=True).start()
    
    def display_stats_from_licenses(self, licenses):
        """Display system statistics calculated from licenses data"""
        self.stats_text.delete(1.0, tk.END)
        
        # Calculate statistics from licenses
        total_licenses = len(licenses)
        active_licenses = sum(1 for lic in licenses if lic.get('activated', False))
        expired_licenses = 0
        by_type = {}
        
        for license in licenses:
            # Count by product type
            product_type = license.get('productType', 'Unknown')
            by_type[product_type] = by_type.get(product_type, 0) + 1
            
            # Check if expired
            expiry = license.get('expiry')
            if expiry:
                try:
                    expiry_date = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                    if datetime.now(expiry_date.tzinfo) > expiry_date:
                        expired_licenses += 1
                except:
                    pass
        
        stats_text = f"""SYSTEM STATISTICS
{'='*50}

Total Licenses: {total_licenses}
Active Licenses: {active_licenses}
Expired Licenses: {expired_licenses}
Pending Licenses: {total_licenses - active_licenses}

LICENSE BREAKDOWN BY TYPE:
{'-'*30}"""
        
        for product_type, count in by_type.items():
            stats_text += f"\n{product_type}: {count}"
        
        stats_text += f"""

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        self.stats_text.insert(1.0, stats_text)
    
    def display_stats(self, stats):
        """Display system statistics (legacy method)"""
        self.stats_text.delete(1.0, tk.END)
        
        stats_text = f"""SYSTEM STATISTICS
{'='*50}

Total Licenses: {stats.get('total_licenses', 0)}
Active Licenses: {stats.get('active_licenses', 0)}
Expired Licenses: {stats.get('expired_licenses', 0)}
Total Revenue: ${stats.get('total_revenue', 0):,.2f}

LICENSE BREAKDOWN BY TYPE:
{'-'*30}
Student: {stats.get('by_type', {}).get('student', 0)}
Startup: {stats.get('by_type', {}).get('startup', 0)}
Professional: {stats.get('by_type', {}).get('professional', 0)}
Professional (Yearly): {stats.get('by_type', {}).get('professional_yearly', 0)}
Enterprise: {stats.get('by_type', {}).get('enterprise', 0)}
Enterprise (Yearly): {stats.get('by_type', {}).get('enterprise_yearly', 0)}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        self.stats_text.insert(1.0, stats_text)
    
    def search_licenses(self):
        """Search for licenses"""
        if not self.admin_key:
            messagebox.showerror("Error", "Please load system statistics first to authenticate")
            return
        
        fingerprint_search = self.fingerprint_search.get().strip()
        
        def search_thread():
            try:
                # Use your existing lookup-email endpoint
                response = requests.post(
                    f"{self.api_base_url}/admin/lookup-email",
                    headers={
                        'Content-Type': 'application/json',
                        'x-app-secret': self.admin_key
                    },
                    json={'email': fingerprint_search},
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'error' in result:
                        self.root.after(0, lambda: messagebox.showerror("Error", result['error']))
                    else:
                        # Convert single license to list format for display
                        licenses = [result] if result else []
                        self.root.after(0, lambda: self.display_licenses(licenses))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API Error: {response.status_code}"))
                    
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: messagebox.showerror("Network Error", str(e)))
        
        threading.Thread(target=search_thread, daemon=True).start()
    
    def display_licenses(self, licenses):
        """Display licenses in the treeview"""
        # Clear existing items
        for item in self.licenses_tree.get_children():
            self.licenses_tree.delete(item)
        
        if not licenses:
            self.licenses_tree.insert("", "end", values=("No licenses found", "", "", "", "", ""))
            return
        
        for license in licenses:
            # Handle your license data format
            expiry = license.get('expiry', '')
            if expiry:
                try:
                    expires_at = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                    now = datetime.now(expires_at.tzinfo)
                    days_remaining = (expires_at - now).days
                    is_expired = days_remaining < 0
                    expires_str = expires_at.strftime('%Y-%m-%d')
                except:
                    expires_at = None
                    days_remaining = 0
                    is_expired = True
                    expires_str = "Invalid Date"
            else:
                expires_at = None
                days_remaining = 0
                is_expired = True
                expires_str = "No Expiry"
            
            status = "Expired" if is_expired else ("Active" if license.get('activated', False) else "Pending")
            days_text = "Expired" if is_expired else f"{days_remaining} days"
            
            # Get machine ID or use email as identifier
            machine_id = license.get('machineId', 'Not Activated')
            if machine_id and machine_id != 'null':
                fingerprint = machine_id[:16] + "..." if len(machine_id) > 16 else machine_id
            else:
                fingerprint = "Not Activated"
            
            # Get product type
            product_type = license.get('productType', 'Unknown')
            
            # Get last verified (use activatedAt if available)
            last_verified = license.get('activatedAt', '')
            if last_verified:
                try:
                    last_verified = datetime.fromisoformat(last_verified.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                except:
                    last_verified = "Unknown"
            else:
                last_verified = "Never"
            
            self.licenses_tree.insert("", "end", values=(
                fingerprint,
                product_type,
                status,
                expires_str,
                days_text,
                last_verified
            ))
    
    def get_current_hardware(self):
        """Get current hardware information"""
        try:
            if platform.system() == "Windows":
                # Get CPU ID
                try:
                    result = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId'], 
                                          capture_output=True, text=True, timeout=10)
                    cpu_id = result.stdout.split('\n')[1].strip()
                except:
                    cpu_id = "Unknown"
                
                # Get Motherboard ID
                try:
                    result = subprocess.run(['wmic', 'baseboard', 'get', 'SerialNumber'], 
                                          capture_output=True, text=True, timeout=10)
                    motherboard_id = result.stdout.split('\n')[1].strip()
                except:
                    motherboard_id = "Unknown"
                
                # Get BIOS Serial
                try:
                    result = subprocess.run(['wmic', 'bios', 'get', 'SerialNumber'], 
                                          capture_output=True, text=True, timeout=10)
                    bios_serial = result.stdout.split('\n')[1].strip()
                except:
                    bios_serial = "Unknown"
                
                # Get MAC Address
                try:
                    result = subprocess.run(['getmac', '/v'], capture_output=True, text=True, timeout=10)
                    mac_lines = result.stdout.split('\n')
                    mac_address = "Unknown"
                    for line in mac_lines:
                        if 'Ethernet' in line or 'Wi-Fi' in line:
                            mac_match = re.search(r'([0-9A-F]{2}[:-]){5}[0-9A-F]{2}', line)
                            if mac_match:
                                mac_address = mac_match.group(0)
                                break
                except:
                    mac_address = "Unknown"
            
            else:
                # For non-Windows systems, use basic system info
                cpu_id = platform.processor() or "Unknown"
                motherboard_id = "Unknown"
                bios_serial = "Unknown"
                mac_address = "Unknown"
            
            # Populate the fields
            self.cpu_id_entry.delete(0, tk.END)
            self.cpu_id_entry.insert(0, cpu_id)
            
            self.motherboard_id_entry.delete(0, tk.END)
            self.motherboard_id_entry.insert(0, motherboard_id)
            
            self.bios_serial_entry.delete(0, tk.END)
            self.bios_serial_entry.insert(0, bios_serial)
            
            self.mac_address_entry.delete(0, tk.END)
            self.mac_address_entry.insert(0, mac_address)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get hardware info: {str(e)}")
    
    def verify_license(self):
        """Verify a license"""
        cpu_id = self.cpu_id_entry.get().strip()
        motherboard_id = self.motherboard_id_entry.get().strip()
        bios_serial = self.bios_serial_entry.get().strip()
        mac_address = self.mac_address_entry.get().strip()
        license_key = self.license_key_entry.get().strip()
        
        if not cpu_id or not motherboard_id:
            messagebox.showerror("Error", "CPU ID and Motherboard ID are required")
            return
            
        if not license_key:
            messagebox.showerror("Error", "License key is required")
            return
        
        def verify_thread():
            try:
                # Create a simple machine ID from hardware info
                machine_id = hashlib.sha256(f"{cpu_id}:{motherboard_id}".encode()).hexdigest()
                
                # Use your existing validate endpoint
                response = requests.post(
                    f"{self.api_base_url}/validate",
                    headers={
                        'Content-Type': 'application/json',
                        'x-app-secret': self.admin_key
                    },
                    json={
                        'license_key': license_key,
                        'machine_id': machine_id
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.root.after(0, lambda: self.display_verification_result(result))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API Error: {response.status_code}"))
                    
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: messagebox.showerror("Network Error", str(e)))
        
        threading.Thread(target=verify_thread, daemon=True).start()
    
    def display_verification_result(self, result):
        """Display license verification result"""
        self.verify_results.delete(1.0, tk.END)
        
        if result.get('valid'):
            result_text = f"""LICENSE VERIFICATION SUCCESSFUL
{'='*40}

Status: VALID
Expires: {result.get('expiry', 'Unknown')}
Machine ID: {result.get('machineId', 'Unknown')}

Features Available: All features included
"""
        else:
            error_msg = result.get('error', 'Unknown error')
            result_text = f"""LICENSE VERIFICATION FAILED
{'='*40}

Status: INVALID
Error: {error_msg}

Possible reasons:
- License key is invalid or expired
- Machine ID doesn't match
- License not activated
- License has expired
"""
        
        result_text += f"\n\nVerification completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.verify_results.insert(1.0, result_text)
    
    def create_license(self):
        """Create a new license"""
        if not self.admin_key:
            messagebox.showerror("Error", "Please load system statistics first to authenticate")
            return
        
        email = self.create_fingerprint_entry.get().strip()  # Using this field for email
        license_type = self.license_type_var.get()
        expires_date = self.expires_date_entry.get().strip()
        notes = self.notes_entry.get(1.0, tk.END).strip()
        
        if not email or not expires_date:
            messagebox.showerror("Error", "Email and expiration date are required")
            return
        
        # Validate email format
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showerror("Error", "Please enter a valid email address")
            return
        
        # Calculate duration in days
        try:
            expiry_date = datetime.strptime(expires_date, '%Y-%m-%d')
            today = datetime.now()
            duration_days = (expiry_date - today).days
            if duration_days <= 0:
                messagebox.showerror("Error", "Expiration date must be in the future")
                return
        except ValueError:
            messagebox.showerror("Error", "Please enter expiration date in YYYY-MM-DD format")
            return
        
        def create_thread():
            try:
                response = requests.post(
                    f"{self.api_base_url}/admin/create-license",
                    headers={
                        'Content-Type': 'application/json',
                        'x-app-secret': self.admin_key
                    },
                    json={
                        'email': email,
                        'productType': license_type,
                        'durationDays': duration_days,
                        'notes': notes
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        self.root.after(0, lambda: self.display_create_result(result))
                    else:
                        self.root.after(0, lambda: messagebox.showerror("Error", result.get('error', 'Unknown error')))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API Error: {response.status_code}"))
                    
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: messagebox.showerror("Network Error", str(e)))
        
        threading.Thread(target=create_thread, daemon=True).start()
    
    def display_create_result(self, result):
        """Display license creation result"""
        self.create_results.delete(1.0, tk.END)
        
        license_data = result.get('license', {})
        
        result_text = f"""LICENSE CREATION SUCCESSFUL
{'='*40}

License ID: {license_data.get('id', 'Unknown')}
License Key: {license_data.get('licenseKey', 'Unknown')}
Email: {license_data.get('email', 'Unknown')}
Product Type: {license_data.get('productType', 'Unknown')}
Expires: {license_data.get('expiry', 'Unknown')}
Created: {license_data.get('createdAt', 'Unknown')}

IMPORTANT: Save this license key!
The customer will need this key to activate their license.

Message: {result.get('message', 'License created successfully')}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        self.create_results.insert(1.0, result_text)
    
    def revoke_license(self):
        """Revoke a license"""
        if not self.admin_key:
            messagebox.showerror("Error", "Please load system statistics first to authenticate")
            return
        
        license_id = self.revoke_fingerprint_entry.get().strip()
        reason = self.revoke_reason_entry.get(1.0, tk.END).strip()
        
        if not license_id:
            messagebox.showerror("Error", "License ID is required")
            return
        
        if not reason:
            reason = "No reason provided"
        
        def revoke_thread():
            try:
                response = requests.post(
                    f"{self.api_base_url}/admin/revoke-license",
                    headers={
                        'Content-Type': 'application/json',
                        'x-app-secret': self.admin_key
                    },
                    json={
                        'licenseId': license_id,
                        'reason': reason
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        self.root.after(0, lambda: self.display_revoke_result(result))
                    else:
                        self.root.after(0, lambda: messagebox.showerror("Error", result.get('error', 'Unknown error')))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API Error: {response.status_code}"))
                    
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: messagebox.showerror("Network Error", str(e)))
        
        threading.Thread(target=revoke_thread, daemon=True).start()
    
    def search_license_for_revoke(self):
        """Search for a license to revoke"""
        if not self.admin_key:
            messagebox.showerror("Error", "Please load system statistics first to authenticate")
            return
        
        search_term = self.revoke_fingerprint_entry.get().strip()
        if not search_term:
            messagebox.showerror("Error", "Please enter an email address to search")
            return
        
        def search_thread():
            try:
                response = requests.post(
                    f"{self.api_base_url}/admin/search-license",
                    headers={
                        'Content-Type': 'application/json',
                        'x-app-secret': self.admin_key
                    },
                    json={'searchTerm': search_term},
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    licenses = result.get('licenses', [])
                    if licenses:
                        # Show first license found
                        license_data = licenses[0]
                        self.root.after(0, lambda: self.revoke_fingerprint_entry.delete(0, tk.END))
                        self.root.after(0, lambda: self.revoke_fingerprint_entry.insert(0, license_data['id']))
                        self.root.after(0, lambda: messagebox.showinfo("License Found", 
                            f"Found license for {license_data['email']}\n"
                            f"Product: {license_data['productType']}\n"
                            f"Status: {'Active' if license_data.get('activated') else 'Pending'}\n"
                            f"License ID: {license_data['id']}"))
                    else:
                        self.root.after(0, lambda: messagebox.showinfo("No License Found", 
                            f"No licenses found for email: {search_term}"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API Error: {response.status_code}"))
                    
            except requests.exceptions.RequestException as e:
                self.root.after(0, lambda: messagebox.showerror("Network Error", str(e)))
        
        threading.Thread(target=search_thread, daemon=True).start()
    
    def display_revoke_result(self, result):
        """Display license revocation result"""
        self.revoke_results.delete(1.0, tk.END)
        
        license_data = result.get('license', {})
        
        result_text = f"""LICENSE REVOCATION SUCCESSFUL
{'='*40}

License ID: {license_data.get('id', 'Unknown')}
Email: {license_data.get('email', 'Unknown')}
Product Type: {license_data.get('productType', 'Unknown')}
Revoked At: {license_data.get('revokedAt', 'Unknown')}
Revocation Reason: {license_data.get('revocationReason', 'Unknown')}

IMPORTANT: This license is now revoked and cannot be used.
The customer will need to purchase a new license if they want to continue using the software.

Message: {result.get('message', 'License revoked successfully')}

Revoked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        self.revoke_results.insert(1.0, result_text)

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = LicenseManagerGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()
