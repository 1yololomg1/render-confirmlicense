#!/usr/bin/env python3
"""
Machine Migration GUI Tool for Admin
Interactive GUI for migrating licenses between machine fingerprints
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import json

class MachineMigrationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CONFIRM License Machine Migration Tool")
        self.root.geometry("600x500")
        self.root.configure(bg='#f5f5f5')
        
        # Server configuration
        self.SERVER_URL = 'https://render-confirmlicense.onrender.com'
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="License Machine Migration Tool", 
                               font=('Arial', 16, 'bold'), foreground='darkblue')
        title_label.pack(pady=(0, 20))
        
        # Input fields
        input_frame = ttk.LabelFrame(main_frame, text="Migration Information", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        # License ID
        ttk.Label(input_frame, text="License ID:").grid(row=0, column=0, sticky='w', pady=5)
        self.license_id_var = tk.StringVar()
        license_entry = ttk.Entry(input_frame, textvariable=self.license_id_var, width=40)
        license_entry.grid(row=0, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Old Machine ID
        ttk.Label(input_frame, text="Old Machine ID:").grid(row=1, column=0, sticky='w', pady=5)
        self.old_machine_var = tk.StringVar()
        old_machine_entry = ttk.Entry(input_frame, textvariable=self.old_machine_var, width=40)
        old_machine_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # New Machine ID
        ttk.Label(input_frame, text="New Machine ID:").grid(row=2, column=0, sticky='w', pady=5)
        self.new_machine_var = tk.StringVar()
        new_machine_entry = ttk.Entry(input_frame, textvariable=self.new_machine_var, width=40)
        new_machine_entry.grid(row=2, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Reason
        ttk.Label(input_frame, text="Reason:").grid(row=3, column=0, sticky='w', pady=5)
        self.reason_var = tk.StringVar(value="Fingerprint algorithm update - stable hardware binding")
        reason_entry = ttk.Entry(input_frame, textvariable=self.reason_var, width=40)
        reason_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Admin Secret
        ttk.Label(input_frame, text="Admin Secret:").grid(row=4, column=0, sticky='w', pady=5)
        self.admin_secret_var = tk.StringVar()
        secret_entry = ttk.Entry(input_frame, textvariable=self.admin_secret_var, width=40, show="*")
        secret_entry.grid(row=4, column=1, sticky='ew', pady=5, padx=(10, 0))
        
        # Configure grid weights
        input_frame.columnconfigure(1, weight=1)
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Button(button_frame, text="Migrate License", command=self.migrate_license, 
                  width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Clear Form", command=self.clear_form, 
                  width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Exit", command=self.root.quit, 
                  width=15).pack(side=tk.RIGHT)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Migration Results", padding="15")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=10, width=70)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(10, 0))
    
    def log_message(self, message):
        """Add a message to the results text area"""
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def clear_form(self):
        """Clear all input fields"""
        self.license_id_var.set("")
        self.old_machine_var.set("")
        self.new_machine_var.set("")
        self.reason_var.set("Fingerprint algorithm update - stable hardware binding")
        self.admin_secret_var.set("")
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Form cleared")
    
    def validate_inputs(self):
        """Validate that all required fields are filled"""
        if not self.license_id_var.get().strip():
            messagebox.showerror("Validation Error", "License ID is required")
            return False
        
        if not self.old_machine_var.get().strip():
            messagebox.showerror("Validation Error", "Old Machine ID is required")
            return False
        
        if not self.new_machine_var.get().strip():
            messagebox.showerror("Validation Error", "New Machine ID is required")
            return False
        
        if not self.admin_secret_var.get().strip():
            messagebox.showerror("Validation Error", "Admin Secret is required")
            return False
        
        return True
    
    def migrate_license(self):
        """Perform the license migration"""
        if not self.validate_inputs():
            return
        
        # Get input values
        license_id = self.license_id_var.get().strip()
        old_machine_id = self.old_machine_var.get().strip()
        new_machine_id = self.new_machine_var.get().strip()
        reason = self.reason_var.get().strip()
        admin_secret = self.admin_secret_var.get().strip()
        
        # Clear results and start logging
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Starting migration...")
        
        self.log_message(f"=== License Migration Started ===")
        self.log_message(f"License ID: {license_id}")
        self.log_message(f"From: {old_machine_id}")
        self.log_message(f"To: {new_machine_id}")
        self.log_message(f"Reason: {reason}")
        self.log_message("")
        
        try:
            # First try the direct update endpoint
            self.log_message("Trying direct license update...")
            self.status_var.set("Attempting direct update...")
            
            response = requests.post(f"{self.SERVER_URL}/admin/update-license", 
                                  json={
                                      "licenseId": license_id,
                                      "computer_id": new_machine_id,
                                      "notes": f"Machine migration: {old_machine_id} → {new_machine_id}. Reason: {reason}"
                                  },
                                  headers={
                                      "x-app-secret": admin_secret,
                                      "Content-Type": "application/json"
                                  })
            
            if response.status_code == 200:
                result = response.json()
                self.log_message("✅ License updated successfully!")
                self.log_message(f"License: {license_id}")
                self.log_message(f"New Machine ID: {new_machine_id}")
                self.log_message(f"Response: {json.dumps(result, indent=2)}")
                self.status_var.set("Migration completed successfully!")
                messagebox.showinfo("Success", f"License {license_id} has been successfully migrated!")
            else:
                self.log_message(f"❌ Direct update failed!")
                self.log_message(f"Status: {response.status_code}")
                self.log_message(f"Error: {response.text}")
                
                # Try the migrate-machine endpoint as fallback
                self.log_message("")
                self.log_message("Trying migrate-machine endpoint...")
                self.status_var.set("Attempting fallback migration...")
                
                response = requests.post(f"{self.SERVER_URL}/admin/migrate-machine", 
                                      json={
                                          "licenseId": license_id,
                                          "oldMachineId": old_machine_id,
                                          "newMachineId": new_machine_id,
                                          "reason": reason
                                      },
                                      headers={
                                          "x-app-secret": admin_secret,
                                          "Content-Type": "application/json"
                                      })
                
                if response.status_code == 200:
                    result = response.json()
                    self.log_message("✅ Migration successful!")
                    self.log_message(f"License: {result['migration']['licenseId']}")
                    self.log_message(f"Migrated at: {result['migration']['migratedAt']}")
                    self.log_message(f"Reason: {result['migration']['reason']}")
                    self.status_var.set("Migration completed successfully!")
                    messagebox.showinfo("Success", f"License {license_id} has been successfully migrated!")
                else:
                    self.log_message(f"❌ Migration also failed!")
                    self.log_message(f"Status: {response.status_code}")
                    self.log_message(f"Error: {response.text}")
                    self.status_var.set("Migration failed")
                    messagebox.showerror("Migration Failed", 
                                      f"Both migration methods failed.\n\nLast error: {response.text}")
            
        except Exception as e:
            self.log_message(f"Error: {e}")
            self.status_var.set("Error occurred")
            messagebox.showerror("Error", f"An error occurred during migration: {e}")
        
        self.log_message("")
        self.log_message("=== Migration Process Complete ===")

def main():
    root = tk.Tk()
    app = MachineMigrationGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
