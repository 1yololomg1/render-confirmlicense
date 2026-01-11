#!/usr/bin/env python3
"""
Machine Migration Script for Admin
Migrates license from old to new machine fingerprint
"""

import requests
import json

def migrate_machine_id():
    """Migrate machine ID using the new server endpoint"""
    
    # Server configuration
    SERVER_URL = 'https://render-confirmlicense.onrender.com'
    ADMIN_SECRET = input("Enter admin secret: ")
    
    # Client information from diagnostic output
    LICENSE_ID = "faf2a7ec5c0127ac"  # Client's license ID
    OLD_MACHINE_ID = "d15424650e95"  # From diagnostic output
    NEW_MACHINE_ID = "3e587cfc5f122560"  # From diagnostic output
    REASON = "Fingerprint algorithm update - stable hardware binding"
    
    print(f"\nMigrating license {LICENSE_ID}...")
    print(f"From: {OLD_MACHINE_ID}")
    print(f"To: {NEW_MACHINE_ID}")
    
    try:
        # First try the direct update endpoint
        print("\nTrying direct license update...")
        response = requests.post(f"{SERVER_URL}/admin/update-license", 
                              json={
                                  "licenseId": LICENSE_ID,
                                  "computer_id": NEW_MACHINE_ID,
                                  "notes": f"Machine migration: {OLD_MACHINE_ID} → {NEW_MACHINE_ID}. Reason: {REASON}"
                              },
                              headers={
                                  "x-app-secret": ADMIN_SECRET,
                                  "Content-Type": "application/json"
                              })
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ License updated successfully!")
            print(f"License: {LICENSE_ID}")
            print(f"New Machine ID: {NEW_MACHINE_ID}")
            print(f"Response: {result}")
        else:
            print(f"\n❌ Direct update failed!")
            print(f"Status: {response.status_code}")
            print(f"Error: {response.text}")
            
            # Try the migrate-machine endpoint as fallback
            print("\nTrying migrate-machine endpoint...")
            response = requests.post(f"{SERVER_URL}/admin/migrate-machine", 
                                  json={
                                      "licenseId": LICENSE_ID,
                                      "oldMachineId": OLD_MACHINE_ID,
                                      "newMachineId": NEW_MACHINE_ID,
                                      "reason": REASON
                                  },
                                  headers={
                                      "x-app-secret": ADMIN_SECRET,
                                      "Content-Type": "application/json"
                                  })
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n✅ Migration successful!")
                print(f"License: {result['migration']['licenseId']}")
                print(f"Migrated at: {result['migration']['migratedAt']}")
                print(f"Reason: {result['migration']['reason']}")
            else:
                print(f"\n❌ Migration also failed!")
                print(f"Status: {response.status_code}")
                print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    migrate_machine_id()
