#!/usr/bin/env python3
"""
Admin script to unbind a license from its current computer
This allows the license to be re-activated on a different machine
"""
import requests
import os
from datetime import datetime

# Configuration
LICENSE_KEY = "dfc2077dbbad862a:2026-11-14T00:33:42.003Z:038b17a3dbc81f44"
FIREBASE_URL = "https://confirm-license-manager-default-rtdb.firebaseio.com"

# Get Firebase auth token from environment
# You need to set this: set CONFIRM_FIREBASE_AUTH_TOKEN=your_token_here
FIREBASE_AUTH_TOKEN = os.getenv("CONFIRM_FIREBASE_AUTH_TOKEN")

if not FIREBASE_AUTH_TOKEN:
    print("ERROR: CONFIRM_FIREBASE_AUTH_TOKEN environment variable not set!")
    print("Please set it first:")
    print("  set CONFIRM_FIREBASE_AUTH_TOKEN=your_firebase_token")
    exit(1)

print("=" * 60)
print("CONFIRM License Unbind Tool")
print("=" * 60)
print()
print(f"License Key: {LICENSE_KEY}")
print(f"Firebase URL: {FIREBASE_URL}")
print()

# Step 1: Get current license data
print("Step 1: Fetching current license data...")
url = f"{FIREBASE_URL}/license/{LICENSE_KEY}.json"
params = {'auth': FIREBASE_AUTH_TOKEN}

try:
    response = requests.get(url, params=params, timeout=15)
    response.raise_for_status()
    license_data = response.json()
    
    if not license_data:
        print(f"ERROR: License {LICENSE_KEY} not found in database!")
        exit(1)
    
    print("✓ License found")
    print(f"  Current computer_id: {license_data.get('computer_id', 'None')}")
    print(f"  Bound at: {license_data.get('bound_at', 'N/A')}")
    print(f"  Tier: {license_data.get('tier', 'N/A')}")
    print(f"  Expires: {license_data.get('expires', 'N/A')}")
    print()
    
    if not license_data.get('computer_id'):
        print("License is already unbound (no computer_id set)")
        exit(0)
    
except requests.exceptions.RequestException as e:
    print(f"ERROR: Failed to fetch license data: {e}")
    exit(1)

# Step 2: Confirm unbind
print("Step 2: Unbinding license...")
confirm = input("Are you sure you want to unbind this license? (yes/no): ")

if confirm.lower() != 'yes':
    print("Unbind cancelled.")
    exit(0)

# Step 3: Update license to remove computer binding
try:
    license_data['computer_id'] = None
    license_data['bound_at'] = None
    license_data['binding_method'] = None
    license_data['unbound_at'] = datetime.now().isoformat()
    license_data['unbound_reason'] = 'admin_unbind_script'
    
    response = requests.patch(url, params=params, json=license_data, timeout=15)
    response.raise_for_status()
    
    print()
    print("=" * 60)
    print("✓ SUCCESS: License successfully unbound!")
    print("=" * 60)
    print()
    print("The license can now be activated on any computer.")
    print()
    
except requests.exceptions.RequestException as e:
    print(f"ERROR: Failed to unbind license: {e}")
    exit(1)
