#!/usr/bin/env python3
"""
Quick Firebase license unbind - direct REST API approach
"""
import requests
from datetime import datetime
import urllib.parse
import os

FIREBASE_URL = "https://confirm-license-manager-default-rtdb.firebaseio.com"

# Get license key from environment variable (security best practice)
# You need to set this: set CONFIRM_LICENSE_KEY=your_license_key_here
LICENSE_KEY = os.getenv("CONFIRM_LICENSE_KEY")

if not LICENSE_KEY:
    print("ERROR: CONFIRM_LICENSE_KEY environment variable not set!")
    print("Please set it first:")
    print("  set CONFIRM_LICENSE_KEY=your_license_key")
    print()
    print("Example:")
    print("  set CONFIRM_LICENSE_KEY=dfc2077dbbad862a:2026-11-14T00:33:42.003Z:038b17a3dbc81f44")
    exit(1)

print("Unbinding license from old computer...")
print(f"License: {LICENSE_KEY}")
print()

# URL encode the license key to handle special characters
encoded_key = urllib.parse.quote(LICENSE_KEY, safe='')
url = f"{FIREBASE_URL}/license/{encoded_key}.json"

print(f"URL: {url}")
print()

# Data to update - set computer binding fields to null
update_data = {
    "computer_id": None,
    "bound_at": None,
    "binding_method": None,
    "unbound_at": datetime.now().isoformat(),
    "unbound_reason": "windows_update_fingerprint_change"
}

try:
    # Try PATCH request to update only these fields
    response = requests.patch(url, json=update_data, timeout=15)
    response.raise_for_status()
    
    print("[SUCCESS] License unbound.")
    print()
    print("The license is now free to activate on your current computer.")
    print("Try running CONFIRM again and enter your license key.")
    print()
    
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 401 or e.response.status_code == 403:
        print("[ERROR] Firebase authentication required.")
        print()
        print("Your Firebase database has security rules that prevent unauthenticated writes.")
        print("You need to either:")
        print("  1. Temporarily disable Firebase rules")
        print("  2. Or use the Firebase console to manually delete the computer_id field")
        print()
        print(f"Go to Firebase Console and navigate to this license")
    elif e.response.status_code == 400:
        print(f"[ERROR] Bad Request: {e}")
        print(f"Response: {e.response.text}")
        print()
        print("The license key might have URL encoding issues.")
        print("Try accessing Firebase Console directly to edit the license.")
    else:
        print(f"[ERROR] HTTP {e.response.status_code}: {e}")
        print(f"Response: {e.response.text}")
except Exception as e:
    print(f"[ERROR] {e}")
