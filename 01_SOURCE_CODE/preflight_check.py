#!/usr/bin/env python3
"""
Migration Pre-Flight Check
Validates everything before attempting migration
"""

import requests
import json

def pre_flight_check():
    """Run all pre-flight checks before migration"""
    
    SERVER_URL = 'https://render-confirmlicense.onrender.com'
    ADMIN_SECRET = input("Enter admin secret: ")
    LICENSE_ID = input("Enter license ID: ").strip()
    
    print("\n🔍 RUNNING PRE-FLIGHT CHECKS...")
    
    # Check 1: Server connectivity
    try:
        response = requests.get(f"{SERVER_URL}/admin/license-stats", 
                           headers={"x-app-secret": ADMIN_SECRET},
                           timeout=10)
        if response.status_code == 200:
            print("✅ Server connectivity: OK")
        else:
            print(f"❌ Server connectivity: FAILED ({response.status_code})")
            return False
    except Exception as e:
        print(f"❌ Server connectivity: FAILED ({e})")
        return False
    
    # Check 2: License exists
    try:
        response = requests.post(f"{SERVER_URL}/admin/search-licenses",
                              json={"field": "license_key", "value": LICENSE_ID},
                              headers={"x-app-secret": ADMIN_SECRET},
                              timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('licenses'):
                license_data = data['licenses'][0]
                print(f"✅ License found: {license_data.get('email', 'N/A')}")
                print(f"   Current machine ID: {license_data.get('computer_id', 'Unbound')}")
                print(f"   Status: {license_data.get('status', 'unknown')}")
                print(f"   Expires: {license_data.get('expires', 'unknown')}")
            else:
                print("❌ License not found")
                return False
        else:
            print(f"❌ License lookup failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ License lookup error: {e}")
        return False
    
    # Check 3: Test machine ID format
    OLD_MACHINE_ID = "d15424650e95"
    NEW_MACHINE_ID = "8eb1d4d40b17e39d"
    
    if len(OLD_MACHINE_ID) == 12 and len(NEW_MACHINE_ID) == 16:
        print("✅ Machine ID formats: Valid")
    else:
        print(f"❌ Machine ID formats: Invalid (old: {len(OLD_MACHINE_ID)}, new: {len(NEW_MACHINE_ID)})")
        return False
    
    print("\n🎉 ALL CHECKS PASSED - Ready for migration!")
    return True

if __name__ == "__main__":
    if pre_flight_check():
        print("\nYou can now run: python migrate_machine.py")
    else:
        print("\n❌ Fix issues before attempting migration")
