#!/usr/bin/env python3
"""
Test your admin key once you set it
"""

import requests
import json

def test_admin_key(admin_key):
    """Test if admin key works"""
    base_url = "https://render-confirmlicense.onrender.com"
    
    print(f"Testing admin key: {admin_key[:8]}...")
    
    try:
        response = requests.get(f"{base_url}/admin/recent-licenses", 
                              headers={'x-app-secret': admin_key}, 
                              timeout=10)
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✓ Admin key works!")
            data = response.json()
            print(f"Found {len(data.get('licenses', []))} recent licenses")
            return True
        elif response.status_code == 403:
            print("✗ Access denied - admin key is wrong")
            return False
        else:
            print(f"✗ Unexpected error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    print("CONFIRM Admin Key Tester")
    print("=" * 30)
    
    # Replace this with your actual admin key
    admin_key = input("Enter your admin key: ").strip()
    
    if not admin_key:
        print("No admin key provided")
    else:
        test_admin_key(admin_key)

