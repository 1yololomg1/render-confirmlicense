#!/usr/bin/env python3
"""
Debug authentication issues
"""

import requests
import json

def test_debug_endpoint():
    """Test the debug endpoint to see what's set on the server"""
    print("Testing debug endpoint...")
    
    try:
        response = requests.get("https://render-confirmlicense.onrender.com/debug", timeout=10)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("Server debug info:")
            print(f"  Has SHARED_SECRET: {data.get('hasSharedSecret')}")
            print(f"  Secret length: {data.get('sharedSecretLength')}")
            print(f"  Secret preview: {data.get('sharedSecretPreview')}")
            print(f"  Node env: {data.get('nodeEnv')}")
            print(f"  Timestamp: {data.get('timestamp')}")
            return True
        else:
            print(f"Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_auth_comparison(admin_key):
    """Test authentication comparison"""
    print(f"\nTesting auth with key: {admin_key[:8]}...")
    
    try:
        response = requests.post("https://render-confirmlicense.onrender.com/test-auth", 
                               headers={'x-app-secret': admin_key}, 
                               timeout=10)
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("Auth comparison:")
            print(f"  Provided key: {data.get('providedKey')}")
            print(f"  Expected key: {data.get('expectedKey')}")
            print(f"  Keys match: {data.get('keysMatch')}")
            print(f"  Provided length: {data.get('providedLength')}")
            print(f"  Expected length: {data.get('expectedLength')}")
            return data.get('keysMatch', False)
        else:
            print(f"Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("CONFIRM Authentication Debugger")
    print("=" * 40)
    
    # Test debug endpoint
    if test_debug_endpoint():
        print("\n" + "=" * 40)
        
        # Test with your admin key
        admin_key = input("Enter your admin key to test: ").strip()
        
        if admin_key:
            test_auth_comparison(admin_key)
        else:
            print("No admin key provided")
    else:
        print("Failed to get debug info")

