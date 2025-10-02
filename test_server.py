#!/usr/bin/env python3
"""
Test script to check if your license server is working
"""

import requests
import json

def test_server():
    """Test the license server endpoints"""
    base_url = "https://render-confirmlicense.onrender.com"
    
    print("Testing CONFIRM License Server")
    print("=" * 40)
    
    # Test 1: Basic health check
    print("\n1. Testing basic health check...")
    try:
        response = requests.get(f"{base_url}/", timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
        return False
    
    # Test 2: Admin endpoint (should fail without key)
    print("\n2. Testing admin endpoint without key...")
    try:
        response = requests.get(f"{base_url}/admin", timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 403:
            print("   ✓ Server is running and protected")
        else:
            print("   ⚠ Unexpected response")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: Admin endpoint with dummy key
    print("\n3. Testing admin endpoint with dummy key...")
    try:
        response = requests.get(f"{base_url}/admin", 
                              headers={'x-app-secret': 'dummy-key'}, 
                              timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 403:
            print("   ✓ Server is properly rejecting invalid keys")
        else:
            print("   ⚠ Server accepted invalid key (this is a problem)")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n" + "=" * 40)
    print("Server test complete!")
    print("\nIf you see 'Access Denied' errors, your server is working correctly.")
    print("The issue is likely that your SHARED_SECRET environment variable")
    print("is not set on Render.com or doesn't match what you're using.")
    
    return True

if __name__ == "__main__":
    test_server()

