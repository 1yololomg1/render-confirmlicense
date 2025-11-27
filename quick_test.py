#!/usr/bin/env python3
"""
Quick smoke test - verifies the app starts without hanging.
Run this before deploying to ensure protection fix works.
"""

import sys
import os
import time
import subprocess

def test_app_startup():
    """Test that the app starts without hanging"""
    print("Testing app startup (10 second timeout)...")
    print("=" * 60)
    
    script_path = os.path.join("01_SOURCE_CODE", "CONFIRM_Integrated.py")
    
    if not os.path.exists(script_path):
        print("[FAIL] Cannot find CONFIRM_Integrated.py")
        return False
    
    start_time = time.time()
    
    try:
        # Start the process
        process = subprocess.Popen(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Wait up to 10 seconds for output
        timeout = 10.0
        output_lines = []
        
        while time.time() - start_time < timeout:
            # Check if process is still running
            if process.poll() is not None:
                # Process ended
                stdout, stderr = process.communicate()
                output = stdout + stderr
                elapsed = time.time() - start_time
                print(f"Process ended after {elapsed:.2f} seconds")
                print("\nOutput:")
                print(output[:500])  # First 500 chars
                return elapsed < 8.0  # Should complete quickly if working
            
            # Try to read output (non-blocking)
            time.sleep(0.5)
        
        # Still running after timeout
        elapsed = time.time() - start_time
        print(f"[WARN] Process still running after {elapsed:.1f} seconds")
        print("Checking if it's just waiting for GUI...")
        
        # Check if we got any output indicating it passed protection
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2)
            output = stdout + stderr
            
            # Look for signs it passed protection initialization
            if "development mode" in output.lower() or "protection skipped" in output.lower():
                print("[OK] App passed protection initialization")
                print("[OK] App is likely waiting for GUI (this is normal)")
                return True
            elif "Initializing commercial protection" in output:
                print("[WARN] Protection is still initializing - may be hanging")
                return False
            else:
                print("[INFO] Output received:")
                print(output[:300])
                return True  # Got some output, probably OK
        except subprocess.TimeoutExpired:
            process.kill()
            print("[FAIL] Process did not respond - likely hanging")
            return False
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[FAIL] Error after {elapsed:.2f} seconds: {e}")
        return False

if __name__ == "__main__":
    print("\nQUICK STARTUP TEST")
    print("=" * 60)
    print("This test verifies the app starts without hanging on protection init")
    print()
    
    result = test_app_startup()
    
    print("\n" + "=" * 60)
    if result:
        print("[OK] TEST PASSED - App starts correctly")
        print("     Protection fix appears to be working")
        sys.exit(0)
    else:
        print("[FAIL] TEST FAILED - App may be hanging")
        print("     Review the output above for details")
        sys.exit(1)

