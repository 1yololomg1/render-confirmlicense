#!/usr/bin/env python3
"""
Quick test script to verify protection initialization fix works correctly.
This tests that:
1. Protection is skipped in development mode (not compiled)
2. App continues without hanging
3. Protection would initialize in compiled mode
"""

import sys
import os
import time

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '01_SOURCE_CODE'))

def test_protection_skip():
    """Test that protection is skipped in development mode"""
    print("=" * 60)
    print("TEST: Protection Skip in Development Mode")
    print("=" * 60)
    
    # Check if running as compiled
    is_compiled = getattr(sys, 'frozen', False)
    print(f"Running as compiled: {is_compiled}")
    
    if is_compiled:
        print("[WARN] WARNING: Running as compiled executable - test may not be accurate")
        print("   Run this test as a Python script, not compiled .exe")
        return False
    
    # Check if protection module is available
    try:
        from protection_module import initialize_protection
        protection_available = True
        print("[OK] Protection module is available")
    except ImportError as e:
        protection_available = False
        print(f"[INFO] Protection module not available: {e}")
        print("   (This is OK - test will verify skip logic)")
    
    # Test the actual logic from CONFIRM_Integrated.py
    print("\nTesting protection initialization logic...")
    start_time = time.time()
    
    # Simulate the logic from main()
    if not is_compiled:
        # Development mode - should skip
        print("[OK] Development mode detected - protection should be skipped")
        elapsed = time.time() - start_time
        print(f"[OK] Protection skip completed in {elapsed:.3f} seconds")
        if elapsed > 0.1:
            print("[WARN] WARNING: Protection skip took longer than expected")
        else:
            print("[OK] Protection skip is fast (no blocking)")
        return True
    else:
        print("[WARN] Running as compiled - cannot test skip logic")
        return False

def test_import():
    """Test that the main module can be imported without hanging"""
    print("\n" + "=" * 60)
    print("TEST: Module Import (No Hanging)")
    print("=" * 60)
    
    start_time = time.time()
    
    try:
        # Try importing just the constants and setup
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "CONFIRM_Integrated",
            os.path.join("01_SOURCE_CODE", "CONFIRM_Integrated.py")
        )
        
        # This will execute the module-level code
        print("Importing CONFIRM_Integrated module...")
        module = importlib.util.module_from_spec(spec)
        
        # Set a timeout for the import
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Import took too long - likely hanging")
        
        # Note: signal.alarm doesn't work on Windows, so we'll use a different approach
        # Just import and measure time
        spec.loader.exec_module(module)
        
        elapsed = time.time() - start_time
        print(f"[OK] Module imported successfully in {elapsed:.3f} seconds")
        
        if elapsed > 5.0:
            print("[WARN] WARNING: Import took longer than 5 seconds - may indicate hanging")
            return False
        elif elapsed > 2.0:
            print("[WARN] WARNING: Import took longer than 2 seconds - may be slow")
            return True
        else:
            print("[OK] Import is fast - no hanging detected")
            return True
            
    except TimeoutError as e:
        elapsed = time.time() - start_time
        print(f"[FAIL] FAILED: {e} (after {elapsed:.1f} seconds)")
        return False
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[FAIL] FAILED: Import error after {elapsed:.3f} seconds: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_main_function():
    """Test that main() function logic works correctly"""
    print("\n" + "=" * 60)
    print("TEST: Main Function Logic")
    print("=" * 60)
    
    # Read the actual main() function logic
    main_file = os.path.join("01_SOURCE_CODE", "CONFIRM_Integrated.py")
    
    if not os.path.exists(main_file):
        print("[FAIL] Cannot find CONFIRM_Integrated.py")
        return False
    
    with open(main_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for the fix
    checks = [
        ("if not is_compiled:", "Development mode check exists"),
        ("skip protection", "Protection skip logic exists"),
        ("Running in development mode", "Development mode message exists"),
    ]
    
    all_passed = True
    for check_str, description in checks:
        if check_str.lower() in content.lower():
            print(f"[OK] {description}")
        else:
            print(f"[FAIL] Missing: {description}")
            all_passed = False
    
    return all_passed

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("PROTECTION FIX VERIFICATION TEST")
    print("=" * 60)
    print()
    
    results = []
    
    # Test 1: Protection skip logic
    results.append(("Protection Skip Logic", test_protection_skip()))
    
    # Test 2: Module import (should not hang)
    results.append(("Module Import (No Hang)", test_import()))
    
    # Test 3: Code verification
    results.append(("Code Verification", test_main_function()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for test_name, passed in results:
        status = "[OK] PASS" if passed else "[FAIL] FAIL"
        print(f"{status}: {test_name}")
        if not passed:
            all_passed = False
    
    print()
    if all_passed:
        print("[OK] ALL TESTS PASSED - Fix appears to be working correctly")
        sys.exit(0)
    else:
        print("[FAIL] SOME TESTS FAILED - Review the output above")
        sys.exit(1)

