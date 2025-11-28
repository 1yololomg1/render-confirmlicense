#!/usr/bin/env python3
"""
Minimal test to see if we can get to the license dialog
"""
import sys
import os
import logging

# Setup verbose logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Add source to path
sys.path.insert(0, r"C:\porfolio\render-confirmlicense\01_SOURCE_CODE")

logger.info("=" * 70)
logger.info("MINIMAL LICENSE DIALOG TEST")
logger.info("=" * 70)

try:
    logger.info("Step 1: Importing modules...")
    from CONFIRM_Integrated import (
        get_computer_fingerprint,
        check_computer_already_licensed,
        get_saved_license,
        LicenseDialog
    )
    logger.info("✓ Imports successful")
    
    logger.info("Step 2: Getting computer fingerprint...")
    computer_id = get_computer_fingerprint()
    logger.info(f"✓ Computer ID: {computer_id}")
    
    logger.info("Step 3: Checking for saved license...")
    saved_license = get_saved_license()
    if saved_license:
        logger.info(f"✓ Found saved license")
    else:
        logger.info("✓ No saved license (expected)")
    
    logger.info("Step 4: Checking if computer already licensed...")
    existing = check_computer_already_licensed(computer_id)
    if existing:
        logger.error(f"✗ Computer already bound to: {existing}")
        logger.error("This shouldn't happen - admin panel says no licenses found")
        sys.exit(1)
    else:
        logger.info("✓ Computer not bound to any license")
    
    logger.info("Step 5: Creating license dialog...")
    dialog = LicenseDialog()
    logger.info("✓ Dialog created")
    
    logger.info("Step 6: Starting dialog mainloop (window should appear now)...")
    dialog.root.mainloop()
    
    logger.info("Step 7: Dialog closed")
    if dialog.result:
        logger.info(f"✓ User entered license: {dialog.result.get('license_key', 'N/A')[:20]}...")
    else:
        logger.info("✗ User cancelled or no result")
    
except Exception as e:
    logger.error(f"ERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

logger.info("=" * 70)
logger.info("TEST COMPLETE")
logger.info("=" * 70)
