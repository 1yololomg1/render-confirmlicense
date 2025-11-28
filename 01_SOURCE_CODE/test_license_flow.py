#!/usr/bin/env python3
"""Test license validation flow"""
import sys
import logging

# Setup logging to see everything
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

logger.info("=" * 60)
logger.info("TEST: Starting license validation test")
logger.info("=" * 60)

# Import the main module
try:
    logger.info("Importing CONFIRM_Integrated module...")
    from CONFIRM_Integrated import validate_license_activation, get_saved_license, LICENSE_FILE
    logger.info("Import successful")
except Exception as e:
    logger.error(f"Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Check if license file exists
logger.info(f"Checking for license file at: {LICENSE_FILE}")
logger.info(f"License file exists: {LICENSE_FILE.exists()}")

# Try to get saved license
logger.info("Attempting to get saved license...")
try:
    saved = get_saved_license()
    if saved:
        logger.info(f"Saved license found: {saved}")
    else:
        logger.info("No saved license found")
except Exception as e:
    logger.error(f"Error getting saved license: {e}")
    import traceback
    traceback.print_exc()

# Try validate_license_activation
logger.info("Calling validate_license_activation()...")
try:
    result = validate_license_activation()
    logger.info(f"Validation result: {result}")
    if result:
        logger.info("✓ License validation SUCCESSFUL")
    else:
        logger.warning("✗ License validation FAILED (returned None/False)")
except Exception as e:
    logger.error(f"✗ License validation CRASHED: {e}")
    import traceback
    traceback.print_exc()

logger.info("=" * 60)
logger.info("TEST COMPLETE")
logger.info("=" * 60)
