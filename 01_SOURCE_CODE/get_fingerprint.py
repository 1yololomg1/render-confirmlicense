import sys
sys.path.insert(0, r"C:\porfolio\render-confirmlicense\01_SOURCE_CODE")

from CONFIRM_Integrated import get_computer_fingerprint

computer_id = get_computer_fingerprint()
print(f"Your current computer fingerprint: {computer_id}")
