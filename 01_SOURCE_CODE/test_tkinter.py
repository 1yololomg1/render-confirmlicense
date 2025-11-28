#!/usr/bin/env python3
"""
Test Tkinter installation and display
"""
import sys

print("Testing Tkinter installation...")
print()

try:
    import tkinter as tk
    print("[OK] tkinter imported successfully")
    print(f"  Tkinter version: {tk.TkVersion}")
    print(f"  Tcl version: {tk.TclVersion}")
    print()
    
    print("Creating test window...")
    root = tk.Tk()
    root.title("Tkinter Test")
    root.geometry("400x200")
    
    label = tk.Label(root, text="If you can see this window, Tkinter is working!", 
                    font=("Arial", 12))
    label.pack(pady=50)
    
    button = tk.Button(root, text="Close", command=root.destroy)
    button.pack()
    
    print("[OK] Test window created")
    print("  Window should be visible now")
    print("  Click 'Close' button to exit")
    print()
    
    root.mainloop()
    
    print("[OK] Tkinter test completed successfully")
    
except ImportError as e:
    print(f"[ERROR] Tkinter not installed: {e}")
    print()
    print("Tkinter is not available in your Python installation.")
    sys.exit(1)
    
except Exception as e:
    print(f"[ERROR] {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
