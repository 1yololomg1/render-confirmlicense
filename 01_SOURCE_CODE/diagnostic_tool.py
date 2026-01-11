#!/usr/bin/env python3
"""
Machine Fingerprint Diagnostic Tool
Helps diagnose and resolve machine ID recognition issues
"""

import sys
import os
import platform
import uuid
import hashlib
import subprocess
import psutil

def get_old_fingerprint():
    """Original fingerprinting method"""
    try:
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0,2*6,2)][::-1])
        processor = platform.processor() or "unknown"
        computer_data = f"{mac_address}_{processor}"
        fingerprint = hashlib.md5(computer_data.encode()).hexdigest()[:12]
        return fingerprint
    except Exception as e:
        return f"ERROR: {e}"

def get_new_fingerprint():
    """New enhanced fingerprinting method"""
    try:
        identifiers = []
        
        # 1. Get first MAC address
        try:
            net_addrs = psutil.net_if_addrs()
            for interface_name, interface_addresses in net_addrs.items():
                for addr in interface_addresses:
                    if addr.family.name == 'AF_LINK' and not addr.address.startswith('00:00:00'):
                        identifiers.append(f"mac_{addr.address.replace(':', '')}")
                        break
                if identifiers:
                    break
        except Exception as e:
            identifiers.append(f"mac_ERROR: {e}")
        
        # 2. Motherboard serial
        if platform.system() == "Windows":
            try:
                result = subprocess.run(['wmic', 'baseboard', 'get', 'serialnumber'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    serial = result.stdout.split('\n')[1].strip()
                    if serial and serial != 'To be filled by O.E.M.':
                        identifiers.append(f"mb_{serial}")
                    else:
                        identifiers.append("mb_OEM")
            except Exception as e:
                identifiers.append(f"mb_ERROR: {e}")
        
        # 3. CPU ID
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['wmic', 'cpu', 'get', 'processorid'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    cpu_id = result.stdout.split('\n')[1].strip()
                    if cpu_id:
                        identifiers.append(f"cpu_{cpu_id}")
                    else:
                        identifiers.append("cpu_EMPTY")
            else:
                identifiers.append(f"proc_{platform.processor()}")
        except Exception as e:
            identifiers.append(f"cpu_ERROR: {e}")
        
        # 4. Disk serial
        try:
            disk_partitions = psutil.disk_partitions()
            if disk_partitions:
                system_drive = disk_partitions[0].device
                disk_usage = psutil.disk_usage(system_drive)
                identifiers.append(f"disk_{hash(str(disk_usage.total))}")
        except Exception as e:
            identifiers.append(f"disk_ERROR: {e}")
        
        combined_data = "_".join(sorted(identifiers))
        fingerprint = hashlib.sha256(combined_data.encode()).hexdigest()[:16]
        return fingerprint, identifiers
    except Exception as e:
        return f"ERROR: {e}", []

def main():
    print("=" * 60)
    print("MACHINE FINGERPRINT DIAGNOSTIC TOOL")
    print("=" * 60)
    
    print(f"\nSystem Information:")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  Machine: {platform.machine()}")
    print(f"  Processor: {platform.processor()}")
    print(f"  Python: {platform.python_version()}")
    
    print(f"\nNetwork Interfaces:")
    try:
        net_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in net_addrs.items():
            for addr in interface_addresses:
                if addr.family.name == 'AF_LINK':
                    print(f"  {interface_name}: {addr.address}")
    except Exception as e:
        print(f"  ERROR: {e}")
    
    print(f"\nFingerprint Comparison:")
    old_fp = get_old_fingerprint()
    new_fp, identifiers = get_new_fingerprint()
    
    print(f"  Old Method: {old_fp}")
    print(f"  New Method: {new_fp}")
    
    if isinstance(new_fp, tuple):
        new_fp = new_fp[0]
        identifiers = new_fp[1]
    
    print(f"\nIdentifiers Used:")
    for ident in identifiers:
        print(f"  {ident}")
    
    print(f"\nHardware Details:")
    if platform.system() == "Windows":
        try:
            print(f"  Motherboard Serial:")
            result = subprocess.run(['wmic', 'baseboard', 'get', 'serialnumber'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                serial = result.stdout.split('\n')[1].strip()
                print(f"    {serial}")
            
            print(f"  CPU ID:")
            result = subprocess.run(['wmic', 'cpu', 'get', 'processorid'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                cpu_id = result.stdout.split('\n')[1].strip()
                print(f"    {cpu_id}")
        except Exception as e:
            print(f"  ERROR: {e}")
    
    print(f"\nRecommendations:")
    if old_fp != new_fp:
        print("  ⚠️  Fingerprints differ - this explains the license recognition issue!")
        print("  ✅ The new method is more stable and should resolve future issues")
        print("  📧 Send both fingerprints to support for manual license migration")
    else:
        print("  ✅ Fingerprints match - no migration needed")
    
    print(f"\nNext Steps:")
    print("  1. Send this output to your software provider")
    print("  2. They will migrate your license to the new fingerprint")
    print("  3. Install the updated software build")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
