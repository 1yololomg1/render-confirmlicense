#!/usr/bin/env python3
"""
Stable Machine Fingerprinting Algorithm
More reliable hardware identification that preserves existing licenses
"""

import hashlib
import platform
import subprocess
import psutil
import uuid

def get_stable_fingerprint():
    """
    Generate a stable machine fingerprint using reliable hardware identifiers
    This method is designed to minimize changes while maintaining uniqueness
    """
    try:
        stable_identifiers = []
        
        # 1. CPU Information (most stable)
        try:
            if platform.system() == "Windows":
                # Get CPU serial number (most stable)
                result = subprocess.run(['wmic', 'cpu', 'get', 'processorid'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    cpu_id = result.stdout.split('\n')[1].strip()
                    if cpu_id and cpu_id != 'ProcessorId':
                        stable_identifiers.append(f"cpu_{cpu_id}")
                    else:
                        # Fallback to processor name
                        proc_info = platform.processor()
                        if proc_info:
                            stable_identifiers.append(f"proc_{proc_info}")
                else:
                    # Fallback to processor name
                    proc_info = platform.processor()
                    if proc_info:
                        stable_identifiers.append(f"proc_{proc_info}")
            else:
                # Non-Windows systems
                proc_info = platform.processor()
                if proc_info:
                    stable_identifiers.append(f"proc_{proc_info}")
        except Exception:
            # CPU info is critical, add a marker if it fails
            stable_identifiers.append("cpu_UNAVAILABLE")
        
        # 2. Motherboard Information (very stable)
        try:
            if platform.system() == "Windows":
                # Try motherboard serial first
                result = subprocess.run(['wmic', 'baseboard', 'get', 'serialnumber'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    serial = result.stdout.split('\n')[1].strip()
                    if serial and serial != 'To be filled by O.E.M.' and serial != 'SerialNumber':
                        stable_identifiers.append(f"mb_{serial}")
                    else:
                        # Fallback to motherboard manufacturer
                        result = subprocess.run(['wmic', 'baseboard', 'get', 'manufacturer'], 
                                              capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            manufacturer = result.stdout.split('\n')[1].strip()
                            if manufacturer and manufacturer != 'Manufacturer':
                                stable_identifiers.append(f"mbm_{manufacturer}")
        except Exception:
            # Motherboard info failed, but don't add marker (optional)
            pass
        
        # 3. System Information (stable)
        try:
            # Add system UUID if available
            if platform.system() == "Windows":
                result = subprocess.run(['wmic', 'csproduct', 'get', 'uuid'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    system_uuid = result.stdout.split('\n')[1].strip()
                    if system_uuid and system_uuid != 'UUID':
                        stable_identifiers.append(f"uuid_{system_uuid}")
        except Exception:
            pass
        
        # 4. Memory Information (stable)
        try:
            memory = psutil.virtual_memory()
            if memory.total:
                # Use total memory as a stable identifier
                stable_identifiers.append(f"mem_{memory.total}")
        except Exception:
            pass
        
        # 5. Fallback to original method if no stable identifiers found
        if not stable_identifiers:
            stable_identifiers.append("fallback")
            # Use original method as fallback
            mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                                   for elements in range(0,2*6,2)][::-1])
            processor = platform.processor() or "unknown"
            computer_data = f"{mac_address}_{processor}"
            fallback_fp = hashlib.md5(computer_data.encode()).hexdigest()[:12]
            stable_identifiers.append(f"old_{fallback_fp}")
        
        # Create stable fingerprint
        combined_data = "_".join(sorted(stable_identifiers))
        fingerprint = hashlib.sha256(combined_data.encode()).hexdigest()[:16]
        
        return fingerprint, stable_identifiers
        
    except Exception as e:
        # Ultimate fallback
        return f"ERROR_{hashlib.md5(str(e).encode()).hexdigest()[:8]}", []

def get_legacy_fingerprint():
    """Original fingerprint method for compatibility"""
    try:
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0,2*6,2)][::-1])
        processor = platform.processor() or "unknown"
        computer_data = f"{mac_address}_{processor}"
        fingerprint = hashlib.md5(computer_data.encode()).hexdigest()[:12]
        return fingerprint
    except Exception:
        return "ERROR_LEGACY"

def get_current_fingerprint():
    """Current (unstable) fingerprint method"""
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

def compare_all_methods():
    """Compare all fingerprinting methods"""
    print("=" * 80)
    print("COMPREHENSIVE FINGERPRINT ANALYSIS")
    print("=" * 80)
    
    print(f"\nSystem Information:")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  Machine: {platform.machine()}")
    print(f"  Processor: {platform.processor()}")
    
    # Legacy method
    legacy_fp = get_legacy_fingerprint()
    print(f"\n🔹 LEGACY Method (Original):")
    print(f"  Fingerprint: {legacy_fp}")
    
    # Current method
    current_fp, current_ids = get_current_fingerprint()
    print(f"\n🔹 CURRENT Method (Unstable):")
    print(f"  Fingerprint: {current_fp}")
    print(f"  Identifiers: {current_ids}")
    
    # Stable method
    stable_fp, stable_ids = get_stable_fingerprint()
    print(f"\n🔹 STABLE Method (New):")
    print(f"  Fingerprint: {stable_fp}")
    print(f"  Identifiers: {stable_ids}")
    
    # Comparison
    print(f"\n📊 Comparison:")
    print(f"  Legacy vs Current: {'✅ SAME' if legacy_fp == current_fp else '❌ DIFFERENT'}")
    print(f"  Legacy vs Stable: {'✅ SAME' if legacy_fp == stable_fp else '❌ DIFFERENT'}")
    print(f"  Current vs Stable: {'✅ SAME' if current_fp == stable_fp else '❌ DIFFERENT'}")
    
    # Recommendation
    print(f"\n💡 Recommendation:")
    if legacy_fp == stable_fp:
        print("  ✅ Stable method matches legacy - no migration needed!")
    elif current_fp == stable_fp:
        print("  ⚠️  Stable method matches current - still unstable")
    else:
        print("  🔄 Stable method is different - one-time migration recommended")
    
    return {
        'legacy': legacy_fp,
        'current': current_fp,
        'stable': stable_fp,
        'stable_identifiers': stable_ids
    }

if __name__ == "__main__":
    compare_all_methods()
