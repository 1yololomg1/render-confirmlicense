# How to Clear Saved License

The application saved a license key that doesn't exist or doesn't work anymore. Here's how to clear it:

## Windows Location

The saved license file is at:
```
%LOCALAPPDATA%\CONFIRM\confirm_license.json
```

Or full path:
```
C:\Users\[YourUsername]\AppData\Local\CONFIRM\confirm_license.json
```

## Quick Fix

1. **Close the CONFIRM application completely**

2. **Delete the license file:**
   - Press `Windows + R`
   - Type: `%LOCALAPPDATA%\CONFIRM`
   - Press Enter
   - Find `confirm_license.json`
   - Delete it (or rename it to `confirm_license.json.backup`)

3. **Restart the application**

4. **Enter a fresh license key:**
   - Use one of the unbound judge licenses from `JUDGE_LICENSE_KEYS.txt`
   - Or enter a new license key

## Alternative: Use a Different License

Instead of clearing, just enter one of these unbound judge licenses directly:

- `f0ab2a970a5da8ce:2026-04-11T11:59:51.774Z:345a2a93bcbf1e69`
- `6fe15926bc022b27:2026-04-11T12:00:20.254Z:da7129f9b475626b`
- Or any of the other 10 from `JUDGE_LICENSE_KEYS.txt`

These are unbound and will work on your current machine.

