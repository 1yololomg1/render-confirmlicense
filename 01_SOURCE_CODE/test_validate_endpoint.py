import requests
import json

# Test the validation endpoint
LICENSE_SERVER_URL = "https://render-confirmlicense.onrender.com"
license_key = "dfc2077dbbad862a:2026-11-14T00:33:42.003Z:038b17a3dbc81f44"
machine_id = "test-machine-id"

print("Testing license validation endpoint...")
print(f"URL: {LICENSE_SERVER_URL}/validate")
print(f"License key: {license_key}")
print(f"Machine ID: {machine_id}")
print()

try:
    response = requests.post(
        f"{LICENSE_SERVER_URL}/validate",
        headers={'Content-Type': 'application/json'},
        json={'license_key': license_key, 'machine_id': machine_id},
        timeout=15
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print()
    print("Response Body:")
    print(json.dumps(response.json(), indent=2))
    
except requests.exceptions.Timeout:
    print("ERROR: Request timed out (>15 seconds)")
except requests.exceptions.ConnectionError as e:
    print(f"ERROR: Connection failed: {e}")
except requests.exceptions.RequestException as e:
    print(f"ERROR: Request failed: {e}")
    print(f"Response text (if any): {e.response.text if hasattr(e, 'response') and e.response else 'N/A'}")
except Exception as e:
    print(f"ERROR: Unexpected error: {e}")
