import time
import random
import requests
from datetime import datetime, timezone

# Central API URL (Change to your API server's IP if remote)
API_URL = "http://localhost:5000/upload_forensic_data"

def collect_forensic_data():
    """Collects forensic data and sends it to a remote API."""
    while True:
        forensic_entry = {
            "case_id": str(random.randint(100, 999)),  # Simulate unique case IDs
            "source": "system_scan",
            "data": f"Suspicious Process {random.randint(1000, 9999)}",
            "host": "monitored-device"
        }

        try:
            response = requests.post(API_URL, json=forensic_entry)
            if response.status_code == 200:
                print(f"📡 Sent forensic data → Case {forensic_entry['case_id']} (Stored in API) ✅")
            else:
                print(f"⚠️ Failed to send log: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")

        time.sleep(10)  # Adjust collection interval as needed

if __name__ == "__main__":
    collect_forensic_data()
