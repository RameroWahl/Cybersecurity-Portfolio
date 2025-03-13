from pymongo import MongoClient
from datetime import datetime, timezone

# Connect to MongoDB
client = MongoClient("mongodb://host.docker.internal:27017")
db = client["return_to_base"]

raw_dumps = db["raw_dumps"]  # Bronze Tier
processed_logs = db["processed_logs"]  # Silver Tier

def process_raw_data():
    """Processes forensic raw logs and moves structured data to Silver Tier."""
    raw_entries = raw_dumps.find()  # Get all raw forensic logs

    for entry in raw_entries:
        # Normalize timestamp
        timestamp = entry.get("timestamp", datetime.now(timezone.utc).isoformat())
        
        # Extract process information (Example: Basic metadata parsing)
        process_info = {
            "pid": entry.get("process_id", None),
            "name": entry.get("process_name", "Unknown"),
            "parent_pid": entry.get("parent_process_id", None),
            "risk_score": "Medium" if "suspicious" in entry.get("data", "").lower() else "Low"
        }

        # Create structured Silver-tier entry
        silver_entry = {
            "case_id": entry["case_id"],
            "timestamp": timestamp,
            "host": entry["host"],
            "source": entry["source"],
            "process_tree": [process_info],
            "metadata": {
                "extracted_hashes": entry.get("hashes", []),
                "suspicious_connections": entry.get("network_connections", [])
            }
        }

        # Insert cleaned data into Silver Tier
        processed_logs.insert_one(silver_entry)
        print(f"Processed Case {entry['case_id']} → Moved to Silver Tier ✅")

        # Optional: Remove raw entry after processing
        raw_dumps.delete_one({"_id": entry["_id"]})

if __name__ == "__main__":
    process_raw_data()
