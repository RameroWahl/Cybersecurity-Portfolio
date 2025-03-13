from pymongo import MongoClient
from datetime import datetime, timezone

# Connect to MongoDB
client = MongoClient("mongodb://host.docker.internal:27017")
db = client["return_to_base"]
raw_dumps = db["raw_dumps"]

# Example forensic data (Replace with real logs later)
forensic_entry = {
    "case_id": "001",
    "timestamp": datetime.now(timezone.utc).isoformat(),  
    "source": "memory_dump",
    "data": "<RAW_MEMORY_HEX>",
    "host": "suspicious-laptop-01"
}

# Insert data into MongoDB
insert_result = raw_dumps.insert_one(forensic_entry)
print(f"Inserted Forensic Entry with ID: {insert_result.inserted_id}")
