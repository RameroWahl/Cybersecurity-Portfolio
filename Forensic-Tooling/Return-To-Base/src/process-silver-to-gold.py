from pymongo import MongoClient
from datetime import datetime, timezone

# Connect to MongoDB
client = MongoClient("mongodb://host.docker.internal:27017")
db = client["return_to_base"]

processed_logs = db["processed_logs"]  # Silver Tier
forensic_reports = db["forensic_reports"]  # Gold Tier

def classify_threat(process_tree):
    """Assigns risk levels based on process behaviors."""
    for process in process_tree:
        if "nc.exe" in process["name"].lower() or "backdoor" in process["name"].lower():
            return "Critical", "Detected potential backdoor access."
        if "cmd.exe" in process["name"].lower() and "powershell" in process["name"].lower():
            return "High", "Suspicious PowerShell execution detected."
        if process["risk_score"] == "Medium":
            return "Medium", "Potentially suspicious process found."
    return "Low", "No immediate threats detected."

def generate_forensic_reports():
    """Processes Silver Tier logs, classifies threats, and generates Gold Tier reports."""
    silver_entries = processed_logs.find()

    for entry in silver_entries:
        risk_level, threat_description = classify_threat(entry["process_tree"])

        report_entry = {
            "case_id": entry["case_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": entry["host"],
            "source": entry["source"],
            "risk_level": risk_level,
            "threat_description": threat_description,
            "metadata": entry["metadata"],
            "recommendation": "Isolate host and investigate." if risk_level in ["High", "Critical"] else "Monitor for further activity."
        }

        forensic_reports.insert_one(report_entry)
        print(f"🚨 Case {entry['case_id']} → Classified as {risk_level} → Moved to Gold Tier ✅")

        # Optional: Remove processed entry after classification
        processed_logs.delete_one({"_id": entry["_id"]})

if __name__ == "__main__":
    generate_forensic_reports()
