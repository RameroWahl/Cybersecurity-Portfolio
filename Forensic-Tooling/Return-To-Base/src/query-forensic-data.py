from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://host.docker.internal:27017")
db = client["return_to_base"]  # Select database

def query_collection(collection_name):
    """Fetches and prints all forensic entries from the specified collection."""
    collection = db[collection_name]
    results = collection.find()

    print(f"\n🔍 Querying {collection_name} Collection:\n")
    for entry in results:
        print(entry)

# Query each tier separately
if __name__ == "__main__":
    query_collection("raw_dumps")       # Bronze Tier
    query_collection("processed_logs")  # Silver Tier
    query_collection("forensic_reports")  # Gold Tier
