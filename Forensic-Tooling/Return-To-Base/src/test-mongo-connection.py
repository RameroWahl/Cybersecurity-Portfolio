import os
from pymongo import MongoClient

# Check if running inside Docker
DOCKER_ENV = os.path.exists("/.dockerenv")

if DOCKER_ENV:
    MONGO_HOST = "return_to_base_mongo"  # Default MongoDB container name in Docker
else:
    MONGO_HOST = os.getenv("MONGO_HOST", "localhost")  # Use localhost if running outside Docker

MONGO_PORT = os.getenv("MONGO_PORT", "27017")

# Construct the MongoDB URI
mongo_uri = f"mongodb://{MONGO_HOST}:{MONGO_PORT}"
client = MongoClient(mongo_uri)

db = client["return_to_base"]

# Test inserting a dummy log
test_entry = {"message": "Universal MongoDB connection successful!"}
db.test_collection.insert_one(test_entry)

# Fetch and print test entry
print(f"✅ Connection successful! MongoDB at {mongo_uri}")
for entry in db.test_collection.find():
    print(entry)

# Compare this snippet from Cybersecurity-Portfolio/Forensic-Tooling/Return-To-Base/docker-compose.yml:
# version: "3.8"

# Define services
'''
services:
  mongodb:
    image: mongo:latest
    container_name: mongodb
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db

  forensic_api:
    build: .
    container_name: forensic_api
    ports:
      - "5000:5000"
    depends_on:
      - mongodb

  process_data:
    build: .
    container_name: process_data
    depends_on:
      - mongodb

  query_data:
    build: .
    container_name: query_data
    depends_on:
      - mongodb

  insert_data:
    build: .
    container_name: insert_data
    depends_on:
      - mongodb'
      '''
# Define volumes
'''
volumes:
  mongodb_data:
'''