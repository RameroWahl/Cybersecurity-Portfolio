# Docker Setup for Return-To-Base

## Overview
This document provides instructions on how to set up and run the Docker container for **Return-To-Base**, a forensic analysis tool designed to identify threats within RAM and file systems. The setup ensures a structured PostgreSQL-based forensic data collection system.

---
## Prerequisites
- **Docker** (Ensure Docker is installed: [Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose** (Included in recent Docker Desktop versions)
- **Git** (For cloning the repository)

---
## Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/RameroWahl/Cybersecurity-Portfolio.git
cd Cybersecurity-Portfolio/Forensic-Tooling/Return-To-Base/docker
```

### 2️⃣ Configure Environment Variables
Create a `.env` file inside the `docker/` directory:
```bash
touch .env
```
Populate it with:
```
POSTGRES_USER=forensic_admin
POSTGRES_PASSWORD=SuperSecure123
POSTGRES_DB=forensic_db
```

### 3️⃣ Start the PostgreSQL Database
```bash
docker-compose up -d
```
This will:
✅ Start a PostgreSQL 14 container.
✅ Automatically execute SQL scripts to initialize the database.
✅ Expose PostgreSQL on **port 5432**.

### 4️⃣ Verify Setup
Check if the container is running:
```bash
docker ps
```
Expected output:
```
CONTAINER ID   IMAGE         COMMAND                  STATUS         PORTS                    NAMES
xxxxx          postgres:14   "docker-entrypoint.s…"   Up (healthy)   0.0.0.0:5432->5432/tcp   return_to_base_db
```

Verify tables are created:
```bash
docker exec -it return_to_base_db psql -U forensic_admin -d forensic_db -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
```
Expected output:
```
 table_name
------------
 cases
 ram_analysis
 file_analysis
 threats
(4 rows)
```

---
## Managing the Database
### Stop the Container
```bash
docker-compose down
```

### Remove Database Volume (Resets Data)
```bash
docker volume rm docker_postgres-data
```

### Restart Fresh Database
```bash
docker-compose up -d --force-recreate
```

---
## Troubleshooting
- **Container not starting?**
  ```bash
docker logs return_to_base_db
  ```
  Check logs for errors.
- **Database tables missing?**
  ```bash
docker exec -it return_to_base_db psql -U forensic_admin -d forensic_db -c "\dt"
  ```
  Ensure scripts executed correctly.
- **Port already in use?**
  ```bash
docker stop return_to_base_db && docker rm return_to_base_db
  ```
  Restart the container.

---
## Next Steps
Once the database is running, you can proceed with forensic data collection using the forensic processing scripts in the `src/` directory.

🚀 **Happy Hunting!**

