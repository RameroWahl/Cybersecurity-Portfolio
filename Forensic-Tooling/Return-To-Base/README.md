# Return to Base - Forensic Threat Analysis Tool

## Overview
**Return to Base** is a forensic threat analysis tool designed for **RAM and file system forensics**. It helps investigators detect **malware, backdoors, timestomping, hidden processes, and other forensic anomalies**. This tool provides a structured forensic database to store and analyze evidence.

## Features
- **Forensic Database**: Stores and categorizes forensic findings
- **RAM Analysis**: Identifies suspicious processes, injected DLLs, and memory-based threats
- **File System Forensics**: Detects timestomping, hidden files, and alternate data streams
- **Threat Classification**: Automated risk level assessment (Low, Medium, High, Critical)
- **Report Generation**: Generates forensic reports in JSON, CSV, and PDF
- **Dockerized Setup**: Fully containerized using PostgreSQL and SQL scripts

## Setup & Installation
### 1. Clone the Repository
```sh
git clone https://github.com/RameroWahl/Cybersecurity-Portfolio.git
cd Cybersecurity-Portfolio/Forensic-Tooling/Return-To-Base
```

### 2. Start the Dockerized Database
```sh
docker-compose up -d
```

### 3. Verify Database is Running
```sh
docker ps
```
Expected output should show `return_to_base_db` running.

### 4. Check If Tables Exist
```sh
docker exec -it return_to_base_db psql -U forensic_admin -d forensic_db -c "\dt"
```
Expected output:
```
           List of relations
 Schema |     Name       | Type  |  Owner  
--------+---------------+-------+----------
 public | cases         | table | forensic_admin
 public | ram_analysis  | table | forensic_admin
 public | file_analysis | table | forensic_admin
 public | threats       | table | forensic_admin
```

## How It Works
1. **Data Collection**
   - RAM snapshots are analyzed for suspicious processes.
   - Filesystem scans detect timestomping and hidden files.

2. **Threat Classification**
   - Identifies **Trojan, Backdoors, Suspicious Files & RAM Processes**
   - Assigns risk levels (**Low, Medium, High, Critical**)

3. **Report Generation**
   - Generates a **forensic summary report** (JSON, CSV, PDF) for analysts.

## Running Queries & Tests
Run forensic queries manually using:
```sh
docker exec -it return_to_base_db psql -U forensic_admin -d forensic_db -c "SELECT * FROM threats;"
```

Check specific forensic cases:
```sh
docker exec -it return_to_base_db psql -U forensic_admin -d forensic_db -c "SELECT * FROM get_case_by_id(1);"
```

## Contributors
- **Ramero Wahl** – Lead Developer & Forensics Architect

## License
This project is released under [MIT License](LICENSE). Use responsibly for forensic analysis only.

