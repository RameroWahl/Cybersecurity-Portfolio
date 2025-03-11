# Forensic Tooling - Return-To-Base

## Overview
**Return-To-Base** is a forensic analysis tool designed to identify suspicious activity, malware, and anti-forensic techniques within a system. It operates by analyzing RAM processes, file system metadata, and extracting relevant threat intelligence. This project is part of the **Cybersecurity-Portfolio** repository under **Forensic-Tooling**.

---
## **Project Features**
🔍 **Core Capabilities:**
- **RAM Forensics**: Analyzes active processes, injected DLLs, and suspicious patterns.
- **File System Analysis**: Identifies hidden files, timestomping, and suspicious file behavior.
- **Threat Detection**: Classifies threats using forensic intelligence rules.
- **Structured Database Storage**: All forensic data is stored in a **PostgreSQL** database.
- **Automated Reporting**: Findings can be exported as **JSON, CSV, and PDF**.

---
## **File Structure**
📂 **Forensic-Tooling/** _(Root folder for all forensic tools)_
- 📂 **Return-To-Base/** _(Main forensic tool project)_
  - 📂 **docker/** _(Docker setup for PostgreSQL)_
  - 📜 `Dockerfile` _(Defines the containerized environment)_
  - 📜 `docker-compose.yml` _(Manages multi-container setup)_
  - 📂 **sql/** _(SQL scripts for forensic database)_
    - 📜 `01-postgres-init.sql` _(Database initialization script)_
    - 📜 `02-create-tables.sql` _(Defines forensic database schema)_
    - 📜 `03-classification-rules.sql` _(Threat classification rules)_
    - 📜 `04-insert-data.sql` _(Sample forensic case data)_
    - 📜 `05-case-retrieval.sql` _(Functions for retrieving forensic cases)_
    - 📜 `06-threat-classification.sql` _(Functions for automated threat detection)_
  - 📂 **python/** _(Python-based forensic automation)_
    - 📜 `forensic_analysis.py` _(Main forensic processing script)_
    - 📜 `report_generator.py` _(Automates forensic reports)_
  - 📜 `README.md` _(Documentation for **Return-To-Base**)_

---
## **Installation & Setup**
### **1️⃣ Clone the Repository**
```sh
$ git clone https://github.com/RameroWahl/Cybersecurity-Portfolio.git
$ cd Cybersecurity-Portfolio/Forensic-Tooling/Return-To-Base/
```

### **2️⃣ Setup Docker & PostgreSQL**
```sh
$ docker-compose up -d
```
> This launches PostgreSQL with the forensic database schema preloaded.

### **3️⃣ Verify Database**
```sh
$ docker exec -it return_to_base_db psql -U forensic_admin -d forensic_db -c "SELECT * FROM cases;"
```
> If you see an empty table or sample cases, the setup is successful.

---
## **Usage**
### **🔹 Running Forensic Analysis**
```sh
$ python python/forensic_analysis.py
```
> This script will analyze RAM, file system metadata, and classify threats.

### **🔹 Generating Reports**
```sh
$ python python/report_generator.py
```
> Generates a forensic report in **JSON, CSV, or PDF** format.

---
## **Contributions & Future Plans**
✅ **Current Status:**
- **Database setup is complete**.
- **Threat classification rules are active**.
- **Next step: Python-based forensic automation.**

🚀 **Planned Enhancements:**
- **GUI Integration** for ease of use.
- **Live Incident Response Mode** (Real-time monitoring).
- **More Threat Intelligence Modules**.

📢 **For contributions, open a PR or issue on GitHub!**

