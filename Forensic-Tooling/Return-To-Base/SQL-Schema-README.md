# SQL Schema for Return-To-Base

## Overview
This document describes the database schema used in **Return-To-Base**, detailing each table, its purpose, and relationships. The database is structured to store forensic case data, RAM analysis, file system metadata, and detected threats.

---
## **Database: `forensic_db`**

### 1️⃣ **Table: `cases`** (Tracks forensic investigations)
| Column      | Type        | Description |
|------------|------------|-------------|
| case_id    | SERIAL PRIMARY KEY | Unique case identifier |
| case_name  | TEXT NOT NULL | Name assigned to the forensic case |
| investigator | TEXT NOT NULL | Name of the investigator |
| start_time | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | Time investigation started |
| end_time   | TIMESTAMP | Time investigation ended (nullable) |
| summary    | TEXT | Case summary |

### 2️⃣ **Table: `ram_analysis`** (Tracks suspicious processes in RAM)
| Column      | Type        | Description |
|------------|------------|-------------|
| ram_id     | SERIAL PRIMARY KEY | Unique process record identifier |
| case_id    | INT REFERENCES cases(case_id) ON DELETE CASCADE | Associated forensic case |
| process_name | TEXT NOT NULL | Name of the process analyzed |
| pid        | INT | Process ID |
| parent_pid | INT | Parent process ID |
| suspicious | BOOLEAN DEFAULT FALSE | Whether process is marked suspicious |
| injected_dlls | TEXT | DLLs injected into the process (nullable) |
| extracted_data | TEXT | Any extracted data from process memory |
| created_at | TIMESTAMP | When the process was originally created |
| detected_at | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | When process was flagged |

### 3️⃣ **Table: `file_analysis`** (Tracks suspicious files in the system)
| Column      | Type        | Description |
|------------|------------|-------------|
| file_id    | SERIAL PRIMARY KEY | Unique file record identifier |
| case_id    | INT REFERENCES cases(case_id) ON DELETE CASCADE | Associated forensic case |
| file_path  | TEXT NOT NULL | Full path of the file |
| file_name  | TEXT NOT NULL | Name of the file |
| owner      | TEXT | File owner (nullable) |
| permissions | TEXT | File permissions (nullable) |
| size       | BIGINT | File size in bytes |
| created_at | TIMESTAMP | When the file was originally created |
| modified_at | TIMESTAMP | Last modification time |
| accessed_at | TIMESTAMP | Last accessed time |
| hash_sha256 | TEXT | SHA-256 hash for integrity verification |
| hidden     | BOOLEAN DEFAULT FALSE | Whether the file is hidden |
| timestomped | BOOLEAN DEFAULT FALSE | Whether timestamps have been altered |
| alternate_data_streams | BOOLEAN DEFAULT FALSE | Whether ADS is present |
| suspicious | BOOLEAN DEFAULT FALSE | Whether file is marked suspicious |
| detected_at | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | When file was flagged |

### 4️⃣ **Table: `threats`** (Tracks threats identified during forensic analysis)
| Column      | Type        | Description |
|------------|------------|-------------|
| threat_id  | SERIAL PRIMARY KEY | Unique threat identifier |
| case_id    | INT REFERENCES cases(case_id) ON DELETE CASCADE | Associated forensic case |
| related_file_id | INT REFERENCES file_analysis(file_id) ON DELETE SET NULL | Related file (nullable) |
| related_ram_id | INT REFERENCES ram_analysis(ram_id) ON DELETE SET NULL | Related process (nullable) |
| threat_type | TEXT NOT NULL | Type of threat (Malware, Rootkit, etc.) |
| risk_level | TEXT CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')) | Risk assessment |
| description | TEXT | Explanation of the threat |
| detected_at | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | When threat was identified |

---
## **Relationships & Constraints**
- **Foreign Keys**:
  - `ram_analysis.case_id` → `cases.case_id`
  - `file_analysis.case_id` → `cases.case_id`
  - `threats.case_id` → `cases.case_id`
  - `threats.related_file_id` → `file_analysis.file_id`
  - `threats.related_ram_id` → `ram_analysis.ram_id`
- **Cascade Deletes**:
  - Deleting a case removes associated RAM & file analysis records.
  - Threats linked to files/processes will have `related_file_id`/`related_ram_id` set to `NULL` upon deletion.
- **Risk Classification**:
  - Threat `risk_level` follows `('Low', 'Medium', 'High', 'Critical')`

---
## **Next Steps**
- The database is now structured and ready for forensic analysis.
- Next, Python scripts will interact with this schema to collect and analyze forensic data.

🚀 **Structured, Secure, and Ready for Forensics!**

