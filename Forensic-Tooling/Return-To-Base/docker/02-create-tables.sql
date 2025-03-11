-- Cases Table (Forensic Investigation Metadata)
CREATE TABLE cases (
    case_id SERIAL PRIMARY KEY,
    case_name TEXT NOT NULL,
    investigator TEXT NOT NULL,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    end_time TIMESTAMP,
    summary TEXT
);

-- RAM Analysis Table (Processes in Memory)
CREATE TABLE ram_analysis (
    ram_id SERIAL PRIMARY KEY,
    case_id INT REFERENCES cases(case_id) ON DELETE CASCADE,
    process_name TEXT NOT NULL,
    pid INT,
    parent_pid INT,
    suspicious BOOLEAN DEFAULT FALSE,
    injected_dlls TEXT,
    extracted_data TEXT,
    created_at TIMESTAMP, 
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  
);

-- File Analysis Table (Filesystem Forensics)
CREATE TABLE file_analysis (
    file_id SERIAL PRIMARY KEY,
    case_id INT REFERENCES cases(case_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    owner TEXT,
    permissions TEXT,
    size BIGINT,
    created_at TIMESTAMP, 
    modified_at TIMESTAMP,
    accessed_at TIMESTAMP,
    hash_sha256 TEXT,
    hidden BOOLEAN DEFAULT FALSE,
    timestomped BOOLEAN DEFAULT FALSE,
    alternate_data_streams BOOLEAN DEFAULT FALSE,
    suspicious BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  
);

-- Threats Table (Detected Threats)
CREATE TABLE threats (
    threat_id SERIAL PRIMARY KEY,
    case_id INT REFERENCES cases(case_id) ON DELETE CASCADE,
    related_file_id INT REFERENCES file_analysis(file_id) ON DELETE SET NULL,
    related_ram_id INT REFERENCES ram_analysis(ram_id) ON DELETE SET NULL,
    threat_type TEXT NOT NULL,
    risk_level TEXT CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
    description TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
