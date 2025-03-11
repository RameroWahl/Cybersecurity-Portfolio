-- Classify 'Low' Suspicion Files
SELECT file_id, file_name, file_path, hidden, timestomped
FROM file_analysis
WHERE hidden = TRUE AND timestomped = FALSE AND suspicious = FALSE;

-- Classify 'Medium' Suspicion RAM Processes
SELECT ram_id, process_name, pid, parent_pid, suspicious
FROM ram_analysis
WHERE suspicious = TRUE AND injected_dlls IS NOT NULL;

-- Classify 'High' Risk Level Threats
SELECT threat_id, threat_type, risk_level, description
FROM threats
WHERE risk_level = 'High';

-- Classify 'Critical' Risk Level Threats
INSERT INTO threats (case_id, threat_type, risk_level, description, detected_at)
SELECT 
    f.case_id, 
    CASE 
        WHEN f.timestomped = TRUE THEN 'Timestomping'
        WHEN f.hidden = TRUE THEN 'Hidden Process'
        ELSE 'Unknown Critical'
    END AS threat_type,
    'Critical' AS risk_level,
    CONCAT('Critical threat detected: ', f.file_name, ' at ', f.file_path) AS description,
    NOW()
FROM file_analysis f
WHERE f.timestomped = TRUE OR f.hidden = TRUE;

-- Classify Backdoors as 'Critical'
INSERT INTO threats (case_id, threat_type, risk_level, description, detected_at)
SELECT 
    r.case_id, 
    'Backdoor' AS threat_type,
    'Critical' AS risk_level,
    CONCAT('Backdoor process detected: ', r.process_name, ' (PID: ', r.pid, ')') AS description,
    NOW()
FROM ram_analysis r
WHERE r.process_name ILIKE '%backdoor%' OR r.process_name ILIKE '%nc.exe%';
