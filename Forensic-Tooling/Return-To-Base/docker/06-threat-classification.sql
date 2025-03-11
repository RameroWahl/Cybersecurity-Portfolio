-- Flag suspicious RAM processes (Injected DLLs or Suspicious Flags)
INSERT INTO threats (case_id, threat_type, risk_level, description, detected_at)
SELECT
    r.case_id,
    'Suspicious RAM Process' AS threat_type,
    CASE
        WHEN r.suspicious = TRUE THEN 'High'
        WHEN array_length(string_to_array(r.injected_dlls, ','), 1) > 0 THEN 'Critical'
        ELSE 'Low'
    END AS risk_level,
    CONCAT('Process "', r.process_name, '" (PID: ', r.pid, ') flagged as suspicious.') AS description,
    NOW()
FROM ram_analysis r
WHERE r.suspicious = TRUE OR array_length(string_to_array(r.injected_dlls, ','), 1) > 0;

-- Flag suspicious files (Hidden, Timestomped, or Unusual Permissions)
INSERT INTO threats (case_id, threat_type, risk_level, description, detected_at)
SELECT 
    f.case_id, 
    'Suspicious File' AS threat_type,
    CASE 
        WHEN f.hidden = TRUE THEN 'High'
        WHEN f.timestomped = TRUE THEN 'Critical'
        ELSE 'Medium'
    END AS risk_level,
    CONCAT('File "', f.file_name, '" located at "', f.file_path, '" is flagged as suspicious.') AS description,
    NOW()
FROM file_analysis f
WHERE f.hidden = TRUE OR f.timestomped = TRUE OR f.suspicious = TRUE;
