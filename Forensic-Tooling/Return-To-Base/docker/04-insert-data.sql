-- Insert sample forensic case
INSERT INTO cases (case_name, investigator, start_time, end_time, summary)
VALUES ('Test Case 001', 'John Doe', '2025-03-10 08:00:00', NULL, 'Initial forensic investigation started.');

-- Insert sample RAM analysis data
INSERT INTO ram_analysis (case_id, process_name, pid, parent_pid, suspicious, injected_dlls, extracted_data, created_at, detected_at)
VALUES 
(1, 'explorer.exe', 1234, 1000, FALSE, '{}', '', '2025-03-09 12:30:00', '2025-03-10 08:10:00'),
(1, 'malware.exe', 5678, 1234, TRUE, '{"trojan.dll"}', 'Suspicious activity detected', '2025-03-09 14:45:00', '2025-03-10 08:15:00');

-- Insert sample file analysis data
INSERT INTO file_analysis (case_id, file_path, file_name, owner, permissions, size, created_at, modified_at, accessed_at, hash_sha256, hidden, timestomped, alternate_data_streams, suspicious, detected_at)
VALUES 
(1, '/Users/Admin/Documents/', 'legit.docx', 'Admin', 'rw-r--r--', 102400, '2025-03-05 10:00:00', '2025-03-09 18:30:00', '2025-03-10 07:50:00', 'abc123...', FALSE, FALSE, FALSE, FALSE, '2025-03-10 08:20:00'),
(1, '/Users/Admin/System32/', 'malicious.exe', 'SYSTEM', 'rwxr-xr-x', 512000, '2025-03-08 15:00:00', '2025-03-09 22:00:00', '2025-03-10 08:00:00', 'xyz789...', TRUE, TRUE, TRUE, TRUE, '2025-03-10 08:25:00');

-- Insert sample detected threats
INSERT INTO threats (case_id, related_file_id, related_ram_id, threat_type, risk_level, description, detected_at)
VALUES 
(1, NULL, 2, 'Trojan', 'High', 'Detected malware running in RAM.', '2025-03-10 08:30:00'),
(1, 2, NULL, 'Backdoor', 'Critical', 'Malicious executable found in System32.', '2025-03-10 08:35:00');
