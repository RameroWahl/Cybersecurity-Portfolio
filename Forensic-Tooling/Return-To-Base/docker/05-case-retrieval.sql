-- Find the Cases by ID and apply the ruleset.
CREATE OR REPLACE FUNCTION get_case_by_id(case_id_param INTEGER)
RETURNS TABLE (
    case_id INTEGER,
    case_name TEXT,
    investigator TEXT,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    summary TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM cases WHERE cases.case_id = case_id_param;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_ram_analysis_by_case(case_id_param INTEGER)
RETURNS TABLE (
    process_name TEXT,
    pid INTEGER,
    parent_pid INTEGER,
    suspicious BOOLEAN,
    injected_dlls TEXT,
    extracted_data TEXT,
    created_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT process_name, pid, parent_pid, suspicious, injected_dlls, extracted_data, created_at
    FROM ram_analysis
    WHERE ram_analysis.case_id = case_id_param
    ORDER BY created_at DESC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_file_analysis_by_case(case_id_param INTEGER)
RETURNS TABLE (
    file_id INTEGER,
    file_path TEXT,
    file_name TEXT,
    owner TEXT,
    permissions TEXT,
    size BIGINT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,
    accessed_at TIMESTAMP,
    hash_sha256 TEXT,
    hidden BOOLEAN,
    timestomped BOOLEAN,
    alternate_data_streams BOOLEAN,
    suspicious BOOLEAN,
    detected_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT file_id, file_path, file_name, owner, permissions, size, created_at, modified_at, accessed_at, 
           hash_sha256, hidden, timestomped, alternate_data_streams, suspicious, detected_at
    FROM file_analysis
    WHERE file_analysis.case_id = case_id_param
    ORDER BY suspicious DESC, modified_at DESC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_threats_by_case(case_id_param INTEGER)
RETURNS TABLE (
    threat_id INTEGER,
    threat_type TEXT,
    risk_level TEXT,
    description TEXT,
    detected_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT threat_id, threat_type, risk_level, description, detected_at
    FROM threats
    WHERE threats.case_id = case_id_param
    ORDER BY risk_level DESC, detected_at DESC;
END;
$$ LANGUAGE plpgsql;

