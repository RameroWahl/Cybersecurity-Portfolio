import psycopg2
import json
import os
from dotenv import load_dotenv

#load the environment variables
load_dotenv()

#Database connection details
DB_NAME = os.getenv('POSTGRES_DB', 'forensic_db')
DB_USER = os.getenv('POSTGRES_USER', 'forensic_admin')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'SuperSecure123')
DB_HOST = os.getenv('POSTGRES_HOST', 'host.docker.internal')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')

#establish database connection
def connect_db():
    try:
        conn = psycopg2.connect(dbname=DB_NAME, 
                                user=DB_USER, 
                                password=DB_PASSWORD, 
                                host=DB_HOST, 
                                port=DB_PORT)
        print('Connected to database')
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None
    
#fetch forensic case details
def get_case():
    conn = connect_db()
    if not conn:
        return
    
    cursor = conn.cursor()
    query = "SELECT * FROM cases;"
    cursor.execute(query)
    cases = cursor.fetchall()

    case_list = []
    for case in cases:
        case_list.append({
            "case_id": case[0],
            "case_name": case[1],
            "investigator": case[2],
            "start_time": case[3],
            "end_time": case[4],
            "summary": case[5]
        })

    cursor.close()
    conn.close()

    print(json.dumps(case_list, indent=4)) #return the case details in JSON format

# Fetch RAM analysis data
def get_ram_analysis():
    conn = connect_db()
    if not conn:
        return
    
    cursor = conn.cursor()
    query = "SELECT * FROM ram_analysis;"
    cursor.execute(query)
    ram_data = cursor.fetchall()

    ram_list = []
    for ram in ram_data:
        ram_list.append({
            "ram_id": ram[0],
            "case_id": ram[1],
            "process_name": ram[2],
            "pid": ram[3],
            "parent_pid": ram[4],
            "suspicious": ram[5],
            "injected_dlls": ram[6],
            "extracted_data": ram[7],
            "created_at": ram[8]
        })

    cursor.close()
    conn.close()

    print(json.dumps(ram_list, indent=4)) #return the RAM analysis data in JSON format

# Fetch File System Forensic Analysis
def get_file_analysis():
    conn = connect_db()
    if not conn:
        return
    
    cursor = conn.cursor()
    query = "SELECT * FROM file_analysis;"
    cursor.execute(query)
    file_data = cursor.fetchall()

    file_list = []
    for file in file_data:
        file_list.append({
            "file_id": file[0],
            "case_id": file[1],
            "file_path": file[2],
            "file_name": file[3],
            "owner": file[4],
            "permissions": file[5],
            "size": file[6],
            "created_at": file[7],
            "modified_at": file[8],
            "accessed_at": file[9],
            "hash_sha256": file[10],
            "hidden": file[11],
            "timestomped": file[12],
            "alternate_data_streams": file[13],
            "suspicious": file[14],
            "detected_at": file[15]
        })

    cursor.close()
    conn.close()

    print(json.dumps(file_list, indent=4)) #return the file system analysis data in JSON format

#Fetch Threat Reports
def get_threats():
    conn = connect_db()
    if not conn:
        return
    
    cursor = conn.cursor()
    query = "SELECT * FROM threats;"
    cursor.execute(query)
    threats = cursor.fetchall()

    threat_list = []
    for threat in threats:
        threat_list.append({
            "threat_id": threat[0],
            "case_id": threat[1],
            "related_file_id": threat[2],
            "related_ram_id": threat[3],
            "threat_type": threat[4],
            "risk_level": threat[5],
            "description": threat[6],
            "detected_at": threat[7]
        })

        cursor.close()
        conn.close()

        print(json.dumps(threat_list, indent=4)) #return the threat reports in JSON format

# MAIN Execution
if __name__ == "__main__":
    print("Fetching forensic case details...")
    get_case()
    print("Fetching RAM analysis data...")
    get_ram_analysis()
    print("Fetching File System Forensic Analysis...")
    get_file_analysis()
    print("Fetching Threat Reports...")
    get_threats()   