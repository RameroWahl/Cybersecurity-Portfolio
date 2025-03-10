import sqlite3
import base64
import os
import sys
from collections import Counter
import socket
import requests
import matplotlib.pyplot as plt
import networkx as nx
from PIL import Image
import piexif
import vt
import time
import ssl
import os

# Manually specify CA bundle path
SSL_CERT_FILE = "C:/Python/certs/cacert.pem"
os.environ["SSL_CERT_FILE"] = SSL_CERT_FILE

# Create a custom SSL context
ssl_context = ssl.create_default_context(cafile=SSL_CERT_FILE)

# VirusTotal API Key (Replace with your actual key)
VT_API_KEY = os.getenv("VT_API_KEY")

# Database setup
def init_db():
    conn = sqlite3.connect("network_logs.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            raw_log TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            threat_score INTEGER,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Save logs to database
def save_log(source_ip, destination_ip, raw_log):
    conn = sqlite3.connect("network_logs.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (source_ip, destination_ip, raw_log) VALUES (?, ?, ?)",
                   (source_ip, destination_ip, raw_log))
    conn.commit()
    conn.close()

# Save IP reputation
def save_ip_reputation(ip, threat_score):
    conn = sqlite3.connect("network_logs.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO ip_reputation (ip, threat_score, last_checked) VALUES (?, ?, CURRENT_TIMESTAMP)",
                   (ip, threat_score))
    conn.commit()
    conn.close()

# Check if IP has already been analyzed
def is_ip_analyzed(ip):
    conn = sqlite3.connect("network_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT threat_score FROM ip_reputation WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Check IP reputation using VirusTotal API
def check_ip_virustotal(ip):
    if is_ip_analyzed(ip) is not None:
        return is_ip_analyzed(ip)
    
    client = vt.Client(VT_API_KEY, timeout=30)  # No need to specify SSL context explicitly

    try:
        ip_info = client.get_object(f"/ip_addresses/{ip}")
        malicious_count = ip_info.last_analysis_stats.get("malicious", 0)
        print(f"🔍 VirusTotal Report for {ip}: Malicious detections: {malicious_count}")
        save_ip_reputation(ip, malicious_count)
        time.sleep(15)  # Avoid API rate limits
        return malicious_count
    except Exception as e:
        print(f"⚠️ Error querying VirusTotal for {ip}: {e}")
        return None
    finally:
        client.close()


# Load logs from image metadata
def get_image_path():
    return os.path.join(os.getenv("APPDATA"), "hidden_logs.png")

def load_image_exif(image_path):
    img = Image.open(image_path)
    return piexif.load(img.info["exif"])

def decode_logs(hidden_logs):
    decoded_logs = []
    for log in hidden_logs.split('\n'):
        log = log.strip()
        if not log or log == "Hidden Logs Initialized":
            continue
        try:
            log += '=' * (-len(log) % 4)
            decoded_log = base64.b64decode(log).decode("utf-8")
            decoded_logs.append(decoded_log)
        except Exception:
            pass
    return decoded_logs

# Extract logs, save to DB, and analyze unique IPs
def process_logs():
    image_path = get_image_path()
    exif_data = load_image_exif(image_path)
    hidden_logs = exif_data["0th"].get(piexif.ImageIFD.ImageDescription, b"").decode("utf-8")
    decoded_logs = decode_logs(hidden_logs)

    connections = Counter()
    unique_ips = set()
    
    for log in decoded_logs:
        try:
            src, dst = log.split(" -> ")
            save_log(src, dst, log)
            connections[(src, dst)] += 1
            unique_ips.update([src, dst])
        except ValueError:
            continue
    
    for ip in unique_ips:
        check_ip_virustotal(ip)  # Only check unique IPs and store results
    
    visualize_network(connections, unique_ips)
    check_suspicious_ips()

# Visualize network graph
def visualize_network(connections, unique_ips):
    G = nx.Graph()
    for (src, dst), count in connections.items():
        G.add_edge(src, dst, weight=count)
    
    pos = nx.spring_layout(G)
    node_colors = []
    for node in G.nodes():
        if node == socket.gethostbyname(socket.gethostname()):
            node_colors.append("black")
        elif node in unique_ips:
            node_colors.append("darkblue")
        else:
            node_colors.append("white")
    
    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_color=node_colors, edge_color='gray',
            font_color='white', width=1, edge_cmap=plt.cm.Blues)
    plt.title("Network Connection Graph")
    plt.show()

# Check and alert on suspicious IPs
def check_suspicious_ips():
    conn = sqlite3.connect("network_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip, threat_score FROM ip_reputation WHERE threat_score > 10")
    suspicious_ips = cursor.fetchall()
    conn.close()
    
    for ip, score in suspicious_ips:
        print(f"🚨 ALERT: High-risk IP detected! {ip} (Threat Score: {score})")

if __name__ == "__main__":
    init_db()
    process_logs()