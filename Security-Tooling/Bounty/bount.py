import os, sys, time, base64, sqlite3, socket, ipaddress
from collections import Counter
from contextlib import contextmanager

import matplotlib.pyplot as plt
import networkx as nx
from PIL import Image
import piexif
import vt  # pip install vt-py

VT_API_KEY = os.getenv("VT_API_KEY")
DB_PATH = os.getenv("BOUNTY_DB", "network_logs.db")
VT_RATE_SLEEP = float(os.getenv("VT_RATE_SLEEP", "16"))  # ~4/min for public keys
ALERT_THRESHOLD = int(os.getenv("BOUNTY_ALERT_THRESHOLD", "10"))

# ---------- DB helpers ----------

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT, destination_ip TEXT, raw_log TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            threat_score INTEGER NOT NULL,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")

def save_log(conn, source_ip, destination_ip, raw_log):
    conn.execute(
        "INSERT INTO logs (source_ip, destination_ip, raw_log) VALUES (?,?,?)",
        (source_ip, destination_ip, raw_log)
    )

def get_cached_rep(conn, ip):
    row = conn.execute("SELECT threat_score FROM ip_reputation WHERE ip = ?", (ip,)).fetchone()
    return row[0] if row else None

def save_rep(conn, ip, score):
    conn.execute(
        "INSERT OR REPLACE INTO ip_reputation (ip, threat_score, last_checked) VALUES (?,?,CURRENT_TIMESTAMP)",
        (ip, score)
    )

# ---------- EXIF -> logs ----------

def get_image_path():
    appdata = os.getenv("APPDATA") or os.getenv("LOCALAPPDATA") or "."
    return os.path.join(appdata, "hidden_logs.png")

def load_image_exif(image_path):
    img = Image.open(image_path)
    exif_blob = img.info.get("exif")
    if not exif_blob:
        return {}
    return piexif.load(exif_blob)

def decode_logs(hidden_logs):
    decoded = []
    for line in hidden_logs.splitlines():
        s = line.strip()
        if not s or s == "Hidden Logs Initialized":
            continue
        try:
            s += "=" * (-len(s) % 4)
            decoded.append(base64.b64decode(s).decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return decoded

# ---------- Intel ----------

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False

def check_ip_virustotal_batch(conn, ips):
    """Check a set of public IPs; reuse client and sleep between calls to respect VT public limits."""
    if not VT_API_KEY:
        print("⚠️ VT_API_KEY not set; skipping VirusTotal checks.")
        return

    client = vt.Client(VT_API_KEY, timeout=30)
    try:
        for ip in sorted(ips):
            cached = get_cached_rep(conn, ip)
            if cached is not None:
                continue
            try:
                obj = client.get_object(f"/ip_addresses/{ip}")
                malicious = obj.last_analysis_stats.get("malicious", 0)
                print(f"🔍 VT {ip}: malicious={malicious}")
                save_rep(conn, ip, malicious)
            except Exception as e:
                print(f"⚠️ VT error for {ip}: {e}")
            time.sleep(VT_RATE_SLEEP)  # simple rate limiter
    finally:
        client.close()

# ---------- Analysis & viz ----------

def visualize_network(connections, my_ip):
    G = nx.DiGraph()
    for (src, dst), count in connections.items():
        G.add_edge(src, dst, weight=count)

    pos = nx.spring_layout(G, seed=1337)
    node_colors = []
    for n in G.nodes():
        if n == my_ip:
            node_colors.append("black")
        else:
            node_colors.append("darkblue")

    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_color=node_colors, edge_color='gray',
            font_color='white', width=1)
    nx.draw_networkx_edge_labels(G, pos, edge_labels={(u, v): d['weight'] for u, v, d in G.edges(data=True)}, font_size=8)
    plt.title("Network Connection Graph (directional)")
    plt.tight_layout()
    plt.show()

def alert_suspicious(conn):
    rows = conn.execute(
        "SELECT ip, threat_score FROM ip_reputation WHERE threat_score > ? ORDER BY threat_score DESC",
        (ALERT_THRESHOLD,)
    ).fetchall()
    for ip, score in rows:
        print(f"🚨 ALERT: High-risk IP detected! {ip} (Threat Score: {score})")

# ---------- Orchestration ----------

def process_logs():
    image_path = get_image_path()
    exif = load_image_exif(image_path)
    hidden = (exif.get("0th", {}).get(piexif.ImageIFD.ImageDescription, b"") or b"").decode("utf-8", errors="ignore")
    decoded_logs = decode_logs(hidden)

    my_ip = socket.gethostbyname(socket.gethostname())
    connections = Counter()
    candidate_vt_ips = set()

    with db() as conn:
        for log in decoded_logs:
            try:
                src, dst = [x.strip() for x in log.split(" -> ", 1)]
            except ValueError:
                continue
            save_log(conn, src, dst, log)
            connections[(src, dst)] += 1
            # VT only for public destination IPs (don’t leak internals)
            if is_public_ip(dst):
                candidate_vt_ips.add(dst)

        check_ip_virustotal_batch(conn, candidate_vt_ips)
        alert_suspicious(conn)

    visualize_network(connections, my_ip)

if __name__ == "__main__":
    init_db()
    process_logs()
