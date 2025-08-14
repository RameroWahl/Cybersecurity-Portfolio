# ctw.py
import tkinter as tk
import threading, queue, time, base64, os, sys, re, uuid
from datetime import datetime, timezone
from PIL import Image
import piexif

from scapy.all import sniff, IP  # requires Npcap (Windows) / root perms (Linux)

APP_EXIF_KEY = piexif.ImageIFD.ImageDescription
APP_IMG_BASENAME = "hidden_logs"
APP_IMG_EXT = ".png"
APP_MAX_EXIF_BYTES = 64 * 1024        # ~64KB cap per image
WRITE_BATCH_SIZE = 100                 # base64 lines per flush
SNIFF_SLICE_SEC = 2.0                  # short capture windows
DEFAULT_BPF = ""                       # e.g., "tcp and host 127.0.0.1"

def appdata_path(name):
    base = os.getenv("APPDATA") or os.getcwd()
    return os.path.join(base, name)

def ensure_img(path):
    if not os.path.exists(path):
        img = Image.new("RGB", (100, 100), color=(255, 255, 255))
        exif_dict = {"0th": {APP_EXIF_KEY: "Hidden Logs Initialized".encode("utf-8")}}
        img.save(path, exif=piexif.dump(exif_dict))

def rotate_if_needed(path):
    """If EXIF payload too large, create a new numbered file."""
    try:
        img = Image.open(path)
        exif_blob = img.info.get("exif")
        if not exif_blob:
            return path
        ex = piexif.load(exif_blob)
        payload = ex["0th"].get(APP_EXIF_KEY, b"")
        if len(payload) < APP_MAX_EXIF_BYTES:
            return path
    except Exception:
        pass
    base, ext = os.path.splitext(path)
    n = 1
    while os.path.exists(f"{base}_{n}{ext}"):
        n += 1
    new_path = f"{base}_{n}{ext}"
    ensure_img(new_path)
    return new_path

class SecretCalculator:
    def __init__(self, master):
        self.master = master
        master.title("Calculator")

        self.entry = tk.Entry(master, width=40, borderwidth=5)
        self.entry.grid(row=0, column=0, columnspan=4)

        self._build_buttons()

        self.secret_ui_visible = False
        self.sniffing_enabled = False
        self.stop_event = threading.Event()
        self.write_q = queue.Queue()
        self.bpf_filter = tk.StringVar(value=DEFAULT_BPF)

        # Session/audit
        self.current_session_id = None
        self.operator = os.getenv("CTW_OPERATOR", os.getenv("USERNAME", "unknown"))
        self.purpose  = os.getenv("CTW_PURPOSE", "demo")

        # image path
        self.image_path = appdata_path(APP_IMG_BASENAME + APP_IMG_EXT)
        ensure_img(self.image_path)

        # writer & sniffer supervisors
        self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer_thread.start()
        self.sniffer_thread = threading.Thread(target=self._sniffer_supervisor, daemon=True)
        self.sniffer_thread.start()

    # ---------- UI ----------
    def _build_buttons(self):
        buttons = [
            ('7', 1, 0), ('8', 1, 1), ('9', 1, 2), ('/', 1, 3),
            ('4', 2, 0), ('5', 2, 1), ('6', 2, 2), ('*', 2, 3),
            ('1', 3, 0), ('2', 3, 1), ('3', 3, 2), ('-', 3, 3),
            ('0', 4, 0), ('.', 4, 1), ('=', 4, 2), ('+', 4, 3),
            ('sqrt', 5, 2)
        ]
        for (text, r, c) in buttons:
            tk.Button(self.master, text=text, width=10, height=3,
                      command=lambda t=text: self.on_button_click(t)).grid(row=r, column=c)

        tk.Button(self.master, text='C', width=10, height=3,
                  command=self.clear_entry).grid(row=5, column=0, columnspan=2)

        # Secret controls (hidden until unlocked via sqrt(1337))
        self.secret_button = tk.Button(self.master, text="View Logs", width=20, height=2, command=self.show_logs)
        self.secret_button.grid(row=6, column=0, columnspan=4); self.secret_button.grid_remove()

        self.sniff_toggle_button = tk.Button(self.master, text="Enable Sniffing", width=20, height=2,
                                             command=self.toggle_sniffing)
        self.sniff_toggle_button.grid(row=7, column=0, columnspan=4); self.sniff_toggle_button.grid_remove()

        self.filter_label = tk.Label(self.master, text="Filter (BPF):"); self.filter_label.grid(row=8, column=0, sticky="e"); self.filter_label.grid_remove()
        self.filter_entry = tk.Entry(self.master, textvariable=self.bpf_filter, width=30)
        self.filter_entry.grid(row=8, column=1, columnspan=3, sticky="w"); self.filter_entry.grid_remove()

    def on_button_click(self, char):
        if char == '=':
            expr = self.entry.get().strip()
            if expr == "sqrt(1337)":
                self.unlock_secret_ui()
            try:
                result = self._safe_eval(expr)
                self.entry.delete(0, tk.END); self.entry.insert(tk.END, str(result))
            except Exception:
                self.entry.delete(0, tk.END); self.entry.insert(tk.END, "Error")
        elif char == 'sqrt':
            txt = self.entry.get().strip() or "0"
            self.entry.delete(0, tk.END); self.entry.insert(tk.END, f"sqrt({txt})")
        else:
            self.entry.insert(tk.END, char)

    def _safe_eval(self, expr: str):
        # Allow digits, (), ., + - * / and sqrt()
        if not re.fullmatch(r"[0-9\.\+\-\*/\(\)\s]*|(sqrt\(\d+(\.\d+)?\))", expr.replace("sqrt", "sqrt")):
            raise ValueError("invalid")
        if "sqrt" in expr:
            m = re.fullmatch(r"sqrt\((\d+(\.\d+)?)\)", expr)
            if not m: raise ValueError("invalid")
            return float(m.group(1)) ** 0.5
        return eval(expr, {"__builtins__": {}})

    def clear_entry(self):
        self.entry.delete(0, tk.END)

    def unlock_secret_ui(self):
        if self.secret_ui_visible: return
        self.secret_ui_visible = True
        self.secret_button.grid()
        self.sniff_toggle_button.grid()
        self.filter_label.grid()
        self.filter_entry.grid()

    def show_logs(self):
        try:
            img = Image.open(self.image_path)
            exif_blob = img.info.get("exif")
            if not exif_blob:
                self._popup("Captured Logs", "No logs found."); return
            ex = piexif.load(exif_blob)
            payload = ex["0th"].get(APP_EXIF_KEY, b"").decode("utf-8", errors="ignore")
            self._popup("Captured Logs", payload if payload else "No logs found.")
        except Exception as e:
            self._popup("Captured Logs", f"Error reading logs: {e}")

    def _popup(self, title, msg):
        top = tk.Toplevel(self.master); top.title(title)
        tk.Message(top, text=msg, width=500, padx=10, pady=10).pack()
        tk.Button(top, text="Close", command=top.destroy).pack(pady=5)

    # ---------- Session/audit helpers ----------
    def _now(self):
        return datetime.now(timezone.utc).isoformat()

    def _append_exif_line(self, line: str):
        target = rotate_if_needed(self.image_path)
        if target != self.image_path:
            self.image_path = target
        try:
            img = Image.open(self.image_path)
            exif_blob = img.info.get("exif")
            ex = piexif.load(exif_blob) if exif_blob else {"0th": {}}
            existing = ex["0th"].get(APP_EXIF_KEY, b"").decode("utf-8", errors="ignore")
            payload = (existing + ("\n" if existing else "") + line).encode("utf-8")
            ex["0th"][APP_EXIF_KEY] = payload
            img.save(self.image_path, exif=piexif.dump(ex))
        except Exception:
            pass

    # ---------- Sniffer ----------
    def toggle_sniffing(self):
        self.sniffing_enabled = not self.sniffing_enabled
        self.sniff_toggle_button.config(text="Disable Sniffing" if self.sniffing_enabled else "Enable Sniffing")
        if not self.sniffing_enabled:
            if self.current_session_id:
                self._append_exif_line(f"#SESSION END id={self.current_session_id} ended_at={self._now()}")
            self.stop_event.set()
            self.current_session_id = None
        else:
            self.stop_event.clear()
            self.current_session_id = str(uuid.uuid4())
            filt = (self.bpf_filter.get() or "").replace(" ", "_")
            self._append_exif_line(
                f"#SESSION START id={self.current_session_id} operator={self.operator} "
                f"purpose={self.purpose} filter={filt} started_at={self._now()}"
            )

    def _sniffer_supervisor(self):
        """Run small timeboxed sniffs repeatedly while enabled; non-blocking."""
        while True:
            if not self.sniffing_enabled:
                time.sleep(0.2); continue
            try:
                sniff(timeout=SNIFF_SLICE_SEC,
                      prn=self._process_packet,
                      store=False,
                      filter=self.bpf_filter.get() or None)
            except PermissionError:
                self._popup("Notice", "Packet capture requires Npcap and admin privileges on Windows.")
                self.sniffing_enabled = False
                self.sniff_toggle_button.config(text="Enable Sniffing")
            except Exception:
                time.sleep(0.2)

    def _process_packet(self, pkt):
        if IP in pkt:
            line = f"{pkt[IP].src} -> {pkt[IP].dst}"
            enc = base64.b64encode(line.encode()).decode()
            self.write_q.put(enc)

    # ---------- Writer ----------
    def _writer_loop(self):
        batch = []
        while True:
            try:
                item = self.write_q.get(timeout=0.5)
                batch.append(item)
                if len(batch) >= WRITE_BATCH_SIZE:
                    self._flush_batch(batch); batch.clear()
            except queue.Empty:
                if batch:
                    self._flush_batch(batch); batch.clear()

    def _flush_batch(self, items):
        target = rotate_if_needed(self.image_path)
        if target != self.image_path:
            self.image_path = target
        try:
            img = Image.open(self.image_path)
            exif_blob = img.info.get("exif")
            ex = piexif.load(exif_blob) if exif_blob else {"0th": {}}
            existing = ex["0th"].get(APP_EXIF_KEY, b"").decode("utf-8", errors="ignore")
            payload = (existing + ("\n" if existing else "") + "\n".join(items)).encode("utf-8")
            ex["0th"][APP_EXIF_KEY] = payload
            img.save(self.image_path, exif=piexif.dump(ex))
        except Exception:
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = SecretCalculator(root)
    root.mainloop()
