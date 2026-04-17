import argparse
import sys
from core.alerting import init_log_file

# Import sniffer inside to avoid Scapy overhead just for help menu
def main():
    parser = argparse.ArgumentParser(description="Real-Time Network Intrusion Detection System")
    parser.add_argument('-i', '--interface', type=str, help='Network interface to sniff on (e.g., Ethernet, Wi-Fi)')
    args = parser.parse_args()

    # Initialize logging system
    print("[*] Initializing Logging System...")
    init_log_file()
    
    # Import here to ensure logging is clean before Scapy spam
    from core.sniffer import start_sniffing

    # Start packet capture and engines
    if args.interface:
        print(f"[*] Starting IDS on interface: {args.interface}")
        start_sniffing(interface=args.interface)
    else:
        print("[*] Starting IDS on all available interfaces (default)")
        start_sniffing()

if __name__ == "__main__":
    # Ensure elevated privileges might be needed for scapy
    main()
