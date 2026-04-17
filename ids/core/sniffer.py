from collections import defaultdict, deque
import datetime
import re
import argparse
from scapy.all import IP, TCP, UDP, ICMP, Raw, DNSQR, conf, sniff

class Alert:
    def __init__(self, severity, signature, src_ip, dst_ip, details):
        self.timestamp = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
        self.severity = severity
        self.signature = signature
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.details = details

    def __str__(self):
        return f"[{self.timestamp}] {self.severity} | {self.signature} | {self.src_ip} -> {self.dst_ip} | {self.details}"


class NIDSEngine:
    def __init__(self, log_file=None):
        self.log_file = log_file
        self.blacklisted_ips = {
            "198.51.100.10",
            "203.0.113.20",
        }
        self.scan_history = defaultdict(lambda: deque())
        self.message_patterns = [
            re.compile(r"(union\s+select|select\s+.*from|drop\s+table|--|;|\bexec\b|\bshutdown\b)", re.I),
            re.compile(r"(\bpassword\b|\bpasswd\b|\bpasswd=|\blogin\b|\badmin\b)", re.I),
            re.compile(r"(\balert\(|\beval\(|\bsystem\(|\bping\b|\bcurl\b|\bwget\b)", re.I),
        ]

    def log_alert(self, alert):
        print(alert)
        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(str(alert) + "\n")

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if self.is_blacklisted_ip(src_ip) or self.is_blacklisted_ip(dst_ip):
            self.log_alert(Alert("HIGH", "Blacklisted IP", src_ip, dst_ip, "Traffic matched known bad host."))

        if packet.haslayer(TCP):
            self.detect_tcp(packet, src_ip, dst_ip)
        elif packet.haslayer(UDP):
            self.detect_udp(packet, src_ip, dst_ip)
        elif packet.haslayer(ICMP):
            self.detect_icmp(packet, src_ip, dst_ip)

    def is_blacklisted_ip(self, ip_address):
        return ip_address in self.blacklisted_ips

    def detect_tcp(self, packet, src_ip, dst_ip):
        tcp = packet[TCP]
        if tcp.flags & 0x02:
            self.detect_port_scan(src_ip, dst_ip, tcp.dport)

        if tcp.dport in {80, 8080, 8000} or tcp.sport in {80, 8080, 8000}:
            self.detect_http(packet, src_ip, dst_ip)

        if tcp.dport == 22 or tcp.sport == 22:
            self.detect_ssh_bruteforce(src_ip, dst_ip)

    def detect_udp(self, packet, src_ip, dst_ip):
        udp = packet[UDP]
        if udp.dport == 53 or udp.sport == 53:
            self.detect_dns(packet, src_ip, dst_ip)
        if udp.dport == 123 or udp.sport == 123:
            self.log_alert(Alert("MEDIUM", "NTP Traffic", src_ip, dst_ip, "UDP NTP traffic observed."))

    def detect_icmp(self, packet, src_ip, dst_ip):
        icmp = packet[ICMP]
        if packet.haslayer(Raw):
            size = len(packet[Raw].load)
            if size > 100:
                self.log_alert(Alert("MEDIUM", "Suspicious ICMP Payload", src_ip, dst_ip, f"ICMP payload size={size}"))

    def detect_port_scan(self, src_ip, dst_ip, dport):
        now = datetime.datetime.now().timestamp()
        history = self.scan_history[src_ip]
        history.append((now, dport))
        while history and now - history[0][0] > 10:
            history.popleft()
        ports = {entry[1] for entry in history}
        if len(ports) >= 10 and len(history) >= 12:
            self.log_alert(Alert("HIGH", "Port Scan", src_ip, dst_ip, f"{len(ports)} distinct ports in 10s"))
            history.clear()

    def detect_http(self, packet, src_ip, dst_ip):
        if not packet.haslayer(Raw):
            return
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return

        if "HTTP" not in payload and "GET" not in payload and "POST" not in payload:
            return

        if any(pattern.search(payload) for pattern in self.message_patterns):
            self.log_alert(Alert("HIGH", "HTTP Injection", src_ip, dst_ip, "Potential SQLi/XSS in HTTP payload."))

        if "Authorization:" in payload and "Basic" in payload:
            self.log_alert(Alert("MEDIUM", "HTTP Basic Auth", src_ip, dst_ip, "Unencrypted HTTP credentials detected."))

        if "User-Agent:" in payload and "sqlmap" in payload.lower():
            self.log_alert(Alert("HIGH", "Malicious User-Agent", src_ip, dst_ip, "Automated scanner detected."))

    def detect_dns(self, packet, src_ip, dst_ip):
        if not packet.haslayer(DNSQR):
            return

        qname = packet[DNSQR].qname.decode(errors="ignore") if isinstance(packet[DNSQR].qname, bytes) else str(packet[DNSQR].qname)
        labels = qname.strip().split('.')
        if len(qname) > 80 or len(labels) > 8:
            self.log_alert(Alert("HIGH", "DNS Exfiltration", src_ip, dst_ip, f"Long or deep DNS query: {qname}"))

        if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", qname):
            self.log_alert(Alert("HIGH", "DNS Data Exfiltration", src_ip, dst_ip, f"Encoded data in DNS query: {qname}"))

        suspicious_domains = ["example-malware.com", "bad-domain.local", "malicious-service.net"]
        if any(domain in qname.lower() for domain in suspicious_domains):
            self.log_alert(Alert("HIGH", "Malicious DNS Query", src_ip, dst_ip, f"Query matched suspicious domain: {qname}"))

    def detect_ssh_bruteforce(self, src_ip, dst_ip):
        self.log_alert(Alert("MEDIUM", "SSH Activity", src_ip, dst_ip, "SSH connection observed."))


def parse_args():
    parser = argparse.ArgumentParser(description="Real-time network intrusion detection using Scapy")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff")
    parser.add_argument("--log", "-l", default="nids_alerts.log", help="Alert log file")
    parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    return parser.parse_args()


def start_sniffing(interface=None, log_file="nids_alerts.log", count=0):
    if interface:
        conf.iface = interface

    engine = NIDSEngine(log_file=log_file)
    print(f"Starting real-time NIDS...")
    if interface:
        print(f"Listening on interface: {interface}")
    print(f"Alerts will be logged to: {log_file}")
    print("Press CTRL+C to stop.")

    # Scapy sniffer
    sniff(prn=engine.process_packet, store=False, count=count)

if __name__ == "__main__":
    args = parse_args()
    start_sniffing(interface=args.interface, log_file=args.log, count=args.count)
