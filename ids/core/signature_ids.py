import time
from collections import defaultdict
from core.alerting import trigger_alert

DOS_PACKET_THRESHOLD = 50       # packets per second
DOS_TIME_WINDOW = 1.0           # second

PORT_SCAN_THRESHOLD = 15        # unique ports
PORT_SCAN_WINDOW = 3.0          # seconds

class SignatureEngine:
    def __init__(self):
        # src_ip -> list of timestamps
        self.packet_history = defaultdict(list)
        # src_ip -> list of (timestamp, dst_port)
        self.port_scan_history = defaultdict(list)
        
    def check_signatures(self, packet_info):
        """
        Takes parsed packet dictionary and checks for known signatures like DoS and Port Scanning.
        """
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        
        if not src_ip or not dst_ip:
            return
            
        current_time = time.time()
        
        # --- Check for DoS ---
        self.packet_history[src_ip].append(current_time)
        self.packet_history[src_ip] = [t for t in self.packet_history[src_ip] if current_time - t <= DOS_TIME_WINDOW]
        
        if len(self.packet_history[src_ip]) > DOS_PACKET_THRESHOLD:
            trigger_alert(
                src_ip, dst_ip, dst_port,
                alert_type="Denial of Service (DoS)",
                severity="HIGH",
                description=f"High packet rate: {len(self.packet_history[src_ip])} pkts/{int(DOS_TIME_WINDOW)}s"
            )
            # Clear history to avoid rapid duplicate alerts
            self.packet_history[src_ip] = []
            
        # --- Check for Port Scanning ---
        if dst_port:
            self.port_scan_history[src_ip].append((current_time, dst_port))
            self.port_scan_history[src_ip] = [(t, p) for t, p in self.port_scan_history[src_ip] if current_time - t <= PORT_SCAN_WINDOW]
            
            unique_ports = set(p for t, p in self.port_scan_history[src_ip])
            if len(unique_ports) > PORT_SCAN_THRESHOLD:
                trigger_alert(
                    src_ip, dst_ip, "Multiple",
                    alert_type="Port Scan",
                    severity="MEDIUM",
                    description=f"Scanned {len(unique_ports)} unique ports in {int(PORT_SCAN_WINDOW)}s"
                )
                self.port_scan_history[src_ip] = []
