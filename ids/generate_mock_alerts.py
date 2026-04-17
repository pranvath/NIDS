import sys
import random
import time
import datetime
from sqlalchemy.orm import Session
from backend.database import SessionLocal, Alert, engine, Base

# Ensure the tables are created
Base.metadata.create_all(bind=engine)

db = SessionLocal()

alert_types = ["SYN Flood", "Port Scan", "Malware Payload", "Data Exfiltration (ML Anomaly)"]
severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
source_ips = ["192.168.1.100", "10.0.0.5", "172.16.0.50", "203.0.113.42", "198.51.100.22"]
dest_ips = ["10.194.125.1", "10.194.125.2", "10.194.125.3"]

print("Generating 50 mock alerts...")

for _ in range(50):
    a_type = random.choice(alert_types)
    sev = "HIGH" if a_type in ["SYN Flood", "Malware Payload"] else random.choice(severities)
    
    alert = Alert(
        src_ip=random.choice(source_ips),
        dst_ip=random.choice(dest_ips),
        dst_port=random.randint(1, 65535),
        alert_type=a_type,
        severity=sev,
        description=f"Generated mock alert for {a_type} detected.",
        timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=random.randint(1, 60))
    )
    db.add(alert)

db.commit()
db.close()

print("Mock alerts inserted successfully! Check your Streamlit dashboard.")
