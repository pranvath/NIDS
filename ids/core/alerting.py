import os
from datetime import datetime
from backend.database import SessionLocal, Alert

def init_log_file():
    """Initializes the database connection (SQLAlchemy handles tables)."""
    print("[INFO] Core Alert engine connected to SQLite Database Backend.")

def trigger_alert(src_ip, dst_ip, dst_port, alert_type, severity, description):
    """
    Logs an alert to the secure SQLite database via SQLAlchemy.
    """
    timestamp = datetime.utcnow()
    
    # Write robustly to local DB instead of a fragile CSV lock file
    try:
        db = SessionLocal()
        new_alert = Alert(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            alert_type=alert_type,
            severity=severity,
            description=description
        )
        db.add(new_alert)
        db.commit()
    except Exception as e:
        print(f"[!] Warning: Could not commit alert to DB: {e}")
    finally:
        db.close()
        
    # Console output with ANSI escape codes
    if severity.upper() == "HIGH":
        color = "\033[91m" # Red
    elif severity.upper() == "MEDIUM":
        color = "\033[93m" # Yellow
    else:
        color = "\033[94m" # Blue
        
    reset = "\033[0m"
    
    print(f"{color}[ALERT] {timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {alert_type} (Sev: {severity}) | {src_ip} -> {dst_ip}:{dst_port} | {description}{reset}")
