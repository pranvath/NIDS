from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from .database import SessionLocal, Alert
from contextlib import asynccontextmanager

app = FastAPI(title="Network IDS Telemetry API")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/api/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()
    return [
        {
            "Severity": a.severity,
            "Source_IP": a.src_ip,
            "Alert_Type": a.alert_type,
            "Description": a.description,
            "Destination_IP": a.dst_ip,
            "Destination_Port": a.dst_port,
            "Timestamp": a.timestamp.isoformat()
        }
        for a in alerts
    ]
