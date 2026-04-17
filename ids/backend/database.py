from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
import datetime

DATABASE_URL = "sqlite:///./nids_alerts.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    alert_type = Column(String)
    severity = Column(String)
    description = Column(String)

# Initialize the Database
Base.metadata.create_all(bind=engine)
