from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime


class User(Base):
    __tablename__ = "accounts"   # or "users" — your real table name
    id = Column(Integer, primary_key=True, index=True)
    fullname = Column(String(100))   # FIXED
    age = Column(Integer)
    email = Column(String(100), unique=True)
    hashed_password = Column(String(255))



class Patient(Base):
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    age = Column(Integer)
    gender = Column(String(10))


class HealthRecord(Base):
    __tablename__ = "health_records"

    id = Column(Integer, primary_key=True, index=True)
    heart_rate = Column(Integer)
    spo2 = Column(Integer)
    glucose = Column(Integer, nullable=True)
    temperature = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.now)
    patient_id = Column(Integer, ForeignKey("patients.id"))


class SensorReading(Base):
    __tablename__ = "sensor_readings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    heart_rate = Column(Float)
    spo2 = Column(Float)
    ir = Column(Integer)
    red = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
